//! WebSocket handler for the mediator server.
//!
//! Provides an Axum-compatible WebSocket upgrade handler that integrates
//! with the handler registry and live session manager for push delivery.

use crate::app::MediatorApp;
use axum::{
    extract::{
        ws::{Message as AxumWsMsg, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Capacity of the per-WS push channel. Fix 4B: raised from 64 to 1024 so a
/// fast streaming sync session (browser-sync full-state push) doesn't trip
/// the live-channel timeout in `forward_service::deliver_or_drop`. Bounded
/// rather than unbounded — a misbehaving / slow client must NOT be able to
/// pin arbitrary memory.
const WS_PUSH_CHANNEL_CAP: usize = 1024;
const MAX_DIDCOMM_MESSAGE_SIZE_BYTES: usize = 512 * 1024;

/// Fix 4A: WS-level ping interval — keeps iOS App Nap and macOS suspend from
/// silently reclaiming the socket during quiet periods. Picked under the
/// ~30s OS-suspend threshold.
const WS_PING_INTERVAL: Duration = Duration::from_secs(25);

/// Spawn a non-blocking reconnect-replay flush (Fix 1B). Runs the
/// forward-service flush in a detached tokio task so the WS read loop can
/// continue processing inbound frames while queued messages drain over the
/// new live session.
fn spawn_reconnect_flush(app: Arc<MediatorApp>, connection_id: String) {
    tokio::spawn(async move {
        match app
            .forward_service
            .flush_queued_for_connection(&connection_id)
            .await
        {
            Ok(0) => {}
            Ok(n) => {
                app.metrics.reconnect_replay_total.inc();
                app.metrics.reconnect_replay_messages_total.inc_by(n as u64);
                tracing::info!(
                    connection_id = %connection_id,
                    delivered = n,
                    "[WS] reconnect-replay drained queued messages"
                );
            }
            Err(e) => tracing::warn!(
                connection_id = %connection_id,
                error = %e,
                "[WS] reconnect-replay failed"
            ),
        }
    });
}

/// Axum handler for WebSocket upgrade requests.
///
/// Usage in router:
/// ```ignore
/// .route("/ws", get(handle_ws_upgrade))
/// ```
pub async fn handle_ws_upgrade(
    ws: WebSocketUpgrade,
    State(app): State<Arc<MediatorApp>>,
) -> impl IntoResponse {
    tracing::info!("WS upgrade requested at /ws");
    ws.on_upgrade(move |socket| handle_ws_connection(socket, app))
}

/// Per-connection WebSocket handler.
///
/// - Reads incoming DIDComm text frames and routes them through the handler registry
/// - When a connection_id is established (first successful DIDComm exchange),
///   registers in LiveSessionManager for push delivery
/// - Forwards push messages from the live session channel to the WS client
async fn handle_ws_connection(socket: WebSocket, app: Arc<MediatorApp>) {
    tracing::info!("WS connection established");
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Channel for push delivery from LiveSessionManager (Fix 4B: 1024 cap).
    let (push_tx, mut push_rx) = mpsc::channel::<String>(WS_PUSH_CHANNEL_CAP);
    // Parallel binary-frame channel — the DCX opaque-relay path
    // (`LiveSessionManager::try_deliver_binary`) pushes encrypted
    // frames here; the push_task select branch below emits them as WS
    // Binary frames. Same cap as the text channel; matched buffer keeps
    // burst tolerance symmetric.
    let (push_bin_tx, mut push_bin_rx) = mpsc::channel::<Vec<u8>>(WS_PUSH_CHANNEL_CAP);

    // Track connection_id once established
    let connection_id: Arc<tokio::sync::RwLock<Option<String>>> =
        Arc::new(tokio::sync::RwLock::new(None));

    let conn_id_clone = connection_id.clone();
    let app_clone = app.clone();

    // Spawn task to forward push messages to the WebSocket client. Also
    // emits periodic protocol-level Ping frames (Fix 4A) so the OS doesn't
    // silently reclaim the socket during quiet periods.
    let metrics_for_push = app_clone.metrics.clone();
    let push_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval(WS_PING_INTERVAL);
        // Skip the immediate tick — we want the FIRST ping at +25s, not 0s.
        ping_interval.tick().await;
        loop {
            tokio::select! {
                maybe_msg = push_rx.recv() => {
                    match maybe_msg {
                        Some(msg) => {
                            if ws_sender.send(AxumWsMsg::Text(msg)).await.is_err() {
                                break;
                            }
                        }
                        None => break, // all senders dropped
                    }
                }
                maybe_bin = push_bin_rx.recv() => {
                    match maybe_bin {
                        Some(bin) => {
                            if ws_sender.send(AxumWsMsg::Binary(bin)).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                _ = ping_interval.tick() => {
                    if ws_sender.send(AxumWsMsg::Ping(Vec::new())).await.is_err() {
                        break;
                    }
                    metrics_for_push.ws_ping_sent_total.inc();
                    tracing::trace!("[WS] sent keepalive Ping");
                }
            }
        }
    });

    // Local cache for connection_id — avoids RwLock read on every message
    let mut local_conn_id: Option<String> = None;

    // Read loop: process incoming DIDComm messages
    while let Some(msg_result) = ws_receiver.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(target: "ws.diag", error = %e, "WebSocket read error / connection ended");
                break;
            }
        };

        // DIAG: log every frame type that arrives so we can see what
        // Implicit-mode clients (credo trust_ping, live-delivery-change)
        // are actually transmitting. Behind tracing::debug! so prod
        // stderr stays quiet; enable with `RUST_LOG=ws.diag=debug`.
        if tracing::enabled!(target: "ws.diag", tracing::Level::DEBUG) {
            let frame_kind = match &msg {
                AxumWsMsg::Text(t) => format!("Text len={}", t.len()),
                AxumWsMsg::Binary(b) => format!("Binary len={}", b.len()),
                AxumWsMsg::Ping(p) => format!("Ping len={}", p.len()),
                AxumWsMsg::Pong(p) => format!("Pong len={}", p.len()),
                AxumWsMsg::Close(_) => "Close".to_string(),
            };
            tracing::debug!(target: "ws.diag", frame = %frame_kind, "frame received");
        }

        // Normalize Binary → Text. RFC 6455 allows either, and credo-ts's
        // WsOutboundTransport sends DIDComm JWEs as Binary frames. DIDComm
        // payloads are always JSON, hence valid UTF-8 — converting is
        // safe.
        //
        // NOTE: the DCX opaque-relay router is not part of this minimal
        // mediator build. All binary frames are treated as JSON-in-binary
        // DIDComm envelopes.
        let msg = match msg {
            AxumWsMsg::Binary(bin) => match String::from_utf8(bin.to_vec()) {
                Ok(s) => AxumWsMsg::Text(s),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "WS Binary frame is not valid UTF-8, dropping"
                    );
                    continue;
                }
            },
            other => other,
        };

        match msg {
            AxumWsMsg::Text(text) => {
                let text_str: &str = &text;
                if text_str.is_empty() {
                    continue;
                }

                if text_str.len() > MAX_DIDCOMM_MESSAGE_SIZE_BYTES {
                    tracing::warn!(
                        size = text_str.len(),
                        max = MAX_DIDCOMM_MESSAGE_SIZE_BYTES,
                        "WebSocket DIDComm message too large"
                    );
                    break;
                }

                // Parse as JSON to detect format
                let json: serde_json::Value = match serde_json::from_str(text_str) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "Invalid JSON on WebSocket");
                        continue;
                    }
                };

                // Detect JWE (encrypted): has "protected" + "ciphertext" fields
                let is_jwe = json.get("protected").is_some() && json.get("ciphertext").is_some();

                // ═══ FAST PATH: Direct-route JWE without crypto ═══
                // If the JWE recipient kid is in the keylist, this message is for
                // a mediated agent — forward opaque bytes without unpacking.
                // This is the 10x performance lever: ~7us vs ~250us per message.
                if is_jwe {
                    let jwe_kids = crate::routes::extract_jwe_recipient_kids(&json);
                    if !jwe_kids.is_empty() {
                        use protocol_coordinate_mediation::KeylistRepositoryTrait;
                        let mut matched_kid: Option<String> = None;
                        for kid in &jwe_kids {
                            if let Ok(Some(_)) = app_clone
                                .keylist_repo
                                .find_mediation_for_recipient_key(kid)
                                .await
                            {
                                matched_kid = Some(kid.clone());
                                break;
                            }
                            if kid.starts_with("did:key:z") {
                                let stripped = kid.strip_prefix("did:key:z").unwrap_or(kid);
                                if let Ok(decoded) = bs58::decode(stripped).into_vec() {
                                    if decoded.len() > 2 {
                                        let raw_verkey = bs58::encode(&decoded[2..]).into_string();
                                        if let Ok(Some(_)) = app_clone
                                            .keylist_repo
                                            .find_mediation_for_recipient_key(&raw_verkey)
                                            .await
                                        {
                                            matched_kid = Some(raw_verkey);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(ref kid) = matched_kid {
                            // Direct-route: forward opaque JWE without crypto.
                            // Offload onto the data-plane runtime so a slow/
                            // wedged forward can't head-of-line-block this
                            // socket read loop or starve the axum runtime that
                            // serves health/login. Awaiting the JoinHandle
                            // PARKS this task (frees the worker) rather than
                            // blocking it.
                            let fs = app_clone.forward_service.clone();
                            let kid_owned = kid.clone();
                            let text_owned = text_str.to_string();
                            let fr_ok =
                                match app_clone
                                    .data_handle
                                    .spawn(async move {
                                        fs.process_forward(&kid_owned, &text_owned).await
                                    })
                                    .await
                                {
                                    Ok(Ok(_)) => {
                                        tracing::debug!("[WS-FAST] Direct-routed JWE to mediated agent (zero crypto)");
                                        true
                                    }
                                    Ok(Err(e)) => {
                                        tracing::warn!("[WS-FAST] Direct-route failed: {}", e);
                                        false
                                    }
                                    Err(join_err) => {
                                        tracing::error!(error = %join_err, "[WS-FAST] forward task panicked");
                                        false
                                    }
                                };
                            // Fix 4C: forward outcome metric.
                            app_clone
                                .metrics
                                .forward_total
                                .with_label_values(&[if fr_ok { "success" } else { "error" }])
                                .inc();

                            // Resolve connection_id from sender skid for session tracking
                            if local_conn_id.is_none() {
                                if let Some(skid) = crate::routes::extract_jwe_sender_skid(&json) {
                                    // Canonical did:key→base58 conversion; falls back to the
                                    // raw skid when it isn't a did:key (behaviour-identical to
                                    // the old inline decode).
                                    let raw = did::methods::key::did_key_to_base58_verkey(&skid)
                                        .unwrap_or_else(|| skid.clone());
                                    if let Some(conn_id) =
                                        crate::routes::resolve_connection_id(&app_clone, &raw).await
                                    {
                                        local_conn_id = Some(conn_id.clone());
                                        *conn_id_clone.write().await = Some(conn_id.clone());
                                        app_clone
                                            .live_sessions
                                            .register_session_with_sender(&conn_id, push_tx.clone())
                                            .await;
                                        app_clone
                                            .live_sessions
                                            .register_binary_sender(&conn_id, push_bin_tx.clone())
                                            .await;
                                        // Mediation records may key by raw verkey instead of UUID
                                        // (when DIDExchange-time resolve_connection_id failed).
                                        // Register under both so forward_service finds the live session.
                                        if conn_id != raw {
                                            app_clone
                                                .live_sessions
                                                .register_session_with_sender(&raw, push_tx.clone())
                                                .await;
                                            app_clone
                                                .live_sessions
                                                .register_binary_sender(&raw, push_bin_tx.clone())
                                                .await;
                                        }
                                        tracing::info!(connection_id = %conn_id, verkey = %raw, "WS connection identified via fast path");
                                        // Reconnect-replay (Fix 1B): flush any queued messages
                                        // that arrived while this connection's WS was down. Done
                                        // in a spawned task so the WS read loop doesn't block.
                                        spawn_reconnect_flush(app_clone.clone(), conn_id.clone());
                                        if conn_id != raw {
                                            spawn_reconnect_flush(app_clone.clone(), raw.clone());
                                        }
                                    }
                                }
                            }
                            continue; // Skip full unpack — message already routed
                        }
                    }
                }

                // Extract recipient kids from the JWE envelope BEFORE we move
                // into the branch — we need them later for the
                // `context.to` fallback when DIDComm v1 leaves the
                // plaintext `to` empty.
                let ws_kids: Vec<String> = if is_jwe {
                    crate::routes::extract_jwe_recipient_kids(&json)
                } else {
                    Vec::new()
                };

                // ═══ SLOW PATH: Full unpack for mediator-addressed messages ═══
                // (mediation-request, keylist-update, pickup, rooms protocol)
                let (didcomm_msg, sender_did, is_encrypted, is_authenticated) = if is_jwe {
                    tracing::debug!(?ws_kids, "JWE for mediator on WebSocket, unpacking");
                    match app_clone.envelope_service.unpack(text_str).await {
                        Ok((msg, metadata)) => {
                            let sender = metadata.from.clone();
                            let encrypted = metadata.encrypted;
                            let authenticated = metadata.authenticated;
                            tracing::info!(
                                msg_type = %msg.msg_type,
                                from = ?sender,
                                encrypted,
                                authenticated,
                                "Unpacked JWE DIDComm message on WebSocket"
                            );
                            (msg, sender, encrypted, authenticated)
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to unpack JWE on WebSocket");
                            continue;
                        }
                    }
                } else {
                    // Plaintext — parse directly
                    match serde_json::from_value::<didcomm::core::Message>(json) {
                        Ok(msg) => {
                            let sender = msg.from.clone();
                            (msg, sender, false, false)
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Invalid DIDComm message on WebSocket"
                            );
                            continue;
                        }
                    }
                };

                let msg_type = didcomm_msg.msg_type.clone();

                // Resolve sender verkey to connection UUID (same as HTTP handler)
                let resolved_connection_id = if let Some(ref raw_key) = sender_did {
                    crate::routes::resolve_connection_id(&app_clone, raw_key)
                        .await
                        .or_else(|| Some(raw_key.clone()))
                } else {
                    None
                };

                // Cache connection_id locally after first resolution (avoids RwLock per message)
                if local_conn_id.is_none() {
                    if let Some(ref resolved_id) = resolved_connection_id {
                        tracing::info!(
                            connection_id = resolved_id,
                            "WebSocket connection identified via verkey resolution"
                        );
                        local_conn_id = Some(resolved_id.clone());
                        // Also store in shared state for cleanup on disconnect
                        *conn_id_clone.write().await = Some(resolved_id.clone());
                        app_clone
                            .live_sessions
                            .register_session_with_sender(resolved_id, push_tx.clone())
                            .await;
                        app_clone
                            .live_sessions
                            .register_binary_sender(resolved_id, push_bin_tx.clone())
                            .await;
                        // Mediation records may key by raw verkey instead of UUID.
                        // Register under both so forward_service can find the live session.
                        if let Some(ref raw) = sender_did {
                            if raw != resolved_id {
                                app_clone
                                    .live_sessions
                                    .register_session_with_sender(raw, push_tx.clone())
                                    .await;
                                app_clone
                                    .live_sessions
                                    .register_binary_sender(raw, push_bin_tx.clone())
                                    .await;
                            }
                        }
                        // Reconnect-replay (Fix 1B).
                        spawn_reconnect_flush(app_clone.clone(), resolved_id.clone());
                        if let Some(ref raw) = sender_did {
                            if raw != resolved_id {
                                spawn_reconnect_flush(app_clone.clone(), raw.clone());
                            }
                        }
                    }
                }

                // For DIDComm v1 the plaintext `to` field is empty (recipient
                // identity only lives in the JWE envelope). Mirror the HTTP
                // route's behaviour by falling back to the JWE recipient_kid
                // when `didcomm_msg.to` is missing, so handlers like
                // V2StatusHandler get the correct per-connection key as
                // `response.from`. Without this fallback the slow path
                // ends up packing responses with the GLOBAL `mediator_did`
                // instead of the per-connection pairwise, and clients (e.g.
                // credo's `assertReadyConnection`) reject the inbound with
                // "No connection associated with incoming message".
                let recipient_kid_fallback: Option<String> = ws_kids.first().cloned();

                // Build inbound context using local cache (zero locks on hot path)
                let inbound = didcomm::messaging::InboundMessage {
                    message: didcomm_msg.clone(),
                    context: didcomm::messaging::MessageContext {
                        from: didcomm_msg.from.clone().or(sender_did.clone()),
                        to: didcomm_msg
                            .to
                            .as_ref()
                            .and_then(|t| t.first())
                            .cloned()
                            .or(recipient_kid_fallback),
                        thread_id: didcomm_msg
                            .thread
                            .as_ref()
                            .and_then(|t| t.thid.clone())
                            .or_else(|| Some(didcomm_msg.id.clone())),
                        parent_thread_id: didcomm_msg.pthid.clone(),
                        // SECURITY: authorization principal from the
                        // cryptographically-resolved sender ONLY (the cached
                        // per-WS identity or this message's authcrypt verkey) —
                        // never the unauthenticated `from`, which an attacker
                        // could set to a victim's connection. Non-authcrypt
                        // messages resolve to None and are dropped by the
                        // sensitive-type gate below.
                        connection_id: local_conn_id.clone().or(resolved_connection_id),
                        encrypted: is_encrypted,
                        authenticated: is_authenticated,
                        sender_endpoint: None,
                        raw_plaintext: None,
                    },
                };

                // SECURITY GATE (mirrors the HTTP route): sensitive types
                // (mediation/keylist, pickup, room fan-out) must be authcrypted.
                // Drop plaintext/anoncrypt forgeries with a spoofed sender.
                if crate::routes::requires_authcrypt(&msg_type) && !inbound.context.authenticated {
                    tracing::warn!(
                        msg_type = %msg_type,
                        "Dropping unauthenticated sensitive message on WS (authcrypt required)"
                    );
                    continue;
                }

                // Route to handler (registry is immutable — no lock needed)
                if let Some(handler) = app_clone.handler_registry.get_handler(&msg_type) {
                    // Offload handler execution onto the data-plane runtime so a
                    // wedged handler parks this task (frees the axum worker)
                    // instead of starving health/login. Response packing below
                    // stays inline (bounded crypto + try_send).
                    let handled = match app_clone
                        .data_handle
                        .spawn(async move { handler.handle(inbound).await })
                        .await
                    {
                        Ok(r) => r,
                        Err(join_err) => {
                            tracing::error!(msg_type = %msg_type, error = %join_err, "WS handler task panicked");
                            continue;
                        }
                    };
                    match handled {
                        Ok(Some(response)) => {
                            // If handler returned a response, check if it reveals connection_id
                            if let Some(cid) = &response.connection_id {
                                let mut conn = conn_id_clone.write().await;
                                if conn.is_none() {
                                    tracing::info!(
                                        connection_id = cid,
                                        "WebSocket connection identified"
                                    );
                                    *conn = Some(cid.clone());

                                    // Register live session
                                    app_clone
                                        .live_sessions
                                        .register_session_with_sender(cid, push_tx.clone())
                                        .await;
                                    app_clone
                                        .live_sessions
                                        .register_binary_sender(cid, push_bin_tx.clone())
                                        .await;
                                    // Reconnect-replay (Fix 1B).
                                    spawn_reconnect_flush(app_clone.clone(), cid.clone());
                                }
                            }

                            // Send response back via push channel
                            // Pack as JWE if original was encrypted and sender is known
                            let response_str = if is_jwe {
                                if let Some(ref to_did) = sender_did {
                                    let is_v1 = !to_did.starts_with("did:");
                                    let recipient_did = crate::routes::ensure_did_key(to_did);
                                    // Use the per-connection sender DID set by the
                                    // handler (rotated peer DID from DIDExchange).
                                    let sender_for_pack = if !response.from.is_empty() {
                                        crate::routes::ensure_did_key(&response.from)
                                    } else {
                                        app_clone.mediator_did.clone()
                                    };
                                    let pack_result = if is_v1 {
                                        let opts = didcomm::core::version::PackOptions {
                                            version: didcomm::core::version::DIDCommVersion::V1Only,
                                            protect_sender: true,
                                            sign_message: false,
                                        };
                                        app_clone
                                            .envelope_service
                                            .pack_encrypted_with_version(
                                                &response.message,
                                                &recipient_did,
                                                Some(&sender_for_pack),
                                                &opts,
                                            )
                                            .await
                                    } else {
                                        app_clone
                                            .envelope_service
                                            .pack_encrypted(
                                                &response.message,
                                                &recipient_did,
                                                Some(&sender_for_pack),
                                                None,
                                            )
                                            .await
                                    };
                                    match pack_result {
                                        Ok(packed) => packed,
                                        Err(e) => {
                                            tracing::warn!(
                                                error = %e,
                                                "Failed to pack WS response as JWE, falling back to plaintext"
                                            );
                                            serde_json::to_string(&response.message)
                                                .unwrap_or_default()
                                        }
                                    }
                                } else {
                                    // No sender DID — return plaintext
                                    serde_json::to_string(&response.message).unwrap_or_default()
                                }
                            } else {
                                serde_json::to_string(&response.message).unwrap_or_default()
                            };

                            if let Err(e) = push_tx.try_send(response_str) {
                                // Channel full or closed — the client can still
                                // fetch the response via Pickup, so this is not
                                // fatal, but log it so a wedged/slow socket is
                                // visible instead of silently dropping replies.
                                tracing::debug!(
                                    msg_type = %msg_type,
                                    error = %e,
                                    "WS response push failed (channel full/closed)"
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(
                                msg_type = msg_type,
                                error = %e,
                                "WS handler error"
                            );
                        }
                    }
                } else {
                    tracing::debug!(msg_type = msg_type, "No handler for WS message type");
                }
            }
            AxumWsMsg::Close(_) => break,
            AxumWsMsg::Ping(_) => {
                // Fix 4A: axum/tokio-tungstenite auto-pongs at the framing
                // layer before we observe the Ping here, so we have nothing
                // to send back. Just log + keep reading.
                tracing::trace!("[WS] inbound Ping (auto-ponged by transport)");
            }
            AxumWsMsg::Pong(_) => {
                // Client responded to our keepalive Ping. Nothing to do —
                // the connection is healthy.
                tracing::trace!("[WS] inbound Pong");
            }
            // Binary frames are handled earlier (DCX router → UTF-8
            // fallback), so they can't reach this arm. Any other
            // frame kind is a raw control frame — drop safely.
            _ => {}
        }
    }

    // Cleanup: remove live session
    let conn = connection_id.read().await;
    if let Some(cid) = conn.as_ref() {
        app.live_sessions.remove_session(cid).await;
        tracing::info!(
            connection_id = cid,
            "WebSocket disconnected, session removed"
        );
    }

    push_task.abort();
}
