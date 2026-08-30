//! HTTP routes for the mediator server.

use crate::app::MediatorApp;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

const MAX_DIDCOMM_MESSAGE_SIZE_BYTES: usize = 512 * 1024;

/// How long an HTTP request that requested `return_route: "all"` waits for the
/// recipient's inline response before falling back to a fire-and-forget ACK.
const RETURN_ROUTE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Buffer size of the per-request return-route live-session channel. Only one
/// response is expected per request, so a small buffer suffices.
const RETURN_ROUTE_CHANNEL_CAP: usize = 10;

/// Build the Axum router with all mediator routes
pub fn build_router(app: Arc<MediatorApp>) -> Router {
    let public_router = Router::new()
        .route("/", post(handle_didcomm_message))
        .route("/health", get(handle_health))
        .route("/invite", get(handle_invite))
        .route("/ws", get(crate::ws::handle_ws_upgrade))
        // Prometheus metrics. No auth — bind to localhost or
        // network-policy-restrict in production.
        .route("/metrics", get(handle_metrics))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_DIDCOMM_MESSAGE_SIZE_BYTES,
        ));

    public_router.with_state(app)
}

/// POST / — DIDComm message handler
///
/// Accepts both JWE-encrypted and plaintext DIDComm messages.
/// JWE messages are unpacked via EnvelopeService, responses are packed back.
/// Plaintext messages are handled directly (for testing / backward compatibility).
async fn handle_didcomm_message(
    State(app): State<Arc<MediatorApp>>,
    body: String,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty message body".to_string()));
    }

    if body.len() > MAX_DIDCOMM_MESSAGE_SIZE_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "DIDComm message too large".to_string(),
        ));
    }

    tracing::debug!(body_len = body.len(), "Received DIDComm message");

    // Parse as JSON to detect format
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
        tracing::warn!(error = %e, "Failed to parse DIDComm message");
        (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e))
    })?;

    // Detect JWE (encrypted): has "protected" + "ciphertext" fields
    let is_jwe = json.get("protected").is_some() && json.get("ciphertext").is_some();

    // Unpack or parse directly
    let (didcomm_msg, sender_did, recipient_kid, is_encrypted, is_authenticated) = if is_jwe {
        // Fast path: check if the JWE is addressed to the mediator before
        // attempting a full unpack. The unpack's find_our_recipient() iterates
        // ALL wallet keys (O(n) crypto operations per key). For direct-routed
        // messages (addressed to a mediated agent), this is wasted work that
        // degrades as the wallet grows with connections.
        //
        // Extract the JWE recipient kid(s) and check if ANY match the
        // mediator's registered keylist entries. If a kid is in the keylist,
        // the message is for a mediated agent — skip unpack, route directly.
        let jwe_kids = extract_jwe_recipient_kids(&json);
        if !jwe_kids.is_empty() {
            // Canonicalise each kid to raw verkey and probe the keylist. Storage
            // is canonicalised on insert so a single exact-match lookup suffices
            // (mirrors Aries TS DidCommMediatorService.ts:171).
            use protocol_coordinate_mediation::KeylistRepositoryTrait;
            let mut matched_recipient_kid: Option<String> = None;
            for kid in &jwe_kids {
                let canonical = canonicalize_kid(kid);
                if let Ok(Some(_)) = app
                    .keylist_repo
                    .find_mediation_for_recipient_key(&canonical)
                    .await
                {
                    matched_recipient_kid = Some(canonical);
                    break;
                }
            }
            if let Some(ref kid) = matched_recipient_kid {
                // JWE is for a mediated agent — skip expensive unpack, route directly.
                // Pass the already-resolved kid to avoid duplicate keylist lookup.
                tracing::debug!("JWE recipient in keylist, direct-routing (skip wallet scan)");
                return direct_route_jwe(&app, &body, &json, Some(kid.clone())).await;
            }
        }

        // JWE is for the mediator — do full unpack
        tracing::debug!("Detected JWE for mediator, unpacking");
        match app.envelope_service.unpack(&body).await {
            Ok((msg, metadata)) => {
                let sender = metadata.from.clone();
                let recipient = metadata.to.clone();
                let encrypted = metadata.encrypted;
                let authenticated = metadata.authenticated;
                tracing::info!(
                    msg_type = %msg.msg_type,
                    from = ?sender,
                    to = ?recipient,
                    encrypted,
                    authenticated,
                    "Unpacked DIDComm message"
                );
                (msg, sender, recipient, encrypted, authenticated)
            }
            Err(e) => {
                // Unpack failed even though kid matched — fall through to direct routing
                tracing::debug!(error = %e, "JWE unpack failed, trying direct-routing fallback");
                return direct_route_jwe(&app, &body, &json, None).await;
            }
        }
    } else {
        // Plaintext — parse directly (for testing / backward compat)
        let msg: didcomm::core::Message = serde_json::from_value(json.clone()).map_err(|e| {
            tracing::warn!(error = %e, "Failed to parse as DIDComm Message");
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid DIDComm message: {}", e),
            )
        })?;
        let sender = msg.from.clone();
        tracing::info!(msg_type = %msg.msg_type, "Processing plaintext DIDComm message");
        (msg, sender, None, false, false)
    };

    let msg_type = didcomm_msg.msg_type.clone();

    // Resolve sender verkey to a stable connection record ID.
    // DIDComm v1 authcrypt returns the sender's raw Ed25519 verkey as sender_did.
    // We look up the connection record by matching their_authentication_key_base58
    // so that mediation-request and pickup use the same connection_id.
    let resolved_connection_id = if let Some(ref raw_key) = sender_did {
        resolve_connection_id(&app, raw_key)
            .await
            .or_else(|| Some(raw_key.clone()))
    } else {
        None
    };

    // Create inbound message with context
    // Ensure `message.from` is set — DIDComm v1 authcrypt doesn't embed `from` in
    // the plaintext, only in the JWE envelope. Handlers use `message.from` to identify
    // the sender, so we backfill from the unpack result.
    let mut msg_for_handler = didcomm_msg.clone();
    if msg_for_handler.from.is_none() {
        msg_for_handler.from = sender_did.clone();
    }

    let inbound = didcomm::messaging::InboundMessage {
        message: msg_for_handler,
        context: didcomm::messaging::MessageContext {
            from: didcomm_msg.from.clone().or(sender_did.clone()),
            // Prefer plaintext `to`; fall back to JWE recipient kid (DIDComm v1
            // doesn't carry `to` in plaintext, only in the envelope's kid).
            // Handlers like MediationRequestHandler use this as the `from` of
            // their response so the per-connection key is used for outbound packing.
            to: didcomm_msg
                .to
                .as_ref()
                .and_then(|t| t.first())
                .cloned()
                .or_else(|| recipient_kid.clone()),
            thread_id: didcomm_msg
                .thread
                .as_ref()
                .and_then(|t| t.thid.clone())
                .or_else(|| Some(didcomm_msg.id.clone())),
            parent_thread_id: didcomm_msg.pthid.clone(),
            // SECURITY: the authorization principal is derived ONLY from the
            // cryptographically-resolved sender (authcrypt verkey → connection).
            // It must NEVER come from an unauthenticated body field
            // (e.g. a `connection_id` in the message body) or the plaintext
            // `from`, either of which
            // an attacker can set to a VICTIM's connection to drain their pickup
            // queue or poison their keylist/mediation routing. On a
            // non-authcrypt message `resolved_connection_id` is None and the
            // sensitive-type gate below drops the message.
            connection_id: resolved_connection_id,
            encrypted: is_encrypted,
            authenticated: is_authenticated,
            sender_endpoint: None,
            raw_plaintext: None,
        },
    };

    // Check for return_route: "all" — register a temporary live session
    // so Forward messages for this connection get pushed immediately
    let return_route = json
        .get("~transport")
        .and_then(|t| t.get("return_route"))
        .and_then(|r| r.as_str())
        .or_else(|| {
            didcomm_msg
                .extra
                .get("~transport")
                .and_then(|t| t.get("return_route"))
                .and_then(|r| r.as_str())
        });

    // If the sender requested return-route AND doesn't already have a WS live
    // session registered, register a temporary HTTP return-route session.
    //
    // If a WS session exists, we DON'T overwrite it — the WS delivers messages
    // fine. Overwriting + removing would kill the WS session for the duration
    // of this HTTP request (or forever if cleanup happens).
    let live_rx = if return_route == Some("all") {
        if let Some(ref conn_id) = inbound.context.connection_id {
            if app.live_sessions.has_session(conn_id).await {
                // WS session already delivers — skip HTTP return-route.
                tracing::debug!(
                    connection_id = conn_id,
                    "Skipping HTTP return-route (WS session already active)"
                );
                None
            } else {
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(RETURN_ROUTE_CHANNEL_CAP);
                app.live_sessions
                    .register_session_with_sender(conn_id, tx)
                    .await;
                tracing::debug!(
                    connection_id = conn_id,
                    "Registered HTTP return-route live session"
                );
                Some((conn_id.clone(), rx))
            }
        } else {
            None
        }
    } else {
        None
    };

    // SECURITY GATE: sensitive message types (mediation/keylist mutation,
    // pickup queue drain, room fan-out whose authorization reads the sender
    // identity) MUST arrive authcrypted. A plaintext or anoncrypt message of
    // these types is dropped — this closes the "plaintext DIDComm bypasses
    // authcrypt" hole where an attacker forged pickup/keylist/rooms messages
    // with a spoofed sender. Forward + connection/OOB/DID-exchange are
    // intentionally excluded (they legitimately arrive anoncrypt).
    if requires_authcrypt(&msg_type) && !inbound.context.authenticated {
        tracing::warn!(
            msg_type = %msg_type,
            "Dropping unauthenticated sensitive message (authcrypt required)"
        );
        if let Some((ref conn_id, _)) = live_rx {
            app.live_sessions.remove_session(conn_id).await;
        }
        return Ok((StatusCode::ACCEPTED, String::new()));
    }

    // Look up handler (registry is immutable — no lock needed)
    let handler = app.handler_registry.get_handler(&msg_type);

    match handler {
        Some(h) => {
            // Offload handler execution onto the data-plane runtime so a wedged
            // handler parks this axum task (frees the worker) instead of
            // starving health/login.
            let result = match app
                .data_handle
                .spawn(async move { h.handle(inbound).await })
                .await
            {
                Ok(r) => r,
                Err(join_err) => {
                    tracing::error!(msg_type = %msg_type, error = %join_err, "HTTP handler task panicked");
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "handler task panicked".to_string(),
                    ));
                }
            };

            match result {
                Ok(Some(response)) => {
                    // Clean up return-route session — handler already produced a response
                    if let Some((ref conn_id, _)) = live_rx {
                        app.live_sessions.remove_session(conn_id).await;
                    }

                    if is_jwe {
                        // Pack response as JWE if original was encrypted
                        if let Some(ref to_did) = sender_did {
                            // DIDComm v1 authcrypt returns the sender's raw base58
                            // verkey, not a DID. Convert to did:key for packing.
                            let is_v1 = !to_did.starts_with("did:");
                            let recipient_did = ensure_did_key(to_did);
                            // Use the per-connection sender DID set by the handler
                            // (from DIDExchange-rotated peer DID). Fall back to the
                            // global mediator DID for messages outside any connection
                            // (e.g. invitation responses).
                            let sender_for_pack = if !response.from.is_empty() {
                                ensure_did_key(&response.from)
                            } else {
                                app.mediator_did.clone()
                            };
                            let packed = if is_v1 {
                                // Incoming was v1 — respond with v1
                                let opts = didcomm::core::version::PackOptions {
                                    version: didcomm::core::version::DIDCommVersion::V1Only,
                                    protect_sender: true,
                                    sign_message: false,
                                };
                                app.envelope_service
                                    .pack_encrypted_with_version(
                                        &response.message,
                                        &recipient_did,
                                        Some(&sender_for_pack),
                                        &opts,
                                    )
                                    .await
                            } else {
                                // v2 — use default pack
                                app.envelope_service
                                    .pack_encrypted(
                                        &response.message,
                                        &recipient_did,
                                        Some(&sender_for_pack),
                                        None,
                                    )
                                    .await
                            }
                            .map_err(|e| {
                                tracing::error!(error = %e, "Failed to pack response");
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    format!("Failed to pack response: {}", e),
                                )
                            })?;
                            Ok((StatusCode::OK, packed))
                        } else {
                            // No sender DID — return plaintext
                            let response_json =
                                serde_json::to_string(&response.message).map_err(|e| {
                                    (
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        format!("Failed to serialize response: {}", e),
                                    )
                                })?;
                            Ok((StatusCode::OK, response_json))
                        }
                    } else {
                        // Plaintext response
                        let response_json =
                            serde_json::to_string(&response.message).map_err(|e| {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    format!("Failed to serialize response: {}", e),
                                )
                            })?;
                        Ok((StatusCode::OK, response_json))
                    }
                }
                Ok(None) => {
                    // Handler returned no response (fire-and-forget, e.g. Forward).
                    //
                    // Return-route optimization: if the sender set return_route: "all"
                    // and we registered a live session, wait for the recipient's response
                    // to arrive on that channel. This enables single-HTTP-round-trip
                    // message delivery like Aries TS (sender → mediator → recipient →
                    // mediator → sender, all in one HTTP request/response).
                    if let Some((conn_id, mut rx)) = live_rx {
                        tracing::debug!(
                            connection_id = conn_id,
                            "Waiting for return-route response from recipient"
                        );
                        let wait_result =
                            tokio::time::timeout(RETURN_ROUTE_TIMEOUT, rx.recv()).await;

                        // Clean up the live session
                        app.live_sessions.remove_session(&conn_id).await;

                        match wait_result {
                            Ok(Some(response_msg)) => {
                                tracing::info!(
                                    connection_id = conn_id,
                                    response_len = response_msg.len(),
                                    "Return-route: delivering response inline"
                                );
                                Ok((StatusCode::OK, response_msg))
                            }
                            Ok(None) => {
                                tracing::debug!(
                                    connection_id = conn_id,
                                    "Return-route: channel closed, no response"
                                );
                                Ok((StatusCode::ACCEPTED, "".to_string()))
                            }
                            Err(_) => {
                                tracing::debug!(
                                    connection_id = conn_id,
                                    "Return-route: timeout waiting for response"
                                );
                                Ok((StatusCode::ACCEPTED, "".to_string()))
                            }
                        }
                    } else {
                        Ok((StatusCode::ACCEPTED, "".to_string()))
                    }
                }
                Err(e) => {
                    // Clean up return-route session on error
                    if let Some((ref conn_id, _)) = live_rx {
                        app.live_sessions.remove_session(conn_id).await;
                    }
                    tracing::error!(error = %e, msg_type = %msg_type, "Handler error");
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Handler error: {}", e),
                    ))
                }
            }
        }
        None => {
            // Bug A fix: the no-handler path used to leak the
            // return-route live session — the receiver (`rx`) would
            // drop here, closing the channel, but the sender (`tx`)
            // stayed in `app.live_sessions`. Subsequent return-route
            // checks then saw a "live" session pointing at a dead
            // channel, and any Forward addressed to this connection
            // would log `live push failed; channel closed` and fall
            // through to queue-only delivery. Clean up on this
            // exit path too.
            if let Some((ref conn_id, _)) = live_rx {
                app.live_sessions.remove_session(conn_id).await;
            }
            tracing::warn!(msg_type = %msg_type, "No handler registered for message type");
            Err((
                StatusCode::NOT_FOUND,
                format!("Unsupported message type: {}", msg_type),
            ))
        }
    }
}

/// GET /health — Health check endpoint
async fn handle_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok"
    }))
}

/// GET /metrics — Prometheus text-format scrape endpoint (Fix 4C).
async fn handle_metrics() -> (
    [(axum::http::header::HeaderName, axum::http::HeaderValue); 1],
    String,
) {
    let (body, content_type) = crate::metrics::Metrics::render();
    let header_value = axum::http::HeaderValue::from_static(content_type);
    ([(axum::http::header::CONTENT_TYPE, header_value)], body)
}

/// GET /invite — Out-of-band invitation endpoint
async fn handle_invite(State(app): State<Arc<MediatorApp>>) -> Json<serde_json::Value> {
    let invitation = &app.invitation_json;

    // Build invitation URL
    let invitation_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        serde_json::to_string(invitation).unwrap_or_default(),
    );
    let invitation_url = format!("{}?oob={}", app.endpoint, invitation_b64);

    Json(serde_json::json!({
        "invitation": invitation,
        "invitationUrl": invitation_url
    }))
}

/// Resolve a sender verkey to a stable connection record ID.
///
/// When a DID exchange completes, the ConnectionRecord stores the agent's
/// Ed25519 verkey in `their_authentication_key_base58`. Subsequent messages
/// from the same agent may arrive with a different `skid` (e.g., X25519 key
/// agreement key vs Ed25519 auth key). By looking up the connection record,
/// we get a stable ID that works across all messages from the same connection.
pub async fn resolve_connection_id(app: &MediatorApp, sender_key: &str) -> Option<String> {
    use protocol_connections::ConnectionRepositoryTrait;

    // Indexed lookup by auth key (O(1) cache hit / O(log n) tag query)
    if let Ok(Some(record)) = app.connection_repo.find_by_auth_key(sender_key).await {
        tracing::debug!(
            sender_key,
            connection_id = record.id,
            "Resolved via auth key"
        );
        return Some(record.id);
    }
    // Fallback: try KA key
    if let Ok(Some(record)) = app.connection_repo.find_by_ka_key(sender_key).await {
        tracing::debug!(sender_key, connection_id = record.id, "Resolved via KA key");
        return Some(record.id);
    }
    tracing::warn!(sender_key, "No connection found for sender key");
    None
}

/// Convert a raw base58 Ed25519 verkey to did:key format.
/// DIDComm v1 authcrypt returns the sender's raw verkey (e.g. "hzPAcoc..."),
/// but pack_encrypted needs a valid DID. If already a DID, returns as-is.
pub fn ensure_did_key(key_or_did: &str) -> String {
    if key_or_did.starts_with("did:") {
        return key_or_did.to_string();
    }
    // Raw base58 Ed25519 verkey → did:key:z6Mk...
    if let Ok(raw_bytes) = bs58::decode(key_or_did).into_vec() {
        // Multicodec prefix for Ed25519 public key: 0xed 0x01
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&raw_bytes);
        let multibase = bs58::encode(&multicodec).into_string();
        format!("did:key:z{}", multibase)
    } else {
        // Can't decode — return as-is and let pack_encrypted report the error
        key_or_did.to_string()
    }
}

/// Message types that mutate a connection's routing / drain its queue, or
/// make an authorization decision from the sender identity. These MUST be
/// authcrypted (sender-authenticated); a plaintext or anoncrypt message of
/// these types is dropped at dispatch. `routing/2.0/forward` and the
/// connection/OOB/DID-exchange handshake are intentionally NOT included —
/// they legitimately arrive anoncrypt.
pub fn requires_authcrypt(msg_type: &str) -> bool {
    msg_type.contains("/coordinate-mediation/")
        || msg_type.contains("/messagepickup/")
        || msg_type == "https://didcomm.org/rooms/1.0/commit"
        || msg_type == "https://didcomm.org/rooms/1.0/msg"
}

/// Extract recipient kid(s) from a raw JWE without decrypting.
///
/// - DIDComm v1: recipients are inside the base64url-decoded `protected` header.
///   Each kid is a raw base58 Ed25519 public key.
/// - DIDComm v2: recipients are at the top level. Each kid is typically a
///   did:key fragment.
///
/// Returns all kids found (senders may have multiple recipients).
pub fn extract_jwe_recipient_kids(jwe_json: &serde_json::Value) -> Vec<String> {
    use base64::Engine;
    let mut kids = Vec::new();

    // v1 path: recipients INSIDE protected header
    if let Some(protected_b64) = jwe_json.get("protected").and_then(|p| p.as_str()) {
        if let Ok(protected_bytes) =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(protected_b64)
        {
            if let Ok(protected_json) =
                serde_json::from_slice::<serde_json::Value>(&protected_bytes)
            {
                if let Some(recipients) =
                    protected_json.get("recipients").and_then(|r| r.as_array())
                {
                    for r in recipients {
                        if let Some(kid) = r
                            .get("header")
                            .and_then(|h| h.get("kid"))
                            .and_then(|k| k.as_str())
                        {
                            kids.push(kid.to_string());
                        }
                    }
                }
            }
        }
    }

    // v2 path: recipients at top level (if not already populated from v1)
    if kids.is_empty() {
        if let Some(recipients) = jwe_json.get("recipients").and_then(|r| r.as_array()) {
            for r in recipients {
                if let Some(kid) = r
                    .get("header")
                    .and_then(|h| h.get("kid"))
                    .and_then(|k| k.as_str())
                {
                    kids.push(kid.to_string());
                }
            }
        }
    }

    kids
}

/// Extract sender kid (`skid`) from a JWE protected header (DIDComm v2 only).
/// For v1 authcrypt, the sender info is encrypted inside each recipient's header.
pub fn extract_jwe_sender_skid(jwe_json: &serde_json::Value) -> Option<String> {
    use base64::Engine;
    let protected_b64 = jwe_json.get("protected").and_then(|p| p.as_str())?;
    let protected_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(protected_b64)
        .ok()?;
    let protected_json: serde_json::Value = serde_json::from_slice(&protected_bytes).ok()?;
    protected_json
        .get("skid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Convert a JWE recipient `kid` to the canonical raw base58 Ed25519 verkey
/// form used by the mediator keylist. Mirrors the canonicalisation applied on
/// keylist-update store (Aries TS `DidCommMediatorService.ts:171`).
fn canonicalize_kid(kid: &str) -> String {
    if let Some(stripped) = kid.strip_prefix("did:key:z") {
        if let Ok(decoded) = bs58::decode(stripped).into_vec() {
            if decoded.len() == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
                return bs58::encode(&decoded[2..]).into_string();
            }
        }
    }
    kid.to_string()
}

/// Direct-routing fallback: mediator can't unpack the JWE (it's for a mediated
/// recipient, not the mediator itself). Extract the recipient kid from the JWE
/// header, look up in keylist, and forward via ForwardService.
///
/// Registers a return-route live session for the sender (if we can identify them)
/// and waits for the recipient's response to deliver inline — matches Aries TS.
async fn direct_route_jwe(
    app: &Arc<MediatorApp>,
    raw_body: &str,
    jwe_json: &serde_json::Value,
    pre_resolved_kid: Option<String>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    // Use pre-resolved kid from fast path if available (avoids duplicate keylist lookup)
    let recipient_kid = if let Some(kid) = pre_resolved_kid {
        Some(kid)
    } else {
        // Fallback: resolve kid from JWE header (called from other paths)
        let kids = extract_jwe_recipient_kids(jwe_json);
        if kids.is_empty() {
            tracing::warn!("Direct-routing: no recipient kids in JWE header");
            return Err((
                StatusCode::BAD_REQUEST,
                "Failed to unpack JWE and no recipient kids found for direct routing".to_string(),
            ));
        }

        // Canonicalise the kid to raw base58 verkey before lookup. Storage
        // is canonicalised on insert (see protocol_coordinate_mediation::
        // services::mediator_service::canonicalize_recipient_key, mirroring
        // Aries TS `DidCommMediatorService.ts:171`). The JWE recipient kid
        // produced by DIDComm v1 packing IS raw base58 verkey already, but
        // we still normalise here so a `did:key:z…` form (e.g. from a v2
        // sender) resolves the same way.
        use protocol_coordinate_mediation::KeylistRepositoryTrait;
        let mut found: Option<String> = None;
        for kid in &kids {
            let canonical = canonicalize_kid(kid);
            if let Ok(Some(_)) = app
                .keylist_repo
                .find_mediation_for_recipient_key(&canonical)
                .await
            {
                found = Some(canonical);
                break;
            }
        }
        found
    };

    let recipient_kid = match recipient_kid {
        Some(k) => k,
        None => {
            let jwe_kids = extract_jwe_recipient_kids(jwe_json);
            tracing::warn!(
                ?jwe_kids,
                "Direct-routing: no mediation found for any recipient kid"
            );
            // Keep the recipient kids server-side only (logged above); the client
            // gets a generic message so we don't echo key material back.
            return Err((
                StatusCode::BAD_REQUEST,
                "No mediation registered for recipient".to_string(),
            ));
        }
    };

    tracing::info!(
        recipient_kid = %recipient_kid,
        "Direct-routing: found mediated recipient, routing via ForwardService"
    );

    // 3. Try to identify the sender for return-route delivery.
    //    v2: skid in protected header. v1: no sender info without decryption,
    //    but we can still register a return-route session keyed by recipient_kid
    //    (the response's Forward will be queued for this recipient's mediation
    //    connection — NOT the sender's — so return-route for v1 direct routing
    //    requires the sender to ALSO be mediated and to use authcrypt. For the
    //    typical "sender routes through mediator" flow, we use the sender's
    //    mediation connection_id by looking up the sender's skid.)
    let sender_skid = extract_jwe_sender_skid(jwe_json);
    let sender_connection_id = if let Some(ref skid) = sender_skid {
        // Try sender skid as raw verkey, then as did:key. Delegates to the
        // canonical did:key→base58 converter; falls back to the raw skid when
        // it isn't a did:key (behaviour-identical to the old inline decode).
        let raw = did::methods::key::did_key_to_base58_verkey(skid).unwrap_or_else(|| skid.clone());
        resolve_connection_id(app, &raw).await
    } else {
        None
    };

    // 4. Register a return-route live session for the sender (if identified).
    //    When the recipient's response arrives as a Forward destined for the
    //    sender, ForwardService.try_deliver will push it to this channel and we
    //    return it inline.
    //
    //    Only register if there's no active WS session — overwriting a WS
    //    session would break live delivery for the sender.
    let live_rx = if let Some(ref sender_conn_id) = sender_connection_id {
        if app.live_sessions.has_session(sender_conn_id).await {
            tracing::debug!(
                sender_conn_id = %sender_conn_id,
                "Direct-routing: WS session active for sender, skipping HTTP return-route"
            );
            None
        } else {
            let (tx, rx) = tokio::sync::mpsc::channel::<String>(RETURN_ROUTE_CHANNEL_CAP);
            app.live_sessions
                .register_session_with_sender(sender_conn_id, tx)
                .await;
            tracing::debug!(
                sender_conn_id = %sender_conn_id,
                "Direct-routing: registered return-route live session for sender"
            );
            Some((sender_conn_id.clone(), rx))
        }
    } else {
        None
    };

    // 5. Queue + live-deliver to the recipient. Offloaded onto the data-plane
    //    runtime so a slow/wedged forward parks this axum task (frees the
    //    worker) instead of starving health/login.
    let queue_result = {
        let fs = app.forward_service.clone();
        let kid_owned = recipient_kid.clone();
        let body_owned = raw_body.to_string();
        match app
            .data_handle
            .spawn(async move { fs.process_forward(&kid_owned, &body_owned).await })
            .await
        {
            Ok(inner) => inner,
            Err(join_err) => {
                tracing::error!(error = %join_err, "Direct-routing: forward task panicked");
                if let Some((ref sid, _)) = live_rx {
                    app.live_sessions.remove_session(sid).await;
                }
                app.metrics
                    .forward_total
                    .with_label_values(&["error"])
                    .inc();
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "forward task panicked".to_string(),
                ));
            }
        }
    };

    // Fix 4C: forward outcome metric.
    let outcome_label = if queue_result.is_ok() {
        "success"
    } else {
        "error"
    };
    app.metrics
        .forward_total
        .with_label_values(&[outcome_label])
        .inc();

    if let Err(e) = queue_result {
        // Cleanup return-route session on error
        if let Some((ref sid, _)) = live_rx {
            app.live_sessions.remove_session(sid).await;
        }
        tracing::warn!(error = %e, "Direct-routing: forward_service.process_forward failed");
        // Detailed error stays server-side (logged above); return a generic body.
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to route message".to_string(),
        ));
    }

    // 6. Wait for the recipient's response on the return-route channel.
    if let Some((conn_id, mut rx)) = live_rx {
        tracing::debug!(
            sender_conn_id = %conn_id,
            "Direct-routing: waiting up to 10s for return-route response"
        );
        let wait_result = tokio::time::timeout(RETURN_ROUTE_TIMEOUT, rx.recv()).await;

        // Always clean up the live session
        app.live_sessions.remove_session(&conn_id).await;

        match wait_result {
            Ok(Some(response_msg)) => {
                tracing::info!(
                    sender_conn_id = %conn_id,
                    response_len = response_msg.len(),
                    "Direct-routing: delivering response inline"
                );
                return Ok((StatusCode::OK, response_msg));
            }
            _ => {
                tracing::debug!(
                    sender_conn_id = %conn_id,
                    "Direct-routing: no return-route response within timeout"
                );
            }
        }
    }

    // 7. No return-route response — fire-and-forget ACK.
    Ok((StatusCode::ACCEPTED, "".to_string()))
}
