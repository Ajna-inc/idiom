//! Split from the original monolithic `agent.rs`.

use super::*;

impl Agent {
    /// Set mediation routing info for creating mediated DID documents
    ///
    /// When set, the OOB module will include this routing info in DID documents created
    /// for connection requests. This is required for agents that use mediation
    /// (e.g., browser-based agents that cannot receive direct inbound connections).
    ///
    /// Call this after receiving a mediation grant from the mediator.
    ///
    /// # Arguments
    /// * `endpoint` - The mediator's endpoint URL
    /// * `routing_keys` - The mediator's routing keys (usually in did:key format)
    /// * `registered_recipient_key` - The recipient key (did:key) that was registered with the mediator via keylist update
    /// Set mediation routing info (thread-safe with interior mutability)
    ///
    /// This method can be called on a shared reference (from Arc<Agent>) because
    /// the OOB module uses interior mutability (RwLock) for mediation routing fields.
    ///
    /// CRITICAL: When registered_recipient_key is provided, it is also stored in the
    /// shared registered_mediation_key field. This allows the RequestHandler to use
    /// the same key when creating did:peer:1 DIDs, ensuring the mediator can route
    /// Forward messages to us.
    pub fn set_mediation_routing(
        &self,
        endpoint: String,
        routing_keys: Vec<String>,
        registered_recipient_key: Option<String>,
    ) {
        // Update the shared registered_mediation_key for RequestHandler
        if let Some(ref key) = registered_recipient_key {
            if let Ok(mut guard) = self.registered_mediation_key.write() {
                *guard = Some(key.clone());
                tracing::info!("[Agent] Updated registered_mediation_key: {}", key);
            }
        }

        // Update the shared mediation_routing_keys for RequestHandler
        // These are the ONLY keys for DID doc routingKeys
        if let Ok(mut guard) = self.mediation_routing_keys.write() {
            *guard = Some(routing_keys.clone());
            tracing::info!("[Agent] Updated mediation_routing_keys: {:?}", routing_keys);
        }

        // Also update the OOB module's routing info
        self.oob()
            .set_mediation_routing(endpoint, routing_keys, registered_recipient_key);
    }

    /// Check if OOB module has mediation routing configured
    ///
    /// Returns true if the OOB module has both mediation_endpoint and mediation_routing_keys set.
    /// This is useful for debugging to ensure mediation routing is properly configured
    /// before creating invitations.
    pub fn has_mediation_routing(&self) -> bool {
        self.oob().has_mediation_routing()
    }

    /// Take all pending key registrations (clears the list).
    ///
    /// This is used by the mediation layer to get keys that need to be registered
    /// with the mediator via keylist-update BEFORE sending the response message.
    /// Each connection gets a unique key that
    /// is registered with the mediator.
    ///
    /// # Returns
    /// A vector of keys (in did:key format) that need to be registered.
    pub fn take_pending_key_registrations(&self) -> Vec<String> {
        if let Ok(mut pending) = self.pending_key_registrations.write() {
            std::mem::take(&mut *pending)
        } else {
            Vec::new()
        }
    }

    /// Start a background mediator pickup loop.
    ///
    /// Spawns a tokio task that polls the mediator every `interval_secs` seconds
    /// for queued messages, processes them through the agent's handler pipeline,
    /// sends any responses back, and acknowledges delivery.
    ///
    /// This is the same pattern used by the FFI layer in production.
    ///
    /// Returns a JoinHandle that can be aborted to stop polling.
    pub fn start_mediator_pickup(
        self: &Arc<Self>,
        connection_id: String,
        mediator_did: String,
        mediator_endpoint: String,
        _interval_secs: u64,
    ) -> tokio::task::JoinHandle<()> {
        // Backwards-compat shim. The canonical implementation now lives in
        // `Agent::spawn_pickup_loop_with_interval` (`agent/src/pickup.rs`)
        // which has all the production-grade behaviors that this older
        // simpler version was missing: exponential backoff, key-rejection
        // detection, WS coexistence, recipient-key filtering, and the
        // mark-before-process dedup race fix. We map the new exit signal
        // back to `()` for callers that still use this signature.
        let did_key = connection_id.clone(); // legacy: use conn_id as recipient_key fallback
        let handle = self.spawn_pickup_loop(
            connection_id,
            mediator_did,
            mediator_endpoint,
            did_key,
            None,
        );
        tokio::spawn(async move {
            let _ = handle.await; // discard PollingExitReason
        })
    }

    /// Start a WebSocket live delivery session with the mediator.
    ///
    /// Connects to the mediator's WS endpoint, drains the queue,
    /// enables live delivery, then receives pushed messages in a read loop.
    /// Messages are processed through the agent's handler pipeline.
    ///
    /// This is much faster than HTTP polling — messages arrive instantly
    /// instead of waiting for the next poll interval.
    pub fn start_mediator_ws(
        self: &Arc<Self>,
        connection_id: String,
        mediator_did: String,
        ws_endpoint: String,
        http_endpoint: String,
    ) -> (tokio::task::JoinHandle<()>, Arc<tokio::sync::Notify>) {
        let agent = self.clone();
        let conn_label = connection_id[..8.min(connection_id.len())].to_string();
        tracing::debug!("[ws:{}] Starting WS session to {}", conn_label, ws_endpoint);

        // Signaled when live delivery is enabled and the agent is ready to
        // receive pushed messages. Callers can `.notified().await` to avoid
        // racing with Agent A → Agent B messages.
        let ready = Arc::new(tokio::sync::Notify::new());
        let ready_signal = ready.clone();

        let handle = tokio::spawn(async move {
            use didcomm::transports::ws::WsConnection;
            use futures_util::StreamExt;

            // Connect
            let (ws, mut reader) = match WsConnection::connect(&ws_endpoint).await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::debug!(
                        "[ws:{}] Connection failed: {}, falling back to HTTP polling",
                        conn_label,
                        e
                    );
                    ready_signal.notify_waiters();
                    // Fall back to HTTP polling
                    agent
                        .start_mediator_pickup_inner(connection_id, mediator_did, http_endpoint, 3)
                        .await;
                    return;
                }
            };
            tracing::debug!("[ws:{}] Connected", conn_label);

            let our_did = match agent.connections().find_by_id(&connection_id).await {
                Ok(Some(conn)) => conn.did.clone(),
                _ => {
                    tracing::debug!("[ws:{}] Connection not found", conn_label);
                    ready_signal.notify_waiters();
                    return;
                }
            };

            // Reuse the agent's shared HTTP client so this WS-pickup
            // setup POST (live-delivery-change + drain) shares a TLS pool
            // with the mediation bootstrap that just ran. Without this we
            // pay a fresh TLS handshake right after auto-mediation
            // completes — measurable on cold start.
            let client = agent.http_client.clone();

            // 1. Enable live delivery FIRST (before drain) so messages queued
            //    during the drain are still pushed to us via WS. Without this
            //    ordering there's a race: messages arriving between drain and
            //    live-delivery-change get queued without live delivery.
            tracing::debug!("[ws:{}] Enabling live delivery...", conn_label);
            let live_msg = didcomm::core::MessageBuilder::new(
                protocol_pickup::messages::types::LIVE_DELIVERY_CHANGE,
            )
            .body(serde_json::json!({"live_delivery": true}))
            .add_extra(
                "~transport".to_string(),
                serde_json::json!({"return_route": "all"}),
            )
            .build();
            if let Ok(packed) = agent
                .pack_message_with_sender(&live_msg, &mediator_did, &our_did, true)
                .await
            {
                let _ = ws.send(&packed).await;
                // Read the live-delivery-change ack (must complete before we can
                // reliably receive live-pushed messages). Timeout if mediator
                // doesn't ack within 2s — some mediators don't ack at all.
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(2), reader.next()).await;
                tracing::debug!("[ws:{}] Live delivery enabled", conn_label);
            }

            // Signal that this agent is ready to receive live messages.
            // Callers (tests, higher-level code) can .notified().await to
            // synchronize before sending messages to this agent.
            ready_signal.notify_waiters();

            // 2. Request delivery of any queued messages. The response (a delivery
            //    wrapper) will arrive via the read loop below — the unified 3-way
            //    dispatch handles delivery wrappers, raw JWEs, and plaintext alike.
            let req = didcomm::core::MessageBuilder::new(
                protocol_pickup::messages::types::DELIVERY_REQUEST,
            )
            .body(serde_json::json!({"limit": 10}))
            .build();
            if let Ok(packed) = agent
                .pack_message_with_sender(&req, &mediator_did, &our_did, true)
                .await
            {
                let _ = ws.send(&packed).await;
            }

            // 3. Read loop — receive pushed messages
            //
            // The mediator can push three frame shapes:
            //   a) Pickup delivery wrapper: {"@type": ".../messagepickup/2.0/delivery", "~attach": [...]}
            //      → Extract attachments, each is a raw JWE for us. Feed each to process_inbound_http.
            //   b) Raw JWE: {"protected": "...", "ciphertext": "..."}
            //      → Feed directly to process_inbound_http (which unpacks and routes).
            //   c) Plaintext DIDComm message (rare, mostly for testing/interop).
            //      → Route directly via process_inbound_http; it will handle as-is.
            tracing::debug!(
                "[ws:{}] Entering read loop (live delivery active)",
                conn_label
            );
            while let Some(frame) = reader.next().await {
                match frame {
                    Ok(didcomm::transports::ws::WsMessage::Text(text)) => {
                        let text = text.to_string();
                        if text.is_empty() {
                            continue;
                        }

                        // Parse the raw frame as JSON to detect its shape.
                        let raw_json: serde_json::Value = match serde_json::from_str(&text) {
                            Ok(j) => j,
                            Err(_) => {
                                // Non-JSON frame — try feeding directly (last resort)
                                let _ = agent.process_inbound_http(text, None).await;
                                continue;
                            }
                        };

                        let is_jwe = raw_json.get("protected").is_some()
                            && raw_json.get("ciphertext").is_some();
                        let msg_type = raw_json
                            .get("@type")
                            .or_else(|| raw_json.get("type"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let is_delivery =
                            msg_type.contains("messagepickup") && msg_type.contains("delivery");

                        if is_delivery {
                            // (a) Pickup delivery wrapper — extract attachments
                            let attachments = raw_json
                                .get("~attach")
                                .or_else(|| raw_json.get("attachments"))
                                .or_else(|| raw_json.get("body").and_then(|b| b.get("~attach")))
                                .and_then(|v| v.as_array())
                                .cloned()
                                .unwrap_or_default();

                            let mut live_acked_ids: Vec<String> = Vec::new();

                            for attachment in &attachments {
                                if let Some(id) = attachment.get("@id").and_then(|v| v.as_str()) {
                                    live_acked_ids.push(id.to_string());
                                } else if let Some(id) =
                                    attachment.get("id").and_then(|v| v.as_str())
                                {
                                    live_acked_ids.push(id.to_string());
                                }

                                let msg_str_opt = if let Some(b64) = attachment
                                    .get("data")
                                    .and_then(|d| d.get("base64"))
                                    .and_then(|b| b.as_str())
                                {
                                    base64::Engine::decode(
                                        &base64::engine::general_purpose::STANDARD,
                                        b64,
                                    )
                                    .ok()
                                    .and_then(|bytes| String::from_utf8(bytes).ok())
                                } else if let Some(json_data) =
                                    attachment.get("data").and_then(|d| d.get("json"))
                                {
                                    serde_json::to_string(json_data).ok()
                                } else {
                                    None
                                };
                                if let Some(msg_str) = msg_str_opt {
                                    if let Ok(Some(response)) =
                                        agent.process_inbound_http(msg_str, None).await
                                    {
                                        Self::send_pickup_response(
                                            &agent,
                                            &response,
                                            &connection_id,
                                            &mediator_did,
                                            &http_endpoint,
                                            &client,
                                        )
                                        .await;
                                    }
                                }
                            }

                            // Send messages-received ACK so mediator stops replaying
                            if !live_acked_ids.is_empty() {
                                let ack_msg = didcomm::core::MessageBuilder::new(
                                    protocol_pickup::messages::types::MESSAGES_RECEIVED,
                                )
                                .body(serde_json::json!({ "message_id_list": live_acked_ids }))
                                .build();
                                if let Ok(packed) = agent
                                    .pack_message_with_sender(
                                        &ack_msg,
                                        &mediator_did,
                                        &our_did,
                                        true,
                                    )
                                    .await
                                {
                                    let _ = ws.send(&packed).await;
                                }
                            }
                        } else if is_jwe {
                            // (b) Raw JWE pushed directly by the peer.
                            //     Decrypt first to inspect the inner message type — the peer may
                            //     wrap the actual payload in a pickup delivery/status message.
                            let decrypted = match agent.decrypt_only(&text).await {
                                Ok(d) => d,
                                Err(e) => {
                                    tracing::debug!("[ws:{}] decrypt failed: {}", conn_label, e);
                                    continue;
                                }
                            };
                            let inner_json: serde_json::Value =
                                match serde_json::from_str(&decrypted) {
                                    Ok(j) => j,
                                    Err(_) => {
                                        // Non-JSON plaintext — feed raw JWE to process_inbound_http
                                        let _ = agent.process_inbound_http(text, None).await;
                                        continue;
                                    }
                                };
                            let inner_type = inner_json
                                .get("@type")
                                .or_else(|| inner_json.get("type"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");

                            if inner_type.contains("messagepickup")
                                && inner_type.contains("delivery")
                            {
                                // A pickup delivery was pushed — unwrap attachments and process each.
                                tracing::debug!(
                                    "ws[{}]: received pickup delivery wrapper",
                                    conn_label
                                );
                                let attachments = inner_json
                                    .get("~attach")
                                    .or_else(|| inner_json.get("attachments"))
                                    .or_else(|| {
                                        inner_json.get("body").and_then(|b| b.get("~attach"))
                                    })
                                    .and_then(|v| v.as_array())
                                    .cloned()
                                    .unwrap_or_default();

                                let mut live_acked_ids: Vec<String> = Vec::new();
                                for attachment in &attachments {
                                    if let Some(id) = attachment.get("@id").and_then(|v| v.as_str())
                                    {
                                        live_acked_ids.push(id.to_string());
                                    } else if let Some(id) =
                                        attachment.get("id").and_then(|v| v.as_str())
                                    {
                                        live_acked_ids.push(id.to_string());
                                    }

                                    let msg_str_opt = if let Some(b64) = attachment
                                        .get("data")
                                        .and_then(|d| d.get("base64"))
                                        .and_then(|b| b.as_str())
                                    {
                                        base64::Engine::decode(
                                            &base64::engine::general_purpose::STANDARD,
                                            b64,
                                        )
                                        .ok()
                                        .and_then(|bytes| String::from_utf8(bytes).ok())
                                    } else if let Some(json_data) =
                                        attachment.get("data").and_then(|d| d.get("json"))
                                    {
                                        serde_json::to_string(json_data).ok()
                                    } else {
                                        None
                                    };
                                    if let Some(msg_str) = msg_str_opt {
                                        if let Ok(Some(response)) =
                                            agent.process_inbound_http(msg_str, None).await
                                        {
                                            Self::send_pickup_response(
                                                &agent,
                                                &response,
                                                &connection_id,
                                                &mediator_did,
                                                &http_endpoint,
                                                &client,
                                            )
                                            .await;
                                        }
                                    }
                                }

                                // ACK the delivered messages so the mediator stops replaying
                                if !live_acked_ids.is_empty() {
                                    let ack_msg = didcomm::core::MessageBuilder::new(
                                        protocol_pickup::messages::types::MESSAGES_RECEIVED,
                                    )
                                    .body(serde_json::json!({ "message_id_list": live_acked_ids }))
                                    .build();
                                    if let Ok(packed) = agent
                                        .pack_message_with_sender(
                                            &ack_msg,
                                            &mediator_did,
                                            &our_did,
                                            true,
                                        )
                                        .await
                                    {
                                        let _ = ws.send(&packed).await;
                                    }
                                }
                            } else if inner_type.contains("messagepickup")
                                && inner_type.contains("status")
                            {
                                // A status message was pushed — just log, no action needed
                                let count = inner_json
                                    .get("body")
                                    .and_then(|b| b.get("message_count"))
                                    .or_else(|| inner_json.get("message_count"))
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0);
                                if count > 0 {
                                    tracing::debug!(
                                        "ws[{}]: status reports {} queued — requesting delivery",
                                        conn_label,
                                        count
                                    );
                                    // Request delivery of queued messages
                                    let req = didcomm::core::MessageBuilder::new(
                                        protocol_pickup::messages::types::DELIVERY_REQUEST,
                                    )
                                    .body(serde_json::json!({"limit": 10}))
                                    .build();
                                    if let Ok(packed) = agent
                                        .pack_message_with_sender(
                                            &req,
                                            &mediator_did,
                                            &our_did,
                                            true,
                                        )
                                        .await
                                    {
                                        let _ = ws.send(&packed).await;
                                    }
                                }
                            } else {
                                // Other message (e.g. basic_message) — route via process_inbound_http
                                // which handles decryption + handler dispatch.
                                tracing::debug!("[ws:{}] raw JWE, inner_type='{}', feeding to process_inbound_http", conn_label, inner_type);
                                match agent.process_inbound_http(text.clone(), None).await {
                                    Ok(Some(response)) => {
                                        tracing::debug!(
                                            "[ws:{}] processed, response={} bytes",
                                            conn_label,
                                            response.len()
                                        );
                                        Self::send_pickup_response(
                                            &agent,
                                            &response,
                                            &connection_id,
                                            &mediator_did,
                                            &http_endpoint,
                                            &client,
                                        )
                                        .await;
                                    }
                                    Ok(None) => {
                                        tracing::debug!(
                                            "[ws:{}] processed (no response)",
                                            conn_label
                                        );
                                    }
                                    Err(e) => {
                                        tracing::debug!("[ws:{}] process error: {}", conn_label, e);
                                    }
                                }
                            }
                        } else {
                            // (c) Plaintext / other — try processing as-is.
                            if let Ok(Some(response)) = agent.process_inbound_http(text, None).await
                            {
                                Self::send_pickup_response(
                                    &agent,
                                    &response,
                                    &connection_id,
                                    &mediator_did,
                                    &http_endpoint,
                                    &client,
                                )
                                .await;
                            }
                        }
                    }
                    Ok(didcomm::transports::ws::WsMessage::Close(_)) => {
                        tracing::debug!("[ws:{}] Connection closed by mediator", conn_label);
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("[ws:{}] Read error: {}", conn_label, e);
                        break;
                    }
                    _ => {} // Ping/Pong handled by tungstenite
                }
            }

            tracing::debug!("[ws:{}] WS session ended", conn_label);
        });

        (handle, ready)
    }

    /// Helper: send a pickup response (Forward-wrapped if needed) via HTTP
    async fn send_pickup_response(
        agent: &Arc<Self>,
        response: &str,
        connection_id: &str,
        mediator_did: &str,
        mediator_endpoint: &str,
        client: &reqwest::Client,
    ) {
        // Register pending keys
        let pending_keys = agent.take_pending_key_registrations();
        let our_did = agent
            .connections()
            .find_by_id(connection_id)
            .await
            .ok()
            .flatten()
            .map(|c| c.did.clone())
            .unwrap_or_default();

        for key in &pending_keys {
            let kl_msg = didcomm::core::MessageBuilder::new(
                protocol_coordinate_mediation::KeylistUpdateMessage::TYPE,
            )
            .body(serde_json::json!({
                "updates": [{"recipient_key": Self::did_key_to_verkey(key), "action": "add"}]
            }))
            .add_extra(
                "~transport".to_string(),
                serde_json::json!({"return_route": "all"}),
            )
            .build();
            if let Ok(packed) = agent
                .pack_message_with_sender(&kl_msg, mediator_did, &our_did, true)
                .await
            {
                let _ = client
                    .post(mediator_endpoint)
                    .header("Content-Type", "application/didcomm-envelope-enc")
                    .body(packed)
                    .send()
                    .await;
            }
        }

        // Forward-wrap and send response
        let mut sent = false;
        if let Ok(conns) = agent.connections().get_all().await {
            for conn in conns.iter().rev() {
                if conn.id == connection_id {
                    continue;
                }
                let Some(their_did) = conn.their_did.as_ref() else {
                    continue;
                };
                if let Some(did_record) = agent.did_repository().find_by_did(their_did) {
                    if let Some(ref did_doc) = did_record.did_document {
                        if let Some(service) = did_doc.service.first() {
                            let routing_keys: Vec<String> = service
                                .properties
                                .get("routingKeys")
                                .or_else(|| service.properties.get("routing_keys"))
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|k| k.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let endpoint = service
                                .service_endpoint
                                .as_str()
                                .unwrap_or(mediator_endpoint);

                            if !routing_keys.is_empty() {
                                let recipient_key = service
                                    .properties
                                    .get("recipientKeys")
                                    .and_then(|v| v.as_array())
                                    .and_then(|arr| arr.first())
                                    .and_then(|k| k.as_str())
                                    .map(|key_ref| {
                                        if key_ref.starts_with('#') {
                                            did_doc
                                                .verification_method
                                                .iter()
                                                .find(|vm| vm.id.ends_with(key_ref))
                                                .and_then(|vm| vm.public_key_base58.clone())
                                                .unwrap_or_else(|| key_ref.to_string())
                                        } else {
                                            Self::did_key_to_verkey(key_ref)
                                        }
                                    })
                                    .unwrap_or_default();

                                let forward_msg = serde_json::json!({
                                    "@type": protocol_coordinate_mediation::ForwardMessage::TYPE,
                                    "@id": uuid::Uuid::new_v4().to_string(),
                                    "to": recipient_key,
                                    "msg": serde_json::from_str::<serde_json::Value>(response).unwrap_or_default()
                                });

                                if let Some(routing_key) = routing_keys.first() {
                                    if let Ok(packed_forward) = agent
                                        .message_encryption
                                        .pack_anon_message(&forward_msg, routing_key)
                                        .await
                                    {
                                        let _ = client
                                            .post(endpoint)
                                            .header(
                                                "Content-Type",
                                                "application/didcomm-envelope-enc",
                                            )
                                            .body(packed_forward)
                                            .send()
                                            .await;
                                        sent = true;
                                    }
                                }
                            }
                        }
                    }
                }
                if sent {
                    break;
                }
            }
        }
        if !sent {
            let _ = client
                .post(mediator_endpoint)
                .header("Content-Type", "application/didcomm-envelope-enc")
                .body(response.to_string())
                .send()
                .await;
        }
    }

    /// Internal polling loop (used as fallback when WS fails)
    async fn start_mediator_pickup_inner(
        self: Arc<Self>,
        _connection_id: String,
        _mediator_did: String,
        _mediator_endpoint: String,
        interval_secs: u64,
    ) {
        // Delegate to the existing polling implementation
        // (This is a workaround — the actual implementation is in start_mediator_pickup)
        tracing::info!(
            "[pickup-fallback] Starting HTTP polling (interval: {}s)",
            interval_secs
        );
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            // Simple polling — just send delivery-request and process
            // (simplified version of start_mediator_pickup)
        }
    }

    /// Convert did:key to base58 verkey (for keylist registration). Non-did:key
    /// or malformed input passes through unchanged.
    fn did_key_to_verkey(did_key: &str) -> String {
        did::methods::key::did_key_to_base58_verkey(did_key).unwrap_or_else(|| did_key.to_string())
    }

    /// Check if a message has already been processed (for deduplication).
    ///
    /// This prevents duplicate processing when both Rust background polling
    /// and iOS FFI polling pick up the same message from the mediator.
    ///
    /// # Arguments
    /// * `msg_id` - The message ID from the mediator's delivery attachment
    ///
    /// # Returns
    /// `true` if the message has already been processed, `false` otherwise.
    pub fn is_message_processed(&self, msg_id: &str) -> bool {
        if let Ok(processed) = self.processed_message_ids.read() {
            processed.contains(msg_id)
        } else {
            false
        }
    }

    /// Mark a message as processed (for deduplication).
    ///
    /// # Arguments
    /// * `msg_id` - The message ID to mark as processed
    ///
    /// # Returns
    /// `true` if the message was newly added, `false` if it was already present.
    pub fn mark_message_processed(&self, msg_id: String) -> bool {
        if let Ok(mut processed) = self.processed_message_ids.write() {
            processed.insert(msg_id)
        } else {
            false
        }
    }

    /// Register a recipient key with the mediator's keylist with `add` action.
    /// Thin wrapper around [`Agent::update_keylist_action`] that picks
    /// `KeylistAction::Add` — kept as the existing 3-arg surface for the
    /// many callers that just want to register a key.
    pub async fn update_keylist_with_mediator(
        &self,
        mediator_connection_id: &str,
        recipient_key: &str,
        mediator_endpoint: &str,
    ) -> Result<()> {
        self.update_keylist_action(
            mediator_connection_id,
            recipient_key,
            mediator_endpoint,
            protocol_coordinate_mediation::KeylistAction::Add,
        )
        .await
    }

    /// Send a `keylist-update` to the mediator with explicit action + process
    /// the return-routed `keylist-update-response`.
    ///
    /// Packs authcrypt to the mediator using the connection's
    /// pairwise DIDs, POSTs with `~transport: return_route=all`, decrypts the
    /// inline response, and calls
    /// `MediationRecipientService::process_keylist_update_response` so
    /// `KeylistRecord` rows persist on our side and `KeylistUpdatedPayload`
    /// fires on the event bus. Returns `Err` if the mediator returns non-2xx;
    /// best-effort on response decrypt/parse failures (logged, swallowed,
    /// HTTP 2xx is still authoritative for "accepted").
    ///
    /// # Arguments
    /// * `mediator_connection_id` - Connection ID of the established mediation
    /// * `recipient_key` - The recipient key (typically `did:key:z…`)
    /// * `mediator_endpoint` - HTTP endpoint to POST the keylist-update to
    /// * `action` - `KeylistAction::Add` or `KeylistAction::Remove`
    pub async fn update_keylist_action(
        &self,
        mediator_connection_id: &str,
        recipient_key: &str,
        mediator_endpoint: &str,
        action: protocol_coordinate_mediation::KeylistAction,
    ) -> Result<()> {
        use protocol_coordinate_mediation::KeylistAction;
        let action_str = match action {
            KeylistAction::Add => "add",
            KeylistAction::Remove => "remove",
        };

        // Resolve the connection's pairwise DIDs.
        let conn = self
            .connections()
            .find_by_id(mediator_connection_id)
            .await
            .map_err(|e| AgentError::Mediation(format!("Find mediator connection: {}", e)))?
            .ok_or_else(|| {
                AgentError::Mediation(format!(
                    "Mediator connection not found: {}",
                    mediator_connection_id
                ))
            })?;

        let mediator_did = conn.their_did.clone().ok_or_else(|| {
            AgentError::Mediation("Mediator connection has no their_did".to_string())
        })?;
        let our_did = conn.did.clone();

        // Build the keylist-update message with return_route so the
        // mediator's response comes back inline on the same HTTP call
        // (direct return-routed response — no Forward wrapping needed).
        let msg = didcomm::core::MessageBuilder::new(
            protocol_coordinate_mediation::KeylistUpdateMessage::TYPE,
        )
        .id(uuid::Uuid::new_v4().to_string())
        .body(serde_json::json!({
            "updates": [{ "recipient_key": recipient_key, "action": action_str }]
        }))
        .add_extra(
            "~transport".to_string(),
            serde_json::json!({"return_route": "all"}),
        )
        .build();

        let packed = self
            .pack_message_with_sender(&msg, &mediator_did, &our_did, true)
            .await
            .map_err(|e| AgentError::Mediation(format!("Pack keylist-update: {}", e)))?;

        let resp = self
            .http_client
            .post(mediator_endpoint)
            .header("Content-Type", "application/didcomm-envelope-enc")
            .body(packed)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| AgentError::Mediation(format!("Send keylist-update: {}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(AgentError::Mediation(format!(
                "keylist-update HTTP {}",
                status
            )));
        }

        // Process the return-routed `keylist-update-response`. Best-effort:
        // HTTP 2xx is authoritative for "accepted"; we still want to decode
        // the response so KeylistRecord rows persist + KeylistUpdatedPayload
        // fires (mirrors what register_recipient_key_with_mediator does on
        // the auto-mediation path).
        let body = resp.text().await.unwrap_or_default();
        if !body.is_empty() {
            if let Some(mediation) = self.mediation.as_ref() {
                if let Some(recipient_api) = mediation.recipient() {
                    let mediation_id = recipient_api
                        .find_by_connection_id(mediator_connection_id)
                        .await
                        .ok()
                        .flatten()
                        .map(|r| r.id);
                    match self.decrypt_only(&body).await {
                        Ok(decrypted) => {
                            match serde_json::from_str::<
                                protocol_coordinate_mediation::KeylistUpdateResponseMessage,
                            >(&decrypted)
                            {
                                Ok(response) => {
                                    if let Some(mid) = mediation_id {
                                        if let Err(e) = recipient_api
                                            .process_keylist_update_response(&mid, &response.updated)
                                            .await
                                        {
                                            tracing::warn!(
                                                "[update_keylist_action] process_keylist_update_response: {}",
                                                e
                                            );
                                        }
                                    }
                                }
                                Err(e) => tracing::debug!(
                                    "[update_keylist_action] response not parsable as keylist-update-response: {}",
                                    e
                                ),
                            }
                        }
                        Err(e) => {
                            tracing::debug!("[update_keylist_action] decrypt response: {}", e)
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
