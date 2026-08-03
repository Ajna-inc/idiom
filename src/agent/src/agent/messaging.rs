//! Split from the original monolithic `agent.rs`.

use super::*;

// MessageReceiver trait impl (moved verbatim)

// Implement MessageReceiver trait for Agent
// This allows HttpInboundTransport to call Agent directly when messages arrive
#[async_trait::async_trait]
impl didcomm::transports::MessageReceiver for Agent {
    async fn receive_message(
        &self,
        packed_message: String,
        metadata: didcomm::transports::TransportMetadata,
    ) -> didcomm::transports::Result<()> {
        // Mesh return-route: if message arrived via mesh, use process_inbound_http
        // (real JWE decryption + protocol handling) and send response back over mesh.
        // This does NOT affect mediator flow — mediator calls process_inbound_http directly.
        if let Some(ref mesh_ep) = metadata.sender_endpoint {
            if mesh_ep.starts_with("mesh://") {
                tracing::debug!(
                    "[MESH-RETURN] Message via mesh ({}), len={}, calling process_inbound_http...",
                    mesh_ep,
                    packed_message.len()
                );
                tracing::debug!(
                    "[MESH-RETURN] Message arrived via mesh ({}), using mesh return route",
                    mesh_ep
                );
                let mesh_endpoint = mesh_ep.clone();
                match self
                    .process_inbound_http(packed_message, Some(mesh_endpoint.clone()))
                    .await
                {
                    Ok(Some(packed_response)) => {
                        tracing::debug!(
                            "[MESH-RETURN] Got response ({} bytes), sending to {}",
                            packed_response.len(),
                            mesh_endpoint
                        );
                        tracing::debug!(
                            "[MESH-RETURN] Got packed response ({} bytes), sending to {}",
                            packed_response.len(),
                            mesh_endpoint
                        );
                        self.transport
                            .send_to_endpoint(&mesh_endpoint, &packed_response)
                            .await
                            .map_err(|e| {
                                didcomm::transports::TransportError::ProcessingFailed(format!(
                                    "Mesh return-route send failed: {}",
                                    e
                                ))
                            })?;
                        tracing::debug!("[MESH-RETURN] Response sent back over mesh");
                        tracing::debug!("[MESH-RETURN] Response sent back over mesh");
                    }
                    Ok(None) => {
                        tracing::debug!("[MESH-RETURN] No response needed");
                        tracing::debug!("[MESH-RETURN] No response needed");
                    }
                    Err(e) => {
                        tracing::debug!("[MESH-RETURN] ❌ Processing failed: {}", e);
                        tracing::debug!("[MESH-RETURN] Processing failed: {}", e);
                        return Err(e);
                    }
                }
                return Ok(());
            }
        }

        trace!("Received message via {}", metadata.transport_type);

        // Check if message is an EncryptedMessage wrapper (from channel transport)
        // If so, extract the actual ciphertext
        let actual_message =
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&packed_message) {
                // Check if this is an EncryptedMessage wrapper:
                // - Has ciphertext field
                // - protected/iv/tag are dummy values like "jwe" or "test" (not real base64)
                if let (Some(protected), Some(ciphertext_val)) = (
                    json.get("protected").and_then(|v| v.as_str()),
                    json.get("ciphertext"),
                ) {
                    // If protected is a dummy value (not a real JWE protected header), this is an EncryptedMessage wrapper
                    if protected == "jwe" || protected == "test" {
                        if let Some(ciphertext) = ciphertext_val.as_str() {
                            trace!("Extracting ciphertext from wrapper");
                            ciphertext.to_string()
                        } else {
                            packed_message.clone()
                        }
                    } else {
                        packed_message.clone()
                    }
                } else {
                    packed_message.clone()
                }
            } else {
                packed_message.clone()
            };

        // Detect if message is JWE format
        let is_jwe = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&actual_message) {
            json.get("protected").is_some()
                && json.get("iv").is_some()
                && json.get("ciphertext").is_some()
                && json.get("tag").is_some()
        } else {
            false
        };

        let plaintext_message = if is_jwe {
            // Parse JWE to detect algorithm
            let jwe_json: serde_json::Value =
                serde_json::from_str(&actual_message).map_err(|e| {
                    didcomm::transports::TransportError::ProcessingFailed(format!(
                        "Failed to parse JWE JSON: {}",
                        e
                    ))
                })?;

            // Decode protected header to check algorithm
            let protected_b64 = jwe_json
                .get("protected")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    didcomm::transports::TransportError::ProcessingFailed(
                        "JWE missing protected header".to_string(),
                    )
                })?;

            let protected_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(protected_b64)
                .map_err(|e| {
                    didcomm::transports::TransportError::ProcessingFailed(format!(
                        "Failed to decode protected header: {}",
                        e
                    ))
                })?;

            let protected_header: serde_json::Value = serde_json::from_slice(&protected_bytes)
                .map_err(|e| {
                    didcomm::transports::TransportError::ProcessingFailed(format!(
                        "Failed to parse protected header: {}",
                        e
                    ))
                })?;

            let alg = protected_header
                .get("alg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            trace!("JWE algorithm: {}", alg);

            // Use DIDComm v1 unpacking for "Authcrypt" or "Anoncrypt"
            if alg == "Authcrypt" || alg == "Anoncrypt" {
                // Parse as EncryptedMessage
                let encrypted: didcomm::v1::EncryptedMessage =
                    serde_json::from_str(&actual_message).map_err(|e| {
                        didcomm::transports::TransportError::ProcessingFailed(format!(
                            "Failed to parse DIDComm v1 message: {}",
                            e
                        ))
                    })?;

                // Unpack using DIDComm v1
                let (message, _metadata) =
                    didcomm::v1::unpack_message(&encrypted, self.wallet_provider.clone())
                        .await
                        .map_err(|e| {
                            didcomm::transports::TransportError::ProcessingFailed(format!(
                                "DIDComm v1 decryption failed: {}",
                                e
                            ))
                        })?;

                debug!("DIDComm v1 message decrypted");

                // Serialize decrypted message back to JSON
                serde_json::to_string(&message).map_err(|e| {
                    didcomm::transports::TransportError::ProcessingFailed(format!(
                        "Failed to serialize decrypted message: {}",
                        e
                    ))
                })?
            } else {
                // Use DIDComm v2 envelope service for other algorithms
                let envelope_service = self.envelope_service.as_ref().ok_or_else(|| {
                    didcomm::transports::TransportError::ProcessingFailed(
                        "EnvelopeService not initialized. Call agent.initialize() first."
                            .to_string(),
                    )
                })?;

                let (message, _unpack_metadata) = envelope_service
                    .unpack(&actual_message)
                    .await
                    .map_err(|e| {
                        didcomm::transports::TransportError::ProcessingFailed(format!(
                            "DIDComm v2 decryption failed: {}",
                            e
                        ))
                    })?;

                debug!("DIDComm v2 message decrypted");

                serde_json::to_string(&message).map_err(|e| {
                    didcomm::transports::TransportError::ProcessingFailed(format!(
                        "Failed to serialize decrypted message: {}",
                        e
                    ))
                })?
            }
        } else {
            // Message is already plaintext
            trace!("Plaintext message received");
            actual_message
        };

        // Create EncryptedMessage from plaintext message
        let mut encrypted_msg = crate::transport::EncryptedMessage::new(
            "test".to_string(),
            "test".to_string(),
            plaintext_message,
            "test".to_string(),
        );

        // Only set sender_endpoint if it's present (don't convert None to empty string)
        if let Some(sender_endpoint) = metadata.sender_endpoint {
            encrypted_msg = encrypted_msg.with_sender_endpoint(sender_endpoint);
        }

        // Route through existing message handling logic
        self.route_message(encrypted_msg)
            .await
            .map_err(|e| didcomm::transports::TransportError::ProcessingFailed(e.to_string()))
    }

    /// Process HTTP message and return optional response
    ///
    /// This method is called by the HTTP inbound transport to get synchronous responses.
    /// It delegates to `process_inbound_http` which handles decryption, routing, and packing.
    async fn receive_message_http(
        &self,
        packed_message: String,
        metadata: didcomm::transports::TransportMetadata,
    ) -> didcomm::transports::Result<Option<String>> {
        // Extract sender_endpoint from metadata
        let sender_endpoint = metadata.sender_endpoint;

        // Use the dedicated HTTP processing method
        self.process_inbound_http(packed_message, sender_endpoint)
            .await
    }
}

impl Agent {
    /// Register an external message handler
    ///
    /// This allows external code to register custom message handlers
    /// for handling DIDComm messages of specific types.
    ///
    /// # Arguments
    /// * `handler` - The message handler to register
    ///
    /// # Example
    /// ```ignore
    /// let handler = Arc::new(MyCustomHandler::new());
    /// agent.register_handler(handler).await;
    /// ```
    pub async fn register_handler(&self, handler: Arc<dyn didcomm::messaging::MessageHandler>) {
        let mut registry = self.handler_registry.write().await;
        let supported_types = handler.supported_types();
        registry.register(handler);
        tracing::info!(
            "✓ External handler registered for types: {:?}",
            supported_types
        );
    }
    /// Route an inbound message through the handler registry
    ///
    /// This is public so TestAgent can call it to route messages.
    /// In production, this would be called by the transport layer.
    pub async fn route_message(
        &self,
        encrypted_msg: crate::transport::EncryptedMessage,
    ) -> Result<()> {
        self.message_router.route_message(encrypted_msg).await
    }

    // (Removed: `pack_message(message)` — a test-only stub that wrapped
    // the payload in literal "test" JWE fields and had zero callers. Real
    // packing goes through `pack_message_with_version` /
    // `pack_message_with_sender`, both of which delegate to the
    // version-aware `EnvelopeService` underneath. The setup-message
    // helpers like `send_to_endpoint_via_https` build their own
    // `EncryptedMessage` after packing.)

    /// Accept an out-of-band invitation and create a connection
    ///
    /// Delegates to the OOB module which orchestrates:
    /// 1. Creating a did:peer:1 DID with service endpoint
    /// 2. Creating a connection request message
    /// 3. Adding signed did_doc~attach to the request
    /// 4. Packing and sending the request message
    ///
    /// # Arguments
    /// * `oob_record` - The out-of-band invitation record
    ///
    /// # Returns
    /// The connection record ID
    pub async fn accept_oob_invitation(
        &self,
        oob_record: &protocol_oob::OutOfBandRecord,
    ) -> Result<String> {
        self.oob().accept_invitation(oob_record).await
    }

    /// Create an out-of-band invitation
    ///
    /// This method automatically adds the agent's endpoint as a service if not provided.
    /// Delegates to the OOB module.
    ///
    /// # Arguments
    /// * `config` - Invitation configuration
    ///
    /// # Returns
    /// The created OutOfBandRecord
    pub async fn create_oob_invitation(
        &self,
        config: crate::modules::oob::InvitationConfig,
    ) -> Result<protocol_oob::OutOfBandRecord> {
        self.oob()
            .create_invitation_with_auto_services(config)
            .await
    }

    /// Receive an out-of-band invitation and optionally auto-create a connection
    ///
    /// If `auto_accept` is true, it will automatically create a connection and send the request message.
    /// Delegates to the OOB module.
    ///
    /// # Arguments
    /// * `invitation` - The out-of-band invitation
    /// * `auto_accept` - Whether to automatically create a connection (default: true)
    ///
    /// # Returns
    /// ReceiveInvitationResult containing the OOB record and optional connection ID
    pub async fn receive_oob_invitation(
        &self,
        invitation: protocol_oob::OutOfBandInvitation,
        auto_accept: Option<bool>,
    ) -> Result<crate::modules::oob::ReceiveInvitationResult> {
        self.oob()
            .receive_invitation_with_auto_accept(invitation, auto_accept)
            .await
    }

    // =========================================================================
    // Blockchain Service (injectable)
    // =========================================================================

    pub async fn process_inbound_http(
        &self,
        packed_message: String,
        sender_endpoint: Option<String>,
    ) -> didcomm::transports::Result<Option<String>> {
        trace!("Processing HTTP inbound message");

        // Event waiter removed — was adding 50ms latency per connection message.
        // The handler emits state_changed events synchronously; no async wait needed.
        let event_waiter = tokio::spawn(async move { None::<agent_events::Event> });

        // Step 2: Process the message as before
        let envelope_service = self.envelope_service.as_ref().ok_or_else(|| {
            didcomm::transports::TransportError::ProcessingFailed(
                "EnvelopeService not initialized".to_string(),
            )
        })?;

        tracing::debug!(
            "[PROCESS-HTTP] Calling envelope_service.unpack() on {} bytes...",
            packed_message.len()
        );
        let unpack_result = envelope_service.unpack(&packed_message).await;
        tracing::debug!(
            "[PROCESS-HTTP] unpack returned: is_ok={}",
            unpack_result.is_ok()
        );

        // Extract both plaintext message and sender DID from unpack metadata
        let (plaintext_message, sender_did) = match unpack_result {
            Ok((message, metadata)) => {
                tracing::debug!(
                    "[PROCESS-HTTP] Unpacked: type={}, id={}, from={:?}",
                    message.msg_type,
                    message.id,
                    metadata.from
                );
                trace!(
                    "Message unpacked (authenticated: {}, encrypted: {})",
                    metadata.authenticated,
                    metadata.encrypted
                );
                if metadata.from.is_none() {
                    warn!("No sender DID in unpack metadata - response will fail");
                }

                // Transport-layer event: a DIDComm message was successfully
                // unpacked. Fires for every inbound JWE — instrumentation
                // hook for audit logs / metrics / latency tracking.
                {
                    let payload = crate::events::DidCommMessageReceivedPayload {
                        message_type: message.msg_type.clone(),
                        sender_did: metadata.from.clone(),
                        encrypted: metadata.encrypted,
                        authenticated: metadata.authenticated,
                    };
                    let meta = agent_events::EventMetadata::for_tenant("agent");
                    let _ = self.events.emit(&meta, payload).await;
                }

                // (Removed: per-message blocking std::fs append of the full
                // pretty-printed decrypted message to /tmp/mediation_e2e.log.
                // It ran on the async worker threads and all tenants contended
                // on one file — a hot-path serialization point.)

                let msg_json = serde_json::to_string(&message).map_err(|e| {
                    didcomm::transports::TransportError::ProcessingFailed(format!(
                        "Failed to serialize unpacked message: {}",
                        e
                    ))
                })?;

                // CRITICAL: Propagate sender DID from unpack metadata to message processor.
                // V1 unpack returns raw base58 verkey as metadata.from (e.g., "9WCgWKU...").
                // This must be converted to did:key format so pack_response() can resolve it.
                // Without this conversion, the ACK response in atomic eCash transfers
                // fails to pack because DID resolution rejects raw verkeys.
                let sender_did = metadata.from.map(|from_val| {
                    if from_val.starts_with("did:") {
                        from_val // Already a DID (V2 unpack or did:key)
                    } else {
                        // Raw base58 Ed25519 verkey from V1 authcrypt — convert to did:key
                        match bs58::decode(&from_val).into_vec() {
                            Ok(key_bytes) if key_bytes.len() == 32 => {
                                let mut multicodec = vec![0xed, 0x01];
                                multicodec.extend_from_slice(&key_bytes);
                                let did_key = format!("did:key:z{}", bs58::encode(&multicodec).into_string());
                                tracing::debug!("[UNPACK] Converted V1 sender verkey to did:key: {}", did_key);
                                did_key
                            }
                            _ => {
                                tracing::warn!("[UNPACK] Could not convert sender verkey to did:key, using as-is: {}", from_val);
                                from_val
                            }
                        }
                    }
                });
                (msg_json, sender_did)
            }
            Err(v2_error) => {
                trace!("V2 unpack failed, trying V1: {}", v2_error);

                let msg = self.message_encryption
                    .decrypt_message(&packed_message)
                    .await
                    .map_err(|v1_error| didcomm::transports::TransportError::ProcessingFailed(
                        format!("DIDComm decryption failed.\n  V2 error (primary): {}\n  V1 error (fallback): {}", v2_error, v1_error)
                    ))?;

                // V1 fallback doesn't have sender DID in metadata
                (msg, None)
            }
        };

        // Check if decrypted message is a Forward (DIDComm v1 routing envelope)
        // This happens when messages are routed through the mediation key to reach
        // a connection-specific key. The mediator delivers the outer anoncrypt JWE,
        // which when decrypted reveals a Forward containing the inner authcrypt JWE.
        let (plaintext_message, sender_did) = {
            let parsed: serde_json::Value =
                serde_json::from_str(&plaintext_message).unwrap_or_default();
            let msg_type = parsed
                .get("@type")
                .or_else(|| parsed.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if msg_type.contains("routing/1.0/forward") {
                tracing::debug!(
                    "[FORWARD-UNWRAP] Received Forward message, unwrapping inner JWE..."
                );
                let to_field = parsed
                    .get("to")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                tracing::debug!("[FORWARD-UNWRAP] Forward 'to': {}", to_field);

                if let Some(inner_msg) = parsed.get("msg") {
                    let inner_jwe = match inner_msg {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Object(_) => {
                            serde_json::to_string(inner_msg).unwrap_or_default()
                        }
                        _ => {
                            return Err(didcomm::transports::TransportError::ProcessingFailed(
                                "Forward message 'msg' field has unexpected type".to_string(),
                            ));
                        }
                    };

                    tracing::debug!(
                        "[FORWARD-UNWRAP] Decrypting inner JWE ({} bytes)...",
                        inner_jwe.len()
                    );

                    // Decrypt inner JWE (try V2 first, then V1 fallback)
                    let inner_unpack = envelope_service.unpack(&inner_jwe).await;
                    match inner_unpack {
                        Ok((inner_message, inner_metadata)) => {
                            tracing::debug!(
                                "[FORWARD-UNWRAP] ✓ Unwrapped Forward, inner type: {}",
                                inner_message.msg_type
                            );
                            let inner_json =
                                serde_json::to_string(&inner_message).map_err(|e| {
                                    didcomm::transports::TransportError::ProcessingFailed(format!(
                                        "Failed to serialize inner message: {}",
                                        e
                                    ))
                                })?;
                            (inner_json, inner_metadata.from)
                        }
                        Err(v2_err) => {
                            // Try V1 fallback
                            match self.message_encryption.decrypt_message(&inner_jwe).await {
                                Ok(inner_msg) => {
                                    tracing::debug!(
                                        "[FORWARD-UNWRAP] ✓ Unwrapped Forward (V1 fallback)"
                                    );
                                    (inner_msg, None)
                                }
                                Err(v1_err) => {
                                    return Err(
                                        didcomm::transports::TransportError::ProcessingFailed(
                                            format!(
                                                "Forward inner JWE decrypt failed. V2: {}, V1: {}",
                                                v2_err, v1_err
                                            ),
                                        ),
                                    );
                                }
                            }
                        }
                    }
                } else {
                    return Err(didcomm::transports::TransportError::ProcessingFailed(
                        "Forward message missing 'msg' field".to_string(),
                    ));
                }
            } else {
                (plaintext_message, sender_did)
            }
        };

        // Log eCash messages for iOS debugging
        if plaintext_message.contains("ecash") || plaintext_message.contains("transfer-note") {
            tracing::debug!(
                "[eCash-RX] process_inbound_http: eCash message detected, dispatching to handler"
            );
        }

        // Check if this is a connection-related message
        let _is_connection_message =
            plaintext_message.contains("didexchange") || plaintext_message.contains("connections");

        // Process the message with sender DID from unpack metadata
        let process_result = self
            .message_processor
            .process_message(&plaintext_message, sender_endpoint, sender_did)
            .await;

        // (Removed: per-message blocking std::fs append of the dispatch
        // result to /tmp/mediation_e2e.log — same hot-path serialization.)

        let response = process_result
            .map_err(|e| didcomm::transports::TransportError::ProcessingFailed(format!("{}", e)))?;

        // Step 3: Cancel the event waiter — it was used for timing diagnostics
        // but adds latency (50ms timeout on every connection message). The handler
        // emits state_changed events synchronously before returning, so waiting
        // provides no benefit for correctness.
        event_waiter.abort();

        // Step 4: Return the response
        Ok(response)
    }

    /// Decrypt a DIDComm message without routing to handlers
    ///
    /// This method is useful for clients that need to decrypt responses from servers
    /// without having handlers registered for response message types.
    ///
    /// # Arguments
    /// * `packed_message` - The encrypted JWE message
    ///
    /// # Returns
    /// The decrypted message as a JSON string
    pub async fn decrypt_only(&self, packed_message: &str) -> Result<String> {
        let envelope_service = self.envelope_service.as_ref().ok_or_else(|| {
            AgentError::Configuration("EnvelopeService not initialized".to_string())
        })?;

        // Try v2 unpack first
        match envelope_service.unpack(packed_message).await {
            Ok((message, _metadata)) => serde_json::to_string(&message)
                .map_err(|e| AgentError::Transport(format!("Failed to serialize message: {}", e))),
            Err(v2_error) => {
                // Fall back to v1 decryption
                trace!("V2 decrypt failed, trying V1: {}", v2_error);
                self.message_encryption
                    .decrypt_message(packed_message)
                    .await
                    .map_err(|v1_error| {
                        AgentError::Transport(format!(
                            "DIDComm decryption failed.\n  V2: {}\n  V1: {}",
                            v2_error, v1_error
                        ))
                    })
            }
        }
    }

    /// Send a DIDComm message to a single DID (DID-only, no connection record needed)
    ///
    /// This method enables direct DID-to-DID messaging without requiring a prior
    /// connection exchange. It:
    /// 1. Resolves the recipient DID to find DIDComm endpoints and keys
    /// 2. Encrypts the message using DIDComm v2 (with optional v1 fallback)
    /// 3. Sends the encrypted message over HTTP
    ///
    /// # Arguments
    /// * `recipient_did` - The DID to send the message to
    /// * `message` - The plaintext message to send
    /// * `use_v1_fallback` - If true, use DIDComm v1 encryption for v1 DIDComm interop
    ///
    /// # Returns
    /// * `Ok(())` - Message sent successfully
    /// * `Err(e)` - Failed to send (resolution, encryption, or transport error)
    ///
    /// # Example
    /// ```ignore
    /// let message = Message::builder("https://didcomm.org/basicmessage/2.0/message")
    ///     .body(serde_json::json!({"content": "Hello!"}))
    ///     .from(agent_did)
    ///     .build();
    ///
    /// agent.send_to_did("did:peer:123", message, false).await?;
    /// ```
    pub async fn send_to_did(
        &self,
        recipient_did: &str,
        message: didcomm::core::Message,
        use_v1_fallback: bool,
    ) -> Result<()> {
        tracing::debug!("📤 [send_to_did] Sending message to {}", recipient_did);
        tracing::debug!("  Message type: {}", message.msg_type);
        tracing::debug!("  Use v1 fallback: {}", use_v1_fallback);

        // Step 1: Resolve recipient DID to get endpoint
        let endpoint = self
            .did_document_service
            .extract_service_endpoint(recipient_did)
            .await
            .map_err(|e| {
                AgentError::DidResolution(format!("Failed to resolve DID {}: {}", recipient_did, e))
            })?;

        tracing::debug!("  Found endpoint: {}", endpoint);

        // Step 2: Pack the message with encryption
        let our_did = self
            .agent_did
            .read()
            .await
            .clone()
            .ok_or(AgentError::NotInitialized)?;

        // Use version-aware packing with automatic detection
        let envelope_service = self
            .envelope_service
            .as_ref()
            .ok_or(AgentError::NotInitialized)?;

        let pack_options = if use_v1_fallback {
            // V1Only mode for explicit v1 DIDComm interop
            tracing::debug!("🔒 Using V1Only mode for Aries TS interop");
            didcomm::core::PackOptions {
                version: didcomm::core::DIDCommVersion::V1Only,
                protect_sender: true,
                sign_message: false,
            }
        } else {
            // V2WithV1Fallback - prefer v2 but fall back to v1 if needed
            tracing::debug!("🔒 Using version-aware packing (V2WithV1Fallback)");
            didcomm::core::PackOptions {
                version: didcomm::core::DIDCommVersion::V2WithV1Fallback,
                protect_sender: true,
                sign_message: false,
            }
        };

        let packed_message = envelope_service
            .pack_encrypted_with_version(&message, recipient_did, Some(&our_did), &pack_options)
            .await
            .map_err(|e| AgentError::Encryption(format!("Message packing failed: {}", e)))?;

        // Step 3: Send to the endpoint
        tracing::debug!("📡 Sending to endpoint: {}", endpoint);

        let result = self
            .transport
            .send_to_endpoint(&endpoint, &packed_message)
            .await
            .map_err(|e| AgentError::Transport(format!("Failed to send to {}: {}", endpoint, e)));

        result?;
        tracing::debug!("✓ Message sent successfully to {}", recipient_did);
        Ok(())
    }

    /// Send a DIDComm message via an established connection.
    ///
    /// Unlike `send_to_did()` which uses the agent's base DID as sender,
    /// this method uses the connection's pairwise DID — matching what the
    /// peer stored during DID Exchange. This is the correct way to send
    /// protocol messages (WebRTC, etc.) over existing connections.
    ///
    /// Uses DIDComm v1 Authcrypt packing with Forward envelope wrapping
    /// for mediated connections (same path as BasicMessages).
    pub async fn send_for_connection(
        &self,
        connection_id: &str,
        message: didcomm::core::Message,
    ) -> Result<()> {
        let is_browser_sync = message.msg_type.contains("browser-sync");
        let body_keys: Vec<String> = message
            .body
            .as_object()
            .map(|body| body.keys().take(8).cloned().collect())
            .unwrap_or_default();

        if is_browser_sync {
            tracing::info!(
                "[send_for_connection] browser-sync start connection_id={} msg_id={} msg_type={} body_keys={:?}",
                connection_id,
                message.id,
                message.msg_type,
                body_keys
            );
        }

        // Look up the connection
        let connection = self
            .connections()
            .find_by_id(connection_id)
            .await?
            .ok_or_else(|| {
                AgentError::Connections(format!("Connection not found: {}", connection_id))
            })?;

        if is_browser_sync {
            tracing::info!(
                "[send_for_connection] browser-sync pairwise connection_id={} our_did={} their_did={:?}",
                connection_id,
                connection.did,
                connection.their_did,
            );
        } else {
            tracing::debug!(
                "[send_for_connection] our_did={}, their_did={:?}",
                connection.did,
                connection.their_did
            );
        }

        // DIAG: always surface the pairwise DIDs the wallet will use to
        // pack this outbound message. We compare these against
        // pack_encrypted_message's `recipient_did` and the mediator's
        // `to=…` log to find where conflation happens.
        tracing::debug!(
            target: "didcomm.diag",
            connection_id = %connection_id,
            msg_type = %message.msg_type,
            our_did = %connection.did,
            their_did = ?connection.their_did,
            their_label = ?connection.their_label,
            "send_for_connection"
        );

        // Convert DIDComm v2 Message to v1 (Aries) form for v1 DIDComm interop.
        let v1_message = Self::message_to_v1(&message);
        if is_browser_sync {
            let v1_json = serde_json::to_string(&v1_message)
                .unwrap_or_else(|e| format!("<failed to serialize v1 preview: {}>", e));
            let preview: String = v1_json.chars().take(600).collect();
            let suffix = if v1_json.chars().count() > 600 {
                "..."
            } else {
                ""
            };
            tracing::info!(
                "[send_for_connection] browser-sync v1_preview connection_id={} msg_id={} body={}{}",
                connection_id,
                message.id,
                preview,
                suffix
            );
        }

        // Delegate the full resolve/pack/forward/POST dance to the
        // canonical sender. It returns any synchronous HTTP response body
        // — if the mediator inlined a DIDComm JWE in the response (e.g.
        // update-available on update-register), dispatch it to registered
        // handlers so it isn't lost.
        match self
            .didcomm_sender
            .send_via_connection(&connection, &v1_message)
            .await
        {
            Ok(response_body) => {
                if is_browser_sync {
                    tracing::info!(
                        "[send_for_connection] browser-sync send ok connection_id={} msg_id={}",
                        connection_id,
                        message.id,
                    );
                }
                if let Some(body) = response_body {
                    let trimmed = body.trim();
                    if !trimmed.is_empty() && trimmed.starts_with('{') {
                        tracing::debug!(
                            connection_id = %connection_id,
                            bytes = trimmed.len(),
                            "send_for_connection: dispatching inline HTTP response body as inbound"
                        );
                        match self.process_inbound_http(trimmed.to_string(), None).await {
                            Ok(Some(reply)) => {
                                // Processing the inline message produced a further
                                // reply for the peer (e.g. issue-credential answering
                                // an inline credential request). The offer's HTTP
                                // response is already consumed, so it can't ride back
                                // inline — ship it as a fresh POST to the connection.
                                tracing::debug!(
                                    connection_id = %connection_id,
                                    bytes = reply.len(),
                                    "send_for_connection: delivering nested return-route reply to peer"
                                );
                                if let Err(e) = self
                                    .didcomm_sender
                                    .send_prepacked_via_connection(&connection, reply)
                                    .await
                                {
                                    tracing::warn!(%e, connection_id = %connection_id,
                                        "send_for_connection: failed to deliver nested reply");
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                tracing::warn!(%e, connection_id = %connection_id,
                                    "send_for_connection: failed to process inline response body");
                            }
                        }
                    }
                }
                Ok(())
            }
            Err(e) => {
                if is_browser_sync {
                    tracing::warn!(
                        "[send_for_connection] browser-sync send failed connection_id={} msg_id={} msg_type={} error={}",
                        connection_id, message.id, message.msg_type, e
                    );
                }
                Err(e)
            }
        }
    }

    /// Send our user profile to a connection (RFC 0711 user-profile).
    ///
    /// Loads the locally stored own profile via `profile_service`, optionally
    /// filters fields via `query`, and sends a `user-profile/1.0/profile`
    /// message over the existing connection. Routing (mediator Forward
    /// envelopes, mesh fallback) is handled by `send_for_connection`.
    ///
    /// # Arguments
    /// * `connection_id` - Connection to send the profile over (must be Completed)
    /// * `send_back_yours` - Ask the peer to reply with their profile
    /// * `query` - Restrict to specific field names (e.g. `["displayName"]`).
    ///   `None` sends the full profile.
    ///
    /// # Errors
    /// * `AgentError::Module` if no own profile is set
    /// * Errors from `send_for_connection` (DID resolution, packing, transport)
    pub async fn send_profile_to_connection(
        &self,
        connection_id: &str,
        send_back_yours: bool,
        query: Option<Vec<String>>,
    ) -> Result<()> {
        let record = self
            .profile_service
            .get_own_profile()
            .await
            .map_err(|e| AgentError::Module(format!("Failed to load own profile: {}", e)))?
            .ok_or_else(|| {
                AgentError::Module("No own profile set — call set_own_profile first".to_string())
            })?;

        let mut profile_msg = protocol_user_profile::UserProfileService::build_profile_message(
            &record,
            query.as_deref(),
        );
        profile_msg.send_back_yours = send_back_yours;

        // Construct didcomm::core::Message with body = full v1 form (including
        // @type/@id) so the v1 packing paths through processor::pack_response
        // emit a wire message with @type. See protocol_connections's
        // request_handler.rs:1027-1034 for the same convention.
        let body = serde_json::to_value(&profile_msg).map_err(|e| {
            AgentError::Module(format!("Failed to serialize ProfileMessage: {}", e))
        })?;
        let didcomm_msg =
            didcomm::core::Message::new(profile_msg.id.clone(), profile_msg.msg_type.clone(), body);

        self.send_for_connection(connection_id, didcomm_msg).await
    }

    /// Ask a connection to send us their profile (RFC 0711 request-profile).
    ///
    /// Sends a `user-profile/1.0/request-profile` message. The peer's
    /// `RequestProfileHandler` will reply with their own profile (filtered
    /// by `query` if provided), which our `ProfileHandler` will save and
    /// emit a `profile.received` / `profile.peer_updated` event for.
    ///
    /// # Arguments
    /// * `connection_id` - Connection to query (must be Completed)
    /// * `query` - Restrict the requested fields (e.g. `["displayName", "displayPicture"]`).
    ///   `None` requests the full profile.
    pub async fn request_profile_from_connection(
        &self,
        connection_id: &str,
        query: Option<Vec<String>>,
    ) -> Result<()> {
        let mut request_msg = protocol_user_profile::RequestProfileMessage::new();
        request_msg.query = query;

        // Body holds the full v1 form (@type/@id at top level inside body) so
        // the agent's packing paths can preserve them on the wire. See
        // send_profile_to_connection above for rationale.
        let body = serde_json::to_value(&request_msg).map_err(|e| {
            AgentError::Module(format!("Failed to serialize RequestProfileMessage: {}", e))
        })?;
        let didcomm_msg =
            didcomm::core::Message::new(request_msg.id.clone(), request_msg.msg_type.clone(), body);

        self.send_for_connection(connection_id, didcomm_msg).await
    }

    /// Convert a DIDComm v2 Message to v1 (Aries-style) JSON for v1 DIDComm interop.
    /// Maps: type→@type, id→@id, body fields flattened to top level, thread→~thread.
    fn message_to_v1(message: &didcomm::core::Message) -> serde_json::Value {
        let mut v1 = serde_json::Map::new();
        v1.insert(
            "@type".to_string(),
            serde_json::Value::String(message.msg_type.clone()),
        );
        v1.insert(
            "@id".to_string(),
            serde_json::Value::String(message.id.clone()),
        );

        // Flatten body fields to top level
        if let Some(body_obj) = message.body.as_object() {
            for (k, v) in body_obj {
                v1.insert(k.clone(), v.clone());
            }
        }

        // Convert thread → ~thread
        if let Some(ref thread) = message.thread {
            if let Ok(thread_val) = serde_json::to_value(thread) {
                v1.insert("~thread".to_string(), thread_val);
            }
        }

        // Carry v2 attachments as the Aries `<role>~attach` decorator so
        // credential/proof payloads (offers, requests, credentials, proofs)
        // survive the v1 bridge — otherwise the receiver sees no attachment.
        if let Some(atts) = &message.attachments {
            if !atts.is_empty() {
                if let Ok(atts_json) = serde_json::to_value(atts) {
                    v1.insert(
                        Self::v1_attach_field(&message.msg_type).to_string(),
                        atts_json,
                    );
                }
            }
        }

        serde_json::Value::Object(v1)
    }

    /// The Aries v1 attachment-decorator field name for a message type
    /// (issue-credential 2.0 / present-proof 2.0). Falls back to a generic
    /// `~attach` so the inbound parser (which matches any `*~attach`) still
    /// reconstructs it.
    fn v1_attach_field(msg_type: &str) -> &'static str {
        if msg_type.ends_with("/offer-credential") {
            "offers~attach"
        } else if msg_type.ends_with("/request-credential") {
            "requests~attach"
        } else if msg_type.ends_with("/issue-credential") {
            "credentials~attach"
        } else if msg_type.ends_with("/request-presentation") {
            "request_presentations~attach"
        } else if msg_type.ends_with("/presentation") {
            "presentations~attach"
        } else {
            "~attach"
        }
    }

    /// Send a DIDComm message to multiple DIDs (batch/broadcast operation)
    ///
    /// This method sends the same message to multiple recipients by packing
    /// a separate encrypted envelope for each recipient. Each send operation
    /// is performed sequentially to avoid cloning issues.
    ///
    /// # Arguments
    /// * `recipient_dids` - List of DIDs to send the message to
    /// * `message` - The plaintext message to send (same for all recipients)
    /// * `use_v1_fallback` - If true, use DIDComm v1 encryption for v1 DIDComm interop
    ///
    /// # Returns
    /// * `Vec<(String, Result<()>)>` - Per-recipient results (DID, send result)
    ///
    /// # Example
    /// ```ignore
    /// let message = Message::builder("https://example.com/gossip/1.0/broadcast")
    ///     .body(serde_json::json!({"data": "Important update"}))
    ///     .from(agent_did)
    ///     .build();
    ///
    /// let results = agent.send_to_dids(
    ///     vec!["did:peer:alice", "did:peer:bob", "did:peer:carol"],
    ///     message,
    ///     false
    /// ).await;
    ///
    /// for (did, result) in results {
    ///     match result {
    ///         Ok(_) => println!("✓ Sent to {}", did),
    ///         Err(e) => println!("✗ Failed to send to {}: {}", did, e),
    ///     }
    /// }
    /// ```
    pub async fn send_to_dids(
        &self,
        recipient_dids: Vec<&str>,
        message: didcomm::core::Message,
        use_v1_fallback: bool,
    ) -> Vec<(String, Result<()>)> {
        tracing::debug!(
            "📤 [send_to_dids] Broadcasting to {} recipients",
            recipient_dids.len()
        );

        let mut results = Vec::new();

        // Send to each recipient sequentially
        // Note: Could be parallelized using join_all with futures, but keeping simple for now
        for recipient_did in recipient_dids {
            let result = self
                .send_to_did(recipient_did, message.clone(), use_v1_fallback)
                .await;
            results.push((recipient_did.to_string(), result));
        }

        tracing::debug!(
            "✓ Broadcast complete: {}/{} successful",
            results.iter().filter(|(_, r)| r.is_ok()).count(),
            results.len()
        );

        results
    }

    /// Pack a DIDComm message with version-aware encryption (without sending)
    ///
    /// This method packs a message using version-aware DIDComm encryption,
    /// automatically choosing v2 for did:peer:2 DIDs with fallback to v1.
    ///
    /// # Arguments
    /// * `message` - The DIDComm message to pack
    /// * `recipient_did` - Recipient's DID
    /// * `use_v1_fallback` - If true, use V1Only mode; if false, use V2WithV1Fallback
    ///
    /// # Returns
    /// * `Ok(String)` - Encrypted message as JSON string
    /// * `Err(e)` - Failed to pack (resolution, encryption error)
    pub async fn pack_message_with_version(
        &self,
        message: &didcomm::core::Message,
        recipient_did: &str,
        use_v1_fallback: bool,
    ) -> Result<String> {
        // Thin wrapper that resolves the sender as the agent's own DID
        // and delegates to `pack_message_with_sender` — the canonical
        // packing entry point. Kept as a separate method so the dozens
        // of existing callers don't need to look up `agent_did`
        // themselves. The actual encryption + version-negotiation logic
        // lives in one place (`pack_message_with_sender` → EnvelopeService).
        let our_did = self
            .agent_did
            .read()
            .await
            .clone()
            .ok_or(AgentError::NotInitialized)?;
        self.pack_message_with_sender(message, recipient_did, &our_did, use_v1_fallback)
            .await
    }

    /// Pack a message with an explicit sender DID
    ///
    /// This is used for bootstrap messaging where we need to use did:peer:2
    /// as the sender (which is self-resolving) rather than did:ajna
    /// (which requires gossip-based resolution).
    ///
    /// # Arguments
    /// * `message` - The DIDComm message to pack
    /// * `recipient_did` - The recipient's DID
    /// * `sender_did` - The sender's DID (e.g., did:peer:2 for bootstrap)
    /// * `use_v1_fallback` - If true, use V1Only mode; otherwise V2WithV1Fallback
    ///
    /// # Returns
    /// * `Ok(String)` - Encrypted message as JSON string
    /// * `Err(e)` - Failed to pack (resolution, encryption error)
    pub async fn pack_message_with_sender(
        &self,
        message: &didcomm::core::Message,
        recipient_did: &str,
        sender_did: &str,
        use_v1_fallback: bool,
    ) -> Result<String> {
        tracing::debug!("📦 [pack_message_with_sender] Packing message");
        tracing::debug!("  To: {}", recipient_did);
        tracing::debug!("  From: {}", sender_did);
        tracing::debug!("  Message type: {}", message.msg_type);

        let envelope_service = self
            .envelope_service
            .as_ref()
            .ok_or(AgentError::NotInitialized)?;

        let pack_options = if use_v1_fallback {
            tracing::debug!("🔒 Using V1Only mode");
            didcomm::core::PackOptions {
                version: didcomm::core::DIDCommVersion::V1Only,
                protect_sender: true,
                sign_message: false,
            }
        } else {
            tracing::debug!("🔒 Using V2WithV1Fallback mode");
            didcomm::core::PackOptions {
                version: didcomm::core::DIDCommVersion::V2WithV1Fallback,
                protect_sender: true,
                sign_message: false,
            }
        };

        let packed_message = envelope_service
            .pack_encrypted_with_version(message, recipient_did, Some(sender_did), &pack_options)
            .await
            .map_err(|e| AgentError::Encryption(format!("Message packing failed: {}", e)))?;

        tracing::debug!("✓ Message packed with explicit sender DID");

        Ok(packed_message)
    }

    /// Synchronous DIDComm request-response over HTTP.
    ///
    /// Encapsulates the JWE authcrypt round-trip:
    /// 1. Build a `didcomm::core::Message` with the given PIURI and JSON body
    /// 2. Pack (authcrypt JWE) to the recipient
    /// 3. POST to `{endpoint}/didcomm`
    /// 4. Decrypt the JWE response
    /// 5. Return the `body` field of the decrypted message (whole message if
    ///    no `body`)
    ///
    /// Used by eCash CBDC flows but generally useful for any blocking RPC
    /// pattern over DIDComm. Lifted from the FFI helper so non-FFI consumers
    /// (vilko-api eCash routes, integration tests) can reuse it instead of
    /// duplicating the pack/POST/decrypt boilerplate.
    pub async fn didcomm_request(
        &self,
        endpoint: &str,
        piuri: &str,
        body: serde_json::Value,
        our_did: &str,
        recipient_did: &str,
    ) -> Result<serde_json::Value> {
        let message = didcomm::core::MessageBuilder::new(piuri.to_string())
            .body(body)
            .from(our_did.to_string())
            .to(vec![recipient_did.to_string()])
            .build();

        let packed = self
            .pack_message_with_sender(&message, recipient_did, our_did, false)
            .await
            .map_err(|e| AgentError::Encryption(format!("DIDComm pack failed: {}", e)))?;

        // Reuse the shared HTTP client (see `agent/src/http.rs`) — every
        // direct DIDComm send to the same peer benefits from a warm pool.
        let resp = self
            .http_client
            .post(format!("{}/didcomm", endpoint))
            .header("Content-Type", "application/didcomm-encrypted+json")
            .body(packed)
            .send()
            .await
            .map_err(|e| AgentError::Transport(format!("DIDComm POST failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AgentError::Transport(format!(
                "DIDComm request failed (HTTP {}): {}",
                status, text
            )));
        }

        let resp_body = resp
            .text()
            .await
            .map_err(|e| AgentError::Transport(format!("Response read failed: {}", e)))?;

        let decrypted = self
            .decrypt_only(&resp_body)
            .await
            .map_err(|e| AgentError::Encryption(format!("DIDComm decrypt failed: {}", e)))?;

        let msg: serde_json::Value = serde_json::from_str(&decrypted)
            .map_err(|e| AgentError::Module(format!("Response JSON parse failed: {}", e)))?;

        // DIDComm v2 messages have a `body` field; if not present, return the
        // whole message (the FFI's caller-side fallback).
        Ok(msg.get("body").cloned().unwrap_or(msg))
    }
}
