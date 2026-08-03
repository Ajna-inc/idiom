//! Message Processing
//!
//! Handles processing of inbound DIDComm messages.
//! Extracted from agent.rs to enable modular transport architecture.

use crate::crypto::KeyExtractor;
use crate::error::{AgentError, Result};
use crate::messaging::{parse_message_to_didcomm, MessageContextBuilder};
use agent_core::traits::WalletProvider;
use did::core::DidRepository;
use didcomm::core::{EnvelopeService, MessageBuilder as DidcommMessageBuilder, PackOptions};
use didcomm::messaging::{
    DidCommDocumentService, HandlerRegistry, InboundMessage, OutboundMessage,
};
use protocol_connections::ConnectionRepositoryTrait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, trace, warn};

/// Processes inbound DIDComm messages and generates responses
pub struct MessageProcessor {
    handler_registry: Arc<RwLock<HandlerRegistry>>,
    connection_repository: Arc<dyn ConnectionRepositoryTrait>,
    did_repository: Arc<DidRepository>,
    wallet_provider: Arc<dyn WalletProvider>,
    did_document_service: Arc<DidCommDocumentService>,
    agent_did: Arc<RwLock<Option<String>>>,
    agent_key_id: Arc<RwLock<Option<String>>>,
    /// EnvelopeService for version-aware DIDComm encryption (v1/v2)
    /// Set after Agent initialization via set_envelope_service()
    /// Uses RwLock for interior mutability since MessageProcessor is wrapped in Arc
    envelope_service: RwLock<Option<Arc<EnvelopeService>>>,
    /// Shared HTTP client for outbound messages (reuses TCP connections via keep-alive).
    /// Creating a new client per message wastes 50-500ms on TLS/pool initialization.
    http_client: reqwest::Client,
}

impl MessageProcessor {
    /// Create a new message processor
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        handler_registry: Arc<RwLock<HandlerRegistry>>,
        connection_repository: Arc<dyn ConnectionRepositoryTrait>,
        did_repository: Arc<DidRepository>,
        wallet_provider: Arc<dyn WalletProvider>,
        did_document_service: Arc<DidCommDocumentService>,
        agent_did: Arc<RwLock<Option<String>>>,
        agent_key_id: Arc<RwLock<Option<String>>>,
    ) -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .pool_max_idle_per_host(10)
                .build()
                .expect("Failed to create HTTP client"),
            handler_registry,
            connection_repository,
            did_repository,
            wallet_provider,
            did_document_service,
            agent_did,
            agent_key_id,
            envelope_service: RwLock::new(None),
        }
    }

    /// Set the EnvelopeService for version-aware DIDComm encryption
    ///
    /// This should be called after Agent::initialize() to enable v2 packing with v1 fallback.
    /// If not set, the processor will use didcomm_v1 directly.
    pub async fn set_envelope_service(&self, envelope_service: Arc<EnvelopeService>) {
        let mut guard = self.envelope_service.write().await;
        *guard = Some(envelope_service);
    }

    /// Process an inbound message and optionally generate a response
    ///
    /// # Arguments
    /// * `message_json` - The decrypted plaintext message as JSON
    /// * `sender_endpoint` - Optional sender endpoint for return routing
    /// * `sender_did` - Optional sender DID from unpack metadata (for responding)
    ///
    /// # Returns
    /// * `Ok(Some(packed_response))` - Handler generated a response to return
    /// * `Ok(None)` - No response needed or async send initiated
    /// * `Err(e)` - Processing failed
    pub async fn process_message(
        &self,
        message_json: &str,
        sender_endpoint: Option<String>,
        sender_did: Option<String>,
    ) -> Result<Option<String>> {
        // Parse to get message type
        let message: serde_json::Value = serde_json::from_str(message_json)
            .map_err(|e| AgentError::Transport(format!("Failed to parse message: {}", e)))?;

        // Try to get @type field, but also check for "type" (DIDComm v1 compatibility)
        let message_type = message
            .get("@type")
            .or_else(|| message.get("type"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AgentError::Transport("Message missing @type or type field".to_string())
            })?;

        debug!("Processing message type: {}", message_type);

        // Look up handler
        let registry = self.handler_registry.read().await;
        let handler = registry.get_handler(message_type);
        drop(registry);

        let handler = handler.ok_or_else(|| {
            AgentError::Transport(format!(
                "No handler registered for message type: {}",
                message_type
            ))
        })?;

        // Parse message using utility function
        let didcomm_msg = parse_message_to_didcomm(&message)?;

        // Determine sender DID:
        // 1. Use sender_did from unpack metadata (for encrypted messages)
        // 2. Fall back to message.from field (for plaintext DIDComm v2 messages)
        // 3. Fall back to "from" in raw message JSON (if not parsed into DidcommMessage)
        let effective_sender = sender_did
            .clone()
            .or_else(|| didcomm_msg.from.clone())
            .or_else(|| {
                message
                    .get("from")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

        // Determine our own DID for context.to (needed for handler responses)
        let our_did = self.agent_did.read().await.clone();

        // Resolve connection_id from sender DID (their_did from our perspective)
        let connection_id = if let Some(ref sender) = effective_sender {
            // First try direct match on their_did
            let mut found = match self.connection_repository.find_by_their_did(sender).await {
                Ok(connections) if !connections.is_empty() => {
                    debug!(
                        "Resolved connection_id={} from their_did={}",
                        connections[0].id, sender
                    );
                    Some(connections[0].id.clone())
                }
                _ => None,
            };
            // If direct match fails, try matching by verkey. The `sender`
            // identifier can arrive in ANY of three forms depending on
            // what packer produced the JWE:
            //   1. `did:key:z…` — extract the raw Ed25519 base58 verkey
            //      via the multicodec-prefix decode, then match against
            //      stored `their_authentication_key_base58`.
            //   2. Raw base58 verkey — DIDComm v1 authcrypt unpack
            //      returns `metadata.from` as a bare base58 string with
            //      no prefix. Match directly against
            //      `their_authentication_key_base58` (no decode needed).
            //   3. `did:peer:…` — matched already by `find_by_their_did`
            //      above, so this path won't run.
            //
            // Without form (2) the receiver-side connection lookup
            // silently misses and the basic-message handler falls back
            // to "most recent completed connection", which is a
            // coin-flip when 2+ tenants exist — messages get filed on
            // the wrong connection and the recipient's DM URL load
            // returns empty.
            if found.is_none() {
                let sender_verkey =
                    extract_verkey_from_did_key(sender).unwrap_or_else(|| sender.to_string());
                if let Ok(all_conns) = self.connection_repository.get_all().await {
                    for c in &all_conns {
                        if let Some(ref their_key) = c.their_authentication_key_base58 {
                            if *their_key == sender_verkey {
                                debug!("Resolved connection_id={} from verkey match", c.id);
                                found = Some(c.id.clone());
                                break;
                            }
                        }
                    }
                }
            }
            if found.is_none() {
                debug!("No connection found for sender_did={}", sender);
            }
            found
        } else {
            None
        };

        // Create message context using builder
        // IMPORTANT: sender_did is critical for authentication and responding
        // IMPORTANT: our_did (context.to) is critical for packing response messages
        let context = MessageContextBuilder::from_decrypted_message(&didcomm_msg)
            .with_from(effective_sender.clone())
            .with_to(our_did)
            .with_connection_id(connection_id)
            .with_sender_endpoint(sender_endpoint)
            .build();

        match context.from.as_ref() {
            Some(sender_did) => trace!("Sender DID: {}", sender_did),
            None => warn!("No sender DID in context - response may fail"),
        }

        // Create inbound message
        let inbound = InboundMessage {
            message: didcomm_msg,
            context,
        };

        // Call handler
        trace!("Calling handler for {}", message_type);
        let response = handler
            .handle(inbound)
            .await
            .map_err(|e| AgentError::Transport(format!("Handler failed: {}", e)))?;

        // Process response
        if let Some(outbound) = response {
            self.process_outbound_response(outbound).await
        } else {
            trace!("No response from handler for {}", message_type);
            Ok(None)
        }
    }

    /// Process an outbound response from a handler
    async fn process_outbound_response(&self, outbound: OutboundMessage) -> Result<Option<String>> {
        // Check for async send (return_route = "none")
        let should_send_async = outbound
            .message
            .extra
            .get("~transport")
            .and_then(|t| t.get("return_route"))
            .and_then(|r| r.as_str())
            .map(|r| r == "none")
            .unwrap_or(false);

        if should_send_async {
            trace!("Async send: return_route=none");
            // Spawn async send task
            self.send_async(outbound).await?;
            return Ok(None);
        }

        trace!("Packing response for return");

        // Pack the response
        self.pack_response(outbound).await.map(Some)
    }

    /// Send a message asynchronously (spawns a background task)
    async fn send_async(&self, outbound: OutboundMessage) -> Result<()> {
        trace!(
            "Async send: {} to {}",
            outbound.message.msg_type,
            outbound.to
        );

        // Clone necessary Arc references for the async task
        let connection_repo = self.connection_repository.clone();
        let did_repo = self.did_repository.clone();
        let agent_did = self.agent_did.clone();
        let agent_key_id = self.agent_key_id.clone();
        let wallet = self.wallet_provider.clone();
        let did_doc_service = self.did_document_service.clone();
        let envelope_service = self.envelope_service.read().await.clone();
        let http_client = self.http_client.clone();

        tokio::spawn(async move {
            if let Err(e) = Self::send_async_static(
                outbound,
                connection_repo,
                did_repo,
                agent_did,
                agent_key_id,
                wallet,
                did_doc_service,
                envelope_service,
                http_client,
            )
            .await
            {
                error!("Failed to send async message: {}", e);
            }
        });

        Ok(())
    }

    /// Static method for sending messages asynchronously
    /// (Used in spawned tasks where self is not available)
    #[allow(clippy::too_many_arguments)]
    async fn send_async_static(
        outbound: OutboundMessage,
        connection_repository: Arc<dyn ConnectionRepositoryTrait>,
        did_repository: Arc<DidRepository>,
        _agent_did: Arc<RwLock<Option<String>>>,
        _agent_key_id: Arc<RwLock<Option<String>>>,
        wallet_provider: Arc<dyn WalletProvider>,
        did_document_service: Arc<DidCommDocumentService>,
        envelope_service: Option<Arc<EnvelopeService>>,
        http_client: reqwest::Client,
    ) -> Result<()> {
        // Get connection record
        let conn_id = outbound.connection_id.as_ref().ok_or_else(|| {
            AgentError::Transport("Complete message missing connection_id".to_string())
        })?;

        let conn_record = connection_repository
            .find_by_id(conn_id)
            .await
            .map_err(|e| AgentError::Transport(format!("Failed to find connection: {}", e)))?
            .ok_or_else(|| AgentError::Transport(format!("Connection not found: {}", conn_id)))?;

        let is_v2 = conn_record.is_v2();

        // Get endpoint from their DID
        let their_did = conn_record
            .their_did
            .clone()
            .ok_or_else(|| AgentError::Transport("Connection missing their_did".to_string()))?;
        let endpoint = did_document_service
            .extract_service_endpoint(&their_did)
            .await
            .map_err(|e| AgentError::Transport(format!("Failed to extract endpoint: {}", e)))?;

        trace!("Async send to endpoint: {} (v2={})", endpoint, is_v2);

        let (packed_json, content_type) = if is_v2 {
            // V2 path: use EnvelopeService for DID-based encryption
            let es = envelope_service.ok_or_else(|| {
                AgentError::Transport(
                    "V2 connection requires EnvelopeService but it is not set".to_string(),
                )
            })?;

            let protocol_message: serde_json::Value = serde_json::to_value(&outbound.message.body)
                .map_err(|e| {
                    AgentError::Transport(format!("Failed to serialize message: {}", e))
                })?;

            let sender_did = outbound.from.clone();
            let didcomm_msg = DidcommMessageBuilder::new(outbound.message.msg_type.clone())
                .id(outbound.message.id.clone())
                .body(protocol_message)
                .from(sender_did.clone())
                .to(vec![their_did.clone()])
                .build();

            // V2WithV1Fallback — same options the sender uses; v2_only can fail to
            // resolve a peer's did:peer:2 verification material.
            let pack_options = PackOptions::with_fallback();
            let packed = es
                .pack_encrypted_with_version(
                    &didcomm_msg,
                    &their_did,
                    Some(&sender_did),
                    &pack_options,
                )
                .await
                .map_err(|e| {
                    AgentError::Transport(format!("EnvelopeService v2 pack failed: {}", e))
                })?;

            (packed, "application/didcomm-encrypted+json")
        } else {
            // V1 path: use stored base58 keys
            let message_value = serde_json::to_value(&outbound.message.body).map_err(|e| {
                AgentError::Transport(format!("Failed to serialize message: {}", e))
            })?;

            let message_map: HashMap<String, serde_json::Value> =
                serde_json::from_value(message_value).map_err(|e| {
                    AgentError::Transport(format!("Failed to convert message: {}", e))
                })?;

            let recipient_auth_key =
                conn_record.their_authentication_key_base58.ok_or_else(|| {
                    AgentError::Transport("No stored auth key in connection".to_string())
                })?;
            let recipient_encryption_key =
                conn_record.their_key_agreement_key_base58.ok_or_else(|| {
                    AgentError::Transport("No stored encryption key in connection".to_string())
                })?;

            // Get sender key ID from the connection's DID
            let sender_key_id = did_repository
                .find_by_did(&conn_record.did)
                .and_then(|record| record.keys.first().map(|key| key.kms_key_id.clone()))
                .ok_or_else(|| {
                    AgentError::Transport(format!(
                        "Connection DID not found in repository: {}",
                        conn_record.did
                    ))
                })?;

            let packed = pack_message_v1(
                &message_map,
                &recipient_auth_key,
                &recipient_encryption_key,
                &sender_key_id,
                wallet_provider.clone(),
            )
            .await?;

            (packed, "application/ssi-agent-wire")
        };

        // Send via HTTP POST (reuse shared client for TCP keep-alive)
        let response = http_client
            .post(&endpoint)
            .header("Content-Type", content_type)
            .body(packed_json)
            .send()
            .await
            .map_err(|e| AgentError::Transport(format!("HTTP POST failed: {}", e)))?;

        if response.status().is_success() {
            debug!("Async message sent (status: {})", response.status());
            Ok(())
        } else {
            Err(AgentError::Transport(format!(
                "HTTP POST failed with status: {}",
                response.status()
            )))
        }
    }

    /// Pack a response message for return routing
    async fn pack_response(&self, outbound: OutboundMessage) -> Result<String> {
        // Extract the protocol message from the body
        let response_message = serde_json::to_value(&outbound.message.body)
            .map_err(|e| AgentError::Transport(format!("Failed to serialize response: {}", e)))?;

        // Strip any fragment from recipient DID - the fragment (e.g., #key-2)
        // comes from JWE's skid field during unpack but should not be in message's to field
        let mut recipient_did = outbound
            .to
            .split('#')
            .next()
            .unwrap_or(&outbound.to)
            .to_string();
        let mut sender_did = outbound.from.clone();

        // Check connection record for DIDComm version and stored keys
        let mut is_v2 = false;
        let mut has_stored_keys = false;
        if let Some(conn_id) = &outbound.connection_id {
            if let Ok(Some(conn_record)) = self.connection_repository.find_by_id(conn_id).await {
                is_v2 = conn_record.is_v2();
                has_stored_keys = conn_record.their_authentication_key_base58.is_some()
                    && conn_record.their_key_agreement_key_base58.is_some();
                // Prefer the connection's negotiated DIDs for packing — the same full
                // did:peer:2 values the outbound sender uses in `send_via_connection`.
                // `outbound.to`/`from` are derived from the inbound JWE context and can
                // be a key-form DID that resolves without base58, which breaks
                // did:peer:2 resolution (why the offer sends but the reply failed).
                if let Some(their) = conn_record.their_did.clone() {
                    recipient_did = their.split('#').next().unwrap_or(&their).to_string();
                }
                if !conn_record.did.is_empty() {
                    sender_did = conn_record.did.clone();
                }
            }
        }

        // Path 0a: the recipient's did:peer:2 advertises a v1 `did-communication`
        // service. Aries agents (credo) use a self-resolving did:peer:2 with NO
        // did_doc~attach but a v1 service — so the DID method is peer:2 yet the
        // channel is DIDComm v1 (RFC19). Packing v2 there sets the JWE `kid` to
        // the did:peer:2 DID URL, which the mediator can't match against its
        // base58 keylist ("no mediation for recipient keys") — the `complete`
        // is dropped and the peer stays at ResponseSent. Pack v1 so the `kid` is
        // the base58 verkey the peer registered; `pack_with_v1` resolves the
        // recipient key straight from the DID.
        if did_peer2_is_v1_did_communication(&recipient_did) {
            trace!("Packing with v1 (did:peer:2 carrying a did-communication service)");
            return self
                .pack_with_v1(
                    message_to_v1_wire(&outbound.message),
                    &recipient_did,
                    &sender_did,
                    &outbound.connection_id,
                )
                .await;
        }

        // Path 0: a v1 peer (did:peer:1) with handshake keys — pack v1 with the
        // stored base58 keys directly. `is_v2` may be true because OUR DID is
        // did:peer:2, but the RECIPIENT is v1 and resolving its DID doc for v2
        // verification material fails ("missing public_key_base58"). This
        // mirrors what `send_via_connection` does for the offer.
        let recipient_is_v2 =
            recipient_did.starts_with("did:peer:2") || recipient_did.starts_with("did:key");
        if has_stored_keys && !recipient_is_v2 {
            trace!("Packing with v1 (stored keys, v1 recipient)");
            return self
                .pack_with_v1(
                    message_to_v1_wire(&outbound.message),
                    &recipient_did,
                    &sender_did,
                    &outbound.connection_id,
                )
                .await;
        }

        // Path 1: V2 connections — always use EnvelopeService (DID-based resolution, not stored keys)
        if is_v2 {
            let envelope_service_guard = self.envelope_service.read().await;
            if let Some(ref envelope_service) = *envelope_service_guard {
                trace!("Packing with EnvelopeService (v2 connection)");

                let mut builder = DidcommMessageBuilder::new(outbound.message.msg_type.clone())
                    .id(outbound.message.id.clone())
                    .body(response_message)
                    .from(sender_did.clone())
                    .to(vec![recipient_did.clone()]);
                // Carry attachments (offers/requests/credentials/proofs) so the
                // v2 return-route reply isn't stripped to its body — the same
                // payloads the outbound sender includes.
                if let Some(atts) = &outbound.message.attachments {
                    for a in atts {
                        builder = builder.add_attachment(a.clone());
                    }
                }
                let mut didcomm_msg = builder.build();
                didcomm_msg.thread = outbound.message.thread.clone();

                // Use V2WithV1Fallback (not v2_only) — the same options the outbound
                // sender uses in `pack_via_envelope_service`. v2_only fails resolving
                // some peers' did:peer:2 verification material ("missing
                // public_key_base58"); the fallback path resolves it correctly, which
                // is why the offer (sent via the sender) works but replies packed here
                // did not.
                let pack_options = PackOptions::with_fallback();
                let packed_response = envelope_service
                    .pack_encrypted_with_version(
                        &didcomm_msg,
                        &recipient_did,
                        Some(&sender_did),
                        &pack_options,
                    )
                    .await
                    .map_err(|e| {
                        AgentError::Transport(format!("EnvelopeService v2 pack failed: {}", e))
                    })?;

                return Ok(packed_response);
            }
            return Err(AgentError::Transport(
                "V2 connection requires EnvelopeService but it is not set".to_string(),
            ));
        }

        // Path 2: V1 with stored keys (from did_doc~attach, not DID resolution)
        if has_stored_keys {
            trace!("Packing with v1 (stored keys from did_doc~attach)");
            return self
                .pack_with_v1(
                    message_to_v1_wire(&outbound.message),
                    &recipient_did,
                    &sender_did,
                    &outbound.connection_id,
                )
                .await;
        }

        // Path 3: Use EnvelopeService for version-aware packing if available
        let envelope_service_guard = self.envelope_service.read().await;
        if let Some(ref envelope_service) = *envelope_service_guard {
            trace!("Packing with EnvelopeService");

            let mut builder = DidcommMessageBuilder::new(outbound.message.msg_type.clone())
                .id(outbound.message.id.clone())
                .body(response_message)
                .from(sender_did.clone())
                .to(vec![recipient_did.clone()]);
            // Carry attachments (offers/requests/credentials/proofs) + thread so
            // the reply isn't stripped to its body — same as Path 1.
            if let Some(atts) = &outbound.message.attachments {
                for a in atts {
                    builder = builder.add_attachment(a.clone());
                }
            }
            let mut didcomm_msg = builder.build();
            didcomm_msg.thread = outbound.message.thread.clone();

            let pack_options = PackOptions::with_fallback();
            let packed_response = envelope_service
                .pack_encrypted_with_version(
                    &didcomm_msg,
                    &recipient_did,
                    Some(&sender_did),
                    &pack_options,
                )
                .await
                .map_err(|e| {
                    AgentError::Transport(format!("EnvelopeService pack failed: {}", e))
                })?;

            return Ok(packed_response);
        }
        drop(envelope_service_guard);

        // Path 4: Fallback to v1 directly. Use the full v1 wire message
        // (`@type` + `~thread` + `<role>~attach`), not the body-only
        // `response_message` — otherwise the reply has no `@type` and the
        // receiver rejects it ("Message missing @type or type field").
        trace!("Packing with v1 (fallback)");
        self.pack_with_v1(
            message_to_v1_wire(&outbound.message),
            &recipient_did,
            &sender_did,
            &outbound.connection_id,
        )
        .await
    }

    /// Pack a message using DIDComm v1
    /// Consolidates the v1 packing logic used in multiple places
    async fn pack_with_v1(
        &self,
        message: serde_json::Value,
        recipient_did: &str,
        sender_did: &str,
        connection_id: &Option<String>,
    ) -> Result<String> {
        // Convert message to HashMap for didcomm::v1::pack_message
        let message_map: HashMap<String, serde_json::Value> = serde_json::from_value(message)
            .map_err(|e| {
                AgentError::Transport(format!("Failed to convert message to HashMap: {}", e))
            })?;

        // Extract recipient keys (checks connection record first, then DID resolution)
        let (recipient_auth_key, recipient_encryption_key) = self
            .extract_recipient_keys(recipient_did, connection_id)
            .await?;

        // Find sender key in wallet
        let sender_key_id = self.find_sender_key(sender_did).await?;

        // Pack with DIDComm v1 using shared helper
        pack_message_v1(
            &message_map,
            &recipient_auth_key,
            &recipient_encryption_key,
            &sender_key_id,
            self.wallet_provider.clone(),
        )
        .await
    }

    /// Extract recipient keys (authentication and encryption keys)
    async fn extract_recipient_keys(
        &self,
        recipient_did: &str,
        connection_id: &Option<String>,
    ) -> Result<(String, String)> {
        if let Some(conn_id) = connection_id {
            // Try to get keys from connection record first
            if let Ok(Some(conn_record)) = self.connection_repository.find_by_id(conn_id).await {
                if let (Some(auth_key), Some(encryption_key)) = (
                    &conn_record.their_authentication_key_base58,
                    &conn_record.their_key_agreement_key_base58,
                ) {
                    trace!("Using stored keys from connection record");
                    return Ok((auth_key.clone(), encryption_key.clone()));
                }
            }
        }

        // Fall back to DID resolution
        trace!("Resolving keys from DID: {}", recipient_did);
        let key_extractor = KeyExtractor::new(
            self.did_document_service.clone(),
            self.wallet_provider.clone(),
        );

        let auth_key = key_extractor
            .extract_public_key_from_did(recipient_did)
            .await?;
        let encryption_key = key_extractor
            .extract_key_agreement_from_did(recipient_did)
            .await?;

        Ok((auth_key, encryption_key))
    }

    /// Find the sender's key ID in the wallet
    async fn find_sender_key(&self, sender_did: &str) -> Result<String> {
        let agent_did_lock = self.agent_did.read().await;
        if let Some(agent_did) = agent_did_lock.as_ref() {
            if sender_did == agent_did {
                // This is the agent's own DID - use stored key ID directly
                drop(agent_did_lock);
                let agent_key_lock = self.agent_key_id.read().await;
                if let Some(key_id) = agent_key_lock.as_ref() {
                    trace!("Using agent's stored key ID");
                    return Ok(key_id.clone());
                }
                // agent_key_id not set — fall through to KeyExtractor lookup
            } else {
                drop(agent_did_lock);
            }
        } else {
            drop(agent_did_lock);
        }

        // Resolve key ID from DID via KeyExtractor (handles did:key, did:peer, etc.)
        let key_extractor = KeyExtractor::new(
            self.did_document_service.clone(),
            self.wallet_provider.clone(),
        );
        key_extractor.find_key_for_did(sender_did).await
    }
}

/// Pack a message using DIDComm v1 (standalone function for use in static contexts)
/// This is the core v1 packing logic shared by multiple methods.
pub async fn pack_message_v1(
    message_map: &HashMap<String, serde_json::Value>,
    recipient_auth_key: &str,
    recipient_encryption_key: &str,
    sender_key_id: &str,
    wallet_provider: Arc<dyn WalletProvider>,
) -> Result<String> {
    let encrypted = didcomm::v1::pack_message(
        message_map,
        &[(
            recipient_auth_key.to_string(),
            recipient_encryption_key.to_string(),
        )],
        Some(sender_key_id),
        wallet_provider,
    )
    .await
    .map_err(|e| AgentError::Transport(format!("Failed to pack v1 message: {}", e)))?;

    serde_json::to_string(&encrypted)
        .map_err(|e| AgentError::Transport(format!("Failed to serialize encrypted message: {}", e)))
}

/// Build the DIDComm v1 (Aries) wire form of an outbound message: `@type` +
/// `@id` at top level, body fields flattened, `~thread`, and the protocol
/// payload carried under its role-specific `<role>~attach` decorator. Mirrors
/// the sender-side `message_to_v1` so return-route replies (packed here) carry
/// the same fields the offer/other outbound messages do. Packing only `body`
/// dropped both the `@type` (recipient rejects: "missing @type") and the
/// `requests~attach`/`credentials~attach` payload — so credential
/// request/issue replies over return-route never completed.
fn message_to_v1_wire(message: &didcomm::core::Message) -> serde_json::Value {
    let mut v1 = serde_json::Map::new();
    v1.insert(
        "@type".to_string(),
        serde_json::Value::String(message.msg_type.clone()),
    );
    v1.insert(
        "@id".to_string(),
        serde_json::Value::String(message.id.clone()),
    );
    if let Some(body_obj) = message.body.as_object() {
        for (k, v) in body_obj {
            v1.insert(k.clone(), v.clone());
        }
    }
    if let Some(ref thread) = message.thread {
        if let Ok(thread_val) = serde_json::to_value(thread) {
            v1.insert("~thread".to_string(), thread_val);
        }
    }
    if let Some(atts) = &message.attachments {
        if !atts.is_empty() {
            if let Ok(atts_json) = serde_json::to_value(atts) {
                v1.insert(v1_attach_field(&message.msg_type).to_string(), atts_json);
            }
        }
    }
    serde_json::Value::Object(v1)
}

/// The Aries v1 attachment-decorator field name for an issue-credential 2.0 /
/// present-proof 2.0 message type (falls back to a generic `~attach`).
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

/// Extract a base58 Ed25519 verkey from a `did:key:z6Mk...` DID.
///
/// The did:key format encodes the public key as multibase(base58btc) of multicodec(ed25519-pub) + raw key.
/// This function decodes it and returns the raw 32-byte key re-encoded as base58.
fn extract_verkey_from_did_key(did: &str) -> Option<String> {
    let multibase_value = did.strip_prefix("did:key:z")?;
    let decoded = bs58::decode(multibase_value).into_vec().ok()?;
    // Ed25519 multicodec prefix is [0xed, 0x01], followed by 32 bytes of key
    if decoded.len() == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
        Some(bs58::encode(&decoded[2..]).into_string())
    } else {
        None
    }
}

/// Pack a message using DIDComm v1 Anoncrypt (no sender authentication)
/// Used for Forward messages in mediation.
/// Note: The wallet_provider is required by the didcomm_v1 API but is NOT used for anoncrypt
/// (only ephemeral keys are generated internally)
pub async fn anon_pack_message_v1(
    message_map: &HashMap<String, serde_json::Value>,
    recipient_auth_key: &str,
    recipient_encryption_key: &str,
    wallet_provider: Arc<dyn WalletProvider>,
) -> Result<String> {
    let encrypted = didcomm::v1::pack_message(
        message_map,
        &[(
            recipient_auth_key.to_string(),
            recipient_encryption_key.to_string(),
        )],
        None,            // No sender key = Anoncrypt
        wallet_provider, // Not used for anoncrypt, but API requires it
    )
    .await
    .map_err(|e| AgentError::Transport(format!("Failed to anon-pack v1 message: {}", e)))?;

    serde_json::to_string(&encrypted)
        .map_err(|e| AgentError::Transport(format!("Failed to serialize encrypted message: {}", e)))
}

/// Returns true if `did` is a did:peer:2 whose DIDComm service is the Aries
/// **v1** `did-communication` type (vs the **v2** `dm`/DIDCommMessaging).
///
/// Aries agents (e.g. credo) advertise a self-resolving did:peer:2 with NO
/// `did_doc~attach` yet a v1 `did-communication` service — so the DID *method*
/// is peer:2 while the DIDComm *version* is v1. Messages to such a peer must be
/// packed v1 (base58 `kid`) so a v1 mediator can route them by its keylist.
fn did_peer2_is_v1_did_communication(did: &str) -> bool {
    matches!(
        did::methods::peer::parse_peer2(did)
            .and_then(|p| p.service_type)
            .as_deref(),
        Some("did-communication") | Some("IndyAgent")
    )
}
