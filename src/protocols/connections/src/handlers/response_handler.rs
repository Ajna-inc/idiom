//! DIDExchange Response Handler
//!
//! Handles incoming DIDExchange response messages (requester side).
//! Implements auto-accept pattern

use crate::messages::DidExchangeResponseMessage;
use crate::services::ConnectionService;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use did::core::{DidDocument, DidDocumentKey, DidRepository};
use didcomm::core::Message as DidcommMessage;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for DIDExchange response messages
///
/// This handler:
/// 1. Receives a connection response from the responder (inviter)
/// 2. Extracts and stores the responder's DID document from did_doc~attach
/// 3. Validates the response DID and updates the connection record
/// 4. Transitions connection to ResponseReceived state
/// 5. If auto-accept is enabled, immediately generates and returns a complete message
///
/// # Auto-Accept Pattern
///
/// Following the auto-accept pattern, the handler checks:
/// - Per-connection auto_accept_connection flag
/// - OR global auto_accept_connections config
///
/// If either is true, the handler generates a complete message and returns it.
/// The dispatcher will automatically send the returned complete message.
pub struct DidExchangeResponseHandler {
    /// Connection service for protocol operations
    connection_service: Arc<ConnectionService>,
    /// DID repository for storing DID documents
    did_repository: Arc<DidRepository>,
    /// Global auto-accept configuration
    auto_accept_connections: bool,
}

impl DidExchangeResponseHandler {
    /// Create a new response handler
    ///
    /// # Arguments
    /// * `connection_service` - Service for connection protocol operations
    /// * `did_repository` - Repository for storing DID documents
    /// * `auto_accept_connections` - Global auto-accept setting
    pub fn new(
        connection_service: Arc<ConnectionService>,
        did_repository: Arc<DidRepository>,
        auto_accept_connections: bool,
    ) -> Self {
        Self {
            connection_service,
            did_repository,
            auto_accept_connections,
        }
    }

    /// Normalize a DID document by extracting embedded verification methods
    ///
    /// Some agents may send DID documents with embedded verification methods in the
    /// authentication and keyAgreement arrays, rather than using a separate
    /// verificationMethod array with references. This method normalizes such
    /// documents by:
    /// 1. Creating a verificationMethod array (if it doesn't exist)
    /// 2. Moving embedded methods to verificationMethod
    /// 3. Replacing embedded methods with references
    fn normalize_did_document(
        &self,
        mut doc_json: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let doc_obj = doc_json
            .as_object_mut()
            .ok_or_else(|| "DID document must be an object".to_string())?;

        // Collect embedded verification methods
        let mut extracted_methods = Vec::new();

        // Process authentication array
        if let Some(auth_array) = doc_obj
            .get_mut("authentication")
            .and_then(|a| a.as_array_mut())
        {
            for item in auth_array.iter_mut() {
                if let Some(embedded) = item.as_object() {
                    // It's an embedded object, extract it
                    if let Some(id) = embedded.get("id").and_then(|id| id.as_str()) {
                        extracted_methods.push(item.clone());
                        // Replace with reference
                        *item = serde_json::json!(id);
                    }
                }
            }
        }

        // Process keyAgreement array
        if let Some(ka_array) = doc_obj
            .get_mut("keyAgreement")
            .and_then(|ka| ka.as_array_mut())
        {
            for item in ka_array.iter_mut() {
                if let Some(embedded) = item.as_object() {
                    // It's an embedded object, extract it
                    if let Some(id) = embedded.get("id").and_then(|id| id.as_str()) {
                        extracted_methods.push(item.clone());
                        // Replace with reference
                        *item = serde_json::json!(id);
                    }
                }
            }
        }

        // Initialize or get verificationMethod array
        if !doc_obj.contains_key("verificationMethod") {
            doc_obj.insert("verificationMethod".to_string(), serde_json::json!([]));
        }

        // Add extracted methods to verificationMethod array
        if !extracted_methods.is_empty() {
            let verification_methods = doc_obj
                .get_mut("verificationMethod")
                .and_then(|v| v.as_array_mut())
                .ok_or_else(|| "verificationMethod must be an array".to_string())?;

            for method in extracted_methods {
                verification_methods.push(method);
            }
        }

        let vm_count = doc_obj
            .get("verificationMethod")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);

        tracing::debug!(
            "  ✓ Normalized DID document: {} verification methods",
            vm_count
        );
        Ok(doc_json)
    }

    /// Extract and store the responder's DID document from did_doc~attach
    ///
    /// This method:
    /// 1. Extracts the base64-encoded DID document from did_doc~attach.data.base64
    /// 2. Decodes and parses the DID document
    /// 3. Extracts authentication and keyAgreement keys
    /// 4. Stores the document in DidRepository as a "Received" DID
    ///
    /// Returns (authentication_key_base58, key_agreement_base58) for storing in ConnectionRecord
    fn extract_and_store_did_document(
        &self,
        response: &DidExchangeResponseMessage,
    ) -> Result<(Option<String>, Option<String>), String> {
        // Check if there's a DID document attachment
        if let Some(did_doc_attach) = &response.did_doc_attach {
            tracing::debug!("  → Found did_doc~attach, extracting and storing DID document...");

            // Navigate to did_doc_attach.data.base64
            if let Some(base64_str) = did_doc_attach
                .get("data")
                .and_then(|data| data.get("base64"))
                .and_then(|b64| b64.as_str())
            {
                tracing::debug!("  → Decoding base64-encoded DID document...");

                // Decode the base64 string
                let decoded_bytes = general_purpose::STANDARD
                    .decode(base64_str)
                    .map_err(|e| format!("Failed to decode base64: {}", e))?;

                // Parse the decoded bytes as JSON
                let did_document_json: serde_json::Value =
                    serde_json::from_slice(&decoded_bytes)
                        .map_err(|e| format!("Failed to parse DID document JSON: {}", e))?;

                tracing::debug!("  ✓ DID document decoded successfully");
                tracing::debug!("  → DID: {}", response.did);
                tracing::debug!(
                    "  → DID Document JSON: {}",
                    serde_json::to_string_pretty(&did_document_json)
                        .unwrap_or_else(|_| "N/A".to_string())
                );

                // Normalize the DID document: some agents may use embedded verification methods
                // in authentication/keyAgreement instead of a verificationMethod array.
                // We need to extract them and create a proper verificationMethod array.
                let normalized_json = self.normalize_did_document(did_document_json.clone())?;

                // Deserialize into DidDocument struct
                let did_document: DidDocument = serde_json::from_value(normalized_json)
                    .map_err(|e| format!("Failed to deserialize DID document: {}", e))?;

                tracing::debug!(
                    "  → Deserialized DID document has {} verification methods",
                    did_document.verification_method.len()
                );

                // Extract authentication and keyAgreement keys (base58) to store in ConnectionRecord
                // This allows quick access without DID resolution when packing messages
                let mut their_auth_key_base58 = None;
                let mut their_key_agreement_base58 = None;

                // Extract authentication key (Ed25519) from verificationMethod
                for vm in &did_document.verification_method {
                    // Check if this is referenced by authentication array
                    let in_authentication = did_document.authentication.iter().any(|auth| {
                        if let did::core::VerificationRelationship::Reference(ref_id) = auth {
                            ref_id == &vm.id
                        } else {
                            false
                        }
                    });

                    // Check if this is referenced by keyAgreement array
                    let in_key_agreement = did_document.key_agreement.iter().any(|ka| {
                        if let did::core::VerificationRelationship::Reference(ref_id) = ka {
                            ref_id == &vm.id
                        } else {
                            false
                        }
                    });

                    if in_authentication && their_auth_key_base58.is_none() {
                        their_auth_key_base58 = vm.public_key_base58.clone();
                    }
                    if in_key_agreement && their_key_agreement_base58.is_none() {
                        their_key_agreement_base58 = vm.public_key_base58.clone();
                    }
                }

                tracing::debug!(
                    "  → Extracted auth key: {:?}",
                    their_auth_key_base58.as_ref().map(|k| &k[..8])
                );
                tracing::debug!(
                    "  → Extracted key agreement: {:?}",
                    their_key_agreement_base58.as_ref().map(|k| &k[..8])
                );

                // Extract keys for DidRepository
                let mut keys = Vec::new();
                if let Some(auth_array) = did_document_json
                    .get("authentication")
                    .and_then(|a| a.as_array())
                {
                    if let Some(first_auth) = auth_array.first() {
                        if let Some(ref_id) = first_auth.as_str() {
                            keys.push(DidDocumentKey::new(
                                format!("key-{}", uuid::Uuid::new_v4()),
                                ref_id.to_string(),
                            ));
                        }
                    }
                }

                // Store the received DID document in DidRepository
                self.did_repository
                    .store_received_did(response.did.clone(), Some(did_document), keys)
                    .map_err(|e| format!("Failed to store DID document: {}", e))?;

                tracing::debug!("  ✓ Stored responder's DID document in DidRepository");
                return Ok((their_auth_key_base58, their_key_agreement_base58));
            }
        }

        tracing::debug!("  ⚠ No did_doc~attach found in response message");
        Ok((None, None))
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for DidExchangeResponseHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![DidExchangeResponseMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        tracing::debug!("→ [ResponseHandler] Received response");

        // Parse the response message from body (where the full protocol message is stored)
        let response: DidExchangeResponseMessage =
            serde_json::from_value(inbound.message.body.clone())
                .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        tracing::debug!("  Parsed response from: {}", response.did);

        // Detect DIDComm v2 by the *protocol shape*, not the DID method. A true
        // v2 peer sends a self-resolving did:peer:2 with NO did_doc~attach. A peer
        // that attaches a v1 did_doc~attach is speaking RFC19 (v1) even when its
        // DID is did:peer:2 — some agents do exactly this (peer:2 DID over a
        // v1 RFC19 channel, and it always attaches its did_doc). Treating that as
        // v2 flips didcomm_version → the follow-up `complete` message mis-packs v2
        // and fails against the v1 peer, leaving the connection stuck.
        let use_v2 = response.did.starts_with("did:peer:2") && response.did_doc_attach.is_none();
        if use_v2 {
            tracing::debug!(
                "  → DIDComm v2 detected: self-resolving did:peer:2, no did_doc~attach"
            );
        }

        // For v2: did:peer:2 is self-resolving — store DID reference, skip did_doc~attach
        // For v1: extract and store the responder's DID document from did_doc~attach
        let (their_auth_key, their_key_agreement) = if use_v2 {
            // Store their did:peer:2 as a received DID (self-resolving)
            self.did_repository
                .store_received_did(response.did.clone(), None, vec![])
                .map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to store did:peer:2: {}",
                        e
                    ))
                })?;
            tracing::debug!(
                "  ✓ Stored responder's did:peer:2 (self-resolving): {}",
                response.did
            );
            // Even though did:peer:2 is self-resolving, store the peer's raw
            // base58 verkeys on the connection so key-based lookups work without
            // re-resolving — inbound basic-message routing (`get_connection` by
            // sender key) and v1 packing both need them, and a did-communication
            // peer (credo) won't be found by its base58 kid otherwise.
            did::methods::peer::parse_peer2_verkeys(&response.did)
        } else {
            self.extract_and_store_did_document(&response)
                .map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to extract DID document: {}",
                        e
                    ))
                })?
        };

        // Process the response (updates connection to ResponseReceived state)
        // Pass the extracted keys so they're stored in the connection record
        let mut connection = self
            .connection_service
            .process_response(&response, their_auth_key, their_key_agreement)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        // Set DIDComm version on the connection
        if use_v2 {
            connection.didcomm_version = Some("2".to_string());
            self.connection_service
                .update(&connection)
                .await
                .map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to save DIDComm version: {}",
                        e
                    ))
                })?;
            tracing::debug!("  ✓ Connection marked as DIDComm v2");
        }

        // Set mesh transport preference if response arrived over mesh
        if let Some(ref ep) = inbound.context.sender_endpoint {
            if ep.starts_with("mesh://") {
                tracing::debug!("  Setting mesh transport preference on requester: {}", ep);
                connection.update_metadata(serde_json::json!({
                    "transport": {
                        "preferred": "mesh",
                        "selected_endpoint": ep
                    }
                }));
                self.connection_service
                    .update(&connection)
                    .await
                    .map_err(|e| {
                        MessageHandlerError::ProcessingFailed(format!(
                            "Failed to save mesh transport metadata: {}",
                            e
                        ))
                    })?;
            }
        }

        // Check auto-accept (per-connection OR global config)
        let should_auto_accept = connection
            .auto_accept_connection
            .unwrap_or(self.auto_accept_connections);

        tracing::debug!("  → Checking auto-accept: connection.auto_accept_connection={:?}, global={}, should_auto_accept={}",
            connection.auto_accept_connection, self.auto_accept_connections, should_auto_accept);

        if should_auto_accept {
            tracing::debug!("  ✓ Auto-accept enabled, creating complete message...");
            // Auto-generate complete message
            let (updated_connection, complete_msg) = self
                .connection_service
                .create_complete(&connection.id)
                .await
                .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

            // DEBUG: Log the connection DID to trace empty DID issue
            tracing::debug!(
                "[RESPONSE-HANDLER] updated_connection.did = '{}'",
                updated_connection.did
            );
            tracing::debug!(
                "[RESPONSE-HANDLER] updated_connection.id = '{}'",
                updated_connection.id
            );
            tracing::debug!("[RESPONSE-HANDLER] response.did = '{}'", response.did);
            if updated_connection.did.is_empty() {
                tracing::debug!("[RESPONSE-HANDLER] WARNING: updated_connection.did is EMPTY! This will cause DID parse error.");
            }

            // Convert complete message to DIDComm Message
            // We need to store the protocol message in the body field
            let complete_json = serde_json::to_value(&complete_msg)
                .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

            let didcomm_msg = DidcommMessage::new(
                complete_msg.id.clone(),
                complete_msg.msg_type.clone(),
                complete_json, // Store the full protocol message as body
            );

            // NOTE: We do NOT set ~transport.return_route: "none" here.
            // This allows the message to be returned synchronously through the normal
            // message pickup path, which properly handles Forward wrapping for mediated
            // connections. The async send path in processor.rs doesn't have ios_log access
            // and historically had issues with Forward wrapping.

            // Create outbound message
            // Use the connection's DID (did:peer:1 created during accept_invitation)
            // NOT the agent's global DID which may be empty if auto_create_did=false
            let outbound = OutboundMessage {
                message: didcomm_msg,
                to: response.did.clone(), // Send to responder's DID
                from: updated_connection.did.clone(), // Use connection's DID from initial request
                connection_id: Some(updated_connection.id.clone()),
            };

            // Return complete for dispatcher to send
            return Ok(Some(outbound));
        }

        // Manual completion required - no automatic response
        Ok(None)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests_disabled {
    use super::*;
    use crate::domain::DidExchangeState;

    use crate::repository::{ConnectionRepository, ConnectionRepositoryTrait};
    use didcomm::messaging::MessageContext;
    use protocol_oob::messages::OutOfBandInvitation;
    use protocol_oob::repository::OutOfBandTags;
    use protocol_oob::OutOfBandRecord;

    async fn setup_test_handler(
        auto_accept: bool,
    ) -> (
        DidExchangeResponseHandler,
        Arc<ConnectionRepository>,
        Arc<ConnectionService>,
    ) {
        let conn_repo = Arc::new(ConnectionRepository::new());
        let did_repo = Arc::new(DidRepository::new());
        let service = Arc::new(ConnectionService::new(conn_repo.clone()));

        let handler = DidExchangeResponseHandler::new(service.clone(), did_repo, auto_accept);

        (handler, conn_repo, service)
    }

    fn create_test_response(thread_id: &str) -> DidExchangeResponseMessage {
        DidExchangeResponseMessage::new("did:peer:responder".to_string(), thread_id.to_string())
    }

    fn create_inbound_message(response: DidExchangeResponseMessage) -> InboundMessage {
        let didcomm_msg: DidcommMessage =
            serde_json::from_value(serde_json::to_value(&response).unwrap()).unwrap();

        InboundMessage {
            message: didcomm_msg,
            context: MessageContext {
                from: Some("did:peer:responder".to_string()),
                to: Some("did:peer:requester".to_string()),
                thread_id: Some(response.thread_id().to_string()),
                parent_thread_id: None,
                connection_id: None,
                encrypted: true,
                authenticated: true,
                sender_endpoint: Some("channel://responder".to_string()),
                raw_plaintext: None,
            },
        }
    }

    async fn create_requester_connection(service: &ConnectionService, _thread_id: &str) -> String {
        // Create OOB invitation
        let oob_record = OutOfBandRecord {
            id: "inv-123".to_string(),
            invitation: OutOfBandInvitation {
                id: "inv-123".to_string(),
                msg_type: "https://didcomm.org/out-of-band/1.1/invitation".to_string(),
                label: Some("Test".to_string()),
                goal_code: None,
                goal: None,
                accept: None,
                handshake_protocols: Some(vec!["https://didcomm.org/didexchange/1.1".to_string()]),
                requests: None,
                services: vec![],
                image_url: None,
            },
            role: protocol_oob::OutOfBandRole::Receiver,
            state: protocol_oob::OutOfBandState::PrepareResponse,
            reusable: false,
            auto_accept_connection: None,
            mediator_id: None,
            alias: None,
            reuse_connection_id: None,
            invitation_inline_service_keys: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            tags: OutOfBandTags::default(),
        };

        // Create connection as requester (in RequestSent state)
        service
            .create_request(&oob_record, "did:peer:requester".to_string(), None)
            .await
            .unwrap()
            .0
            .id
    }

    #[tokio::test]
    #[ignore = "Requires proper mock setup - message serialization incompatible"]
    async fn test_response_handler_auto_accept() {
        let (handler, conn_repo, service) = setup_test_handler(true).await;

        // Create a connection in RequestSent state
        let thread_id = "thread-123";
        let connection_id = create_requester_connection(&service, thread_id).await;

        // Create response message
        let response = create_test_response(thread_id);
        let inbound = create_inbound_message(response.clone());

        // Handle the message
        let result = handler.handle(inbound).await;
        assert!(result.is_ok());

        let complete = result.unwrap();
        assert!(complete.is_some(), "Should auto-generate complete");

        let outbound = complete.unwrap();
        assert_eq!(outbound.to, response.did);
        assert_eq!(outbound.from, "did:peer:requester");

        // Verify connection was updated to Completed state
        let connection = conn_repo.find_by_id(&connection_id).await.unwrap().unwrap();
        assert_eq!(connection.state, DidExchangeState::Completed);
    }

    #[tokio::test]
    #[ignore = "Requires proper mock setup - message serialization incompatible"]
    async fn test_response_handler_manual_accept() {
        let (handler, conn_repo, service) = setup_test_handler(false).await;

        // Create a connection in RequestSent state
        let thread_id = "thread-456";
        let connection_id = create_requester_connection(&service, thread_id).await;

        // Create response message
        let response = create_test_response(thread_id);
        let inbound = create_inbound_message(response);

        // Handle the message
        let result = handler.handle(inbound).await;
        assert!(result.is_ok());

        let complete = result.unwrap();
        assert!(complete.is_none(), "Should NOT auto-generate complete");

        // Verify connection was updated to ResponseReceived state
        let connection = conn_repo.find_by_id(&connection_id).await.unwrap().unwrap();
        assert_eq!(connection.state, DidExchangeState::ResponseReceived);
    }

    #[tokio::test]
    #[ignore = "Requires proper mock setup - message serialization incompatible"]
    async fn test_response_handler_missing_connection() {
        let (handler, _, _) = setup_test_handler(true).await;

        // Create response with non-existent thread ID
        let response = create_test_response("nonexistent-thread");
        let inbound = create_inbound_message(response);

        // Handle the message
        let result = handler.handle(inbound).await;
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, MessageHandlerError::ProcessingFailed(_)));
    }
}
