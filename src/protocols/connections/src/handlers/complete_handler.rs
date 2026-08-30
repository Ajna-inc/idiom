//! DIDExchange Complete Handler
//!
//! Handles incoming DIDExchange complete messages (responder side).

use crate::messages::DidExchangeCompleteMessage;
use crate::services::ConnectionService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for DIDExchange complete messages
///
/// This handler:
/// 1. Receives a complete message from the requester
/// 2. Validates and finalizes the connection
/// 3. Transitions connection to Completed state
/// 4. Returns None (no response needed)
///
/// # No Response Pattern
///
/// Unlike request and response handlers, the complete handler does NOT generate
/// a response. Complete is the final message in the DIDExchange protocol.
/// Both parties are now in Completed state.
pub struct DidExchangeCompleteHandler {
    /// Connection service for protocol operations
    connection_service: Arc<ConnectionService>,
}

impl DidExchangeCompleteHandler {
    /// Create a new complete handler
    ///
    /// # Arguments
    /// * `connection_service` - Service for connection protocol operations
    pub fn new(connection_service: Arc<ConnectionService>) -> Self {
        Self { connection_service }
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for DidExchangeCompleteHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![DidExchangeCompleteMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        tracing::debug!("[COMPLETE-HANDLER] Received complete message");
        // Parse the complete message from body (where the full protocol message is stored)
        let complete: DidExchangeCompleteMessage =
            serde_json::from_value(inbound.message.body.clone()).map_err(|e| {
                tracing::debug!(
                    "[COMPLETE-HANDLER] ERROR: Failed to parse complete message: {}",
                    e
                );
                MessageHandlerError::InvalidMessage(e.to_string())
            })?;

        tracing::debug!(
            "[COMPLETE-HANDLER] Parsed complete for thread_id: {}",
            complete.thread_id()
        );

        // Process the complete message (finalizes connection to Completed state)
        let result = self
            .connection_service
            .process_complete(&complete)
            .await
            .map_err(|e| {
                tracing::debug!(
                    "[COMPLETE-HANDLER] ERROR: Failed to process complete: {}",
                    e
                );
                MessageHandlerError::ProcessingFailed(e.to_string())
            })?;

        tracing::debug!(
            "[COMPLETE-HANDLER] Connection COMPLETED: id={}, state={:?}, role={:?}, thread_id={}",
            result.id,
            result.state,
            result.role,
            result.thread_id
        );

        // No response needed - complete is the final message
        Ok(None)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests_disabled {
    use super::*;
    use crate::domain::DidExchangeState;
    use crate::messages::DidExchangeRequestMessage;
    use crate::repository::{ConnectionRepository, ConnectionRepositoryTrait};
    use didcomm::messaging::MessageContext;
    use protocol_oob::messages::OutOfBandInvitation;
    use protocol_oob::repository::OutOfBandTags;
    use protocol_oob::OutOfBandRecord;

    async fn setup_test_handler() -> (
        DidExchangeCompleteHandler,
        Arc<ConnectionRepository>,
        Arc<ConnectionService>,
    ) {
        let conn_repo = Arc::new(ConnectionRepository::new());
        let service = Arc::new(ConnectionService::new(conn_repo.clone()));
        let handler = DidExchangeCompleteHandler::new(service.clone());

        (handler, conn_repo, service)
    }

    fn create_test_complete(thread_id: &str, parent_thread_id: &str) -> DidExchangeCompleteMessage {
        DidExchangeCompleteMessage::new(thread_id.to_string(), parent_thread_id.to_string())
    }

    fn create_inbound_message(complete: DidExchangeCompleteMessage) -> InboundMessage {
        let didcomm_msg: didcomm::core::Message =
            serde_json::from_value(serde_json::to_value(&complete).unwrap()).unwrap();

        InboundMessage {
            message: didcomm_msg,
            context: MessageContext {
                from: Some("did:peer:requester".to_string()),
                to: Some("did:peer:responder".to_string()),
                thread_id: Some(complete.thread_id().to_string()),
                parent_thread_id: complete.parent_thread_id().map(|s| s.to_string()),
                connection_id: None,
                encrypted: true,
                authenticated: true,
                sender_endpoint: Some("channel://requester".to_string()),
                raw_plaintext: None,
            },
        }
    }

    async fn create_responder_connection(service: &ConnectionService, thread_id: &str) -> String {
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
            role: protocol_oob::OutOfBandRole::Sender,
            state: protocol_oob::OutOfBandState::AwaitResponse,
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

        // Create request (simulating what we received)
        let request = DidExchangeRequestMessage {
            msg_type: DidExchangeRequestMessage::TYPE.to_string(),
            id: "req-1".to_string(),
            label: "Requester".to_string(),
            did: "did:peer:requester".to_string(),
            thread: didcomm::core::models::Thread {
                thid: Some(thread_id.to_string()),
                pthid: Some("inv-123".to_string()),
                sender_order: None,
                received_orders: None,
            },
            did_doc_attach: None,
        };

        // Process request and create response (as responder)
        let connection = service
            .process_request(
                &request,
                &oob_record,
                "did:peer:responder".to_string(),
                None,
                None,
            )
            .await
            .unwrap();

        // Create response (moves to ResponseSent state)
        let (connection, _) = service.create_response(&connection.id).await.unwrap();

        connection.id
    }

    #[tokio::test]
    #[ignore = "Requires proper mock setup - message serialization incompatible"]
    async fn test_complete_handler() {
        let (handler, conn_repo, service) = setup_test_handler().await;

        // Create a connection in ResponseSent state
        let thread_id = "thread-123";
        let parent_thread_id = "inv-123";
        let connection_id = create_responder_connection(&service, thread_id).await;

        // Verify initial state
        let connection = conn_repo.find_by_id(&connection_id).await.unwrap().unwrap();
        assert_eq!(connection.state, DidExchangeState::ResponseSent);

        // Create complete message
        let complete = create_test_complete(thread_id, parent_thread_id);
        let inbound = create_inbound_message(complete);

        // Handle the message
        let result = handler.handle(inbound).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(
            response.is_none(),
            "Complete handler should not return a response"
        );

        // Verify connection was updated to Completed state
        let connection = conn_repo.find_by_id(&connection_id).await.unwrap().unwrap();
        assert_eq!(connection.state, DidExchangeState::Completed);
    }

    #[tokio::test]
    #[ignore = "Requires proper mock setup - message serialization incompatible"]
    async fn test_complete_handler_missing_connection() {
        let (handler, _, _) = setup_test_handler().await;

        // Create complete with non-existent thread ID
        let complete = create_test_complete("nonexistent-thread", "inv-123");
        let inbound = create_inbound_message(complete);

        // Handle the message
        let result = handler.handle(inbound).await;
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, MessageHandlerError::ProcessingFailed(_)));
    }

    #[tokio::test]
    #[ignore = "Requires proper mock setup - message serialization incompatible"]
    async fn test_complete_handler_wrong_state() {
        let (handler, _, service) = setup_test_handler().await;

        // Create OOB invitation
        let oob_record = OutOfBandRecord {
            id: "inv-456".to_string(),
            invitation: OutOfBandInvitation {
                id: "inv-456".to_string(),
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
            role: protocol_oob::OutOfBandRole::Sender,
            state: protocol_oob::OutOfBandState::AwaitResponse,
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

        // Create request
        let request = DidExchangeRequestMessage::new(
            "Test".to_string(),
            "did:peer:req".to_string(),
            "inv-456".to_string(),
        );

        // Process request only (connection is in RequestReceived state, not ResponseSent)
        let _connection = service
            .process_request(
                &request,
                &oob_record,
                "did:peer:resp".to_string(),
                None,
                None,
            )
            .await
            .unwrap();

        // Try to send complete (should fail - wrong state)
        let complete = create_test_complete(request.thread_id(), "inv-456");
        let inbound = create_inbound_message(complete);

        let result = handler.handle(inbound).await;
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, MessageHandlerError::ProcessingFailed(_)));
    }
}
