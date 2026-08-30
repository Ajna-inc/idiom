//! Basic Message Handler
//!
//! Processes incoming basic messages

use crate::messages::{BasicMessage, BASIC_MESSAGE_TYPE};
use crate::services::BasicMessageService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, OutboundMessage};
use protocol_connections::ConnectionRepositoryTrait;
use std::sync::Arc;

pub type Result<T> = std::result::Result<T, BasicMessageHandlerError>;

#[derive(Debug, thiserror::Error)]
pub enum BasicMessageHandlerError {
    #[error("Failed to parse basic message: {0}")]
    ParseError(String),

    #[error("Connection not found")]
    ConnectionNotFound,

    #[error("Service error: {0}")]
    ServiceError(String),
}

/// Handler for incoming basic messages
pub struct BasicMessageHandler {
    service: Arc<BasicMessageService>,
    connection_repository: Arc<dyn ConnectionRepositoryTrait>,
}

impl BasicMessageHandler {
    pub fn new(
        service: Arc<BasicMessageService>,
        connection_repository: Arc<dyn ConnectionRepositoryTrait>,
    ) -> Self {
        Self {
            service,
            connection_repository,
        }
    }

    /// Get connection from inbound message context.
    ///
    /// Two authoritative sources, no fallbacks:
    ///   1. `inbound.context.connection_id` — populated by the message
    ///      processor when it resolved the sender's key to a stored
    ///      connection. This is the correct answer whenever unpack
    ///      metadata was mapped through `processor.rs`.
    ///   2. `inbound.message.from` — the sender's DID as it appears in
    ///      the plaintext body. Used only if (1) is missing.
    ///
    /// If neither hits, error out. A previous "most-recent-completed"
    /// fallback was a coin-flip when 2+ connections existed and quietly
    /// filed messages on the wrong connection, breaking DM URL loads
    /// (recipient queries `/api/dms/:cid/messages` for their real
    /// connection, but the message was saved on an unrelated one).
    /// Making the miss visible surfaces the real routing bug instead of
    /// corrupting local state.
    async fn get_connection(
        &self,
        inbound: &InboundMessage,
    ) -> Result<protocol_connections::ConnectionRecord> {
        if let Some(connection_id) = &inbound.context.connection_id {
            tracing::debug!(
                "[BASIC-MSG-HANDLER] Trying connection_id from context: {}",
                connection_id
            );
            if let Ok(Some(conn)) = self.connection_repository.find_by_id(connection_id).await {
                tracing::debug!(
                    "[BASIC-MSG-HANDLER] Found connection by context id: {}",
                    conn.id
                );
                return Ok(conn);
            }
        }

        if let Some(from) = &inbound.message.from {
            tracing::debug!("[BASIC-MSG-HANDLER] Trying find_by_their_did: {}", from);
            if let Ok(connections) = self.connection_repository.find_by_their_did(from).await {
                if let Some(conn) = connections.first() {
                    tracing::debug!(
                        "[BASIC-MSG-HANDLER] Found connection by their_did: id={}, state={:?}",
                        conn.id,
                        conn.state
                    );
                    return Ok(conn.clone());
                }
            }
            tracing::debug!(
                "[BASIC-MSG-HANDLER] No connection found for their_did: {}",
                from
            );

            // A mediated did:peer:2 peer is addressed by its base58 verkey
            // (`from` is the JWE sender kid), not its DID URL, so
            // `find_by_their_did` misses it. Fall back to matching the sender
            // key against the base58 keys stored on each connection.
            if let Ok(all) = self.connection_repository.get_all().await {
                if let Some(conn) = all.into_iter().find(|c| {
                    c.their_authentication_key_base58.as_deref() == Some(from.as_str())
                        || c.their_key_agreement_key_base58.as_deref() == Some(from.as_str())
                }) {
                    tracing::debug!(
                        "[BASIC-MSG-HANDLER] Found connection by sender key: {}",
                        conn.id
                    );
                    return Ok(conn);
                }
            }
        }

        tracing::debug!("[BASIC-MSG-HANDLER] ERROR: No connection found for incoming message");
        Err(BasicMessageHandlerError::ConnectionNotFound)
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for BasicMessageHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![BASIC_MESSAGE_TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        tracing::debug!("[BASIC-MSG-HANDLER] Processing incoming basic message");

        // Parse the message
        let message: BasicMessage =
            serde_json::from_value(inbound.message.body.clone()).map_err(|e| {
                tracing::debug!("[BASIC-MSG-HANDLER] ERROR: Failed to parse: {}", e);
                didcomm::messaging::MessageHandlerError::InvalidMessage(format!(
                    "Failed to parse basic message: {}",
                    e
                ))
            })?;

        tracing::debug!(
            "[BASIC-MSG-HANDLER] Message ID: {}, Content: '{}', From: {:?}",
            message.id,
            message.content,
            inbound.message.from
        );

        // Get connection
        let connection = self.get_connection(&inbound).await.map_err(|e| {
            tracing::debug!("[BASIC-MSG-HANDLER] ERROR: Failed to get connection: {}", e);
            didcomm::messaging::MessageHandlerError::ProcessingFailed(format!(
                "Failed to get connection: {}",
                e
            ))
        })?;

        tracing::debug!(
            "[BASIC-MSG-HANDLER] Matched connection: id={}, their_did={:?}",
            connection.id,
            connection.their_did
        );

        // Save the incoming message
        self.service
            .save_incoming(&message, &connection)
            .await
            .map_err(|e| {
                tracing::debug!("[BASIC-MSG-HANDLER] ERROR: Failed to save message: {}", e);
                didcomm::messaging::MessageHandlerError::ProcessingFailed(format!(
                    "Failed to save message: {}",
                    e
                ))
            })?;

        tracing::debug!(
            "[BASIC-MSG-HANDLER] Message saved successfully: id={}, connection={}",
            message.id,
            connection.id
        );

        // Basic messages don't require a response
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::{BasicMessageRepository, BasicMessageRepositoryTrait};
    use didcomm::core::Message as DidCommMessage;
    use didcomm::messaging::MessageContext;
    use protocol_connections::domain::{DidExchangeRole, DidExchangeState};
    use protocol_connections::ConnectionRecord;
    use protocol_connections::ConnectionRepository;
    use uuid::Uuid;

    fn create_test_connection(their_did: &str) -> ConnectionRecord {
        use protocol_connections::repository::ConnectionTags;

        ConnectionRecord {
            id: Uuid::new_v4().to_string(),
            state: DidExchangeState::Completed,
            role: DidExchangeRole::Requester,
            thread_id: "thread-1".to_string(),
            out_of_band_id: "oob-1".to_string(),
            did: "did:peer:test".to_string(),
            their_did: Some(their_did.to_string()),
            their_authentication_key_base58: None,
            their_key_agreement_key_base58: None,
            our_label: None,
            their_label: None,
            previous_dids: vec![],
            previous_their_dids: vec![],
            auto_accept_connection: None,
            image_url: None,
            error_message: None,
            metadata: None,
            didcomm_version: None,
            protocol: "connections/1.0".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            tags: ConnectionTags {
                role: DidExchangeRole::Requester,
                state: DidExchangeState::Completed,
                thread_id: "thread-1".to_string(),
                out_of_band_id: "oob-1".to_string(),
                did: "did:peer:test".to_string(),
                their_did: Some(their_did.to_string()),
            },
        }
    }

    #[tokio::test]
    async fn test_handle_basic_message() {
        let repo = Arc::new(BasicMessageRepository::new());

        #[cfg(not(feature = "events"))]
        let service = Arc::new(BasicMessageService::new(repo.clone()));

        #[cfg(feature = "events")]
        let service = Arc::new(BasicMessageService::new(
            repo.clone(),
            Arc::new(agent_events::event_bus::EventBus::new(100)),
            "test-agent".to_string(),
        ));

        let conn_repo = Arc::new(ConnectionRepository::new());
        let connection = create_test_connection("did:peer:sender");
        conn_repo.save(&connection).await.unwrap();

        let handler = BasicMessageHandler::new(service, conn_repo);

        // Create a basic message
        let message = BasicMessage::new("Test message");
        let message_json = serde_json::to_value(&message).unwrap();

        // Create inbound message
        let didcomm_msg = DidCommMessage {
            id: message.id.clone(),
            msg_type: BASIC_MESSAGE_TYPE.to_string(),
            body: message_json,
            from: Some("did:peer:sender".to_string()),
            to: None,
            thread: None,
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: std::collections::HashMap::new(),
        };

        let context = MessageContext {
            encrypted: false,
            authenticated: false,
            from: Some("did:peer:sender".to_string()),
            to: None,
            thread_id: None,
            parent_thread_id: None,
            connection_id: None,
            sender_endpoint: None,
            raw_plaintext: None,
        };

        let inbound = InboundMessage {
            message: didcomm_msg,
            context,
        };

        // Handle the message
        let result = handler.handle(inbound).await;
        assert!(result.is_ok());

        // Verify saved
        let saved = repo.find_by_id(&message.id).await.unwrap();
        assert!(saved.is_some());
        assert_eq!(saved.unwrap().content, "Test message");
    }
}
