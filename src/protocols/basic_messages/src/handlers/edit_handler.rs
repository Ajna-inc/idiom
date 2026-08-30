//! Edit Message Handler
//!
//! Processes incoming edit requests for basic messages

use crate::messages::edit_message::{EditMessage, EDIT_MESSAGE_TYPE};
use crate::repository::BasicMessageRepositoryTrait;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, OutboundMessage};
use protocol_connections::ConnectionRepositoryTrait;
use std::sync::Arc;

#[cfg(feature = "events")]
use agent_events::event_bus::EventBus;

pub type Result<T> = std::result::Result<T, EditHandlerError>;

#[derive(Debug, thiserror::Error)]
pub enum EditHandlerError {
    #[error("Failed to parse edit message: {0}")]
    ParseError(String),

    #[error("Connection not found")]
    ConnectionNotFound,

    #[error("Original message not found: {0}")]
    MessageNotFound(String),

    #[error("Sender mismatch: edit sender does not match original message sender")]
    SenderMismatch,

    #[error("Repository error: {0}")]
    RepositoryError(String),
}

/// Handler for incoming edit messages
pub struct EditHandler {
    repository: Arc<dyn BasicMessageRepositoryTrait>,
    connection_repository: Arc<dyn ConnectionRepositoryTrait>,

    #[cfg(feature = "events")]
    event_bus: Arc<EventBus>,

    #[cfg(feature = "events")]
    agent_id: String,
}

impl EditHandler {
    /// Create a new edit handler without event bus
    #[cfg(not(feature = "events"))]
    pub fn new(
        repository: Arc<dyn BasicMessageRepositoryTrait>,
        connection_repository: Arc<dyn ConnectionRepositoryTrait>,
    ) -> Self {
        Self {
            repository,
            connection_repository,
        }
    }

    /// Create a new edit handler with event bus
    #[cfg(feature = "events")]
    pub fn new(
        repository: Arc<dyn BasicMessageRepositoryTrait>,
        connection_repository: Arc<dyn ConnectionRepositoryTrait>,
        event_bus: Arc<EventBus>,
        agent_id: String,
    ) -> Self {
        Self {
            repository,
            connection_repository,
            event_bus,
            agent_id,
        }
    }

    /// Get connection from inbound message context
    async fn get_connection(
        &self,
        inbound: &InboundMessage,
    ) -> Result<protocol_connections::ConnectionRecord> {
        // Try connection_id from context
        if let Some(connection_id) = &inbound.context.connection_id {
            if let Ok(Some(conn)) = self.connection_repository.find_by_id(connection_id).await {
                return Ok(conn);
            }
        }

        // Fallback: try sender DID
        if let Some(from) = &inbound.message.from {
            if let Ok(connections) = self.connection_repository.find_by_their_did(from).await {
                if let Some(conn) = connections.first() {
                    return Ok(conn.clone());
                }
            }
        }

        Err(EditHandlerError::ConnectionNotFound)
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for EditHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![EDIT_MESSAGE_TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        tracing::debug!("[EDIT-HANDLER] Processing incoming edit message");

        // Parse the edit message
        let edit_msg: EditMessage =
            serde_json::from_value(inbound.message.body.clone()).map_err(|e| {
                didcomm::messaging::MessageHandlerError::InvalidMessage(format!(
                    "Failed to parse edit message: {}",
                    e
                ))
            })?;

        tracing::debug!(
            "[EDIT-HANDLER] Edit request: id={}, message_id={}, new_content='{}'",
            edit_msg.id,
            edit_msg.message_id,
            edit_msg.content
        );

        // Get connection to verify sender
        let connection = self.get_connection(&inbound).await.map_err(|e| {
            didcomm::messaging::MessageHandlerError::ProcessingFailed(format!(
                "Failed to get connection: {}",
                e
            ))
        })?;

        // Look up the original message
        let original = self
            .repository
            .find_by_id(&edit_msg.message_id)
            .await
            .map_err(|e| {
                didcomm::messaging::MessageHandlerError::ProcessingFailed(format!(
                    "Repository error: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                didcomm::messaging::MessageHandlerError::ProcessingFailed(format!(
                    "Original message not found: {}",
                    edit_msg.message_id
                ))
            })?;

        // Verify the edit is from the same connection as the original message
        if original.connection_id != connection.id {
            return Err(didcomm::messaging::MessageHandlerError::ProcessingFailed(
                "Sender mismatch: edit sender does not match original message connection"
                    .to_string(),
            ));
        }

        // Update the content
        let mut updated = original;
        updated.content = edit_msg.content.clone();

        self.repository.update(&updated).await.map_err(|e| {
            didcomm::messaging::MessageHandlerError::ProcessingFailed(format!(
                "Failed to update message: {}",
                e
            ))
        })?;

        // Emit typed event.
        #[cfg(feature = "events")]
        {
            let payload = crate::events::BasicMessageEditedPayload {
                message_id: edit_msg.message_id.clone(),
                new_content: edit_msg.content.clone(),
                edited_time: edit_msg.edited_time.clone(),
                connection_id: connection.id.clone(),
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            let _ = self.event_bus.emit(&meta, payload).await;
        }

        tracing::debug!(
            "[EDIT-HANDLER] Message {} edited successfully",
            edit_msg.message_id
        );

        // Edit messages don't require a response
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::{BasicMessageRecord, BasicMessageRepository, BasicMessageRole};
    use didcomm::core::Message as DidCommMessage;
    use didcomm::messaging::MessageContext;
    use protocol_connections::domain::{DidExchangeRole, DidExchangeState};
    use protocol_connections::{ConnectionRecord, ConnectionRepository};
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
    async fn test_handle_edit_message() {
        let repo = Arc::new(BasicMessageRepository::new());
        let conn_repo = Arc::new(ConnectionRepository::new());

        let connection = create_test_connection("did:peer:sender");
        conn_repo.save(&connection).await.unwrap();

        // Save the original message for this connection
        let original = BasicMessageRecord::new(
            "msg-original",
            &connection.id,
            BasicMessageRole::Receiver,
            "Original content",
            "2026-01-01T00:00:00Z",
        );
        repo.save(&original).await.unwrap();

        #[cfg(not(feature = "events"))]
        let handler = EditHandler::new(repo.clone(), conn_repo);

        #[cfg(feature = "events")]
        let handler = EditHandler::new(
            repo.clone(),
            conn_repo,
            Arc::new(agent_events::event_bus::EventBus::new(100)),
            "test-agent".to_string(),
        );

        // Create edit message
        let edit_msg = EditMessage::new("msg-original", "Edited content");
        let edit_json = serde_json::to_value(&edit_msg).unwrap();

        let didcomm_msg = DidCommMessage {
            id: edit_msg.id.clone(),
            msg_type: EDIT_MESSAGE_TYPE.to_string(),
            body: edit_json,
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

        let result = handler.handle(inbound).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Verify content was updated
        let updated = repo.find_by_id("msg-original").await.unwrap().unwrap();
        assert_eq!(updated.content, "Edited content");
    }

    #[tokio::test]
    async fn test_edit_nonexistent_message() {
        let repo = Arc::new(BasicMessageRepository::new());
        let conn_repo = Arc::new(ConnectionRepository::new());

        let connection = create_test_connection("did:peer:sender");
        conn_repo.save(&connection).await.unwrap();

        #[cfg(not(feature = "events"))]
        let handler = EditHandler::new(repo.clone(), conn_repo);

        #[cfg(feature = "events")]
        let handler = EditHandler::new(
            repo.clone(),
            conn_repo,
            Arc::new(agent_events::event_bus::EventBus::new(100)),
            "test-agent".to_string(),
        );

        let edit_msg = EditMessage::new("nonexistent-msg", "New content");
        let edit_json = serde_json::to_value(&edit_msg).unwrap();

        let didcomm_msg = DidCommMessage {
            id: edit_msg.id.clone(),
            msg_type: EDIT_MESSAGE_TYPE.to_string(),
            body: edit_json,
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

        let result = handler.handle(inbound).await;
        assert!(result.is_err());
    }
}
