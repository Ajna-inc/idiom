//! Basic Message Service
//!
//! Business logic for creating and managing basic messages

use crate::messages::BasicMessage;
use crate::repository::{BasicMessageRecord, BasicMessageRepositoryTrait, BasicMessageRole};
use protocol_connections::ConnectionRecord;
use std::sync::Arc;

#[cfg(feature = "events")]
use agent_events::event_bus::EventBus;

pub type Result<T> = std::result::Result<T, BasicMessageServiceError>;

/// Errors that can occur in basic message service operations
#[derive(Debug, thiserror::Error)]
pub enum BasicMessageServiceError {
    #[error("Repository error: {0}")]
    Repository(#[from] crate::repository::BasicMessageError),

    #[error("Connection not found")]
    ConnectionNotFound,

    #[error("Invalid message: {0}")]
    InvalidMessage(String),
}

/// Basic Message Service
///
/// Coordinates message creation, storage, and event emission
pub struct BasicMessageService {
    repository: Arc<dyn BasicMessageRepositoryTrait>,

    #[cfg(feature = "events")]
    event_bus: Arc<EventBus>,

    #[cfg(feature = "events")]
    agent_id: String,
}

impl BasicMessageService {
    /// Create a new basic message service
    #[cfg(not(feature = "events"))]
    pub fn new(repository: Arc<dyn BasicMessageRepositoryTrait>) -> Self {
        Self { repository }
    }

    /// Create a new basic message service with event bus
    #[cfg(feature = "events")]
    pub fn new(
        repository: Arc<dyn BasicMessageRepositoryTrait>,
        event_bus: Arc<EventBus>,
        agent_id: String,
    ) -> Self {
        Self {
            repository,
            event_bus,
            agent_id,
        }
    }

    /// Create a basic message for sending
    ///
    /// # Arguments
    /// * `content` - The message text
    /// * `connection` - The connection to send the message to
    /// * `parent_thread_id` - Optional parent thread ID for replies
    ///
    /// # Returns
    /// Tuple of (message, record)
    pub async fn create_message(
        &self,
        content: String,
        connection: &ConnectionRecord,
        parent_thread_id: Option<String>,
    ) -> Result<(BasicMessage, BasicMessageRecord)> {
        // Create the DIDComm message
        let mut message = BasicMessage::new(content.clone());

        // Add threading if this is a reply
        if let Some(ptid) = parent_thread_id.as_ref() {
            message = message.with_thread(ptid.clone());
        }

        // Create the record
        let mut record = BasicMessageRecord::new(
            message.id.clone(),
            connection.id.clone(),
            BasicMessageRole::Sender,
            content,
            message.sent_time.clone(),
        );

        // Add thread info to record
        if let Some(thread_id) = message.thread_id() {
            record = record.with_thread(thread_id.to_string(), parent_thread_id);
        }

        // Save to repository
        self.repository.save(&record).await?;

        // Emit event
        #[cfg(feature = "events")]
        self.emit_state_changed_event(&record, &message).await;

        tracing::debug!(
            "✓ [BasicMessageService] Created message {} for connection {}",
            message.id,
            connection.id
        );

        Ok((message, record))
    }

    /// Save an incoming basic message
    ///
    /// # Arguments
    /// * `message` - The received message
    /// * `connection` - The connection it was received on
    ///
    /// # Returns
    /// The saved record
    pub async fn save_incoming(
        &self,
        message: &BasicMessage,
        connection: &ConnectionRecord,
    ) -> Result<BasicMessageRecord> {
        tracing::debug!(
            "✓ [BasicMessageService] Saving incoming message {} from connection {}",
            message.id,
            connection.id
        );

        // Create the record
        let mut record = BasicMessageRecord::new(
            message.id.clone(),
            connection.id.clone(),
            BasicMessageRole::Receiver,
            message.content.clone(),
            message.sent_time.clone(),
        );

        // Add thread info
        if let Some(thread_id) = message.thread_id() {
            record = record.with_thread(
                thread_id.to_string(),
                message.parent_thread_id().map(String::from),
            );
        }

        // Save to repository
        self.repository.save(&record).await?;

        // Emit event
        #[cfg(feature = "events")]
        self.emit_state_changed_event(&record, message).await;

        tracing::debug!(
            "✓ [BasicMessageService] Message saved with ID: {}",
            record.id
        );

        Ok(record)
    }

    /// Emit a basic message state changed event via the typed bus.
    #[cfg(feature = "events")]
    async fn emit_state_changed_event(&self, record: &BasicMessageRecord, message: &BasicMessage) {
        let payload = crate::events::BasicMessageStateChangedPayload {
            record: record.clone(),
            message: message.clone(),
        };
        let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
        let _ = self.event_bus.emit(&meta, payload).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::BasicMessageRepository;
    use protocol_connections::domain::DidExchangeState;
    use uuid::Uuid;

    fn create_test_connection() -> ConnectionRecord {
        use protocol_connections::repository::ConnectionTags;

        ConnectionRecord {
            id: Uuid::new_v4().to_string(),
            state: DidExchangeState::Completed,
            role: protocol_connections::domain::DidExchangeRole::Requester,
            thread_id: "thread-1".to_string(),
            out_of_band_id: "oob-1".to_string(),
            did: "did:peer:test".to_string(),
            their_did: Some("did:peer:their".to_string()),
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
                role: protocol_connections::domain::DidExchangeRole::Requester,
                state: DidExchangeState::Completed,
                thread_id: "thread-1".to_string(),
                out_of_band_id: "oob-1".to_string(),
                did: "did:peer:test".to_string(),
                their_did: Some("did:peer:their".to_string()),
            },
        }
    }

    #[tokio::test]
    async fn test_create_message() {
        let repo = Arc::new(BasicMessageRepository::new());

        #[cfg(not(feature = "events"))]
        let service = BasicMessageService::new(repo.clone());

        #[cfg(feature = "events")]
        let service = BasicMessageService::new(
            repo.clone(),
            Arc::new(EventBus::new(100)),
            "test-agent".to_string(),
        );

        let connection = create_test_connection();
        let (message, record) = service
            .create_message("Hello!".to_string(), &connection, None)
            .await
            .unwrap();

        assert_eq!(message.content, "Hello!");
        assert_eq!(record.content, "Hello!");
        assert_eq!(record.connection_id, connection.id);
        assert!(matches!(record.role, BasicMessageRole::Sender));

        // Verify saved in repository
        let saved = repo.find_by_id(&record.id).await.unwrap();
        assert!(saved.is_some());
    }

    #[tokio::test]
    async fn test_create_threaded_message() {
        let repo = Arc::new(BasicMessageRepository::new());

        #[cfg(not(feature = "events"))]
        let service = BasicMessageService::new(repo);

        #[cfg(feature = "events")]
        let service =
            BasicMessageService::new(repo, Arc::new(EventBus::new(100)), "test-agent".to_string());

        let connection = create_test_connection();
        let parent_id = "parent-thread-123";

        let (message, record) = service
            .create_message(
                "Reply".to_string(),
                &connection,
                Some(parent_id.to_string()),
            )
            .await
            .unwrap();

        assert!(message.thread.is_some());
        assert_eq!(message.parent_thread_id(), Some(parent_id));
        assert_eq!(record.parent_thread_id, Some(parent_id.to_string()));
    }

    #[tokio::test]
    async fn test_save_incoming() {
        let repo = Arc::new(BasicMessageRepository::new());

        #[cfg(not(feature = "events"))]
        let service = BasicMessageService::new(repo.clone());

        #[cfg(feature = "events")]
        let service = BasicMessageService::new(
            repo.clone(),
            Arc::new(EventBus::new(100)),
            "test-agent".to_string(),
        );

        let connection = create_test_connection();
        let message = BasicMessage::new("Incoming message");

        let record = service.save_incoming(&message, &connection).await.unwrap();

        assert_eq!(record.content, "Incoming message");
        assert!(matches!(record.role, BasicMessageRole::Receiver));

        // Verify saved in repository
        let saved = repo.find_by_id(&record.id).await.unwrap();
        assert!(saved.is_some());
    }
}
