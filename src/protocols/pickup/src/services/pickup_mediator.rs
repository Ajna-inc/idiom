//! Pickup Mediator Service
//!
//! Server-side service for handling message pickup requests at a mediator.

use didcomm::core::models::{Attachment, AttachmentData};
use std::sync::Arc;

use crate::domain::QueuedMessage;
use crate::error::Result;
use crate::messages::{
    DeliveryRequestMessage, MessageDeliveryMessage, MessagesReceivedMessage, StatusMessage,
    StatusRequestMessage,
};
use crate::repository::MessageQueueRepositoryTrait;

/// Service for mediators to handle message pickup requests
pub struct PickupMediatorService<R: MessageQueueRepositoryTrait> {
    repository: Arc<R>,
}

impl<R: MessageQueueRepositoryTrait> PickupMediatorService<R> {
    /// Create a new mediator pickup service
    pub fn new(repository: Arc<R>) -> Self {
        Self { repository }
    }

    /// Remove messages from the queue (e.g. after successful live delivery).
    /// This prevents the in-memory cache from growing unboundedly.
    pub async fn remove_messages(&self, message_ids: &[String]) -> Result<()> {
        self.repository.remove_messages(message_ids).await
    }

    /// Get the number of pending messages for a connection.
    pub async fn pending_count(&self, connection_id: &str) -> Result<u64> {
        self.repository.get_pending_count(connection_id, None).await
    }

    /// Queue a message for a recipient
    pub async fn queue_message(
        &self,
        connection_id: &str,
        recipient_keys: Vec<String>,
        encrypted_message: &str,
    ) -> Result<String> {
        let message = QueuedMessage::new(
            connection_id.to_string(),
            recipient_keys,
            encrypted_message.to_string(),
        );
        self.repository.add_message(message).await
    }

    /// Process a status request and return a status response
    pub async fn process_status_request(
        &self,
        request: StatusRequestMessage,
        connection_id: &str,
    ) -> Result<StatusMessage> {
        let recipient_key = request.recipient_key.as_deref();

        // Get counts
        let message_count = self
            .repository
            .get_pending_count(connection_id, recipient_key)
            .await?;

        let total_bytes = self
            .repository
            .get_total_bytes(connection_id, recipient_key)
            .await?;

        let oldest_time = self
            .repository
            .get_oldest_message_time(connection_id, recipient_key)
            .await?;

        // Calculate longest waited seconds
        let longest_waited_seconds = oldest_time.map(|t| {
            let now = chrono::Utc::now();
            now.signed_duration_since(t).num_seconds().max(0) as u64
        });

        // Build response
        let mut response = StatusMessage::new(request.id.clone(), message_count);

        if let Some(key) = request.recipient_key {
            response = response.with_recipient_key(key);
        }
        if let Some(seconds) = longest_waited_seconds {
            response = response.with_longest_waited_seconds(seconds);
        }
        if total_bytes > 0 {
            response = response.with_total_bytes(total_bytes);
        }

        Ok(response)
    }

    /// Process a delivery request and return a delivery response
    pub async fn process_delivery_request(
        &self,
        request: DeliveryRequestMessage,
        connection_id: &str,
    ) -> Result<MessageDeliveryMessage> {
        let recipient_key = request.recipient_key.as_deref();

        // Take messages from queue
        let messages = self
            .repository
            .take_from_queue(connection_id, recipient_key, request.limit)
            .await?;

        // Convert to attachments
        let attachments: Vec<Attachment> = messages
            .into_iter()
            .map(|msg| Attachment {
                id: Some(msg.id),
                description: None,
                filename: None,
                media_type: Some("application/didcomm-encrypted+json".to_string()),
                format: None,
                lastmod_time: None,
                byte_count: Some(msg.encrypted_message.len()),
                data: AttachmentData::Base64 {
                    base64: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        msg.encrypted_message.as_bytes(),
                    ),
                },
            })
            .collect();

        // Build response
        let mut response = MessageDeliveryMessage::new(request.id.clone(), attachments);

        if let Some(key) = request.recipient_key {
            response = response.with_recipient_key(key);
        }

        Ok(response)
    }

    /// Process a messages-received acknowledgment
    /// Removes the acknowledged messages from the queue
    pub async fn process_messages_received(
        &self,
        ack: MessagesReceivedMessage,
        connection_id: &str,
    ) -> Result<StatusMessage> {
        // Remove acknowledged messages
        self.repository
            .remove_messages(&ack.message_id_list)
            .await?;

        // Return updated status
        let message_count = self
            .repository
            .get_pending_count(connection_id, None)
            .await?;

        // Use the ack message ID as thread ID for the response
        let thread_id = ack
            .thread_id()
            .map(|s| s.to_string())
            .unwrap_or_else(|| ack.id.clone());

        Ok(StatusMessage::new(thread_id, message_count))
    }

    /// Return messages to pending state (delivery failed)
    pub async fn return_messages_to_pending(&self, message_ids: &[String]) -> Result<()> {
        self.repository.return_to_pending(message_ids).await
    }

    /// Clear all messages for a connection
    pub async fn clear_queue(&self, connection_id: &str) -> Result<u64> {
        self.repository.clear_connection(connection_id).await
    }

    /// Get pending message count for a connection
    pub async fn get_queue_count(&self, connection_id: &str) -> Result<u64> {
        self.repository.get_pending_count(connection_id, None).await
    }

    /// Delete messages older than `max_age` across all connections.
    /// Returns the number deleted. Called periodically by the mediator's
    /// TTL cleanup task so a stale (uninstalled / abandoned) recipient
    /// can't pin the per-connection cap with messages that will never be
    /// picked up.
    pub async fn delete_expired(&self, max_age: std::time::Duration) -> Result<u64> {
        self.repository.delete_expired(max_age).await
    }

    /// Delete expired messages for a single connection (cap-relief path).
    /// Returns the number deleted. The forward path calls this when the
    /// queue hits its per-connection cap, BEFORE rejecting the forward
    /// with "queue full" — so legitimate fresh traffic isn't blocked by a
    /// stale backlog.
    pub async fn delete_expired_for_connection(
        &self,
        connection_id: &str,
        max_age: std::time::Duration,
    ) -> Result<u64> {
        self.repository
            .delete_expired_for_connection(connection_id, max_age)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::InMemoryMessageQueueRepository;

    fn create_service() -> PickupMediatorService<InMemoryMessageQueueRepository> {
        let repo = Arc::new(InMemoryMessageQueueRepository::new());
        PickupMediatorService::new(repo)
    }

    #[tokio::test]
    async fn test_queue_message() {
        let service = create_service();

        let id = service
            .queue_message(
                "conn-1",
                vec!["key1".to_string()],
                r#"{"encrypted": "data"}"#,
            )
            .await
            .unwrap();

        assert!(!id.is_empty());
    }

    #[tokio::test]
    async fn test_status_request() {
        let service = create_service();

        // Queue some messages
        service
            .queue_message("conn-1", vec![], "msg1")
            .await
            .unwrap();
        service
            .queue_message("conn-1", vec![], "msg2")
            .await
            .unwrap();

        // Request status
        let request = StatusRequestMessage::new();
        let response = service
            .process_status_request(request, "conn-1")
            .await
            .unwrap();

        assert_eq!(response.message_count, 2);
        assert!(response.total_bytes.is_some());
    }

    #[tokio::test]
    async fn test_delivery_request() {
        let service = create_service();

        // Queue messages
        service
            .queue_message("conn-1", vec![], "msg1")
            .await
            .unwrap();
        service
            .queue_message("conn-1", vec![], "msg2")
            .await
            .unwrap();

        // Request delivery
        let request = DeliveryRequestMessage::new(10);
        let response = service
            .process_delivery_request(request, "conn-1")
            .await
            .unwrap();

        assert_eq!(response.attachments.len(), 2);
    }

    #[tokio::test]
    async fn test_messages_received() {
        let service = create_service();

        // Queue and deliver messages
        let id1 = service
            .queue_message("conn-1", vec![], "msg1")
            .await
            .unwrap();
        let id2 = service
            .queue_message("conn-1", vec![], "msg2")
            .await
            .unwrap();

        // Deliver them
        let request = DeliveryRequestMessage::new(10);
        let delivery = service
            .process_delivery_request(request.clone(), "conn-1")
            .await
            .unwrap();
        assert_eq!(delivery.attachments.len(), 2);

        // Acknowledge receipt
        let ack = MessagesReceivedMessage::new(vec![id1, id2]);
        let status = service
            .process_messages_received(ack, "conn-1")
            .await
            .unwrap();

        assert_eq!(status.message_count, 0);
    }

    #[tokio::test]
    async fn test_recipient_key_filter() {
        let service = create_service();

        // Queue messages for different keys
        service
            .queue_message("conn-1", vec!["key1".to_string()], "for-key1")
            .await
            .unwrap();
        service
            .queue_message("conn-1", vec!["key2".to_string()], "for-key2")
            .await
            .unwrap();

        // Status for key1 only
        let request = StatusRequestMessage::new().with_recipient_key("key1".to_string());
        let response = service
            .process_status_request(request, "conn-1")
            .await
            .unwrap();
        assert_eq!(response.message_count, 1);

        // Delivery for key1 only
        let request = DeliveryRequestMessage::new(10).with_recipient_key("key1".to_string());
        let response = service
            .process_delivery_request(request, "conn-1")
            .await
            .unwrap();
        assert_eq!(response.attachments.len(), 1);
    }
}
