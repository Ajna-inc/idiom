//! Pickup Recipient Service
//!
//! Client-side service for requesting message pickup from a mediator.

use crate::error::{PickupError, Result};
use crate::messages::{
    DeliveryRequestMessage, MessageDeliveryMessage, MessagesReceivedMessage, StatusMessage,
    StatusRequestMessage,
};
use std::sync::Arc;

/// Service for recipients to pick up messages from a mediator
pub struct PickupRecipientService {
    /// Last known message count from status
    last_message_count: Arc<tokio::sync::RwLock<u64>>,
}

impl PickupRecipientService {
    /// Create a new pickup recipient service
    pub fn new() -> Self {
        Self {
            last_message_count: Arc::new(tokio::sync::RwLock::new(0)),
        }
    }

    /// Create a status request message
    pub fn create_status_request(&self, recipient_key: Option<String>) -> StatusRequestMessage {
        let mut msg = StatusRequestMessage::new();
        if let Some(key) = recipient_key {
            msg = msg.with_recipient_key(key);
        }
        msg
    }

    /// Create a delivery request message
    pub fn create_delivery_request(
        &self,
        limit: u32,
        recipient_key: Option<String>,
    ) -> DeliveryRequestMessage {
        let mut msg = DeliveryRequestMessage::new(limit);
        if let Some(key) = recipient_key {
            msg = msg.with_recipient_key(key);
        }
        msg
    }

    /// Create a messages received acknowledgment
    pub fn create_messages_received(
        &self,
        message_ids: Vec<String>,
        thread_id: Option<String>,
    ) -> MessagesReceivedMessage {
        match thread_id {
            Some(tid) => MessagesReceivedMessage::new_with_thread(tid, message_ids),
            None => MessagesReceivedMessage::new(message_ids),
        }
    }

    /// Process a status response
    pub async fn process_status(&self, msg: StatusMessage) -> Result<PickupStatus> {
        let mut count = self.last_message_count.write().await;
        *count = msg.message_count;

        Ok(PickupStatus {
            message_count: msg.message_count,
            recipient_key: msg.recipient_key,
            longest_waited_seconds: msg.longest_waited_seconds,
            total_bytes: msg.total_bytes,
            live_delivery: msg.live_delivery.unwrap_or(false),
        })
    }

    /// Process a message delivery response
    /// Returns the message IDs and their encrypted contents
    pub async fn process_delivery(
        &self,
        msg: MessageDeliveryMessage,
    ) -> Result<Vec<DeliveredMessage>> {
        let mut messages = Vec::new();

        for attachment in msg.attachments {
            let id = attachment.id.clone().unwrap_or_default();

            // Extract the base64 encoded message from the attachment
            let encrypted_message = match &attachment.data {
                didcomm::core::models::AttachmentData::Base64 { base64 } => {
                    // Decode from base64
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, base64)
                        .map_err(|e| PickupError::Protocol(format!("Invalid base64: {}", e)))?
                }
                didcomm::core::models::AttachmentData::Json { json } => {
                    // Already JSON, convert to bytes
                    serde_json::to_vec(json).map_err(PickupError::Serialization)?
                }
                didcomm::core::models::AttachmentData::Links { .. } => {
                    return Err(PickupError::Protocol(
                        "Link attachments not supported for message delivery".to_string(),
                    ));
                }
            };

            messages.push(DeliveredMessage {
                id,
                encrypted_message,
            });
        }

        Ok(messages)
    }

    /// Get the last known message count
    pub async fn last_message_count(&self) -> u64 {
        *self.last_message_count.read().await
    }
}

impl Default for PickupRecipientService {
    fn default() -> Self {
        Self::new()
    }
}

/// Status information from the mediator
#[derive(Debug, Clone)]
pub struct PickupStatus {
    /// Number of messages waiting
    pub message_count: u64,
    /// Recipient key this status is for (if filtered)
    pub recipient_key: Option<String>,
    /// Seconds since oldest message was queued
    pub longest_waited_seconds: Option<u64>,
    /// Total bytes of all queued messages
    pub total_bytes: Option<u64>,
    /// Whether live delivery is enabled
    pub live_delivery: bool,
}

/// A delivered message from the mediator
#[derive(Debug, Clone)]
pub struct DeliveredMessage {
    /// The queue message ID (for acknowledgment)
    pub id: String,
    /// The encrypted DIDComm message bytes
    pub encrypted_message: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use didcomm::core::models::{Attachment, AttachmentData};

    #[test]
    fn test_create_status_request() {
        let service = PickupRecipientService::new();

        let msg = service.create_status_request(None);
        assert_eq!(msg.msg_type, StatusRequestMessage::TYPE);
        assert!(msg.recipient_key.is_none());

        let msg = service.create_status_request(Some("did:key:z6Mkk...".to_string()));
        assert!(msg.recipient_key.is_some());
    }

    #[test]
    fn test_create_delivery_request() {
        let service = PickupRecipientService::new();

        let msg = service.create_delivery_request(10, None);
        assert_eq!(msg.limit, 10);
    }

    #[test]
    fn test_create_messages_received() {
        let service = PickupRecipientService::new();

        let msg =
            service.create_messages_received(vec!["msg-1".to_string(), "msg-2".to_string()], None);
        assert_eq!(msg.message_id_list.len(), 2);

        let msg = service
            .create_messages_received(vec!["msg-1".to_string()], Some("thread-123".to_string()));
        assert_eq!(msg.thread_id(), Some("thread-123"));
    }

    #[tokio::test]
    async fn test_process_status() {
        let service = PickupRecipientService::new();

        let status_msg =
            StatusMessage::new("thread-123".to_string(), 5).with_longest_waited_seconds(120);

        let status = service.process_status(status_msg).await.unwrap();
        assert_eq!(status.message_count, 5);
        assert_eq!(status.longest_waited_seconds, Some(120));

        // Check cached count
        assert_eq!(service.last_message_count().await, 5);
    }

    #[tokio::test]
    async fn test_process_delivery() {
        let service = PickupRecipientService::new();

        // Create a delivery message with base64 encoded content
        let attachment = Attachment {
            id: Some("msg-1".to_string()),
            description: None,
            filename: None,
            media_type: None,
            format: None,
            lastmod_time: None,
            byte_count: None,
            data: AttachmentData::Base64 {
                base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"test message",
                ),
            },
        };

        let delivery_msg = MessageDeliveryMessage::new("thread-123".to_string(), vec![attachment]);

        let messages = service.process_delivery(delivery_msg).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, "msg-1");
        assert_eq!(messages[0].encrypted_message, b"test message");
    }
}
