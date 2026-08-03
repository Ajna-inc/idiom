//! Message Pickup Protocol V2 Implementation (RFC 0685)
//!
//! This crate implements the Message Pickup Protocol V2 for DIDComm agents.
//! The protocol enables recipients behind NAT (like mobile devices or browsers)
//! to retrieve messages that have been queued at a mediator.
//!
//! # Protocol Flow
//!
//! **Recipient (Client) Side:**
//! ```text
//! 1. Send StatusRequest -> Receive Status (message count)
//! 2. Send DeliveryRequest (limit N) -> Receive Delivery (N messages)
//! 3. Send MessagesReceived (acknowledgment) -> Receive Status (updated count)
//! ```
//!
//! **Mediator (Server) Side:**
//! ```text
//! 1. Queue incoming messages for recipients
//! 2. Respond to StatusRequest with queue status
//! 3. Respond to DeliveryRequest with queued messages
//! 4. Remove messages after MessagesReceived acknowledgment
//! ```
//!
//! # Key Features
//!
//! - Query message queue status (count, oldest message age)
//! - Request delivery of queued messages with limit
//! - Acknowledge receipt to remove messages from queue
//! - Filter by recipient key for multi-key mediations
//!
//! # Example
//!
//! ```rust,no_run
//! use protocol_pickup::{
//!     PickupRecipientService, StatusRequestMessage, DeliveryRequestMessage,
//! };
//!
//! // Create a status request
//! let service = PickupRecipientService::new();
//! let status_request = service.create_status_request(None);
//!
//! // Create a delivery request for up to 10 messages
//! let delivery_request = service.create_delivery_request(10, None);
//! ```

pub mod domain;
pub mod events;
pub mod handlers;
pub mod messages;
pub mod repository;
pub mod services;

// Re-export commonly used types
pub use domain::{QueuedMessage, QueuedMessageState};
pub use events::{
    topics, types, MessageQueuedPayload, MessagesDeliveredPayload, MessagesReceivedPayload,
};
pub use handlers::{
    DeliveryRequestHandler, LiveDeliveryChangeHandler, MessagesReceivedHandler,
    StatusRequestHandler,
};
pub use messages::{
    DeliveryRequestMessage, LiveDeliveryChangeMessage, MessageDeliveryMessage,
    MessagesReceivedMessage, StatusMessage, StatusRequestMessage,
};
pub use repository::{
    InMemoryMessageQueueRepository, MessageQueueRepositoryTrait,
    StorageBackedMessageQueueRepository,
};
pub use services::{DeliveredMessage, PickupMediatorService, PickupRecipientService, PickupStatus};

/// Error types for the Message Pickup protocol
pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum PickupError {
        #[error("Message not found: {0}")]
        NotFound(String),

        #[error("Queue operation failed: {0}")]
        QueueError(String),

        #[error("Protocol error: {0}")]
        Protocol(String),

        #[error("Storage error: {0}")]
        Storage(String),

        #[error("Serialization error: {0}")]
        Serialization(#[from] serde_json::Error),
    }

    pub type Result<T> = std::result::Result<T, PickupError>;
}

pub use error::{PickupError, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_types() {
        assert_eq!(
            StatusRequestMessage::TYPE,
            "https://didcomm.org/messagepickup/2.0/status-request"
        );
        assert_eq!(
            StatusMessage::TYPE,
            "https://didcomm.org/messagepickup/2.0/status"
        );
        assert_eq!(
            DeliveryRequestMessage::TYPE,
            "https://didcomm.org/messagepickup/2.0/delivery-request"
        );
        assert_eq!(
            MessageDeliveryMessage::TYPE,
            "https://didcomm.org/messagepickup/2.0/delivery"
        );
        assert_eq!(
            MessagesReceivedMessage::TYPE,
            "https://didcomm.org/messagepickup/2.0/messages-received"
        );
    }

    #[test]
    fn test_queued_message_state() {
        let state = QueuedMessageState::Pending;
        assert_eq!(state.to_string(), "pending");

        let state = QueuedMessageState::Sending;
        assert_eq!(state.to_string(), "sending");
    }
}
