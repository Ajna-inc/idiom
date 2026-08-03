//! Basic Messages Protocol
//!
//! Implementation of DIDComm Basic Messages protocol (https://didcomm.org/basicmessage/1.0/message)
//!
//! This crate provides:
//! - Message definitions for basic text messaging
//! - Message handler for processing incoming messages
//! - Repository for storing message history
//! - Service layer for business logic
//!
//! # Example
//!
//! ```ignore
//! use protocol_basic_messages::messages::BasicMessage;
//! use protocol_basic_messages::repository::BasicMessageRepository;
//! use protocol_basic_messages::services::BasicMessageService;
//! use agent_events::EventBus;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create repository
//! let repo = Arc::new(BasicMessageRepository::new());
//! let event_bus = Arc::new(EventBus::new(100));
//!
//! // Create service
//! let service = Arc::new(BasicMessageService::new(repo, event_bus));
//!
//! // Create a message
//! let message = BasicMessage::new("Hello, world!");
//! # Ok(())
//! # }
//! ```

pub mod events;
pub mod handlers;
pub mod messages;
pub mod repository;
pub mod services;

// Re-export commonly used types
pub use handlers::{BasicMessageHandler, BasicMessageHandlerError};
pub use handlers::{DeleteHandler, DeleteHandlerError};
pub use handlers::{EditHandler, EditHandlerError};
pub use messages::{BasicMessage, L10n, Thread, BASIC_MESSAGE_TYPE};
pub use messages::{DeleteMessage, DELETE_MESSAGE_TYPE};
pub use messages::{EditMessage, EDIT_MESSAGE_TYPE};
pub use repository::{
    BasicMessageError, BasicMessageQuery, BasicMessageRecord, BasicMessageRepository,
    BasicMessageRepositoryTrait, BasicMessageRole, BasicMessageTags,
    StorageBackedBasicMessageRepository,
};
pub use services::{BasicMessageService, BasicMessageServiceError};
