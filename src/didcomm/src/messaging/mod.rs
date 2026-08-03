//! # DIDComm Messaging
//!
//! Message routing, handling, and dispatching for DIDComm.
//!
//! ## Overview
//!
//! This crate provides the messaging layer for DIDComm:
//!
//! - **Handler Registry**: Maps message types to handlers
//! - **Message Dispatcher**: Routes messages to appropriate handlers
//! - **Message Context**: Metadata about messages (sender, thread, etc.)
//!
//! ## Example
//!
//! ```rust,no_run
//! use didcomm::messaging::{HandlerRegistry, MessageDispatcher};
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! # async fn example() {
//! let registry = Arc::new(RwLock::new(HandlerRegistry::new()));
//! // Register handlers...
//!
//! // dispatcher = MessageDispatcher::new(registry, envelope_service);
//! // Process messages...
//! # }
//! ```

pub mod handlers;
pub mod services;

// Re-exports
pub use handlers::{
    HandlerRef, HandlerRegistry, InboundMessage, MessageContext, MessageHandler,
    MessageHandlerError, OutboundMessage,
};
pub use services::{DidCommDocumentError, DidCommDocumentService};

// MessageDispatcher requires EnvelopeService which is native-only
#[cfg(feature = "native")]
pub use services::MessageDispatcher;

// Re-export Result type alias from handlers for convenience
pub type Result<T> = std::result::Result<T, MessageHandlerError>;
