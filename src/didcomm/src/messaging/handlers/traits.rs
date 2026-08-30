//! Message Handler Traits
//!
//! Defines the core traits and types for DIDComm message handling.
//!
//! This module provides platform-aware async traits:
//! - Native: Uses `Send + Sync` bounds for multi-threaded environments
//! - WASM: No thread safety bounds (single-threaded)

use crate::core::Message as DidcommMessage;
use async_trait::async_trait;
use std::error::Error;
use std::fmt;

/// Error type for message handler operations
#[derive(Debug)]
pub enum MessageHandlerError {
    /// Handler processing failed
    ProcessingFailed(String),
    /// Invalid message format
    InvalidMessage(String),
    /// Handler not found
    HandlerNotFound(String),
    /// Generic error (native: Send+Sync, WASM: no bounds)
    #[cfg(not(target_arch = "wasm32"))]
    Other(Box<dyn Error + Send + Sync>),
    #[cfg(target_arch = "wasm32")]
    Other(Box<dyn Error>),
}

impl fmt::Display for MessageHandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessingFailed(msg) => write!(f, "Handler processing failed: {}", msg),
            Self::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            Self::HandlerNotFound(msg) => write!(f, "Handler not found: {}", msg),
            Self::Other(e) => write!(f, "Handler error: {}", e),
        }
    }
}

impl Error for MessageHandlerError {}

/// Result type for message handler operations
pub type Result<T> = std::result::Result<T, MessageHandlerError>;

/// Message context provided to handlers
///
/// Contains metadata about the message transport and security.
#[derive(Debug, Clone)]
pub struct MessageContext {
    /// Sender DID (if authenticated)
    pub from: Option<String>,
    /// Recipient DID
    pub to: Option<String>,
    /// Thread ID from the message
    pub thread_id: Option<String>,
    /// Parent thread ID (for nested protocols)
    pub parent_thread_id: Option<String>,
    /// Connection ID (resolved by handler)
    pub connection_id: Option<String>,
    /// Whether the message was encrypted
    pub encrypted: bool,
    /// Whether the message was authenticated
    pub authenticated: bool,
    /// Sender's endpoint for return routing
    /// This enables responses to be routed back to the sender's endpoint
    pub sender_endpoint: Option<String>,
    /// The exact decrypted plaintext before any v1→v2 normalization
    /// (see `UnpackMetadata::raw_plaintext`). Handlers that forward messages
    /// to an external controller MUST use this instead of re-serializing
    /// `InboundMessage::message`, which is lossy for v1 wire form.
    pub raw_plaintext: Option<String>,
}

/// Inbound message with parsed content
///
/// This is what handlers receive when processing incoming messages.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// The parsed DIDComm message
    pub message: DidcommMessage,
    /// Message context (security metadata)
    pub context: MessageContext,
}

/// Outbound message to be sent
///
/// Handlers return this when they want to send a response.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    /// The DIDComm message to send
    pub message: DidcommMessage,
    /// Recipient DID
    pub to: String,
    /// Sender DID
    pub from: String,
    /// Connection ID (optional, for routing)
    pub connection_id: Option<String>,
}

/// Message handler trait
///
/// Handlers process incoming DIDComm messages and optionally return responses.
///
/// # Important: Auto-Accept Pattern
///
/// If a handler returns `Some(response)`, the dispatcher will automatically
/// send it. This enables the auto-accept pattern where handlers can immediately
/// respond without manual intervention.
///
/// # Example
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use crate::messaging::{MessageHandler, InboundMessage, OutboundMessage};
///
/// struct MyHandler;
///
/// #[async_trait]
/// impl MessageHandler for MyHandler {
///     fn supported_types(&self) -> Vec<String> {
///         vec!["https://didcomm.org/myprotocol/1.0/request".to_string()]
///     }
///
///     async fn handle(
///         &self,
///         inbound: InboundMessage,
///     ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
///         // Process the message
///         // ...
///
///         // Auto-respond if configured
///         if should_auto_respond {
///             let response = create_response(&inbound)?;
///             return Ok(Some(response));  // Dispatcher will send this
///         }
///
///         Ok(None)  // No automatic response
///     }
/// }
/// ```

// Native: Multi-threaded with Send + Sync bounds
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Get the message types this handler supports
    ///
    /// Returns a list of message type URIs (e.g., "https://didcomm.org/didexchange/1.1/request")
    fn supported_types(&self) -> Vec<String>;

    /// Handle an inbound message
    ///
    /// # Arguments
    /// * `inbound` - The inbound message with context
    ///
    /// # Returns
    /// * `Ok(Some(response))` - Handler generated a response (dispatcher will send it)
    /// * `Ok(None)` - Message processed, no automatic response
    /// * `Err(e)` - Handler failed to process the message
    async fn handle(&self, inbound: InboundMessage) -> Result<Option<OutboundMessage>>;
}

// WASM: Single-threaded, no Send + Sync bounds
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait MessageHandler {
    /// Get the message types this handler supports
    ///
    /// Returns a list of message type URIs (e.g., "https://didcomm.org/didexchange/1.1/request")
    fn supported_types(&self) -> Vec<String>;

    /// Handle an inbound message
    ///
    /// # Arguments
    /// * `inbound` - The inbound message with context
    ///
    /// # Returns
    /// * `Ok(Some(response))` - Handler generated a response (dispatcher will send it)
    /// * `Ok(None)` - Message processed, no automatic response
    /// * `Err(e)` - Handler failed to process the message
    async fn handle(&self, inbound: InboundMessage) -> Result<Option<OutboundMessage>>;
}
