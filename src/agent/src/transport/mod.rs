//! Transport management and routing
//!
//! This module provides a modular transport architecture
//! - Transport traits (InboundTransport, OutboundTransport) for pluggable transports
//! - HTTP transport implementation
//! - Channel transport for testing
//! - TransportManager for orchestrating multiple transports
//! - Session management for bidirectional communication

pub mod channel;
pub mod http;
pub mod manager;
pub mod traits;
pub mod ws_mediator_outbound;

pub use channel::{ChannelInboundTransport, ChannelOutboundTransport};
pub use http::{HttpInboundTransport, HttpOutboundTransport};
pub use manager::TransportManager;
pub use traits::{
    InboundMetadata, InboundResponse, InboundTransport, OutboundPackage, OutboundTransport,
    TransportSession,
};
pub use ws_mediator_outbound::WsMediatorOutboundTransport;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Encrypted DIDComm message in JWE format
///
/// This matches the structure used by DIDComm v1.
/// The message consists of JWE (JSON Web Encryption) components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedMessage {
    /// The "protected" member contains BASE64URL(UTF8(JWE Protected Header))
    /// These Header Parameter values are integrity protected.
    pub protected: String,

    /// The "iv" member contains BASE64URL(JWE Initialization Vector)
    pub iv: String,

    /// The "ciphertext" member contains BASE64URL(JWE Ciphertext)
    pub ciphertext: String,

    /// The "tag" member contains BASE64URL(JWE Authentication Tag)
    pub tag: String,

    /// Sender's endpoint for return routing (test mode only)
    /// In production, this would be derived from DID resolution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_endpoint: Option<String>,
}

impl EncryptedMessage {
    /// Create a new encrypted message
    pub fn new(protected: String, iv: String, ciphertext: String, tag: String) -> Self {
        Self {
            protected,
            iv,
            ciphertext,
            tag,
            sender_endpoint: None,
        }
    }

    /// Set the sender's endpoint for return routing
    pub fn with_sender_endpoint(mut self, endpoint: String) -> Self {
        self.sender_endpoint = Some(endpoint);
        self
    }

    /// Parse an encrypted message from a JSON string
    pub fn from_json(json: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize the encrypted message to a JSON string
    pub fn to_json(&self) -> std::result::Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize the encrypted message to pretty JSON
    pub fn to_json_pretty(&self) -> std::result::Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Transport errors
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Transport not found for endpoint: {0}")]
    NotFound(String),

    #[error("Transport send error: {0}")]
    Send(String),

    #[error("Transport receive error: {0}")]
    Receive(String),

    #[error("Invalid endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("Transport error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TransportError>;

// Note: InboundTransport and OutboundTransport traits are now re-exported
// from didcomm_transports (see pub use above)
