//! Error types for the signing protocol

use thiserror::Error;

/// Result type alias for the signing protocol
pub type Result<T> = std::result::Result<T, SigningProtocolError>;

/// Errors that can occur during signing protocol operations
#[derive(Debug, Error)]
pub enum SigningProtocolError {
    #[error("Invalid message type: {0}")]
    InvalidMessageType(String),

    #[error("Invalid message body: {0}")]
    InvalidBody(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Threshold not met: have {have}, need {need}")]
    ThresholdNotMet { have: u32, need: u32 },

    #[error("HPKE error: {0}")]
    HpkeError(String),

    #[error("Counter replay detected: counter {counter} not greater than last seen {last_seen}")]
    CounterReplay { counter: u64, last_seen: u64 },

    #[error("Token verification failed: {0}")]
    TokenVerificationFailed(String),

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Duplicate signer: {0}")]
    DuplicateSigner(String),

    #[error("Unknown signer: {0}")]
    UnknownSigner(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<serde_json::Error> for SigningProtocolError {
    fn from(e: serde_json::Error) -> Self {
        SigningProtocolError::SerializationError(e.to_string())
    }
}
