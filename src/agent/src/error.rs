//! Error types for the agent crate

use thiserror::Error;

/// Result type alias for agent operations
pub type Result<T> = std::result::Result<T, AgentError>;

/// Errors that can occur during agent operations
#[derive(Debug, Error)]
pub enum AgentError {
    /// Agent configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Agent not initialized
    #[error("Agent not initialized - call initialize() first")]
    NotInitialized,

    /// Agent already initialized
    #[error("Agent already initialized")]
    AlreadyInitialized,

    /// Agent already shutdown
    #[error("Agent already shutdown")]
    AlreadyShutdown,

    /// Module error
    #[error("Module error: {0}")]
    Module(String),

    /// Transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// Dispatcher error
    #[error("Dispatcher error: {0}")]
    Dispatcher(String),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Wallet error
    #[error("Wallet error: {0}")]
    Wallet(String),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// DID error
    #[error("DID error: {0}")]
    Did(String),

    /// DID resolution error
    #[error("DID resolution error: {0}")]
    DidResolution(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Protocol error - Out-of-Band
    #[error("Out-of-Band protocol error: {0}")]
    OutOfBand(String),

    /// Protocol error - Connections
    #[error("Connections protocol error: {0}")]
    Connections(String),

    /// Protocol error - Mediation
    #[error("Mediation protocol error: {0}")]
    Mediation(String),

    /// Protocol error - Bootstrap
    #[error("Bootstrap protocol error: {0}")]
    Bootstrap(String),

    /// DIDComm error
    #[error("DIDComm error: {0}")]
    DIDComm(String),

    /// Event bus error
    #[error("Event bus error: {0}")]
    Events(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// URL parsing error
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl From<protocol_oob::error::OutOfBandError> for AgentError {
    fn from(err: protocol_oob::error::OutOfBandError) -> Self {
        AgentError::OutOfBand(err.to_string())
    }
}

impl From<protocol_connections::error::ConnectionError> for AgentError {
    fn from(err: protocol_connections::error::ConnectionError) -> Self {
        AgentError::Connections(err.to_string())
    }
}

impl From<did::core::DidError> for AgentError {
    fn from(err: did::core::DidError) -> Self {
        AgentError::Did(err.to_string())
    }
}

impl From<didcomm::core::error::DidcommError> for AgentError {
    fn from(err: didcomm::core::error::DidcommError) -> Self {
        AgentError::DIDComm(err.to_string())
    }
}
