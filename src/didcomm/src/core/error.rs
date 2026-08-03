use thiserror::Error;

/// Errors that can occur in DIDComm operations
#[derive(Debug, Error)]
pub enum DidcommError {
    /// DID resolution failed
    #[error("DID resolution failed: {0}")]
    DidResolution(String),

    /// Secret (key) not found
    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    /// Packing failed
    #[error("Failed to pack message: {0}")]
    PackingFailed(String),

    /// Unpacking failed
    #[error("Failed to unpack message: {0}")]
    UnpackingFailed(String),

    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    /// Invalid DID format
    #[error("Invalid DID: {0}")]
    InvalidDid(String),

    /// Invalid key format
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// No recipients specified
    #[error("No recipients specified for message")]
    NoRecipients,

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    /// Service endpoint not found
    #[error("Service endpoint not found for DID: {0}")]
    ServiceNotFound(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// DIDComm library error
    #[error("DIDComm error: {0}")]
    DIDCommLib(String),

    /// Agent core error (native-only, requires agent_core)
    #[cfg(feature = "v1-compat")]
    #[error("Agent error: {0}")]
    Agent(#[from] agent_core::error::AgentError),

    /// DID core error
    #[error("DID error: {0}")]
    Did(String),

    /// Other error
    #[error("DIDComm error: {0}")]
    Other(String),
}

/// Result type for DIDComm operations
pub type Result<T> = std::result::Result<T, DidcommError>;
