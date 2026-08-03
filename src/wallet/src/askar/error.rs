//! Error types for wallet operations

use thiserror::Error;

pub type Result<T> = std::result::Result<T, AskarWalletError>;

#[derive(Error, Debug)]
pub enum AskarWalletError {
    #[error("Askar error: {0}")]
    Askar(#[from] aries_askar::Error),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key type: expected {expected}, found {found}")]
    InvalidKeyType { expected: String, found: String },

    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Key agreement error: {0}")]
    KeyAgreement(String),

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Configuration error: {0}")]
    Config(String),
}

// Convert to agent_core error
impl From<AskarWalletError> for agent_core::AgentError {
    fn from(err: AskarWalletError) -> Self {
        agent_core::AgentError::wallet(err.to_string())
    }
}
