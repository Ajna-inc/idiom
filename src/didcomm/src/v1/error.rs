//! Error types for DIDComm v1

use thiserror::Error;

pub type Result<T> = std::result::Result<T, DIDCommV1Error>;

#[derive(Error, Debug)]
pub enum DIDCommV1Error {
    #[error("Invalid JWE structure: {0}")]
    InvalidJWE(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Wallet error: {0}")]
    Wallet(#[from] agent_core::AgentError),

    #[error("Askar error: {0}")]
    Askar(#[from] aries_askar::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("{0}")]
    Other(String),
}
