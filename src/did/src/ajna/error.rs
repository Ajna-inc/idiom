//! Error types for did:ajna

use thiserror::Error;

pub type Result<T> = std::result::Result<T, AjnaError>;

#[derive(Error, Debug)]
pub enum AjnaError {
    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    #[error("DID not found: {0}")]
    DidNotFound(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("CRDT merge conflict: {0}")]
    MergeConflict(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Vector clock error: {0}")]
    VectorClock(String),

    #[error("Merkle DAG error: {0}")]
    MerkleDag(String),

    #[error("Agent error: {0}")]
    Agent(String),

    #[error("Storage error: {0}")]
    Storage(String),

    // Sync protocol errors
    #[error("Invalid bloom filter: {0}")]
    InvalidBloomFilter(String),

    #[error("Bundle too large: {size} bytes (max: {max} bytes)")]
    BundleTooLarge { size: usize, max: usize },

    #[error("Invalid bundle ID")]
    InvalidBundleId,

    #[error("Insufficient context in bundle")]
    InsufficientContext,

    #[error("Resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("Anchor not ZK-final")]
    AnchorNotFinal,

    #[error("DID is deactivated")]
    DeactivatedDID,

    #[error("Invalid reference: {0}")]
    InvalidReference(String),

    // Bloom crate error
    #[error("Bloom filter error: {0}")]
    BloomError(String),
}
