use thiserror::Error;

/// Errors that can occur when working with Sanskrit SIDs
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SIDError {
    /// Invalid DID prefix (expected "did:ajna:")
    #[error("Invalid DID prefix, expected 'did:ajna:'")]
    InvalidPrefix,

    /// Invalid syllable in Sanskrit encoding
    #[error("Invalid Sanskrit syllable: {0}")]
    InvalidSyllable(String),

    /// Invalid length for Sanskrit SID
    #[error("Invalid SID length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    /// Checksum validation failed
    #[error("Checksum validation failed")]
    InvalidChecksum,

    /// Invalid format
    #[error("Invalid SID format: {0}")]
    InvalidFormat(String),

    /// Overflow during encoding/decoding
    #[error("Numeric overflow during SID encoding/decoding")]
    Overflow,

    /// Invalid header version
    #[error("Invalid header version: {0}")]
    InvalidVersion(u8),

    /// Reserved bits are non-zero
    #[error("Reserved bits must be zero")]
    ReservedBitsSet,

    /// Invalid English word in mnemonic
    #[error("Invalid English word in mnemonic: {0}")]
    InvalidWord(String),

    /// Invalid mnemonic phrase format
    #[error("Invalid mnemonic phrase format")]
    InvalidMnemonicFormat,
}

/// Result type for SID operations
pub type Result<T> = std::result::Result<T, SIDError>;
