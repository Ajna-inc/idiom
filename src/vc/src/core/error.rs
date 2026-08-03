use thiserror::Error;

/// Errors that can occur in credential operations
#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Invalid credential format: {0}")]
    InvalidFormat(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Credential expired at {0}")]
    CredentialExpired(String),

    #[error("Credential not yet valid until {0}")]
    CredentialNotYetValid(String),

    #[error("Invalid issuer: {0}")]
    InvalidIssuer(String),

    #[error("Invalid subject: {0}")]
    InvalidSubject(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Unsupported credential format: {0}")]
    UnsupportedFormat(String),

    #[error("Key resolution failed: {0}")]
    KeyResolutionFailed(String),

    #[error("JSON processing error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Credential status check failed: {0}")]
    StatusCheckFailed(String),

    #[error("Schema validation failed: {0}")]
    SchemaValidationFailed(String),

    #[error("Context loading failed: {0}")]
    ContextLoadingFailed(String),

    #[error("Canonicalization failed: {0}")]
    CanonicalizationFailed(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Other error: {0}")]
    Other(String),
}

impl From<Box<dyn std::error::Error + Send + Sync>> for CredentialError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        CredentialError::Other(err.to_string())
    }
}

/// Result type for credential operations
pub type Result<T> = std::result::Result<T, CredentialError>;
