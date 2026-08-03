use thiserror::Error;

#[derive(Error, Debug)]
pub enum MdocError {
    #[error("CBOR encoding error: {0}")]
    CborEncodingError(#[from] ciborium::ser::Error<std::io::Error>),

    #[error("CBOR decoding error: {0}")]
    CborDecodingError(#[from] ciborium::de::Error<std::io::Error>),

    // Note: coset::CoseError doesn't implement std::error::Error
    // so we handle conversion manually in code using MdocError::Other
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Missing required field: {field}")]
    MissingField { field: String },

    #[error("Invalid data type for field {field}: expected {expected}")]
    InvalidDataType { field: String, expected: String },

    #[error("Namespace not found: {namespace}")]
    NamespaceNotFound { namespace: String },

    #[error("Element not found: {element} in namespace {namespace}")]
    ElementNotFound { element: String, namespace: String },

    #[error("Document type mismatch: expected {expected}, got {actual}")]
    DocTypeMismatch { expected: String, actual: String },

    #[error("Digest verification failed for element {element}")]
    DigestVerificationFailed { element: String },

    #[error("Invalid mobile security object: {reason}")]
    InvalidMSO { reason: String },

    #[error("Device authentication failed: {reason}")]
    DeviceAuthFailed { reason: String },

    #[error("Issuer authentication failed: {reason}")]
    IssuerAuthFailed { reason: String },

    #[error("Presentation definition error: {0}")]
    PresentationDefinitionError(String),

    #[error("Session transcript error: {0}")]
    SessionTranscriptError(String),

    #[error("Certificate validation error: {0}")]
    CertificateError(String),

    #[error("Crypto operation failed: {0}")]
    CryptoError(String),

    #[error("Context error: {0}")]
    ContextError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, MdocError>;
