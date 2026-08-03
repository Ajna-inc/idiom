//! OID4VCI error types.

#[derive(Debug, thiserror::Error)]
pub enum Oid4vciError {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Invalid credential offer: {0}")]
    InvalidOffer(String),

    #[error("Invalid issuer metadata: {0}")]
    InvalidMetadata(String),

    #[error("Token request failed: {0}")]
    TokenError(String),

    #[error("Nonce request failed: {0}")]
    NonceError(String),

    #[error("Credential request failed: {0}")]
    CredentialError(String),

    #[error("AnonCreds error: {0}")]
    AnonCreds(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("Missing parameter: {0}")]
    MissingParameter(String),

    #[error("Proof error: {0}")]
    ProofError(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<reqwest::Error> for Oid4vciError {
    fn from(e: reqwest::Error) -> Self {
        Oid4vciError::Http(e.to_string())
    }
}

impl From<String> for Oid4vciError {
    fn from(s: String) -> Self {
        Oid4vciError::CredentialError(s)
    }
}

impl From<&str> for Oid4vciError {
    fn from(s: &str) -> Self {
        Oid4vciError::CredentialError(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Oid4vciError>;
