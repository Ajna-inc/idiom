//! OID4VP error types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Oid4vpError {
    #[error("Invalid authorization request: {0}")]
    InvalidRequest(String),

    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("Invalid JWT: {0}")]
    InvalidJwt(String),

    #[error("DCQL validation error: {0}")]
    DcqlError(String),

    #[error("No matching credentials found")]
    NoMatchingCredentials,

    #[error("Transport error: {0}")]
    TransportError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("mDoc error: {0}")]
    MdocError(String),

    #[error("Missing required parameter: {0}")]
    MissingParameter(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
}

impl From<reqwest::Error> for Oid4vpError {
    fn from(e: reqwest::Error) -> Self {
        Oid4vpError::HttpError(e.to_string())
    }
}

impl From<serde_json::Error> for Oid4vpError {
    fn from(e: serde_json::Error) -> Self {
        Oid4vpError::EncodingError(e.to_string())
    }
}

impl From<url::ParseError> for Oid4vpError {
    fn from(e: url::ParseError) -> Self {
        Oid4vpError::InvalidRequest(format!("URL parse error: {}", e))
    }
}

impl From<String> for Oid4vpError {
    fn from(s: String) -> Self {
        Oid4vpError::InvalidRequest(s)
    }
}

impl From<&str> for Oid4vpError {
    fn from(s: &str) -> Self {
        Oid4vpError::InvalidRequest(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Oid4vpError>;
