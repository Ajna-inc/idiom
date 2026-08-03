//! Error type for the Kanon registry, with a bridge into `AnonCredsError`
//! so it drops cleanly into the `AnonCredsRegistry` trait surface.

use anoncreds_core::AnonCredsError;

#[derive(Debug, thiserror::Error)]
pub enum KanonError {
    #[error("chain error: {0}")]
    Chain(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("operation not supported: {0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, KanonError>;

impl From<KanonError> for AnonCredsError {
    fn from(e: KanonError) -> Self {
        match e {
            KanonError::NotFound(m) => AnonCredsError::NotFound(m),
            KanonError::Storage(m) => AnonCredsError::Storage(m),
            KanonError::Invalid(m) => AnonCredsError::InvalidInput(m),
            KanonError::Encoding(m) => AnonCredsError::Registry(format!("encoding: {m}")),
            KanonError::Config(m) => AnonCredsError::Registry(format!("config: {m}")),
            KanonError::Chain(m) => AnonCredsError::Registry(format!("chain: {m}")),
            KanonError::Unsupported(m) => AnonCredsError::Unsupported(m),
        }
    }
}
