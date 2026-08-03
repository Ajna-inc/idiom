/// Error types for anoncreds_core

#[derive(Debug, thiserror::Error)]
pub enum AnonCredsError {
    #[error("Schema error: {0}")]
    Schema(String),

    #[error("Credential definition error: {0}")]
    CredentialDefinition(String),

    #[error("Credential error: {0}")]
    Credential(String),

    #[error("Presentation error: {0}")]
    Presentation(String),

    #[error("Registry error: {0}")]
    Registry(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Anoncreds library error: {0}")]
    AnoncredsLib(String),

    #[error("Operation not supported: {0}")]
    Unsupported(String),
}

impl From<anoncreds::Error> for AnonCredsError {
    fn from(e: anoncreds::Error) -> Self {
        AnonCredsError::AnoncredsLib(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AnonCredsError>;
