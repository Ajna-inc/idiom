//! Error types for the agent framework

use thiserror::Error;

/// Main error type for agent operations
#[derive(Error, Debug)]
pub enum AgentError {
    /// Storage-related errors
    #[error("Storage error: {0}")]
    Storage(String),

    /// Wallet/KMS errors
    #[error("Wallet error: {0}")]
    Wallet(String),

    /// DID resolution errors
    #[error("DID resolution error: {0}")]
    DidResolution(String),

    /// DIDComm messaging errors
    #[error("DIDComm error: {0}")]
    DidComm(String),

    /// Protocol errors
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Connection errors
    #[error("Connection error: {0}")]
    Connection(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Module initialization errors
    #[error("Module '{module}' initialization failed: {source}")]
    ModuleInit {
        module: String,
        source: Box<AgentError>,
    },

    /// Module not found
    #[error("Module not found: {0}")]
    ModuleNotFound(String),

    /// Service not registered in DI container
    #[error("Service not registered: {0}")]
    ServiceNotRegistered(String),

    /// Serialization/deserialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic error with context
    #[error("{0}")]
    Other(String),

    /// Wrapped external errors
    #[error(transparent)]
    External(#[from] anyhow::Error),
}

/// Result type alias using AgentError
pub type Result<T> = std::result::Result<T, AgentError>;

impl AgentError {
    /// Create a storage error
    pub fn storage(msg: impl Into<String>) -> Self {
        Self::Storage(msg.into())
    }

    /// Create a wallet error
    pub fn wallet(msg: impl Into<String>) -> Self {
        Self::Wallet(msg.into())
    }

    /// Create a DID resolution error
    pub fn did_resolution(msg: impl Into<String>) -> Self {
        Self::DidResolution(msg.into())
    }

    /// Create a DIDComm error
    pub fn didcomm(msg: impl Into<String>) -> Self {
        Self::DidComm(msg.into())
    }

    /// Create a protocol error
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    /// Create a connection error
    pub fn connection(msg: impl Into<String>) -> Self {
        Self::Connection(msg.into())
    }

    /// Create a configuration error
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create a module initialization error
    pub fn module_init(module: impl Into<String>, source: AgentError) -> Self {
        Self::ModuleInit {
            module: module.into(),
            source: Box::new(source),
        }
    }

    /// Create a module not found error
    pub fn module_not_found(module: impl Into<String>) -> Self {
        Self::ModuleNotFound(module.into())
    }

    /// Create a service not registered error
    pub fn service_not_registered(service: impl Into<String>) -> Self {
        Self::ServiceNotRegistered(service.into())
    }

    /// Create a generic error
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = AgentError::storage("test error");
        assert!(matches!(err, AgentError::Storage(_)));
        assert_eq!(err.to_string(), "Storage error: test error");
    }

    #[test]
    fn test_module_init_error() {
        let source = AgentError::config("invalid config");
        let err = AgentError::module_init("test_module", source);
        assert!(matches!(err, AgentError::ModuleInit { .. }));
    }
}
