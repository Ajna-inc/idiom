//! Error types for Askar storage

use thiserror::Error;

/// Result type for Askar storage operations
pub type Result<T> = std::result::Result<T, AskarError>;

/// Errors that can occur in Askar storage operations
#[derive(Error, Debug)]
pub enum AskarError {
    /// Error from Askar library
    #[error("Askar error: {0}")]
    Askar(#[from] aries_askar::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Storage operation error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Record not found
    #[error("Record not found: category={category}, name={name}")]
    NotFound { category: String, name: String },

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Agent core error
    #[error("Agent error: {0}")]
    Agent(#[from] agent_core::AgentError),
}

impl AskarError {
    /// Create a configuration error
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create a storage error
    pub fn storage(msg: impl Into<String>) -> Self {
        Self::Storage(msg.into())
    }

    /// Create a not found error
    pub fn not_found(category: impl Into<String>, name: impl Into<String>) -> Self {
        Self::NotFound {
            category: category.into(),
            name: name.into(),
        }
    }
}
