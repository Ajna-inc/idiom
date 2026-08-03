//! Dependency injection error types

use thiserror::Error;

/// Dependency injection errors
#[derive(Error, Debug)]
pub enum DependencyError {
    /// Service not registered
    #[error("Service not registered: {0}")]
    NotRegistered(String),

    /// Service already registered
    #[error("Service already registered: {0}")]
    AlreadyRegistered(String),

    /// Circular dependency detected
    #[error("Circular dependency detected: {path}")]
    CircularDependency { path: String },

    /// Missing dependency
    #[error("Missing dependency: {service} requires {dependency}")]
    MissingDependency { service: String, dependency: String },

    /// Resolution failed
    #[error("Failed to resolve service: {0}")]
    ResolutionFailed(String),

    /// Invalid lifecycle
    #[error("Invalid lifecycle operation: {0}")]
    InvalidLifecycle(String),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, DependencyError>;

impl DependencyError {
    pub fn not_registered(service: impl Into<String>) -> Self {
        Self::NotRegistered(service.into())
    }

    pub fn already_registered(service: impl Into<String>) -> Self {
        Self::AlreadyRegistered(service.into())
    }

    pub fn circular_dependency(path: impl Into<String>) -> Self {
        Self::CircularDependency { path: path.into() }
    }

    pub fn missing_dependency(service: impl Into<String>, dependency: impl Into<String>) -> Self {
        Self::MissingDependency {
            service: service.into(),
            dependency: dependency.into(),
        }
    }

    pub fn resolution_failed(msg: impl Into<String>) -> Self {
        Self::ResolutionFailed(msg.into())
    }
}
