//! Issue Credential v3 Protocol Implementation (AnonCreds)
//!
//! This crate implements the Issue Credential v3 DIDComm protocol for AnonCreds
//! credential issuance and acceptance.
//!
//! # Protocol Flow
//!
//! **Issuer Side:**
//! ```text
//! OfferSent -> RequestReceived -> CredentialIssued -> Done
//! ```
//!
//! **Holder Side:**
//! ```text
//! OfferReceived -> RequestSent -> CredentialReceived -> Done
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use protocol_credentials::{CredentialExchangeService, CredentialExchangeRole, CredentialExchangeState};
//!
//! // Create credential exchange from offer
//! // let service = CredentialExchangeService::new(issuer, holder, repository);
//! // let (record, outbound) = service.create_offer(connection_id, schema_id, cred_def_id).await?;
//! ```

pub mod domain;
pub mod events;
pub mod handlers;
pub mod messages;
pub mod repository;
pub mod services;

// Re-export commonly used types
pub use domain::{CredentialExchangeRole, CredentialExchangeState};
pub use events::{topics, types, CredentialStateChangedPayload};
pub use handlers::{
    CredentialAckHandler, IssueCredentialHandler, OfferCredentialHandler, ProblemReportHandler,
    ProposeCredentialHandler, RequestCredentialHandler,
};
pub use messages::{
    are_preview_attributes_equal, problem_codes, AckMessage, AckStatus, CredentialPreviewAttribute,
    FixHint, Impact, IssueCredentialMessage, OfferCredentialMessage, ProblemDescription,
    ProblemReportMessage, ProposeCredentialMessage, RequestCredentialMessage, Where, WhoRetries,
};
pub use repository::{
    CredentialExchangeRecord, CredentialExchangeRepository, CredentialExchangeRepositoryTrait,
    StorageBackedCredentialExchangeRepository,
};
pub use services::CredentialExchangeService;

/// Error types for the Issue Credential protocol
pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum CredentialError {
        #[error("Credential exchange not found: {0}")]
        NotFound(String),

        #[error("Credential exchange already exists: {0}")]
        AlreadyExists(String),

        #[error("Invalid state transition: from {from:?} to {to:?}")]
        InvalidStateTransition {
            from: crate::CredentialExchangeState,
            to: crate::CredentialExchangeState,
        },

        #[error("Invalid role for operation: expected {expected:?}, got {actual:?}")]
        InvalidRole {
            expected: crate::CredentialExchangeRole,
            actual: crate::CredentialExchangeRole,
        },

        #[error("Invalid state for operation: expected one of {expected:?}, got {actual:?}")]
        InvalidState {
            expected: Vec<crate::CredentialExchangeState>,
            actual: crate::CredentialExchangeState,
        },

        #[error("Missing thread ID in message")]
        MissingThreadId,

        #[error("Missing attachment in message")]
        MissingAttachment,

        #[error("Invalid attachment format: {0}")]
        InvalidAttachmentFormat(String),

        #[error("AnonCreds error: {0}")]
        AnonCreds(String),

        #[error("Serialization error: {0}")]
        Serialization(#[from] serde_json::Error),

        #[error("Protocol error: {0}")]
        Protocol(String),
    }

    impl From<anoncreds_core::AnonCredsError> for CredentialError {
        fn from(e: anoncreds_core::AnonCredsError) -> Self {
            CredentialError::AnonCreds(e.to_string())
        }
    }

    pub type Result<T> = std::result::Result<T, CredentialError>;
}

pub use error::{CredentialError, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_types() {
        let role = CredentialExchangeRole::Issuer;
        assert_eq!(role.to_string(), "issuer");

        let state = CredentialExchangeState::OfferSent;
        assert_eq!(state.to_string(), "offer-sent");
        assert!(state.is_active());
    }
}
