//! Present Proof v3 Protocol Implementation
//!
//! This crate implements the Present Proof 3.0 DIDComm protocol for AnonCreds
//! verifiable presentations. It supports the full proof exchange lifecycle
//! between a Verifier and a Prover.
//!
//! # Protocol Flow
//!
//! **Verifier Side:**
//! ```text
//! RequestSent -> PresentationReceived -> Done
//! ```
//!
//! **Prover Side:**
//! ```text
//! RequestReceived -> PresentationSent -> Done
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use protocol_proofs::{ProofExchangeRole, ProofExchangeState};
//!
//! // Create a proof request
//! // let service = ProofExchangeService::new(holder, verifier, repository);
//! // let (record, outbound) = service.create_request(...).await?;
//! ```

pub mod domain;
pub mod events;
pub mod handlers;
pub mod messages;
pub mod repository;
pub mod services;

// Re-export commonly used types
pub use domain::{ProofExchangeRole, ProofExchangeState};
pub use events::{topics, types, ProofStateChangedPayload};
pub use handlers::{
    AckHandler, PresentationHandler, ProblemReportHandler, RequestPresentationHandler,
};
pub use messages::{
    problem_codes, AckMessage, AckStatus, FixHint, Impact, PresentationMessage, ProblemDescription,
    ProblemReportMessage, RequestPresentationMessage, Where, WhoRetries, ANONCREDS_PROOF,
    ANONCREDS_PROOF_REQUEST,
};
pub use repository::{
    ProofExchangeRecord, ProofExchangeRepository, ProofExchangeRepositoryTrait,
    StorageBackedProofExchangeRepository,
};
pub use services::ProofExchangeService;

/// Error types for the Present Proof protocol
pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum ProofError {
        #[error("Proof exchange not found: {0}")]
        NotFound(String),

        #[error("Proof exchange already exists: {0}")]
        AlreadyExists(String),

        #[error("Invalid state transition: from {from:?} to {to:?}")]
        InvalidStateTransition {
            from: crate::ProofExchangeState,
            to: crate::ProofExchangeState,
        },

        #[error("Invalid role for operation: expected {expected:?}, got {actual:?}")]
        InvalidRole {
            expected: crate::ProofExchangeRole,
            actual: crate::ProofExchangeRole,
        },

        #[error("Invalid state for operation: expected one of {expected:?}, got {actual:?}")]
        InvalidState {
            expected: Vec<crate::ProofExchangeState>,
            actual: crate::ProofExchangeState,
        },

        #[error("Missing thread ID in message")]
        MissingThreadId,

        #[error("Missing attachment in message")]
        MissingAttachment,

        #[error("Presentation verification failed: {0}")]
        VerificationFailed(String),

        #[error("AnonCreds error: {0}")]
        AnonCreds(String),

        #[error("Serialization error: {0}")]
        Serialization(#[from] serde_json::Error),

        #[error("Protocol error: {0}")]
        Protocol(String),
    }

    pub type Result<T> = std::result::Result<T, ProofError>;
}

pub use error::{ProofError, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_types() {
        let role = ProofExchangeRole::Verifier;
        assert_eq!(role.to_string(), "verifier");

        let state = ProofExchangeState::RequestSent;
        assert_eq!(state.to_string(), "request-sent");
        assert!(state.is_active());
    }
}
