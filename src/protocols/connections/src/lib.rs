//! Connections & DID Exchange Protocol Implementation
//!
//! This crate implements the DID Exchange 1.1 protocol (RFC 0023) for establishing
//! secure, pairwise connections between DIDComm agents.
//!
//! # Protocol Flow
//!
//! **Requester (Invitee) Side:**
//! ```text
//! InvitationReceived → RequestSent → ResponseReceived → Completed
//! ```
//!
//! **Responder (Inviter) Side:**
//! ```text
//! InvitationSent → RequestReceived → ResponseSent → Completed
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use protocol_connections::{ConnectionService, DidExchangeRole, DidExchangeState};
//!
//! // Create connection from OOB invitation
//! // let service = ConnectionService::new(storage, wallet, did_registry);
//! // let connection = service.create_from_invitation(invitation).await?;
//! ```

pub mod domain;
pub mod events;
pub mod handlers;
pub mod messages;
pub mod repository;
pub mod services;

// Re-export commonly used types
pub use domain::{ConnectionState, DidExchangeRole, DidExchangeState};
pub use events::{topics, types, ConnectionStateChangedPayload};
pub use handlers::{
    DidExchangeCompleteHandler, DidExchangeRequestHandler, DidExchangeResponseHandler,
};
pub use messages::{
    DidExchangeCompleteMessage, DidExchangeRequestMessage, DidExchangeResponseMessage,
};
pub use repository::{
    ConnectionRecord, ConnectionRecordBuilder, ConnectionRepository, ConnectionRepositoryTrait,
    ConnectionTags, StorageBackedConnectionRepository,
};
pub use services::ConnectionService;

/// Error types for the Connections protocol
pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum ConnectionError {
        #[error("Connection not found: {0}")]
        NotFound(String),

        #[error("Connection already exists: {0}")]
        AlreadyExists(String),

        #[error("Invalid state transition: from {from:?} to {to:?}")]
        InvalidStateTransition {
            from: crate::DidExchangeState,
            to: crate::DidExchangeState,
        },

        #[error("Invalid role for operation: expected {expected}, got {actual}")]
        InvalidRole {
            expected: crate::DidExchangeRole,
            actual: crate::DidExchangeRole,
        },

        #[error("Invalid state for operation: expected one of {expected:?}, got {actual:?}")]
        InvalidState {
            expected: Vec<crate::DidExchangeState>,
            actual: crate::DidExchangeState,
        },

        #[error("Missing parent thread ID in request message")]
        MissingParentThreadId,

        #[error("Missing thread ID in message")]
        MissingThreadId,

        #[error("Out-of-band invitation not found: {0}")]
        OutOfBandNotFound(String),

        #[error("Invalid DID: {0}")]
        InvalidDid(String),

        #[error("DID resolution failed: {0}")]
        DidResolutionFailed(String),

        #[error("Storage error: {0}")]
        Storage(String),

        #[error("Serialization error: {0}")]
        Serialization(#[from] serde_json::Error),

        #[error("Protocol error: {0}")]
        Protocol(String),
    }

    pub type Result<T> = std::result::Result<T, ConnectionError>;
}

pub use error::{ConnectionError, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_types() {
        let role = DidExchangeRole::Requester;
        assert_eq!(role.to_string(), "requester");

        let state = DidExchangeState::InvitationReceived;
        assert_eq!(state.to_string(), "invitation-received");
        assert!(state.is_active());
    }
}
