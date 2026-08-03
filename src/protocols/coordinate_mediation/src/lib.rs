//! Coordinate Mediation Protocol Implementation
//!
//! This crate implements the Coordinate Mediation Protocol (RFC 0211) for DIDComm agents.
//! The protocol allows agents to request mediation services from a mediator, enabling
//! indirect message routing for agents without persistent endpoints.
//!
//! # Protocol Flow
//!
//! **Recipient (Client) Side:**
//! ```text
//! Requested → Granted (or Denied)
//! ```
//!
//! **Mediator (Server) Side:**
//! ```text
//! Received Request → Grant or Deny
//! ```
//!
//! # Key Features
//!
//! - Request mediation from a mediator service
//! - Receive routing information (endpoint + routing keys)
//! - Update keylist (add/remove recipient keys)
//! - Forward messages through mediator
//!
//! # Example
//!
//! ```rust,no_run
//! use protocol_coordinate_mediation::{MediationRecipientService, MediatorService, MediationState};
//!
//! // Recipient side: request mediation from a mediator
//! // let recipient = MediationRecipientService::with_defaults();
//! // let (record, request_msg) = recipient.create_request("conn-id".to_string()).await?;
//!
//! // Mediator side: grant or deny the request
//! // let mediator = MediatorService::with_defaults("https://m.example".to_string(), vec![]);
//! // let record = mediator.process_request("conn-id".to_string()).await?;
//! // let (granted, grant_msg) = mediator.grant_mediation(&record.id, "thread-1".to_string()).await?;
//! ```

pub mod domain;
pub mod events;
pub mod handlers;
pub mod messages;
pub mod repository;
pub mod services;

/// Maximum size (in bytes) of a single encrypted message payload that the
/// mediator will accept for forwarding. Shared by the mediator forward handler
/// and `ForwardService` so both layers enforce the identical wire limit.
pub const MAX_FORWARDED_MESSAGE_SIZE_BYTES: usize = 512 * 1024;

// Re-export commonly used types
pub use domain::{KeylistAction, KeylistResult, MediationRole, MediationState};
pub use events::{topics, types, KeylistUpdatedPayload, MediationStateChangedPayload};
pub use handlers::{
    ForwardHandler, KeylistUpdateHandler, KeylistUpdateResponseHandler, MediationDenyHandler,
    MediationGrantHandler, MediationRequestHandler, MediatorForwardHandler,
};
pub use messages::{
    ForwardMessage, KeylistUpdate, KeylistUpdateMessage, KeylistUpdateResponseMessage,
    KeylistUpdated, MediationDenyMessage, MediationGrantMessage, MediationRequestMessage,
};
pub use repository::{
    KeylistRecord, KeylistRepository, KeylistRepositoryTrait, KeylistTags, MediationRecord,
    MediationRecordBuilder, MediationRepository, MediationRepositoryTrait, MediationTags,
    StorageBackedKeylistRepository, StorageBackedMediationRepository,
};
pub use services::{
    ForwardService, ForwardingStrategy, LiveSessionManager, MediationRecipientService,
    MediatorService,
};

/// Error types for the Coordinate Mediation protocol
pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum MediationError {
        #[error("Mediation not found: {0}")]
        NotFound(String),

        #[error("Mediation already exists: {0}")]
        AlreadyExists(String),

        #[error("Invalid state transition: from {from:?} to {to:?}")]
        InvalidStateTransition {
            from: crate::MediationState,
            to: crate::MediationState,
        },

        #[error("Invalid role for operation: expected {expected:?}, got {actual:?}")]
        InvalidRole {
            expected: crate::MediationRole,
            actual: crate::MediationRole,
        },

        #[error("Invalid state for operation: expected one of {expected:?}, got {actual:?}")]
        InvalidState {
            expected: Vec<crate::MediationState>,
            actual: crate::MediationState,
        },

        #[error("Missing thread ID in message")]
        MissingThreadId,

        #[error("Connection not found: {0}")]
        ConnectionNotFound(String),

        #[error("Keylist update failed: {0}")]
        KeylistUpdateFailed(String),

        #[error("No mediation granted for connection: {0}")]
        NoMediationGranted(String),

        #[error("Storage error: {0}")]
        Storage(String),

        #[error("Serialization error: {0}")]
        Serialization(#[from] serde_json::Error),

        #[error("Protocol error: {0}")]
        Protocol(String),

        #[error("DIDComm error: {0}")]
        DIDComm(String),
    }

    pub type Result<T> = std::result::Result<T, MediationError>;
}

pub use error::{MediationError, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_types() {
        let role = MediationRole::Recipient;
        assert_eq!(role.to_string(), "recipient");

        let state = MediationState::Requested;
        assert_eq!(state.to_string(), "requested");
    }
}
