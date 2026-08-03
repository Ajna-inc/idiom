//! Out-of-Band (OOB) Protocol Implementation
//!
//! This crate implements the Out-of-Band Protocol (RFC 0434) for establishing
//! connections and initiating protocol exchanges in SSI agents.
//!
//! # Overview
//!
//! The OOB protocol enables agents to:
//! - Create and share invitations (via URLs, QR codes, etc.)
//! - Initiate connection establishment
//! - Reuse existing connections
//! - Attach protocol requests to invitations
//!
//! # Message Types
//!
//! - `OutOfBandInvitation`: Main invitation message
//! - `HandshakeReuseMessage`: Request to reuse existing connection
//! - `HandshakeReuseAcceptedMessage`: Acknowledgment of reuse
//!
//! # State Machine
//!
//! **Sender (Inviter)**:
//! ```text
//! Initial → AwaitResponse → Done (non-reusable)
//!                        → AwaitResponse (reusable)
//! ```
//!
//! **Receiver (Invitee)**:
//! ```text
//! Initial → PrepareResponse → Done
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use protocol_oob::{OutOfBandInvitation, OutOfBandService};
//!
//! // Create an invitation with a DID reference
//! let invitation = OutOfBandInvitation::new(vec![
//!     OutOfBandService::Did("did:example:123".to_string())
//! ])
//! .with_label("Faber College".to_string())
//! .with_handshake_protocols(vec![
//!     "https://didcomm.org/didexchange/1.1".to_string()
//! ]);
//!
//! // Encode to URL for sharing
//! let url = invitation.to_url("https://faber.edu").unwrap();
//! println!("Share this URL: {}", url);
//!
//! // Decode from URL
//! let decoded = OutOfBandInvitation::from_url(&url).unwrap();
//! assert_eq!(decoded.id, invitation.id);
//! ```

pub mod api;
pub mod domain;
pub mod events;
pub mod messages;
pub mod repository;
pub mod services;

// Re-export commonly used types
pub use api::OutOfBandApi;
pub use domain::{InvitationType, OutOfBandRole, OutOfBandState};
pub use messages::{
    HandshakeReuseAcceptedMessage, HandshakeReuseMessage, InlineService, OutOfBandInvitation,
    OutOfBandService,
};
pub use repository::{OutOfBandRecord, OutOfBandRepository};
pub use services::OutOfBandService as OutOfBandServiceImpl;

/// Error types for the OOB protocol
pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum OutOfBandError {
        #[error("Invalid invitation URL: {0}")]
        InvalidInvitationUrl(String),

        #[error("Out-of-band record not found: {0}")]
        RecordNotFound(String),

        #[error("Out-of-band record already exists: {0}")]
        RecordAlreadyExists(String),

        #[error("Invalid role for operation: expected {expected}, got {actual}")]
        InvalidRole {
            expected: crate::OutOfBandRole,
            actual: crate::OutOfBandRole,
        },

        #[error("Invalid state for operation: expected one of {expected:?}, got {actual:?}")]
        InvalidState {
            expected: Vec<crate::OutOfBandState>,
            actual: crate::OutOfBandState,
        },

        #[error("Missing parent thread ID")]
        MissingParentThreadId,

        #[error("Parent thread ID mismatch")]
        ParentThreadIdMismatch,

        #[error("Connection already exists for non-reusable invitation")]
        ConnectionAlreadyExists,

        #[error("Invitation must have either handshake protocols or requests")]
        NoHandshakeOrRequests,

        #[error("Multi-use invitations cannot have attached messages")]
        MultiUseWithMessages,

        #[error("Storage error: {0}")]
        Storage(String),

        #[error("Serialization error: {0}")]
        Serialization(#[from] serde_json::Error),

        #[error("Base64 decode error: {0}")]
        Base64Decode(#[from] base64::DecodeError),

        #[error("URL parse error: {0}")]
        UrlParse(#[from] url::ParseError),
    }

    pub type Result<T> = std::result::Result<T, OutOfBandError>;
}

pub use error::{OutOfBandError, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_invitation_flow() {
        // Create invitation
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())])
                .with_label("Test Agent".to_string());

        // Encode to URL
        let url = invitation.to_url("https://example.com").unwrap();
        assert!(url.contains("?oob="));

        // Decode from URL
        let decoded = OutOfBandInvitation::from_url(&url).unwrap();
        assert_eq!(decoded.id, invitation.id);
        assert_eq!(decoded.label, invitation.label);
    }
}
