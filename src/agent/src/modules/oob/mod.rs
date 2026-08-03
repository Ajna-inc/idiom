//! Out-of-Band Module
//!
//! This module provides high-level APIs for the Out-of-Band protocol,
//! enabling the creation and receipt of OOB invitations.

mod module;

// Re-export module types
pub use module::{
    InvitationConfig, OobExt, OutOfBandModule, ParsedInvitationInfo, ReceiveInvitationResult,
    ServiceInfo,
};
