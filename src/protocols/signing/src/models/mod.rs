//! Model types for the DIDComm Signing Protocol 1.0
//!
//! This module contains the core data structures used across the protocol:
//! - Signable objects and cryptographic constraints
//! - Signing sessions with participant tracking
//! - Authorization tokens with monotonic counter replay protection
//! - HPKE sealed secret envelopes

pub mod sealed_secret;
pub mod session;
pub mod signable_object;
pub mod token;

// Re-export all public types for convenience
pub use sealed_secret::{HpkeAad, HpkeEncParams, SealedSecret};
pub use session::{SessionMode, SessionParticipant, SigningSession, ThresholdConfig};
pub use signable_object::{
    Canonicalization, Constraints, Digest, DisplayHints, KeyBinding, SignableObject, Suite,
};
pub use token::{AuthorizationToken, SignedAuthorizationToken, TokenSignature};
