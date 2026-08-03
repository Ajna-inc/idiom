//! # DIDComm Signing Protocol 1.0
//!
//! Implementation of the DIDComm Signing Protocol for orchestrating digital signatures
//! across DIDComm agents. Supports single-signer and N-of-M threshold multi-signature modes.
//!
//! ## Features
//!
//! - **Single-signer and multi-party (N-of-M threshold) signing**
//! - **10 message types**: propose, request, consent, partial-signature, combine,
//!   provide-artifacts, issue-token, ack, decline, problem-report
//! - **Sealed secrets via HPKE** (X25519 KEM + HKDF-SHA256 + AES-256-GCM)
//! - **Authorization tokens** with monotonic counter replay protection
//! - **Coordinator role** for session management and signature aggregation
//!
//! ## Protocol Flow
//!
//! ```text
//! Proposer          Coordinator           Signer-1        Signer-2
//!     | propose ------>|                      |               |
//!     |                | request-signing ---->|               |
//!     |                | request-signing ---->|-------------->|
//!     |                |<---- consent --------|               |
//!     |                |<---- consent --------|<--------------|
//!     |                |<-- partial-sig ------|               |
//!     |                |<-- partial-sig ------|<--------------|
//!     |                | combine/artifacts -->|               |
//!     |                | issue-token -------->|               |
//!     |<--- ack -------|<---- ack ------------|<---- ack -----|
//! ```

pub mod coordinator;
pub mod counter;
pub mod errors;
pub mod events;
pub mod handler;
pub mod hpke;
pub mod messages;
pub mod models;
pub mod state;
pub mod storage;
pub mod types;

// Re-exports
pub use coordinator::SigningCoordinator;
pub use counter::MonotonicCounterManager;
pub use errors::{Result, SigningProtocolError};
pub use handler::SigningProtocolHandler;
pub use hpke::HpkeBase;
pub use state::SigningSessionState;
pub use types::*;
