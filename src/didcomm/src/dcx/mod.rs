//! # DCX — DIDComm Express
//!
//! Binary transport profile for DIDComm v2 sessions. Runs over a single
//! bidirectional WebSocket between a wallet and its mediator.
//!
//! Consumes session keys from a pluggable [`SessionKeyProvider`] —
//! `ClassicalX25519Provider` is shipped in this crate; `PqBridgeDcxProvider`
//! is shipped in the `pq_bridge` crate.
//!
//! ## Crate layout
//!
//! - [`frame`] — binary frame codec (encode / decode / type constants)
//! - [`crypto`] — ChaCha20-Poly1305 AEAD + HKDF directional keys + counter nonces
//! - [`session`] — [`SessionKeyProvider`] trait and [`SessionKeys`] type
//! - [`channel`] — channel state + manager
//! - [`providers`] — built-in `ClassicalX25519Provider`
//! - [`routing`] — `routing_prefix = SHA-256(kid)[0..16]` helpers
//! - [`padding`] — 64-byte boundary padding helpers
//! - [`errors`] — DCX error types

#![warn(missing_docs)]
#![allow(clippy::result_large_err)]

pub mod agent_integration;
pub mod channel;
pub mod crypto;
pub mod errors;
pub mod frame;
pub mod padding;
pub mod providers;
pub mod routing;
pub mod session;
pub mod transports;

pub use agent_integration::DcxRuntime;

pub use channel::{Channel, ChannelState};
pub use errors::{ChannelError, FrameError, ProviderError};
pub use frame::{Frame, FrameBody, FrameHeader, FrameType, FRAME_VERSION, MAX_FRAME_SIZE};
pub use session::{SessionEvent, SessionKeyProvider, SessionKeys};
