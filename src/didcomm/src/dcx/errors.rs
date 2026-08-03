//! DCX error types.
//!
//! Three layers: [`FrameError`] for codec-level problems, [`ChannelError`]
//! for state-machine problems, [`ProviderError`] for SessionKeyProvider
//! handshake/rotation problems.

use thiserror::Error;

/// Errors from the binary frame codec.
#[derive(Debug, Error)]
pub enum FrameError {
    /// Frame too short to contain a valid header.
    #[error("frame too short: got {got} bytes, need at least {need}")]
    TooShort {
        /// How many bytes we got.
        got: usize,
        /// How many bytes we needed.
        need: usize,
    },

    /// Frame larger than the 1 MiB cap.
    #[error("frame too large: {got} bytes exceeds MAX_FRAME_SIZE")]
    TooLarge {
        /// How many bytes we got.
        got: usize,
    },

    /// Frame type byte not one of the 11 defined types (0x01..=0x0B).
    #[error("unknown frame type: {0:#x}")]
    UnknownType(u8),

    /// Version byte not the supported value.
    #[error("unsupported version: {0:#x}")]
    UnsupportedVersion(u8),

    /// The nonce on the wire doesn't match the deterministic
    /// `0x00000000 || msg_id_be(8)` derivation.
    #[error("nonce mismatch: wire nonce does not match deterministic derivation")]
    NonceMismatch,

    /// Inner payload length fields don't agree (e.g.,
    /// `application_payload_length + padding_length` overflows the
    /// plaintext).
    #[error("malformed payload: {0}")]
    MalformedPayload(String),

    /// AEAD verification failed (invalid tag or tampering).
    #[error("AEAD verification failed")]
    AeadFailed,
}

/// Errors from channel state operations.
#[derive(Debug, Error)]
pub enum ChannelError {
    /// `channel_id` not in the receiver's lookup tables.
    #[error("unknown channel: {0:?}")]
    UnknownChannel([u8; 16]),

    /// Frame `msg_id` is not strictly greater than the last seen one.
    #[error("replay detected: got msg_id {got}, expected > {last}")]
    Replay {
        /// The `msg_id` we received.
        got: u64,
        /// The last `msg_id` we observed.
        last: u64,
    },

    /// Receiver's flow window exceeded by the sender.
    #[error("flow violation: sender exceeded {window} byte window")]
    FlowViolation {
        /// The window size in bytes.
        window: u32,
    },

    /// channel-confirm hash didn't match → transport downgrade detected.
    #[error("downgrade detected: channel-confirm hash mismatch")]
    DowngradeDetected,

    /// Generic state-machine error.
    #[error("invalid state transition: {0}")]
    InvalidTransition(String),
}

/// Errors from SessionKeyProvider operations.
#[derive(Debug, Error)]
pub enum ProviderError {
    /// No active session with this peer.
    #[error("no session with peer {0}")]
    NoSession(String),

    /// Handshake didn't complete within the configured timeout.
    #[error("handshake timeout")]
    HandshakeTimeout,

    /// Peer rejected the handshake (e.g., suite mismatch).
    #[error("handshake rejected: {0}")]
    HandshakeRejected(String),

    /// X25519 shared secret was all zeros (low-order point attack).
    #[error("low-order X25519 point: shared secret is zero")]
    LowOrderX25519,

    /// Provider internal error (e.g., wallet I/O, storage I/O).
    #[error("provider internal: {0}")]
    Internal(String),

    /// Provider not yet implemented (used by pq_bridge during the port).
    #[error("provider feature not yet implemented: {0}")]
    NotImplemented(String),
}
