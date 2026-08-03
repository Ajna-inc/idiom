//! DCX binary frame codec.
//!
//! Wire format:
//!
//! ```text
//! 0     1     2          18         34       42         54
//! +-----+-----+----------+----------+--------+----------+--------------+
//! |type |ver  |channel_id|routing_  | msg_id | nonce    | ciphertext   |
//! |(1B) |(1B) |  (16B)   |prefix    |  (8B)  | (12B)    | + tag        |
//! |     |     |          | (16B)    |        |          |              |
//! +-----+-----+----------+----------+--------+----------+--------------+
//!  \____________ 38-byte header (AAD) ______________/
//! ```

pub mod decode;
pub mod encode;
pub mod types;

pub use decode::{decode_and_verify, decode_full, decode_header};
pub use encode::{encode_body, pack};
pub use types::*;

use crate::dcx::errors::FrameError;

/// Convenience wrapper bundling a header + body.
///
/// Most call sites work with [`pack`] / [`decode_full`] directly.
/// [`Frame`] is provided for callers that want to hold the header +
/// body together (e.g., test helpers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Frame header (38 bytes on the wire).
    pub header: FrameHeader,
    /// Decoded body.
    pub body: FrameBody,
}

impl Frame {
    /// Encode this frame into bytes ready for the WS.
    pub fn encode(&self, k_send: &[u8; 32]) -> Result<Vec<u8>, FrameError> {
        pack(&self.header, &self.body, k_send)
    }

    /// Decode a frame from bytes (verifies AEAD).
    pub fn decode(bytes: &[u8], k_recv: &[u8; 32]) -> Result<Self, FrameError> {
        let (header, body) = decode_full(bytes, k_recv)?;
        Ok(Self { header, body })
    }
}

/// Parsed frame header (everything before the nonce).
///
/// The header is plaintext on the wire and serves as AEAD AAD for the
/// payload ciphertext. The mediator parses it to find `routing_prefix`;
/// the recipient parses it to find `channel_id` and `msg_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Frame type (`FRAME_TYPE_*`).
    pub frame_type: u8,
    /// Protocol version (MUST be `FRAME_VERSION`).
    pub version: u8,
    /// 16-byte channel identifier.
    pub channel_id: [u8; 16],
    /// 16-byte routing prefix = `SHA-256(recipient_kid)[0..16]`.
    pub routing_prefix: [u8; 16],
    /// Strictly-monotonic per-direction counter.
    pub msg_id: u64,
}

impl FrameHeader {
    /// Encode the header as the 38-byte AAD blob.
    pub fn encode_aad(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = self.frame_type;
        buf[1] = self.version;
        buf[2..18].copy_from_slice(&self.channel_id);
        buf[18..34].copy_from_slice(&self.routing_prefix);
        buf[34..42].copy_from_slice(&self.msg_id.to_be_bytes());
        buf
    }
}

/// Parsed plaintext body of a frame (after AEAD decryption).
///
/// One variant per frame type; the variant a sender chose corresponds
/// to `header.frame_type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameBody {
    /// Application message (the most common case).
    Data {
        /// The DIDComm message (or arbitrary application payload).
        application_payload: Vec<u8>,
        /// Padding bytes (already inside ciphertext; receiver strips them).
        padding: Vec<u8>,
    },
    /// Forward a JWE through the mediator to a non-DCX peer.
    DataForward {
        /// Inner JWE bytes.
        inner_jwe: Vec<u8>,
        /// Endpoint to forward to.
        next_endpoint: String,
        /// Padding bytes.
        padding: Vec<u8>,
    },
    /// Acknowledgement of a received DATA frame.
    Ack {
        /// `msg_id` being acked.
        acked_msg_id: u64,
        /// Application status (0 = OK, 1 = PROCESSED).
        status: u8,
    },
    /// Liveness probe.
    Ping {
        /// 8-byte nonce echoed in the matching PONG.
        nonce_data: [u8; 8],
    },
    /// Reply to PING.
    Pong {
        /// Echoed nonce.
        nonce_data: [u8; 8],
    },
    /// Provider rotation notification — provider already rotated, this
    /// just propagates the new `channel_id`.
    RotateNotify {
        /// Generation we rotated away from.
        old_generation: u32,
        /// Generation we rotated to.
        new_generation: u32,
        /// New `channel_id` derived under the new generation.
        new_channel_id: [u8; 16],
    },
    /// Tear down the channel.
    ChannelClose {
        /// Reason code (`CLOSE_REASON_*`).
        reason_code: u16,
        /// Optional human-readable message.
        message: String,
    },
    /// Update receiver's flow window.
    FlowWindow {
        /// New window credit in bytes.
        window_credit: u32,
    },
    /// Report a protocol error.
    Error {
        /// Error code (`ERR_CODE_*`).
        error_code: u16,
        /// Human-readable message.
        message: String,
    },
    /// Channel-confirm exchange for downgrade defense.
    ChannelConfirm {
        /// `SHA-256(observed_peer_accept_list || provider_id)`.
        confirm_hash: [u8; 32],
    },
}
