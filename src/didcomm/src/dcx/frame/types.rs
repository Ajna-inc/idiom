//! DCX frame type constants and on-wire layout values.

/// 42-byte plaintext header (type, version, channel_id, routing_prefix, msg_id).
///
/// Layout: `type(1) || version(1) || channel_id(16) || routing_prefix(16) || msg_id(8)`.
/// Used as AEAD AAD for every frame.
pub const HEADER_LEN: usize = 42;

/// 12-byte AEAD nonce, derived from `msg_id`.
pub const NONCE_LEN: usize = 12;

/// 16-byte AEAD authentication tag (Poly1305).
pub const TAG_LEN: usize = 16;

/// Maximum frame size on the wire (1 MiB).
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Wire version supported by this crate.
pub const FRAME_VERSION: u8 = 0x01;

/// Application message.
pub const FRAME_TYPE_DATA: u8 = 0x01;
/// Wrap a JWE for the mediator to forward to a non-DCX peer.
pub const FRAME_TYPE_DATA_FORWARD: u8 = 0x02;
/// Acknowledgement.
pub const FRAME_TYPE_ACK: u8 = 0x03;
/// Liveness probe.
pub const FRAME_TYPE_PING: u8 = 0x04;
/// Liveness response.
pub const FRAME_TYPE_PONG: u8 = 0x05;
/// Provider rotation notification.
pub const FRAME_TYPE_ROTATE_NOTIFY: u8 = 0x06;
/// Channel teardown.
pub const FRAME_TYPE_CHANNEL_CLOSE: u8 = 0x07;
/// Flow-control window update.
pub const FRAME_TYPE_FLOW_WINDOW: u8 = 0x08;
/// Protocol error report.
pub const FRAME_TYPE_ERROR: u8 = 0x09;
/// Channel-confirm for downgrade defense.
pub const FRAME_TYPE_CHANNEL_CONFIRM: u8 = 0x0A;

/// Strongly-typed enum view over the frame type codes.
///
/// `from_u8` is the canonical entry point — it returns `None` for any
/// unknown code, so callers cannot accidentally hand an unrecognized
/// type to downstream code paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Application message.
    Data = FRAME_TYPE_DATA,
    /// Wrap a JWE for the mediator to forward.
    DataForward = FRAME_TYPE_DATA_FORWARD,
    /// Acknowledgement.
    Ack = FRAME_TYPE_ACK,
    /// Liveness probe.
    Ping = FRAME_TYPE_PING,
    /// Liveness response.
    Pong = FRAME_TYPE_PONG,
    /// Provider rotation notification.
    RotateNotify = FRAME_TYPE_ROTATE_NOTIFY,
    /// Channel teardown.
    ChannelClose = FRAME_TYPE_CHANNEL_CLOSE,
    /// Flow window update.
    FlowWindow = FRAME_TYPE_FLOW_WINDOW,
    /// Protocol error report.
    Error = FRAME_TYPE_ERROR,
    /// Channel-confirm for downgrade defense.
    ChannelConfirm = FRAME_TYPE_CHANNEL_CONFIRM,
}

impl FrameType {
    /// Parse a wire byte into a [`FrameType`]. Returns `None` for
    /// unrecognized codes.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            FRAME_TYPE_DATA => Some(Self::Data),
            FRAME_TYPE_DATA_FORWARD => Some(Self::DataForward),
            FRAME_TYPE_ACK => Some(Self::Ack),
            FRAME_TYPE_PING => Some(Self::Ping),
            FRAME_TYPE_PONG => Some(Self::Pong),
            FRAME_TYPE_ROTATE_NOTIFY => Some(Self::RotateNotify),
            FRAME_TYPE_CHANNEL_CLOSE => Some(Self::ChannelClose),
            FRAME_TYPE_FLOW_WINDOW => Some(Self::FlowWindow),
            FRAME_TYPE_ERROR => Some(Self::Error),
            FRAME_TYPE_CHANNEL_CONFIRM => Some(Self::ChannelConfirm),
            _ => None,
        }
    }
}

// CHANNEL_CLOSE reason codes.
/// User explicitly tore down the channel.
pub const CLOSE_REASON_USER_REQUESTED: u16 = 0x0001;
/// Channel idle past TTL.
pub const CLOSE_REASON_IDLE_TIMEOUT: u16 = 0x0002;
/// Generic protocol error.
pub const CLOSE_REASON_PROTOCOL_ERROR: u16 = 0x0003;
/// Downgrade attack detected.
pub const CLOSE_REASON_DOWNGRADE_DETECTED: u16 = 0x0004;
/// Wallet restored from backup; channels invalidated.
pub const CLOSE_REASON_BACKUP_RESTORE: u16 = 0x0005;

// ERROR frame codes.
/// AEAD decryption failed.
pub const ERR_CODE_DECRYPT_FAILED: u16 = 0x0001;
/// `msg_id` was not greater than last seen.
pub const ERR_CODE_REPLAY_DETECTED: u16 = 0x0002;
/// `channel_id` not in receiver's table.
pub const ERR_CODE_UNKNOWN_CHANNEL: u16 = 0x0003;
/// Mediator: routing prefix not registered.
pub const ERR_CODE_UNKNOWN_ROUTING_PREFIX: u16 = 0x0004;
/// Version byte not supported.
pub const ERR_CODE_VERSION_UNSUPPORTED: u16 = 0x0005;
/// Header could not be parsed.
pub const ERR_CODE_FRAME_MALFORMED: u16 = 0x0006;
/// Frame larger than 1 MiB.
pub const ERR_CODE_FRAME_TOO_LARGE: u16 = 0x0007;
/// Unrecognized frame type.
pub const ERR_CODE_FRAME_TYPE_UNKNOWN: u16 = 0x0008;
/// Sender exceeded the receiver's flow window.
pub const ERR_CODE_FLOW_VIOLATION: u16 = 0x0009;
/// Channel-confirm hash mismatch.
pub const ERR_CODE_DOWNGRADE_DETECTED: u16 = 0x000B;
