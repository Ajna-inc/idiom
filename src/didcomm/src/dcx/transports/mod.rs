//! WebSocket transport integration.
//!
//! - [`outbound::DcxOutboundTransport`] packs application messages
//!   into [`crate::dcx::Frame`] DATA frames and writes them as WS binary
//!   frames via a `mpsc::UnboundedSender<Vec<u8>>` shared with the
//!   pickup loop.
//! - [`inbound::DcxInboundExtension`] is a callback the pickup loop
//!   hands every binary WS frame to before falling through to the
//!   legacy text-frame path. If the binary parses as a DCX frame and
//!   the channel is known, it dispatches; otherwise returns false and
//!   the caller handles the frame normally.

pub mod inbound;
pub mod outbound;

pub use inbound::{DcxInboundExtension, InboundOutcome};
pub use outbound::DcxOutboundTransport;
