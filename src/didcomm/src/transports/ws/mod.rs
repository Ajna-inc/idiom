//! WebSocket transport for DIDComm messaging
//!
//! Provides WebSocket connectivity for real-time message delivery via
//! mediators that support RFC 0685 live delivery.

mod outbound;

pub use outbound::{WsConnection, WsReadStream};
pub use tokio_tungstenite::tungstenite::Message as WsMessage;
