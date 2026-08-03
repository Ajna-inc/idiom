//! HTTP Transport Implementation
//!
//! Supports both inbound (HTTP server) and outbound (HTTP client) communication.

mod inbound;
mod outbound;

pub use inbound::HttpInboundTransport;
pub use outbound::HttpOutboundTransport;
