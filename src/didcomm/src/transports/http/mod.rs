// Inbound transport requires axum server (native-only)
#[cfg(feature = "native")]
mod inbound;
mod outbound;

#[cfg(feature = "native")]
pub use inbound::HttpInboundTransport;
pub use outbound::HttpOutboundTransport;
