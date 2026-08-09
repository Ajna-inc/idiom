// Inbound transport requires axum server (native-only)
#[cfg(feature = "native")]
mod inbound;
// Outbound needs an HTTP client: reqwest (native) or web-sys fetch (wasm)
#[cfg(any(feature = "native", feature = "wasm"))]
mod outbound;

#[cfg(feature = "native")]
pub use inbound::HttpInboundTransport;
#[cfg(any(feature = "native", feature = "wasm"))]
pub use outbound::HttpOutboundTransport;
