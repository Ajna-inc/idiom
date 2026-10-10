// Inbound transport requires axum server (native-only)
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod inbound;
// Outbound needs an HTTP client: reqwest (native) or web-sys fetch (wasm)
#[cfg(any(all(feature = "native", not(target_arch = "wasm32")), feature = "wasm"))]
mod outbound;

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use inbound::HttpInboundTransport;
#[cfg(any(all(feature = "native", not(target_arch = "wasm32")), feature = "wasm"))]
pub use outbound::HttpOutboundTransport;
