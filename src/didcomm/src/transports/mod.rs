//! # DIDComm Transports
//!
//! Transport layer for sending and receiving DIDComm messages.
//!
//! ## Overview
//!
//! This crate provides transport implementations for DIDComm messaging:
//!
//! - **HTTP Transport**: Send and receive messages over HTTP/HTTPS
//! - **Transport Traits**: Abstractions for implementing custom transports
//!
//! ## Features
//!
//! - `native` (default): Uses reqwest for HTTP client, axum for server
//! - `wasm`: Uses web-sys fetch API for browser/WASM environments
//!
//! ## Example
//!
//! ```rust,no_run
//! use didcomm::transports::{HttpOutboundTransport, OutboundTransport};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let transport = HttpOutboundTransport::new();
//!
//! // Send a packed DIDComm message
//! let packed_message = r#"{"protected":"...","iv":"...","ciphertext":"...","tag":"..."}"#;
//! transport.send("https://example.com/didcomm", packed_message).await?;
//! # Ok(())
//! # }
//! ```

pub mod http;
pub mod traits;

#[cfg(feature = "native")]
pub mod ws;

// Re-exports - HttpInboundTransport is native-only (requires axum server)
#[cfg(feature = "native")]
pub use http::HttpInboundTransport;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use http::HttpOutboundTransport;
pub use traits::{Result, TransportError, TransportMetadata};
// OutboundTransport is only defined for native (Send + Sync) or wasm builds
#[cfg(any(feature = "native", feature = "wasm"))]
pub use traits::OutboundTransport;

// InboundTransport and MessageReceiver are native-only (require full async runtime)
#[cfg(feature = "native")]
pub use traits::{InboundTransport, MessageReceiver};
