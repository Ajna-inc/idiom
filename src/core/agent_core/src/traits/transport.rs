//! Transport provider trait
//!
//! This module provides platform-aware async traits:
//! - Native: Uses `Send + Sync` bounds for multi-threaded environments
//! - WASM: No thread safety bounds (single-threaded)

use crate::Result;
use async_trait::async_trait;

/// Transport session for bidirectional communication
#[async_trait]
pub trait TransportSession: Send + Sync {
    /// Send a message through this session
    async fn send(&self, message: &[u8]) -> Result<()>;

    /// Close the session
    async fn close(&self) -> Result<()>;

    /// Check if the session is still active
    fn is_active(&self) -> bool;

    /// Get the session ID
    fn id(&self) -> &str;
}

/// Transport provider trait for sending and receiving messages.
///
/// Implementations provide different transport mechanisms (HTTP, WebSocket, etc.)
#[async_trait]
pub trait TransportProvider: Send + Sync {
    /// Send a message to an endpoint
    async fn send(&self, endpoint: &str, message: &[u8]) -> Result<Vec<u8>>;

    /// Send a message without expecting a response
    async fn send_one_way(&self, endpoint: &str, message: &[u8]) -> Result<()>;

    /// Start listening for inbound messages
    async fn start_listener(&self, host: &str, port: u16) -> Result<()>;

    /// Stop the listener
    async fn stop_listener(&self) -> Result<()>;

    /// Check if the listener is running
    fn is_listening(&self) -> bool;
}
