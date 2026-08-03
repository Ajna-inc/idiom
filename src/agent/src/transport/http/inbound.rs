//! HTTP Inbound Transport
//!
//! Receives DIDComm messages via HTTP server.

use crate::error::Result;
use crate::transport::traits::InboundTransport;
use agent_core::context::AgentContext;
use async_trait::async_trait;
use std::sync::Arc;

/// HTTP inbound transport for receiving DIDComm messages
///
/// Implements the InboundTransport trait for HTTP/HTTPS endpoints.
/// This is a lightweight wrapper around the existing didcomm_transports implementation.
pub struct HttpInboundTransport {
    /// Host to listen on (e.g., "0.0.0.0")
    host: String,
    /// Port to listen on (e.g., 3002)
    port: u16,
}

impl HttpInboundTransport {
    /// Create a new HTTP inbound transport
    ///
    /// # Arguments
    /// * `host` - Host to bind to (e.g., "0.0.0.0" for all interfaces)
    /// * `port` - Port to listen on (e.g., 3002)
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Get the port this transport is listening on
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the host this transport is listening on
    pub fn host(&self) -> &str {
        &self.host
    }
}

#[async_trait]
impl InboundTransport for HttpInboundTransport {
    async fn start(&mut self, _context: Arc<AgentContext>) -> Result<()> {
        // The actual start logic is handled by the didcomm_transports layer
        // which is registered with the TransportManager
        tracing::info!(
            "✓ HTTP inbound transport ready on {}:{}",
            self.host,
            self.port
        );
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        tracing::info!("✓ HTTP inbound transport stopped");
        Ok(())
    }

    fn transport_type(&self) -> &str {
        "http"
    }
}
