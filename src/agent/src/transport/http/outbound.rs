//! HTTP Outbound Transport
//!
//! Sends DIDComm messages via HTTP POST requests.

use crate::error::{AgentError, Result};
use crate::transport::traits::{OutboundPackage, OutboundTransport};
use agent_core::context::AgentContext;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

/// HTTP outbound transport for sending DIDComm messages
///
/// Implements the OutboundTransport trait for HTTP/HTTPS endpoints.
/// Uses reqwest for HTTP client functionality.
pub struct HttpOutboundTransport {
    /// HTTP client for sending requests
    client: reqwest::Client,
}

impl HttpOutboundTransport {
    /// Create a new HTTP outbound transport with default settings
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Create a new HTTP outbound transport with custom timeout
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }
}

impl Default for HttpOutboundTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OutboundTransport for HttpOutboundTransport {
    fn supported_schemes(&self) -> &[&str] {
        &["http", "https"]
    }

    async fn send_message(&self, package: OutboundPackage) -> Result<Option<String>> {
        tracing::debug!(
            "→ [HttpOutboundTransport] Sending message to: {}",
            package.endpoint
        );

        // Verify the endpoint scheme is supported
        let url = reqwest::Url::parse(&package.endpoint)
            .map_err(|e| AgentError::Transport(format!("Invalid endpoint URL: {}", e)))?;

        let scheme = url.scheme();
        if !self.supported_schemes().contains(&scheme) {
            return Err(AgentError::Transport(format!(
                "Unsupported scheme '{}' for HTTP transport",
                scheme
            )));
        }

        // Send HTTP POST request
        let response = self
            .client
            .post(&package.endpoint)
            .header("Content-Type", "application/ssi-agent-wire")
            .body(package.payload.clone())
            .send()
            .await
            .map_err(|e| AgentError::Transport(format!("HTTP POST failed: {}", e)))?;

        let status = response.status();

        if !status.is_success() {
            return Err(AgentError::Transport(format!(
                "HTTP POST failed with status: {}",
                status
            )));
        }

        tracing::debug!("✓ Message sent successfully (status: {})", status);

        // For 202 Accepted (fire-and-forget), skip reading the body entirely.
        // This saves 10-50ms per message by not waiting for the response stream.
        // Only read the body for 200 OK (return-routed response expected).
        if status == reqwest::StatusCode::ACCEPTED || status == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }

        // 200 OK: read the response body (return routing)
        let body = response
            .text()
            .await
            .map_err(|e| AgentError::Transport(format!("Failed to read response: {}", e)))?;

        if body.is_empty() {
            Ok(None)
        } else {
            tracing::debug!("✓ Received return-routed response ({} bytes)", body.len());
            Ok(Some(body))
        }
    }

    async fn start(&mut self, _context: Arc<AgentContext>) -> Result<()> {
        tracing::debug!("✓ HTTP outbound transport started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        tracing::debug!("✓ HTTP outbound transport stopped");
        Ok(())
    }

    fn transport_type(&self) -> &str {
        "http"
    }
}
