//! HTTP Outbound Transport
//!
//! Provides HTTP transport for sending DIDComm messages.
//! - Native: Uses reqwest HTTP client
//! - WASM: Uses web-sys fetch API

use crate::transports::traits::{OutboundTransport, Result, TransportError};
use async_trait::async_trait;

/// HTTP Outbound Transport
///
/// Sends DIDComm messages over HTTP.
/// Uses reqwest on native, web-sys fetch on WASM.
pub struct HttpOutboundTransport {
    /// HTTP client (native only)
    #[cfg(feature = "native")]
    client: reqwest::Client,
}

impl HttpOutboundTransport {
    /// Create a new HTTP outbound transport with default settings.
    ///
    /// Builds a bare `reqwest::Client` — fine for one-off / testing use,
    /// but `Agent` wires up its shared `http_client` via
    /// [`HttpOutboundTransport::with_client`] so all outbound DIDComm
    /// shares one TLS pool with the mediation bootstrap + pickup loops.
    #[cfg(feature = "native")]
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Create a new HTTP outbound transport that reuses a caller-provided
    /// `reqwest::Client`. Used by `Agent` to share one TLS pool across
    /// the connection-request POST (via this transport), the mediation
    /// bootstrap POSTs (via `Agent::setup_mediation`), and pickup polls
    /// (via `Agent::poll_pickup_once`).
    #[cfg(feature = "native")]
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Create a new HTTP outbound transport with default settings (WASM)
    #[cfg(all(feature = "wasm", not(feature = "native")))]
    pub fn new() -> Self {
        Self {}
    }

    /// Create a new HTTP outbound transport with custom timeout
    #[cfg(feature = "native")]
    pub fn with_timeout(timeout_secs: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { client }
    }

    /// Create a new HTTP outbound transport with custom timeout (WASM)
    #[cfg(all(feature = "wasm", not(feature = "native")))]
    pub fn with_timeout(_timeout_secs: u64) -> Self {
        Self {}
    }
}

impl Default for HttpOutboundTransport {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// NATIVE IMPLEMENTATION (reqwest)
// =============================================================================

#[cfg(feature = "native")]
#[async_trait]
impl OutboundTransport for HttpOutboundTransport {
    async fn send(&self, endpoint: &str, message: &str) -> Result<Option<String>> {
        // Validate endpoint
        if !self.supports_endpoint(endpoint) {
            return Err(TransportError::InvalidEndpoint(format!(
                "Endpoint must be HTTP or HTTPS: {}",
                endpoint
            )));
        }

        tracing::debug!("[HTTP Outbound] Sending POST to {}", endpoint);
        tracing::debug!("  Content-Type: application/didcomm-envelope-enc");
        tracing::debug!("  Body length: {} bytes", message.len());

        let response = self
            .client
            .post(endpoint)
            .header("Content-Type", "application/didcomm-envelope-enc")
            .body(message.to_string())
            .send()
            .await
            .map_err(|e| TransportError::SendFailed(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        tracing::debug!("[HTTP Outbound] Response status: {}", status);

        // Check response status
        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::debug!("[HTTP Outbound] Error response: {}", error_body);
            return Err(TransportError::SendFailed(format!(
                "HTTP {} - {}",
                status, error_body
            )));
        }

        // Read response body and return it
        let response_body = response.text().await.unwrap_or_else(|_| String::new());

        if !response_body.is_empty() {
            tracing::debug!(
                "[HTTP Outbound] Response body: {} bytes",
                response_body.len()
            );
            Ok(Some(response_body))
        } else {
            tracing::debug!("[HTTP Outbound] Empty response (202 Accepted)");
            Ok(None)
        }
    }

    fn supports_endpoint(&self, endpoint: &str) -> bool {
        endpoint.starts_with("http://") || endpoint.starts_with("https://")
    }
}

// =============================================================================
// WASM IMPLEMENTATION (web-sys fetch)
// =============================================================================

#[cfg(all(feature = "wasm", not(feature = "native")))]
#[async_trait(?Send)]
impl OutboundTransport for HttpOutboundTransport {
    async fn send(&self, endpoint: &str, message: &str) -> Result<Option<String>> {
        use wasm_bindgen::JsCast;
        use wasm_bindgen_futures::JsFuture;
        use web_sys::{Request, RequestInit, RequestMode, Response};

        // Validate endpoint
        if !self.supports_endpoint(endpoint) {
            return Err(TransportError::InvalidEndpoint(format!(
                "Endpoint must be HTTP or HTTPS: {}",
                endpoint
            )));
        }

        // Create request options
        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        opts.body(Some(&wasm_bindgen::JsValue::from_str(message)));

        // Create request
        let request = Request::new_with_str_and_init(endpoint, &opts).map_err(|e| {
            TransportError::SendFailed(format!("Failed to create request: {:?}", e))
        })?;

        // Set headers
        request
            .headers()
            .set("Content-Type", "application/ssi-agent-wire")
            .map_err(|e| TransportError::SendFailed(format!("Failed to set header: {:?}", e)))?;
        request
            .headers()
            .set("Accept", "application/json")
            .map_err(|e| TransportError::SendFailed(format!("Failed to set header: {:?}", e)))?;

        // Get window or worker global scope
        let global = js_sys::global();
        let promise = if let Some(window) = global.dyn_ref::<web_sys::Window>() {
            window.fetch_with_request(&request)
        } else if let Some(worker) = global.dyn_ref::<web_sys::WorkerGlobalScope>() {
            worker.fetch_with_request(&request)
        } else {
            return Err(TransportError::SendFailed(
                "No window or worker global scope available".to_string(),
            ));
        };

        // Execute fetch
        let response_value = JsFuture::from(promise)
            .await
            .map_err(|e| TransportError::SendFailed(format!("Fetch failed: {:?}", e)))?;

        let response: Response = response_value
            .dyn_into()
            .map_err(|_| TransportError::SendFailed("Invalid response object".to_string()))?;

        let status = response.status();

        // Check response status
        if !response.ok() {
            let error_body = match response.text() {
                Ok(promise) => JsFuture::from(promise)
                    .await
                    .ok()
                    .and_then(|v| v.as_string())
                    .unwrap_or_else(|| "Unknown error".to_string()),
                Err(_) => "Unknown error".to_string(),
            };
            return Err(TransportError::SendFailed(format!(
                "HTTP {} - {}",
                status, error_body
            )));
        }

        // Read response body
        let text_promise = response
            .text()
            .map_err(|e| TransportError::SendFailed(format!("Failed to read response: {:?}", e)))?;

        let text_value = JsFuture::from(text_promise)
            .await
            .map_err(|e| TransportError::SendFailed(format!("Failed to read response: {:?}", e)))?;

        let response_body = text_value.as_string().unwrap_or_default();

        if !response_body.is_empty() {
            Ok(Some(response_body))
        } else {
            Ok(None)
        }
    }

    fn supports_endpoint(&self, endpoint: &str) -> bool {
        endpoint.starts_with("http://") || endpoint.starts_with("https://")
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_outbound_creation() {
        let transport = HttpOutboundTransport::new();
        assert!(transport.supports_endpoint("http://example.com"));
        assert!(transport.supports_endpoint("https://example.com"));
        assert!(!transport.supports_endpoint("ws://example.com"));
        assert!(!transport.supports_endpoint("did:example:123"));
    }

    #[test]
    fn test_supports_endpoint() {
        let transport = HttpOutboundTransport::new();

        // Valid HTTP endpoints
        assert!(transport.supports_endpoint("http://localhost:9002"));
        assert!(transport.supports_endpoint("https://example.com/didcomm"));
        assert!(transport.supports_endpoint("http://192.168.1.1:8080"));

        // Invalid endpoints
        assert!(!transport.supports_endpoint("ws://example.com"));
        assert!(!transport.supports_endpoint("wss://example.com"));
        assert!(!transport.supports_endpoint("ftp://example.com"));
        assert!(!transport.supports_endpoint("example.com"));
        assert!(!transport.supports_endpoint("did:key:z6Mk..."));
    }

    #[cfg(feature = "native")]
    #[tokio::test]
    async fn test_send_to_invalid_endpoint() {
        let transport = HttpOutboundTransport::new();
        let result = transport.send("ws://example.com", "{}").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::InvalidEndpoint(_) => (),
            e => panic!("Expected InvalidEndpoint error, got: {:?}", e),
        }
    }
}
