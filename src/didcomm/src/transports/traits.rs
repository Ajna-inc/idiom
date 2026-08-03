use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Transport metadata (sender info, etc.)
#[derive(Debug, Clone)]
pub struct TransportMetadata {
    /// Sender endpoint (if available)
    pub sender_endpoint: Option<String>,

    /// Transport type (e.g., "http", "ws")
    pub transport_type: String,

    /// When the message was received
    pub received_at: DateTime<Utc>,
}

/// Errors that can occur in transport operations
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Failed to send message
    #[error("Failed to send message: {0}")]
    SendFailed(String),

    /// Failed to start transport
    #[error("Failed to start transport: {0}")]
    StartFailed(String),

    /// Failed to stop transport
    #[error("Failed to stop transport: {0}")]
    StopFailed(String),

    /// Message processing failed
    #[error("Message processing failed: {0}")]
    ProcessingFailed(String),

    /// Transport not available
    #[error("Transport not available for endpoint: {0}")]
    NotAvailable(String),

    /// Invalid endpoint
    #[error("Invalid endpoint: {0}")]
    InvalidEndpoint(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// HTTP error
    #[error("HTTP error: {0}")]
    Http(String),

    /// WebSocket connection error
    #[error("WebSocket connection error: {0}")]
    Connection(String),

    /// Other error
    #[error("Transport error: {0}")]
    Other(String),
}

/// Result type for transport operations
pub type Result<T> = std::result::Result<T, TransportError>;

// =============================================================================
// NATIVE TRAITS (with Send + Sync bounds)
// =============================================================================

/// Inbound transport - receives messages (native only)
///
/// Implementations listen for incoming messages and forward them to a MessageReceiver.
#[cfg(feature = "native")]
#[async_trait]
pub trait InboundTransport: Send + Sync {
    /// Start the transport listener
    async fn start(&mut self) -> Result<()>;

    /// Stop the transport listener
    async fn stop(&mut self) -> Result<()>;

    /// Get the endpoint URL for this transport
    fn endpoint(&self) -> String;

    /// Check if the transport is running
    fn is_running(&self) -> bool;
}

/// Outbound transport - sends messages (native)
///
/// Implementations send messages to remote endpoints.
#[cfg(feature = "native")]
#[async_trait]
pub trait OutboundTransport: Send + Sync {
    /// Send a packed message to an endpoint
    ///
    /// # Returns
    /// Ok(Some(response)) if a response was received, Ok(None) if no response, Err on failure
    async fn send(&self, endpoint: &str, message: &str) -> Result<Option<String>>;

    /// Check if this transport supports the given endpoint
    fn supports_endpoint(&self, endpoint: &str) -> bool;
}

/// Message receiver - callback for inbound messages (native)
#[cfg(feature = "native")]
#[async_trait]
pub trait MessageReceiver: Send + Sync {
    /// Called when a message is received
    async fn receive_message(
        &self,
        packed_message: String,
        metadata: TransportMetadata,
    ) -> Result<()>;

    /// Process an HTTP message and optionally return a packed response
    async fn receive_message_http(
        &self,
        packed_message: String,
        metadata: TransportMetadata,
    ) -> Result<Option<String>> {
        self.receive_message(packed_message, metadata).await?;
        Ok(None)
    }
}

// =============================================================================
// WASM TRAITS (without Send + Sync bounds - single-threaded)
// =============================================================================

/// Outbound transport - sends messages (WASM)
///
/// WASM is single-threaded, so no Send/Sync bounds required.
#[cfg(all(feature = "wasm", not(feature = "native")))]
#[async_trait(?Send)]
pub trait OutboundTransport {
    /// Send a packed message to an endpoint
    ///
    /// # Returns
    /// Ok(Some(response)) if a response was received, Ok(None) if no response, Err on failure
    async fn send(&self, endpoint: &str, message: &str) -> Result<Option<String>>;

    /// Check if this transport supports the given endpoint
    fn supports_endpoint(&self, endpoint: &str) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_metadata_creation() {
        let metadata = TransportMetadata {
            sender_endpoint: Some("https://example.com".to_string()),
            transport_type: "http".to_string(),
            received_at: Utc::now(),
        };

        assert_eq!(metadata.transport_type, "http");
        assert_eq!(
            metadata.sender_endpoint,
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::SendFailed("connection refused".to_string());
        assert_eq!(
            err.to_string(),
            "Failed to send message: connection refused"
        );

        let err = TransportError::InvalidEndpoint("not a url".to_string());
        assert_eq!(err.to_string(), "Invalid endpoint: not a url");
    }
}
