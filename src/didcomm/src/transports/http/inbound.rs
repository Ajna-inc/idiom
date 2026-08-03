use crate::transports::traits::{
    InboundTransport, MessageReceiver, Result, TransportError, TransportMetadata,
};
use async_trait::async_trait;
use axum::{
    body::Body, extract::State, http::StatusCode, response::Response, routing::post, Router,
};
use chrono::Utc;
use std::sync::Arc;
use tokio::task::JoinHandle;

/// HTTP Inbound Transport
///
/// Listens for incoming DIDComm messages over HTTP using Axum.
/// Can either create its own server or merge with an existing Axum Router.
pub struct HttpInboundTransport {
    /// The host to bind to (e.g., "0.0.0.0")
    host: String,

    /// The port to listen on
    port: u16,

    /// The message receiver to forward messages to
    receiver: Arc<dyn MessageReceiver>,

    /// Optional existing Axum Router to merge with
    app: Option<Router>,

    /// Path for DIDComm endpoint (default: "/")
    path: String,

    /// Server handle (set when started)
    server_handle: Option<JoinHandle<()>>,

    /// Whether the transport is running
    running: bool,
}

impl HttpInboundTransport {
    /// Create a new HTTP inbound transport
    ///
    /// # Arguments
    /// * `host` - The host to bind to (e.g., "0.0.0.0" or "127.0.0.1")
    /// * `port` - The port to listen on
    /// * `receiver` - The message receiver to forward messages to
    pub fn new(host: impl Into<String>, port: u16, receiver: Arc<dyn MessageReceiver>) -> Self {
        Self {
            host: host.into(),
            port,
            receiver,
            app: None,
            path: "/".to_string(),
            server_handle: None,
            running: false,
        }
    }

    /// Set an existing Axum Router to merge with
    ///
    /// The DIDComm endpoint will be added to this router.
    /// If not set, a new router will be created.
    pub fn with_app(mut self, app: Router) -> Self {
        self.app = Some(app);
        self
    }

    /// Set the path for the DIDComm endpoint
    ///
    /// Default is "/" if not specified.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }
}

#[async_trait]
impl InboundTransport for HttpInboundTransport {
    async fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(TransportError::StartFailed(
                "Transport is already running".to_string(),
            ));
        }

        // Merge with existing app if provided, otherwise use standalone
        let app = if let Some(existing_app) = self.app.take() {
            // Add DIDComm handler as a fallback so it doesn't shadow
            // specific POST routes (e.g., /webrtc/offer) from the app.
            // The fallback only handles requests that don't match any
            // registered route in the existing app.
            let didcomm_handler = post(handle_didcomm_message).with_state(self.receiver.clone());
            existing_app.fallback_service(didcomm_handler)
        } else {
            // Use standalone DIDComm route
            Router::new()
                .route(&self.path, post(handle_didcomm_message))
                .with_state(self.receiver.clone())
        };

        let addr = format!("{}:{}", self.host, self.port);
        let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
            TransportError::StartFailed(format!("Failed to bind to {}: {}", addr, e))
        })?;

        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(target: "didcomm.transport", error = %e, "HTTP inbound transport server error");
            }
        });

        self.server_handle = Some(handle);
        self.running = true;

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }

        self.running = false;
        Ok(())
    }

    fn endpoint(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    fn is_running(&self) -> bool {
        self.running
    }
}

/// HTTP handler for DIDComm messages
///
/// This handler processes incoming DIDComm messages and returns responses synchronously.
/// If the message handler generates a response (e.g., auto-accept DID Exchange), it will
/// be returned in the HTTP response body. Otherwise, returns 202 ACCEPTED.
async fn handle_didcomm_message(
    State(receiver): State<Arc<dyn MessageReceiver>>,
    body: String,
) -> Response<Body> {
    let metadata = TransportMetadata {
        sender_endpoint: None, // Could extract from headers if available
        transport_type: "http".to_string(),
        received_at: Utc::now(),
    };

    // Use receive_message_http which can return optional response
    match receiver.receive_message_http(body, metadata).await {
        Ok(Some(packed_response)) => {
            // Handler generated a response - return it in HTTP body with 200 OK
            tracing::debug!(target: "didcomm.transport", bytes = packed_response.len(), "returning response in HTTP body");
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Body::from(packed_response))
                .unwrap()
        }
        Ok(None) => {
            // No response needed - return 202 ACCEPTED
            tracing::debug!(target: "didcomm.transport", "no response from handler, returning 202 ACCEPTED");
            Response::builder()
                .status(StatusCode::ACCEPTED)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            // Processing failed - return 400 BAD REQUEST
            tracing::warn!(target: "didcomm.transport", error = %e, "error processing inbound message");
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("Error processing message: {}", e)))
                .unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::traits::TransportMetadata;

    struct MockReceiver;

    #[async_trait]
    impl MessageReceiver for MockReceiver {
        async fn receive_message(
            &self,
            _packed_message: String,
            _metadata: TransportMetadata,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_http_inbound_creation() {
        let receiver = Arc::new(MockReceiver);
        let transport = HttpInboundTransport::new("127.0.0.1", 9002, receiver);

        assert_eq!(transport.endpoint(), "http://127.0.0.1:9002");
        assert!(!transport.is_running());
    }

    #[tokio::test]
    async fn test_http_inbound_start_stop() {
        let receiver = Arc::new(MockReceiver);
        let mut transport = HttpInboundTransport::new("127.0.0.1", 0, receiver); // Port 0 = random port

        // Start
        transport.start().await.unwrap();
        assert!(transport.is_running());

        // Stop
        transport.stop().await.unwrap();
        assert!(!transport.is_running());
    }

    #[tokio::test]
    async fn test_http_inbound_double_start_fails() {
        let receiver = Arc::new(MockReceiver);
        let mut transport = HttpInboundTransport::new("127.0.0.1", 0, receiver);

        transport.start().await.unwrap();
        let result = transport.start().await;
        assert!(result.is_err());

        transport.stop().await.unwrap();
    }
}
