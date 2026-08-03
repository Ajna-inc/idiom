//! Transport layer traits
//!
//! Defines the core interfaces for pluggable DIDComm transports,

use crate::error::Result;
use agent_core::context::AgentContext;
use async_trait::async_trait;
use std::sync::Arc;

/// Represents a DIDComm message packaged for transport
#[derive(Debug, Clone)]
pub struct OutboundPackage {
    /// The encrypted/packed message payload
    pub payload: String,
    /// The endpoint to send the message to
    pub endpoint: String,
    /// Optional connection ID for session management
    pub connection_id: Option<String>,
    /// Optional sender endpoint for return routing
    pub sender_endpoint: Option<String>,
}

/// Represents metadata about how a message was received
#[derive(Debug, Clone)]
pub struct InboundMetadata {
    /// Optional sender endpoint for return routing
    pub sender_endpoint: Option<String>,
    /// Optional session ID for bidirectional communication
    pub session_id: Option<String>,
}

/// Response from processing an inbound message
#[derive(Debug, Clone)]
pub enum InboundResponse {
    /// No response needed (e.g., one-way message)
    None,
    /// Response should be sent via the same transport session
    /// Contains the packed response message
    Response(String),
    /// Response should be sent asynchronously (e.g., return_route=none)
    Async(OutboundPackage),
}

/// Inbound transport interface
///
/// Implements receiving DIDComm messages from external agents.
/// Examples: HTTP server, WebSocket server, Bluetooth listener
#[async_trait]
pub trait InboundTransport: Send + Sync {
    /// Start the inbound transport
    ///
    /// This should initialize any listeners (e.g., HTTP server, WebSocket server)
    /// and begin accepting incoming messages.
    ///
    /// # Arguments
    /// * `context` - Agent context for dependency access
    async fn start(&mut self, context: Arc<AgentContext>) -> Result<()>;

    /// Stop the inbound transport
    ///
    /// This should gracefully shutdown listeners and clean up resources.
    async fn stop(&mut self) -> Result<()>;

    /// Get the transport type identifier
    fn transport_type(&self) -> &str;
}

/// Outbound transport interface
///
/// Implements sending DIDComm messages to external agents.
/// Examples: HTTP client, WebSocket client, Bluetooth sender
#[async_trait]
pub trait OutboundTransport: Send + Sync {
    /// Get the URL schemes this transport supports
    ///
    /// Examples:
    /// - HTTP: ["http", "https"]
    /// - WebSocket: ["ws", "wss"]
    /// - Custom: ["coap", "coaps"]
    fn supported_schemes(&self) -> &[&str];

    /// Send a message to an endpoint
    ///
    /// # Arguments
    /// * `package` - The outbound message package with destination
    ///
    /// # Returns
    /// * `Ok(Some(response))` - Synchronous response received (e.g., HTTP return routing)
    /// * `Ok(None)` - Message sent, no response expected
    /// * `Err(e)` - Failed to send
    async fn send_message(&self, package: OutboundPackage) -> Result<Option<String>>;

    /// Start the outbound transport
    ///
    /// Initialize any connection pools or resources needed for sending.
    async fn start(&mut self, context: Arc<AgentContext>) -> Result<()>;

    /// Stop the outbound transport
    ///
    /// Clean up connection pools and resources.
    async fn stop(&mut self) -> Result<()>;

    /// Get the transport type identifier
    fn transport_type(&self) -> &str;
}

/// Transport session for bidirectional communication
///
/// Represents an active communication channel that can be reused
/// for sending responses without establishing a new connection.
#[async_trait]
pub trait TransportSession: Send + Sync {
    /// Get unique session ID
    fn id(&self) -> &str;

    /// Get transport type (e.g., "http", "ws")
    fn session_type(&self) -> &str;

    /// Get associated connection ID (if any)
    fn connection_id(&self) -> Option<&str>;

    /// Send a message via this session
    ///
    /// Used for return routing - sending a response on the same
    /// connection that received the original message.
    async fn send(&self, message: String) -> Result<()>;

    /// Close the session
    async fn close(&self) -> Result<()>;
}
