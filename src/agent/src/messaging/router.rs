//! Message Routing Logic
//!
//! Handles routing incoming messages to appropriate handlers based on message type.
//! Extracted from agent.rs to improve modularity and separation of concerns.

use super::{parse_message_to_didcomm, MessageContextBuilder};
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use crate::transport::{EncryptedMessage, TransportManager};
use didcomm::messaging::HandlerRegistry;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Message Router handles routing incoming messages to appropriate handlers
///
/// This service coordinates between:
/// - Handler registry (to find the right handler for a message type)
/// - Message parsing and context building
/// - Response handling and transport sending
pub struct MessageRouter {
    /// Handler registry for message type → handler mapping
    handler_registry: Arc<RwLock<HandlerRegistry>>,

    /// Transport manager for sending responses
    transport: Arc<TransportManager>,

    /// Agent configuration (for endpoints)
    config: AgentConfig,
}

impl MessageRouter {
    /// Create a new MessageRouter
    pub fn new(
        handler_registry: Arc<RwLock<HandlerRegistry>>,
        transport: Arc<TransportManager>,
        config: AgentConfig,
    ) -> Self {
        Self {
            handler_registry,
            transport,
            config,
        }
    }

    /// Route an inbound message through the handler registry
    ///
    /// This is the main routing method that:
    /// 1. Parses the encrypted message
    /// 2. Looks up the appropriate handler
    /// 3. Calls the handler
    /// 4. Sends any response via transport
    ///
    /// # Arguments
    /// * `encrypted_msg` - The encrypted message to route
    ///
    /// # Returns
    /// * `Ok(())` - Message routed successfully
    /// * `Err(e)` - Routing failed
    pub async fn route_message(&self, encrypted_msg: EncryptedMessage) -> Result<()> {
        tracing::info!("← [MessageRouter] Received encrypted message");
        // Parse the message from the ciphertext (in test mode, it's actually JSON)
        let message_json = &encrypted_msg.ciphertext;
        tracing::debug!("  Raw ciphertext: {}", message_json);

        // Parse to get message type
        let message: serde_json::Value = serde_json::from_str(message_json).map_err(|e| {
            tracing::debug!("  ERROR: Failed to parse message JSON: {}", e);
            AgentError::Transport(format!("Failed to parse message: {}", e))
        })?;
        tracing::debug!("  Parsed message: {:?}", message);

        let message_type = message
            .get("@type")
            .or_else(|| message.get("type"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AgentError::Transport("Message missing @type field".into()))?;

        // Look up handler
        let registry = self.handler_registry.read().await;
        let handler = registry.get_handler(message_type);
        drop(registry);

        let handler = handler.ok_or_else(|| {
            AgentError::Transport(format!(
                "No handler registered for message type: {}",
                message_type
            ))
        })?;

        // Parse message using extracted utility function
        let didcomm_msg = parse_message_to_didcomm(&message)?;

        // Create message context using builder (plaintext/test mode)
        let context = MessageContextBuilder::from_plaintext_message(&didcomm_msg)
            .with_sender_endpoint(encrypted_msg.sender_endpoint.clone())
            .build();

        // Create inbound message
        let inbound = didcomm::messaging::InboundMessage {
            message: didcomm_msg,
            context,
        };

        // Call handler
        let response = handler
            .handle(inbound.clone())
            .await
            .map_err(|e| AgentError::Transport(format!("Handler failed: {}", e)))?;

        // If handler returned a response, send it
        if let Some(outbound) = response {
            self.send_response(outbound, &inbound, &encrypted_msg)
                .await?;
        }

        Ok(())
    }

    /// Send a response message
    ///
    /// Handles packing the response and sending it via transport with proper endpoint resolution.
    async fn send_response(
        &self,
        outbound: didcomm::messaging::OutboundMessage,
        inbound: &didcomm::messaging::InboundMessage,
        _original_msg: &EncryptedMessage,
    ) -> Result<()> {
        tracing::info!("✓ Handler generated response, sending to: {}", outbound.to);
        tracing::debug!(
            "  DEBUG: outbound.message = {:?}",
            serde_json::to_value(&outbound.message).unwrap_or(serde_json::Value::Null)
        );
        tracing::debug!(
            "  DEBUG: outbound.message.body = {:?}",
            outbound.message.body
        );

        // Extract the protocol message from the body
        // The handler stored the full protocol message in the body field
        let protocol_message_json = serde_json::to_string(&outbound.message.body)
            .map_err(|e| AgentError::Transport(format!("Failed to serialize response: {}", e)))?;
        tracing::debug!("  DEBUG: serialized body = {}", protocol_message_json);

        let mut encrypted_response = EncryptedMessage::new(
            "test".to_string(),
            "test".to_string(),
            protocol_message_json,
            "test".to_string(),
        );

        // Attach our endpoint for return routing (so recipient can respond back)
        if let Some(our_endpoint) = self.config.endpoints.first() {
            encrypted_response = encrypted_response.with_sender_endpoint(our_endpoint.clone());
            tracing::debug!("  Attached our sender_endpoint: {}", our_endpoint);
        }

        // Determine the endpoint to send to:
        // 1. Use sender_endpoint from context (for return routing in tests)
        // 2. Fall back to resolving the DID (for production)
        let endpoint = if let Some(sender_endpoint) = &inbound.context.sender_endpoint {
            tracing::debug!(
                "  Using sender_endpoint for return routing: {}",
                sender_endpoint
            );
            sender_endpoint.clone()
        } else {
            tracing::debug!("  No sender_endpoint, using DID: {}", outbound.to);
            // In production, resolve outbound.to DID to endpoint
            // For now, just use the DID as endpoint (will fail in test)
            outbound.to.clone()
        };

        // Send response via transport
        tracing::debug!("  Sending response to endpoint: {}", endpoint);
        self.transport
            .send_message(encrypted_response, &endpoint)
            .await
            .map_err(|e| AgentError::Transport(e.to_string()))?;
        tracing::info!("✓ Response sent successfully");

        Ok(())
    }
}
