//! Transport manager for orchestrating multiple transports

use super::{EncryptedMessage, TransportError};
use didcomm::transports::{InboundTransport, OutboundTransport};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Manages multiple inbound and outbound transports
pub struct TransportManager {
    inbound: Arc<RwLock<Vec<Box<dyn InboundTransport>>>>,
    outbound: Arc<RwLock<Vec<Box<dyn OutboundTransport>>>>,
}

impl TransportManager {
    /// Create a new transport manager
    pub fn new() -> Self {
        Self {
            inbound: Arc::new(RwLock::new(Vec::new())),
            outbound: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register an inbound transport
    pub async fn register_inbound(&self, transport: Box<dyn InboundTransport>) {
        let mut inbound = self.inbound.write().await;
        inbound.push(transport);
    }

    /// Register an outbound transport (appended — lowest priority).
    pub async fn register_outbound(&self, transport: Box<dyn OutboundTransport>) {
        let mut outbound = self.outbound.write().await;
        outbound.push(transport);
    }

    /// Register an outbound transport at the **front** of the list.
    /// `send_message` matches the first transport whose
    /// `supports_endpoint` returns true, so a transport registered
    /// here takes priority over earlier-registered ones for any
    /// endpoint it claims to support.
    ///
    /// Used by `WsMediatorOutboundTransport` so it shadows the HTTP
    /// outbound for the wallet's mediator endpoint while the WS is
    /// connected. When the WS drops, `supports_endpoint` returns false
    /// and the next transport (HTTP) takes over transparently.
    pub async fn register_outbound_first(&self, transport: Box<dyn OutboundTransport>) {
        let mut outbound = self.outbound.write().await;
        outbound.insert(0, transport);
    }

    /// Start all inbound transports
    pub async fn start_all(&self) -> super::Result<()> {
        let mut inbound = self.inbound.write().await;
        for transport in inbound.iter_mut() {
            transport
                .start()
                .await
                .map_err(|e| TransportError::Other(e.to_string()))?;
        }
        Ok(())
    }

    /// Stop all inbound transports
    pub async fn stop_all(&self) -> super::Result<()> {
        let mut inbound = self.inbound.write().await;
        for transport in inbound.iter_mut() {
            transport
                .stop()
                .await
                .map_err(|e| TransportError::Other(e.to_string()))?;
        }
        Ok(())
    }

    /// Send a message to an endpoint using the appropriate outbound transport
    pub async fn send_message(
        &self,
        message: EncryptedMessage,
        endpoint: &str,
    ) -> super::Result<Option<String>> {
        let outbound = self.outbound.read().await;

        tracing::debug!(
            "🔍 [TransportManager] Looking for transport for endpoint: {}",
            endpoint
        );
        tracing::debug!("  Available transports: {}", outbound.len());

        // Detect if ciphertext is already a JWE string (starts with '{' and contains JWE fields)
        // For HTTP endpoints: send JWE directly
        // For channel endpoints: serialize the whole EncryptedMessage to preserve sender_endpoint
        let message_str = if endpoint.starts_with("channel://") {
            // Always serialize full EncryptedMessage for channel transport to preserve sender_endpoint
            tracing::debug!("  Channel transport, serializing full EncryptedMessage");
            message
                .to_json()
                .map_err(|e| TransportError::Send(format!("Failed to serialize message: {}", e)))?
        } else if message.ciphertext.starts_with('{') {
            // For HTTP endpoints, check if it's a JWE and send directly
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&message.ciphertext) {
                if parsed.get("protected").is_some() && parsed.get("ciphertext").is_some() {
                    tracing::debug!("  Detected JWE in ciphertext, sending JWE directly");
                    message.ciphertext.clone()
                } else {
                    // Not a JWE, serialize normally
                    message.to_json().map_err(|e| {
                        TransportError::Send(format!("Failed to serialize message: {}", e))
                    })?
                }
            } else {
                // Not valid JSON, serialize normally
                message.to_json().map_err(|e| {
                    TransportError::Send(format!("Failed to serialize message: {}", e))
                })?
            }
        } else {
            // Not JSON, serialize normally
            message
                .to_json()
                .map_err(|e| TransportError::Send(format!("Failed to serialize message: {}", e)))?
        };

        // Find a transport that can handle this endpoint
        for (idx, transport) in outbound.iter().enumerate() {
            let supports = transport.supports_endpoint(endpoint);
            tracing::debug!(
                "  Transport[{}]: supports_endpoint('{}') = {}",
                idx,
                endpoint,
                supports
            );
            if supports {
                tracing::debug!("✓ Found transport for endpoint: {}", endpoint);
                return transport
                    .send(endpoint, &message_str)
                    .await
                    .map_err(|e| TransportError::Send(e.to_string()));
            }
        }

        tracing::debug!("❌ No transport found for endpoint: {}", endpoint);
        Err(TransportError::NotFound(format!(
            "No transport available for endpoint: {}",
            endpoint
        )))
    }

    /// Get all inbound endpoints
    pub async fn inbound_endpoints(&self) -> Vec<String> {
        let inbound = self.inbound.read().await;
        inbound.iter().map(|t| t.endpoint()).collect()
    }

    /// Get count of registered transports
    pub async fn transport_counts(&self) -> (usize, usize) {
        let inbound = self.inbound.read().await;
        let outbound = self.outbound.read().await;
        (inbound.len(), outbound.len())
    }

    /// Send a packed message string to an endpoint
    ///
    /// This is a convenience method for sending already-packed JWE strings
    /// without needing to construct an EncryptedMessage.
    ///
    /// # Arguments
    /// * `endpoint` - The target endpoint URL
    /// * `packed_message` - The already-packed JWE string
    ///
    /// # Returns
    /// Ok(()) on success, Err on failure
    pub async fn send_to_endpoint(
        &self,
        endpoint: &str,
        packed_message: &str,
    ) -> super::Result<Option<String>> {
        let outbound = self.outbound.read().await;

        // Find a transport that can handle this endpoint
        for transport in outbound.iter() {
            if transport.supports_endpoint(endpoint) {
                return transport
                    .send(endpoint, packed_message)
                    .await
                    .map_err(|e| TransportError::Send(e.to_string()));
            }
        }

        tracing::error!(
            endpoint = endpoint,
            registered_count = outbound.len(),
            "No transport available — MeshOutboundTransport may not have been registered"
        );
        Err(TransportError::NotFound(format!(
            "No transport available for endpoint: {} (registered: {})",
            endpoint,
            outbound.len()
        )))
    }
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TransportManager {
    fn clone(&self) -> Self {
        Self {
            inbound: Arc::clone(&self.inbound),
            outbound: Arc::clone(&self.outbound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_manager_creation() {
        let manager = TransportManager::new();
        let (inbound_count, outbound_count) = manager.transport_counts().await;
        assert_eq!(inbound_count, 0);
        assert_eq!(outbound_count, 0);
    }

    #[tokio::test]
    async fn test_transport_manager_endpoints() {
        let manager = TransportManager::new();
        let endpoints = manager.inbound_endpoints().await;
        assert_eq!(endpoints.len(), 0);
    }
}
