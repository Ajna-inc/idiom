//! In-memory channel-based transport for testing
//!
//! This transport implementation uses tokio mpsc channels to route messages
//! between agents in the same process

use async_trait::async_trait;
use chrono::Utc;
use didcomm::transports::{
    InboundTransport, MessageReceiver, OutboundTransport, Result, TransportError, TransportMetadata,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Inbound transport that receives messages via a channel
pub struct ChannelInboundTransport {
    endpoint: String,
    receiver: Arc<RwLock<Option<mpsc::Receiver<String>>>>,
    running: Arc<RwLock<bool>>,
    message_receiver: Arc<dyn MessageReceiver>,
}

impl ChannelInboundTransport {
    /// Create a new channel inbound transport
    pub fn new(
        endpoint: impl Into<String>,
        receiver: mpsc::Receiver<String>,
        message_receiver: Arc<dyn MessageReceiver>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            receiver: Arc::new(RwLock::new(Some(receiver))),
            running: Arc::new(RwLock::new(false)),
            message_receiver,
        }
    }

    /// Process incoming messages
    async fn process_messages(&self) {
        let mut receiver_guard = self.receiver.write().await;
        if let Some(mut receiver) = receiver_guard.take() {
            drop(receiver_guard); // Release lock before processing

            while *self.running.read().await {
                tokio::select! {
                    msg = receiver.recv() => {
                        if let Some(message) = msg {
                            // Try to extract sender_endpoint from the message
                            // Messages in channel transport may be JWE or EncryptedMessage JSON
                            let sender_endpoint = Self::extract_sender_endpoint(&message);

                            let metadata = TransportMetadata {
                                sender_endpoint,
                                transport_type: "channel".to_string(),
                                received_at: Utc::now(),
                            };

                            if let Err(e) = self.message_receiver.receive_message(message, metadata).await {
                                tracing::warn!("Error processing channel message: {}", e);
                            }
                        } else {
                            // Channel closed
                            break;
                        }
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        if !*self.running.read().await {
                            break;
                        }
                    }
                }
            }

            // Put receiver back
            let mut receiver_guard = self.receiver.write().await;
            *receiver_guard = Some(receiver);
        }
    }

    /// Extract sender_endpoint from message JSON if present
    ///
    /// Messages may be either:
    /// 1. EncryptedMessage with sender_endpoint field (sent via channel transport)
    /// 2. JWE format with sender_endpoint (HTTP transport compatibility)
    /// 3. Plain protocol messages (test mode)
    fn extract_sender_endpoint(message: &str) -> Option<String> {
        // Try to parse as JSON
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(message) {
            // Check if it's an EncryptedMessage with sender_endpoint
            if let Some(sender_endpoint) = json.get("sender_endpoint") {
                if let Some(endpoint) = sender_endpoint.as_str() {
                    // Only return if not empty
                    if !endpoint.is_empty() {
                        return Some(endpoint.to_string());
                    }
                }
            }

            // Also check inside ciphertext if it's there (for nested JWE messages)
            if let Some(ciphertext) = json.get("ciphertext") {
                if let Some(ciphertext_str) = ciphertext.as_str() {
                    if let Ok(inner_json) =
                        serde_json::from_str::<serde_json::Value>(ciphertext_str)
                    {
                        if let Some(sender_endpoint) = inner_json.get("sender_endpoint") {
                            if let Some(endpoint) = sender_endpoint.as_str() {
                                if !endpoint.is_empty() {
                                    return Some(endpoint.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

#[async_trait]
impl InboundTransport for ChannelInboundTransport {
    async fn start(&mut self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        *running = true;
        drop(running);

        let endpoint = self.endpoint.clone();
        let receiver = Arc::clone(&self.receiver);
        let running_flag = Arc::clone(&self.running);
        let message_receiver = Arc::clone(&self.message_receiver);

        tokio::spawn(async move {
            let transport = ChannelInboundTransport {
                endpoint,
                receiver,
                running: running_flag,
                message_receiver,
            };
            transport.process_messages().await;
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        let mut running = self.running.write().await;
        *running = false;
        Ok(())
    }

    fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    fn is_running(&self) -> bool {
        // Note: We can't use async in sync method, so this is a best-effort check
        // In production, consider using an AtomicBool instead of RwLock<bool>
        self.running.try_read().map(|r| *r).unwrap_or(false)
    }
}

/// Outbound transport that sends messages via channels
pub struct ChannelOutboundTransport {
    /// Map of endpoint -> sender
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<String>>>>,
}

impl ChannelOutboundTransport {
    /// Create a new channel outbound transport
    pub fn new() -> Self {
        Self {
            senders: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a sender for an endpoint
    pub async fn register_sender(&self, endpoint: String, sender: mpsc::Sender<String>) {
        let mut senders = self.senders.write().await;
        senders.insert(endpoint, sender);
    }

    /// Get all registered endpoints
    pub async fn endpoints(&self) -> Vec<String> {
        let senders = self.senders.read().await;
        senders.keys().cloned().collect()
    }
}

impl Default for ChannelOutboundTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ChannelOutboundTransport {
    fn clone(&self) -> Self {
        Self {
            senders: Arc::clone(&self.senders),
        }
    }
}

#[async_trait]
impl OutboundTransport for ChannelOutboundTransport {
    async fn send(&self, endpoint: &str, message: &str) -> Result<Option<String>> {
        let senders = self.senders.read().await;
        let sender = senders.get(endpoint).ok_or_else(|| {
            TransportError::SendFailed(format!("No sender registered for endpoint: {}", endpoint))
        })?;

        sender
            .send(message.to_string())
            .await
            .map_err(|e| TransportError::SendFailed(format!("Failed to send message: {}", e)))?;

        // Channel transport doesn't have responses (one-way communication)
        Ok(None)
    }

    fn supports_endpoint(&self, endpoint: &str) -> bool {
        endpoint.starts_with("channel://")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock MessageReceiver for testing
    struct MockReceiver;

    #[async_trait]
    impl MessageReceiver for MockReceiver {
        async fn receive_message(
            &self,
            _message: String,
            _metadata: TransportMetadata,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_channel_transport_creation() {
        let (_tx, rx) = mpsc::channel(100);
        let receiver = Arc::new(MockReceiver);
        let inbound = ChannelInboundTransport::new("channel://test", rx, receiver);
        let outbound = ChannelOutboundTransport::new();

        assert_eq!(inbound.endpoint(), "channel://test");
        assert!(outbound.supports_endpoint("channel://test"));
        assert!(!outbound.supports_endpoint("http://test"));
    }

    #[tokio::test]
    async fn test_outbound_register_sender() {
        let outbound = ChannelOutboundTransport::new();
        let (tx, _rx) = mpsc::channel(100);

        outbound
            .register_sender("channel://test".to_string(), tx)
            .await;

        let endpoints = outbound.endpoints().await;
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0], "channel://test");
    }
}
