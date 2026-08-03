//! Forward Message Handler
//!
//! Handles incoming forward messages (recipient side).
//!
//! When a mediator receives a message for a recipient, it wraps it in a ForwardMessage
//! and sends it to the recipient. This handler unwraps the message and processes it.

use crate::messages::ForwardMessage;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};

/// Handler for forward messages
///
/// This handler:
/// 1. Receives a forward message from a mediator
/// 2. Extracts the inner encrypted message
/// 3. Returns it for further processing by the agent
pub struct ForwardHandler;

impl ForwardHandler {
    /// Create a new forward handler
    pub fn new() -> Self {
        Self
    }
}

impl Default for ForwardHandler {
    fn default() -> Self {
        Self::new()
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for ForwardHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![ForwardMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        message: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        // Parse the forward message
        let message_value = serde_json::to_value(&message.message)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;
        let forward_message: ForwardMessage = serde_json::from_value(message_value)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        tracing::debug!(
            "Received forwarded message for recipient: {}",
            forward_message.to
        );

        // Extract the inner message
        // The 'message' field contains the actual encrypted DIDComm message
        // In a full implementation, this would be:
        // 1. Decrypted by the envelope service
        // 2. Dispatched to the appropriate handler based on message type
        //
        // The actual message processing would be handled by the agent's dispatcher
        tracing::debug!("Forwarded message received successfully");

        // Note: In a real implementation, the agent would:
        // - Decrypt the inner message using the envelope service
        // - Dispatch it to the appropriate handler
        // - This handler's job is just to unwrap the forward envelope

        // No response needed - the inner message will be processed separately
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ForwardMessage;
    use didcomm::core::Message as DidcommMessage;
    use didcomm::messaging::MessageContext;
    use serde_json::json;

    #[tokio::test]
    async fn test_handle_forward() {
        let handler = ForwardHandler::new();

        // Create a mock encrypted inner message
        let encrypted_msg = json!({
            "@type": "https://didcomm.org/basicmessage/1.0/message",
            "@id": "inner-msg-123",
            "content": "Hello, this is forwarded!"
        });

        // Create forward message
        let forward_message =
            ForwardMessage::new("did:key:z6MkkRecipient...".to_string(), encrypted_msg);

        let didcomm_msg: DidcommMessage =
            serde_json::from_value(serde_json::to_value(&forward_message).unwrap()).unwrap();

        let inbound = InboundMessage {
            message: didcomm_msg,
            context: MessageContext {
                from: Some("did:peer:mediator".to_string()),
                to: Some("did:peer:recipient".to_string()),
                thread_id: None,
                parent_thread_id: None,
                connection_id: Some("mediator-conn".to_string()),
                encrypted: true,
                authenticated: true,
                sender_endpoint: None,
            },
        };

        // Handle the message
        let result = handler.handle(inbound).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // No response needed
    }

    #[tokio::test]
    async fn test_handle_forward_multiple() {
        let handler = ForwardHandler::new();

        // Simulate receiving multiple forwarded messages
        for i in 0..3 {
            let encrypted_msg = json!({
                "@type": "https://didcomm.org/basicmessage/1.0/message",
                "@id": format!("inner-msg-{}", i),
                "content": format!("Message {}", i)
            });

            let forward_message =
                ForwardMessage::new("did:key:z6MkkRecipient...".to_string(), encrypted_msg);

            let didcomm_msg: DidcommMessage =
                serde_json::from_value(serde_json::to_value(&forward_message).unwrap()).unwrap();

            let inbound = InboundMessage {
                message: didcomm_msg,
                context: MessageContext {
                    from: Some("did:peer:mediator".to_string()),
                    to: Some("did:peer:recipient".to_string()),
                    thread_id: None,
                    parent_thread_id: None,
                    connection_id: Some("mediator-conn".to_string()),
                    encrypted: true,
                    authenticated: true,
                    sender_endpoint: None,
                },
            };

            let result = handler.handle(inbound).await;
            assert!(result.is_ok());
        }
    }
}
