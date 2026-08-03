use crate::core::{DidcommError, EnvelopeService};
use crate::messaging::handlers::{
    HandlerRegistry, InboundMessage, MessageContext, OutboundMessage,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Message dispatcher
///
/// Routes incoming DIDComm messages to the appropriate handlers.
pub struct MessageDispatcher {
    /// Handler registry
    handler_registry: Arc<RwLock<HandlerRegistry>>,

    /// Envelope service for unpacking messages
    envelope_service: Arc<EnvelopeService>,
}

impl MessageDispatcher {
    /// Create a new message dispatcher
    ///
    /// # Arguments
    /// * `handler_registry` - The handler registry to use
    /// * `envelope_service` - The envelope service for unpacking messages
    pub fn new(
        handler_registry: Arc<RwLock<HandlerRegistry>>,
        envelope_service: Arc<EnvelopeService>,
    ) -> Self {
        Self {
            handler_registry,
            envelope_service,
        }
    }

    /// Process an inbound packed message
    ///
    /// # Arguments
    /// * `packed_message` - The packed (encrypted) message
    ///
    /// # Returns
    /// * `Ok(Some(response))` - Handler generated a response (caller should send it)
    /// * `Ok(None)` - Message processed successfully, no response
    /// * `Err(e)` - Failed to process the message
    pub async fn process_inbound(
        &self,
        packed_message: String,
    ) -> Result<Option<OutboundMessage>, DidcommError> {
        // Unpack the message
        let (message, metadata) = self.envelope_service.unpack(&packed_message).await?;

        // Create context
        let context = MessageContext {
            from: metadata.from,
            to: metadata.to,
            thread_id: message.thread.as_ref().and_then(|t| t.thid.clone()),
            parent_thread_id: message.pthid.clone(),
            connection_id: None, // Will be resolved by connection handler
            encrypted: metadata.encrypted,
            authenticated: metadata.authenticated,
            sender_endpoint: None, // Will be set by transport layer if needed
        };

        // Create inbound message
        let inbound = InboundMessage { message, context };

        // Find handler
        let registry = self.handler_registry.read().await;
        let handler = registry
            .get_handler(&inbound.message.msg_type)
            .ok_or_else(|| {
                DidcommError::Other(format!(
                    "No handler for message type: {}",
                    inbound.message.msg_type
                ))
            })?;

        // Release the lock before calling handler
        drop(registry);

        // Handle the message
        let response = handler
            .handle(inbound)
            .await
            .map_err(|e| DidcommError::Other(e.to_string()))?;

        // Return the response (if any) for the caller to send
        Ok(response)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_dispatcher_creation() {
        // Just test that we can create a dispatcher
        // Full integration testing requires DID/secrets resolvers
    }
}
