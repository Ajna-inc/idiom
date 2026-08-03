//! Mediation Grant Handler
//!
//! Handles incoming mediation grant messages (recipient side).

use crate::messages::MediationGrantMessage;
use crate::services::MediationRecipientService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for mediation grant messages
///
/// This handler:
/// 1. Receives a mediation grant from the mediator
/// 2. Updates the mediation record with endpoint and routing keys
/// 3. Stores the routing information for future use
pub struct MediationGrantHandler {
    mediation_service: Arc<MediationRecipientService>,
}

impl MediationGrantHandler {
    /// Create a new grant handler
    pub fn new(mediation_service: Arc<MediationRecipientService>) -> Self {
        Self { mediation_service }
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for MediationGrantHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![MediationGrantMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        message: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        // Parse the grant message
        let message_value = serde_json::to_value(&message.message)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;
        let grant_message: MediationGrantMessage = serde_json::from_value(message_value)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        // Get connection ID from message metadata
        let connection_id = message
            .context
            .connection_id
            .ok_or_else(|| MessageHandlerError::InvalidMessage("Missing connection ID".into()))?;

        // Process the grant
        self.mediation_service
            .process_grant(&connection_id, &grant_message)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        tracing::info!(
            "Mediation granted for connection {}: endpoint={}",
            connection_id,
            grant_message.endpoint
        );

        // No response message needed
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MediationRecipientService;
    use didcomm::core::Message as DidcommMessage;
    use didcomm::messaging::MessageContext;

    #[tokio::test]
    async fn test_handle_grant() {
        let service = Arc::new(MediationRecipientService::with_defaults());

        // Create a mediation request first
        let (_, _) = service
            .create_request("conn-123".to_string())
            .await
            .unwrap();

        // Create grant message
        let grant_message = MediationGrantMessage::new(
            "thread-123".to_string(),
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        );

        // Create inbound message
        let didcomm_msg: DidcommMessage =
            serde_json::from_value(serde_json::to_value(&grant_message).unwrap()).unwrap();

        let inbound = InboundMessage {
            message: didcomm_msg,
            context: MessageContext {
                from: Some("did:peer:mediator".to_string()),
                to: Some("did:peer:recipient".to_string()),
                thread_id: Some("thread-123".to_string()),
                parent_thread_id: None,
                connection_id: Some("conn-123".to_string()),
                encrypted: true,
                authenticated: true,
                sender_endpoint: None,
            },
        };

        // Handle the message
        let handler = MediationGrantHandler::new(service.clone());
        let result = handler.handle(inbound).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // No response

        // Verify mediation was granted
        let mediation = service
            .find_by_connection_id("conn-123")
            .await
            .unwrap()
            .unwrap();
        assert!(mediation.state.is_active());
    }
}
