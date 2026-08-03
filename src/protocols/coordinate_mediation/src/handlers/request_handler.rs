//! Mediation Request Handler
//!
//! Handles incoming mediation request messages (mediator side).

use crate::messages::MediationRequestMessage;
use crate::services::MediatorService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for mediation request messages
///
/// This handler:
/// 1. Receives a mediation request from a recipient
/// 2. Creates a mediation record in Requested state
/// 3. Optionally auto-grants mediation (or waits for manual approval)
pub struct MediationRequestHandler {
    mediator_service: Arc<MediatorService>,
    auto_grant: bool,
}

impl MediationRequestHandler {
    /// Create a new request handler
    pub fn new(mediator_service: Arc<MediatorService>) -> Self {
        Self {
            mediator_service,
            auto_grant: false,
        }
    }

    /// Create a new request handler with auto-grant enabled
    pub fn with_auto_grant(mediator_service: Arc<MediatorService>) -> Self {
        Self {
            mediator_service,
            auto_grant: true,
        }
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for MediationRequestHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![MediationRequestMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        message: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        // Parse the request message
        let message_value = serde_json::to_value(&message.message)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;
        let request_message: MediationRequestMessage = serde_json::from_value(message_value)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        // Get connection ID from message metadata
        let connection_id = message
            .context
            .connection_id
            .ok_or_else(|| MessageHandlerError::InvalidMessage("Missing connection ID".into()))?;

        // Process the request
        let record = self
            .mediator_service
            .process_request(connection_id.clone())
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        tracing::info!(
            "Mediation request received from connection {}",
            connection_id
        );

        // If auto-grant is enabled, immediately grant mediation
        if self.auto_grant {
            let (updated_record, grant_message) = self
                .mediator_service
                .grant_mediation(&record.id, request_message.id.clone())
                .await
                .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

            tracing::info!(
                "Auto-granted mediation {}: endpoint={}",
                updated_record.id,
                grant_message.endpoint
            );

            // Return grant message
            let grant_value = serde_json::to_value(&grant_message)
                .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;
            let didcomm_msg: didcomm::core::Message = serde_json::from_value(grant_value)
                .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

            return Ok(Some(OutboundMessage {
                message: didcomm_msg,
                to: message.context.from.clone().unwrap_or_default(),
                from: message.context.to.clone().unwrap_or_default(),
                connection_id: Some(connection_id.clone()),
            }));
        }

        // Otherwise, manual approval required - no response yet
        tracing::info!("Waiting for manual approval of mediation {}", record.id);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MediationGrantMessage, MediatorService};
    use didcomm::core::Message as DidcommMessage;

    #[tokio::test]
    async fn test_handle_request_manual() {
        let service = Arc::new(MediatorService::with_defaults(
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        ));

        let handler = MediationRequestHandler::new(service.clone());

        // Create request message
        let request_message = MediationRequestMessage::new();
        let didcomm_msg: DidcommMessage =
            serde_json::from_value(serde_json::to_value(&request_message).unwrap()).unwrap();

        let inbound = InboundMessage {
            message: didcomm_msg,
            context: didcomm::messaging::MessageContext {
                from: Some("did:peer:recipient".to_string()),
                to: Some("did:peer:mediator".to_string()),
                thread_id: Some(request_message.id.clone()),
                parent_thread_id: None,
                connection_id: Some("conn-123".to_string()),
                encrypted: true,
                authenticated: true,
                sender_endpoint: None,
            },
        };

        // Handle the message (manual mode)
        let result = handler.handle(inbound).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // No immediate response
    }

    #[tokio::test]
    async fn test_handle_request_auto_grant() {
        let service = Arc::new(MediatorService::with_defaults(
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        ));

        let handler = MediationRequestHandler::with_auto_grant(service.clone());

        // Create request message
        let request_message = MediationRequestMessage::new();
        let didcomm_msg: DidcommMessage =
            serde_json::from_value(serde_json::to_value(&request_message).unwrap()).unwrap();

        let inbound = InboundMessage {
            message: didcomm_msg,
            context: didcomm::messaging::MessageContext {
                from: Some("did:peer:recipient".to_string()),
                to: Some("did:peer:mediator".to_string()),
                thread_id: Some(request_message.id.clone()),
                parent_thread_id: None,
                connection_id: Some("conn-123".to_string()),
                encrypted: true,
                authenticated: true,
                sender_endpoint: None,
            },
        };

        // Handle the message (auto-grant mode)
        let result = handler.handle(inbound).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_some()); // Should have grant response

        // Verify it's a grant message
        let outbound = response.unwrap();
        let grant: MediationGrantMessage =
            serde_json::from_value(serde_json::to_value(&outbound.message).unwrap()).unwrap();
        assert_eq!(grant.endpoint, "https://mediator.example.com");
    }
}
