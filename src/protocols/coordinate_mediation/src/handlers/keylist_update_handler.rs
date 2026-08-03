//! Keylist Update Handler
//!
//! Handles incoming keylist update request messages (mediator side).

use crate::messages::{KeylistUpdateMessage, KeylistUpdateResponseMessage};
use crate::services::MediatorService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for keylist update request messages
///
/// This handler:
/// 1. Receives a keylist update request from a recipient
/// 2. Processes each update (add/remove recipient keys)
/// 3. Returns a keylist update response with results
pub struct KeylistUpdateHandler {
    mediator_service: Arc<MediatorService>,
}

impl KeylistUpdateHandler {
    /// Create a new keylist update handler
    pub fn new(mediator_service: Arc<MediatorService>) -> Self {
        Self { mediator_service }
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for KeylistUpdateHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![KeylistUpdateMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        message: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        // Parse the update request message
        let message_value = serde_json::to_value(&message.message)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;
        let update_message: KeylistUpdateMessage = serde_json::from_value(message_value)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        // Get connection ID from message metadata
        let connection_id = message
            .context
            .connection_id
            .ok_or_else(|| MessageHandlerError::InvalidMessage("Missing connection ID".into()))?;

        // Find mediation record by connection ID
        let mediation = self
            .mediator_service
            .mediation_repository
            .find_by_connection_id(&connection_id)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?
            .ok_or_else(|| {
                MessageHandlerError::ProcessingFailed(format!(
                    "Mediation not found for connection {}",
                    connection_id
                ))
            })?;

        tracing::info!(
            "Processing {} keylist updates for mediation {}",
            update_message.updates.len(),
            mediation.id
        );

        // Process the keylist updates
        let results = self
            .mediator_service
            .process_keylist_updates(&mediation.id, &update_message.updates)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        // Create response message
        let response_message =
            KeylistUpdateResponseMessage::new(update_message.id.clone(), results);

        tracing::info!("Completed keylist updates for mediation {}", mediation.id);

        // Return response message
        let response_value = serde_json::to_value(&response_message)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;
        let didcomm_msg: didcomm::core::Message = serde_json::from_value(response_value)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        Ok(Some(OutboundMessage {
            message: didcomm_msg,
            to: message.context.from.clone().unwrap_or_default(),
            from: message.context.to.clone().unwrap_or_default(),
            connection_id: Some(connection_id.clone()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::KeylistResult, KeylistUpdate, KeylistUpdateResponseMessage, MediatorService,
    };
    use didcomm::core::Message as DidcommMessage;
    use didcomm::messaging::MessageContext;

    #[tokio::test]
    async fn test_handle_keylist_update() {
        let service = Arc::new(MediatorService::with_defaults(
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        ));

        // Create a mediation first
        let mediation = service
            .process_request("conn-123".to_string())
            .await
            .unwrap();

        service
            .grant_mediation(&mediation.id, "thread-123".to_string())
            .await
            .unwrap();

        let handler = KeylistUpdateHandler::new(service.clone());

        // Create keylist update message
        let updates = vec![
            KeylistUpdate::add("did:key:z6Mkk1...".to_string()),
            KeylistUpdate::add("did:key:z6Mkk2...".to_string()),
        ];
        let update_message = KeylistUpdateMessage::new(updates);

        let didcomm_msg: DidcommMessage =
            serde_json::from_value(serde_json::to_value(&update_message).unwrap()).unwrap();

        let inbound = InboundMessage {
            message: didcomm_msg,
            context: MessageContext {
                from: Some("did:peer:recipient".to_string()),
                to: Some("did:peer:mediator".to_string()),
                thread_id: Some("thread-123".to_string()),
                parent_thread_id: None,
                connection_id: Some("conn-123".to_string()),
                encrypted: true,
                authenticated: true,
                sender_endpoint: None,
            },
        };

        // Handle the message
        let result = handler.handle(inbound).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_some());

        // Verify response
        let outbound = response.unwrap();
        let response_msg: KeylistUpdateResponseMessage =
            serde_json::from_value(serde_json::to_value(&outbound.message).unwrap()).unwrap();

        assert_eq!(response_msg.updated.len(), 2);
        assert!(response_msg
            .updated
            .iter()
            .all(|u| u.result == KeylistResult::Success));
    }

    #[tokio::test]
    async fn test_handle_keylist_update_no_mediation() {
        let service = Arc::new(MediatorService::with_defaults(
            "https://mediator.example.com".to_string(),
            vec![],
        ));

        let handler = KeylistUpdateHandler::new(service.clone());

        // Create keylist update message without having a mediation
        let updates = vec![KeylistUpdate::add("did:key:z6Mkk1...".to_string())];
        let update_message = KeylistUpdateMessage::new(updates);

        let didcomm_msg: DidcommMessage =
            serde_json::from_value(serde_json::to_value(&update_message).unwrap()).unwrap();

        let inbound = InboundMessage {
            message: didcomm_msg,
            context: MessageContext {
                from: Some("did:peer:recipient".to_string()),
                to: Some("did:peer:mediator".to_string()),
                thread_id: Some("thread-123".to_string()),
                parent_thread_id: None,
                connection_id: Some("conn-123".to_string()),
                encrypted: true,
                authenticated: true,
                sender_endpoint: None,
            },
        };

        // Handle should fail - no mediation exists
        let result = handler.handle(inbound).await;
        assert!(result.is_err());
    }
}
