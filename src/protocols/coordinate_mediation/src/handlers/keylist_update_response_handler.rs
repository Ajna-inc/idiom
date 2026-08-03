//! Keylist Update Response Handler
//!
//! Handles incoming keylist update response messages (recipient side).

use crate::messages::KeylistUpdateResponseMessage;
use crate::services::MediationRecipientService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for keylist update response messages
///
/// This handler:
/// 1. Receives a keylist update response from the mediator
/// 2. Updates the keylist repository based on the results
pub struct KeylistUpdateResponseHandler {
    mediation_service: Arc<MediationRecipientService>,
}

impl KeylistUpdateResponseHandler {
    /// Create a new keylist update response handler
    pub fn new(mediation_service: Arc<MediationRecipientService>) -> Self {
        Self { mediation_service }
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for KeylistUpdateResponseHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![KeylistUpdateResponseMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        message: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        // Parse the response message
        let message_value = serde_json::to_value(&message.message)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;
        let response: KeylistUpdateResponseMessage = serde_json::from_value(message_value)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        // Get connection ID from message metadata
        let connection_id = message
            .context
            .connection_id
            .ok_or_else(|| MessageHandlerError::InvalidMessage("Missing connection ID".into()))?;

        // Find mediation record
        let mediation = self
            .mediation_service
            .find_by_connection_id(&connection_id)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?
            .ok_or_else(|| {
                MessageHandlerError::ProcessingFailed(format!(
                    "Mediation not found for connection {}",
                    connection_id
                ))
            })?;

        // Process the keylist updates
        self.mediation_service
            .process_keylist_update_response(&mediation.id, &response.updated)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        tracing::info!(
            "Processed {} keylist updates for mediation {}",
            response.updated.len(),
            mediation.id
        );

        // No response message needed
        Ok(None)
    }
}
