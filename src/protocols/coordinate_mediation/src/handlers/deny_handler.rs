//! Mediation Deny Handler
//!
//! Handles incoming mediation deny messages (recipient side).

use crate::messages::MediationDenyMessage;
use crate::services::MediationRecipientService;
use crate::MediationState;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for mediation deny messages
///
/// This handler:
/// 1. Receives a mediation deny from the mediator
/// 2. Updates the mediation record to Denied state
pub struct MediationDenyHandler {
    mediation_service: Arc<MediationRecipientService>,
}

impl MediationDenyHandler {
    /// Create a new deny handler
    pub fn new(mediation_service: Arc<MediationRecipientService>) -> Self {
        Self { mediation_service }
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for MediationDenyHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![MediationDenyMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        message: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        // Parse the deny message
        let message_value = serde_json::to_value(&message.message)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;
        let _deny_message: MediationDenyMessage = serde_json::from_value(message_value)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        // Get connection ID from message metadata
        let connection_id = message
            .context
            .connection_id
            .ok_or_else(|| MessageHandlerError::InvalidMessage("Missing connection ID".into()))?;

        // Find and update the mediation record
        let mut record = self
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

        // Update state to Denied
        record.state = MediationState::Denied;

        // Note: In a real implementation, we'd update via repository
        // For now, just log the denial
        tracing::info!("Mediation denied for connection {}", connection_id);

        // No response message needed
        Ok(None)
    }
}
