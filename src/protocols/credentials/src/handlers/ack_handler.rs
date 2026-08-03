//! Ack Handler (Issue Credential)
//!
//! Handles incoming ack messages for the Issue Credential protocol. The holder
//! sends this after storing the issued credential; the issuer transitions the
//! exchange to Done. Registering it also silences the "No handler registered
//! for issue-credential/2.0/ack" warning for a completed exchange.

use crate::messages::AckMessage;
use crate::services::CredentialExchangeService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for issue-credential ack messages (issuer side)
pub struct CredentialAckHandler {
    service: Arc<CredentialExchangeService>,
}

impl CredentialAckHandler {
    pub fn new(service: Arc<CredentialExchangeService>) -> Self {
        Self { service }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for CredentialAckHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![AckMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        let ack = AckMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        tracing::debug!(
            thread_id = %ack.thread_id,
            status = ?ack.status,
            "Received credential ack"
        );

        // Transition the exchange to Done. A missing exchange (e.g. ephemeral
        // store restarted) is not fatal — the credential was already delivered.
        match self.service.process_ack(&ack.thread_id).await {
            Ok(record) => tracing::debug!(
                exchange_id = %record.id,
                "Credential exchange completed via ack"
            ),
            Err(e) => tracing::debug!("Credential ack for unknown exchange ignored: {}", e),
        }

        // Ack is the final message — no response.
        Ok(None)
    }
}
