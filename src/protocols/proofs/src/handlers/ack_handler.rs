//! Ack Handler
//!
//! Handles incoming ack messages for the Present Proof protocol.
//! Transitions the exchange to Done state.

use crate::messages::AckMessage;
use crate::services::ProofExchangeService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for ack messages
///
/// This handler:
/// 1. Receives an ack from the Verifier (after verifying)
/// 2. Transitions the proof exchange to Done state
/// 3. Returns None (no response needed)
pub struct AckHandler {
    /// Proof exchange service for protocol operations
    proof_service: Arc<ProofExchangeService>,
}

impl AckHandler {
    /// Create a new ack handler
    pub fn new(proof_service: Arc<ProofExchangeService>) -> Self {
        Self { proof_service }
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for AckHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![AckMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        tracing::debug!("Received proof ack message");

        // Parse the ack from the DIDComm message
        let ack = AckMessage::from_didcomm_message(&inbound.message).map_err(|e| {
            tracing::debug!("Failed to parse ack: {}", e);
            MessageHandlerError::InvalidMessage(e)
        })?;

        tracing::debug!(
            "Parsed ack: id={}, thread_id={}, status={:?}",
            ack.id,
            ack.thread_id,
            ack.status
        );

        // Process the ack (transitions to Done state)
        let record = self.proof_service.process_ack(&ack).await.map_err(|e| {
            tracing::debug!("Failed to process ack: {}", e);
            MessageHandlerError::ProcessingFailed(e.to_string())
        })?;

        tracing::debug!(
            "Proof exchange completed via ack: id={}, state={:?}",
            record.id,
            record.state
        );

        // No response needed - ack is the final message for Prover side
        Ok(None)
    }
}
