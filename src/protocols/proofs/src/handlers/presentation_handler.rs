//! Presentation Handler
//!
//! Handles incoming presentation messages (Verifier side).
//! Verifies the presentation and optionally auto-acknowledges.

use crate::messages::{AckMessage, AckStatus, PresentationMessage};
use crate::services::ProofExchangeService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for presentation messages
///
/// This handler:
/// 1. Receives and parses a presentation from the Prover.
/// 2. Stores it and transitions the exchange to `PresentationReceived`.
/// 3. If `auto_verify` is set: verifies the presentation and sends an ack
///    (`ok`/`fail`) back to the Prover. Otherwise returns `None` and leaves
///    verification to the caller.
pub struct PresentationHandler {
    /// Proof exchange service for protocol operations
    proof_service: Arc<ProofExchangeService>,
    /// Whether to automatically verify and acknowledge presentations
    auto_verify: bool,
}

impl PresentationHandler {
    /// Create a new presentation handler
    pub fn new(proof_service: Arc<ProofExchangeService>, auto_verify: bool) -> Self {
        Self {
            proof_service,
            auto_verify,
        }
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for PresentationHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![PresentationMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        tracing::debug!("Received presentation message");

        // Parse the presentation from the DIDComm message
        let presentation =
            PresentationMessage::from_didcomm_message(&inbound.message).map_err(|e| {
                tracing::debug!("Failed to parse presentation: {}", e);
                MessageHandlerError::InvalidMessage(e)
            })?;

        tracing::debug!(
            "Parsed presentation: id={}, thread_id={}",
            presentation.id,
            presentation.thread_id
        );

        // Process the presentation (stores it and transitions to PresentationReceived)
        let record = self
            .proof_service
            .process_presentation(&presentation)
            .await
            .map_err(|e| {
                tracing::debug!("Failed to process presentation: {}", e);
                MessageHandlerError::ProcessingFailed(e.to_string())
            })?;

        tracing::debug!(
            "Presentation received: exchange_id={}, state={:?}",
            record.id,
            record.state
        );

        if self.auto_verify {
            // Auto-verify the presentation
            let verified = self
                .proof_service
                .verify_presentation(&record.id)
                .await
                .map_err(|e| {
                    tracing::debug!("Failed to verify presentation: {}", e);
                    MessageHandlerError::ProcessingFailed(e.to_string())
                })?;

            tracing::debug!("Presentation verified: {}", verified);

            // Create ack message
            let status = if verified {
                AckStatus::Ok
            } else {
                AckStatus::Fail
            };
            let ack = AckMessage::new(presentation.thread_id.clone(), status);
            let ack_didcomm = ack.to_didcomm_message();

            // Build the outbound message
            if let Some(from) = &inbound.context.from {
                let outbound = OutboundMessage {
                    message: ack_didcomm,
                    to: from.clone(),
                    from: inbound.context.to.clone().unwrap_or_default(),
                    connection_id: inbound.context.connection_id.clone(),
                };
                return Ok(Some(outbound));
            }
        }

        // No automatic response
        Ok(None)
    }
}
