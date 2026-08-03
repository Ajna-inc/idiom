//! Request Presentation Handler
//!
//! Handles incoming request-presentation messages (Prover side).
//! Stores the proof request and transitions to RequestReceived state.

use crate::messages::RequestPresentationMessage;
use crate::services::ProofExchangeService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for request-presentation messages
///
/// This handler:
/// 1. Receives a request-presentation from the Verifier
/// 2. Parses the proof request from the attachment
/// 3. Creates a ProofExchangeRecord in RequestReceived state
/// 4. Returns None (Prover must explicitly accept the request to create a presentation)
pub struct RequestPresentationHandler {
    /// Proof exchange service for protocol operations
    proof_service: Arc<ProofExchangeService>,
}

impl RequestPresentationHandler {
    /// Create a new request presentation handler
    pub fn new(proof_service: Arc<ProofExchangeService>) -> Self {
        Self { proof_service }
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for RequestPresentationHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![RequestPresentationMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        tracing::debug!("Received request-presentation message");

        // Parse the request-presentation from the DIDComm message
        let request =
            RequestPresentationMessage::from_didcomm_message(&inbound.message).map_err(|e| {
                tracing::debug!("Failed to parse request-presentation: {}", e);
                MessageHandlerError::InvalidMessage(e)
            })?;

        tracing::debug!(
            "Parsed request-presentation: id={}, has_comment={}",
            request.id,
            request.comment.is_some()
        );

        // Process the request (creates record in RequestReceived state)
        let connection_id = inbound.context.connection_id.clone();
        let thread_id = inbound.message.thread_id().to_string();

        let _record = self
            .proof_service
            .process_request(&request, &thread_id, connection_id)
            .await
            .map_err(|e| {
                tracing::debug!("Failed to process request-presentation: {}", e);
                MessageHandlerError::ProcessingFailed(e.to_string())
            })?;

        tracing::debug!(
            "Proof exchange created: id={}, state={:?}",
            _record.id,
            _record.state
        );

        // No automatic response - Prover must explicitly accept
        Ok(None)
    }
}
