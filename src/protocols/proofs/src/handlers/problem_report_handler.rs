//! Problem-report Handler (Present Proof v3)
//!
//! On receipt, looks up the proof exchange by thread id, transitions it to
//! Abandoned, and records the reason. Implements the Aries RFC 0035
//! problem-report flow for present-proof exchanges.

use crate::messages::ProblemReportMessage;
use crate::services::ProofExchangeService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

pub struct ProblemReportHandler {
    proof_service: Arc<ProofExchangeService>,
}

impl ProblemReportHandler {
    pub fn new(proof_service: Arc<ProofExchangeService>) -> Self {
        Self { proof_service }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for ProblemReportHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![ProblemReportMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        let msg = ProblemReportMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        let record = self
            .proof_service
            .get_by_thread_id(&msg.thread_id)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let Some(record) = record else {
            tracing::warn!(
                thread_id = %msg.thread_id,
                "problem-report received for unknown proof exchange — ignoring"
            );
            return Ok(None);
        };

        let reason = format!("{}: {}", msg.description.code, msg.description.en);
        self.proof_service
            .abandon_exchange(&record.id, &reason)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        tracing::info!(
            exchange_id = %record.id,
            code = %msg.description.code,
            "proof exchange abandoned via problem-report"
        );
        Ok(None)
    }
}
