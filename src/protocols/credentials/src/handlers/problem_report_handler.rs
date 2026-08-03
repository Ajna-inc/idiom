//! Problem-report Handler (Issue Credential v3)
//!
//! On receipt, marks the credential exchange as Abandoned and records the
//! reason so callers can inspect why issuance failed. Implements the
//! Aries RFC 0035 problem-report flow for credential exchanges.

use crate::messages::ProblemReportMessage;
use crate::services::CredentialExchangeService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

pub struct ProblemReportHandler {
    service: Arc<CredentialExchangeService>,
}

impl ProblemReportHandler {
    pub fn new(service: Arc<CredentialExchangeService>) -> Self {
        Self { service }
    }

    async fn process(&self, inbound: InboundMessage) -> Result<(), MessageHandlerError> {
        let msg = ProblemReportMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let record = self
            .service
            .find_exchange_by_thread_id(&msg.thread_id)
            .await
            .map_err(|e| {
                MessageHandlerError::ProcessingFailed(format!(
                    "failed to look up credential exchange: {}",
                    e
                ))
            })?;

        let Some(record) = record else {
            tracing::warn!(
                thread_id = %msg.thread_id,
                "problem-report received for unknown credential exchange — ignoring"
            );
            return Ok(());
        };

        // Already terminal — nothing to abandon.
        if record.state.is_terminal() {
            tracing::debug!(
                exchange_id = %record.id,
                state = %record.state,
                "problem-report received for terminal exchange — ignoring"
            );
            return Ok(());
        }

        let reason = format!("{}: {}", msg.description.code, msg.description.en);
        self.service
            .abandon_exchange(&record.id, &reason)
            .await
            .map_err(|e| {
                MessageHandlerError::ProcessingFailed(format!(
                    "failed to abandon credential exchange: {}",
                    e
                ))
            })?;

        tracing::info!(
            exchange_id = %record.id,
            code = %msg.description.code,
            "credential exchange abandoned via problem-report"
        );

        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl MessageHandler for ProblemReportHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![ProblemReportMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        self.process(inbound).await?;
        Ok(None)
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl MessageHandler for ProblemReportHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![ProblemReportMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        self.process(inbound).await?;
        Ok(None)
    }
}
