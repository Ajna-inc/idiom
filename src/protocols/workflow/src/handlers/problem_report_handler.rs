use async_trait::async_trait;
use tracing;

use crate::messages::ProblemReportMessage;
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage,
};

pub struct ProblemReportHandler;

impl ProblemReportHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ProblemReportHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MessageHandler for ProblemReportHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![ProblemReportMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> std::result::Result<Option<OutboundMessage>, MessageHandlerError> {
        let report: ProblemReportMessage = serde_json::from_value(inbound.message.body.clone())
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        tracing::warn!(
            "Workflow problem report received: code={}, comment={:?}",
            report.code,
            report.comment
        );

        // No-op — just log the error
        Ok(None)
    }
}
