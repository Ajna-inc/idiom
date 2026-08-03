use std::sync::Arc;

use async_trait::async_trait;
use tracing;

use crate::messages::template_response::TemplateResponseMessage;
use crate::services::WorkflowService;
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage,
};

/// Handles incoming TemplateMessage (response to a FetchTemplateMessage).
/// Stores the received template locally.
pub struct TemplateHandler {
    service: Arc<WorkflowService>,
}

impl TemplateHandler {
    pub fn new(service: Arc<WorkflowService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl MessageHandler for TemplateHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![TemplateResponseMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> std::result::Result<Option<OutboundMessage>, MessageHandlerError> {
        let template_msg: TemplateResponseMessage =
            serde_json::from_value(inbound.message.body.clone())
                .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        tracing::info!(
            "Received workflow template: {} v{}",
            template_msg.template.template_id,
            template_msg.template.version
        );

        self.service
            .publish_template(template_msg.template)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        Ok(None)
    }
}
