use std::sync::Arc;

use async_trait::async_trait;

use crate::messages::PublishTemplateMessage;
use crate::services::WorkflowService;
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage,
};

pub struct PublishTemplateHandler {
    service: Arc<WorkflowService>,
}

impl PublishTemplateHandler {
    pub fn new(service: Arc<WorkflowService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl MessageHandler for PublishTemplateHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![PublishTemplateMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> std::result::Result<Option<OutboundMessage>, MessageHandlerError> {
        let publish_msg: PublishTemplateMessage =
            serde_json::from_value(inbound.message.body.clone())
                .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        self.service
            .publish_template(publish_msg.template)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        Ok(None)
    }
}
