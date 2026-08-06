use std::sync::Arc;

use async_trait::async_trait;

use crate::messages::{StatusMessage, StatusRequestMessage};
use crate::services::{StatusOptions, WorkflowService};
use didcomm::core::Message;
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage,
};

pub struct StatusHandler {
    service: Arc<WorkflowService>,
}

impl StatusHandler {
    pub fn new(service: Arc<WorkflowService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl MessageHandler for StatusHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![
            StatusRequestMessage::TYPE.to_string(),
            StatusMessage::TYPE.to_string(),
        ]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> std::result::Result<Option<OutboundMessage>, MessageHandlerError> {
        if inbound
            .message
            .body
            .get("state")
            .and_then(|s| s.as_str())
            .is_some()
        {
            tracing::debug!(
                target: "workflow",
                instance_id = ?inbound.message.body.get("instance_id"),
                "workflow status response received; acknowledged"
            );
            return Ok(None);
        }

        let status_req: StatusRequestMessage = serde_json::from_value(inbound.message.body.clone())
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        let opts = StatusOptions {
            instance_id: status_req.instance_id,
            include_actions: status_req.include_actions,
            include_ui: status_req.include_ui,
            ui_profile: status_req.ui_profile,
            viewer: status_req.viewer,
        };

        let status_response = self
            .service
            .status(opts)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        // Build response message
        let response_body = serde_json::to_value(&status_response.message)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let response_msg = Message::new(
            uuid::Uuid::new_v4().to_string(),
            StatusMessage::TYPE.to_string(),
            response_body,
        );

        if let (Some(from), Some(to)) = (&inbound.context.to, &inbound.context.from) {
            Ok(Some(OutboundMessage {
                message: response_msg,
                to: to.clone(),
                from: from.clone(),
                connection_id: inbound.context.connection_id,
            }))
        } else {
            Ok(None)
        }
    }
}
