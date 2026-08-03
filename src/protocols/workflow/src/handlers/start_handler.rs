use std::sync::Arc;

use async_trait::async_trait;

use crate::messages::fetch_template::FetchTemplateMessage;
use crate::messages::StartMessage;
use crate::queue::command_queue::PersistentCommandQueue;
use crate::repository::command_record::CommandType;
use crate::services::WorkflowService;
use didcomm::core::Message;
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage,
};

pub struct StartHandler {
    command_queue: Arc<PersistentCommandQueue>,
    service: Arc<WorkflowService>,
}

impl StartHandler {
    pub fn new(command_queue: Arc<PersistentCommandQueue>, service: Arc<WorkflowService>) -> Self {
        Self {
            command_queue,
            service,
        }
    }
}

#[async_trait]
impl MessageHandler for StartHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![StartMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> std::result::Result<Option<OutboundMessage>, MessageHandlerError> {
        let start_msg: StartMessage = serde_json::from_value(inbound.message.body.clone())
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        let instance_id = start_msg
            .instance_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let connection_id = inbound.context.connection_id.clone();

        self.command_queue
            .enqueue(
                CommandType::Start,
                &instance_id,
                connection_id.as_deref(),
                None,
                serde_json::to_value(&start_msg)
                    .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?,
            )
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        // Auto-fetch: if we don't have the template locally, send a fetch-template
        // request back to the sender. The TemplateHandler will store the response,
        // and the command queue will retry the Start command (max_attempts=3).
        let allow_discover = start_msg.allow_discover.unwrap_or(true);
        if allow_discover {
            let has_template = self
                .service
                .get_template(
                    &start_msg.template_id,
                    start_msg.template_version.as_deref(),
                )
                .await
                .ok()
                .flatten()
                .is_some();

            if !has_template {
                let (from, to) = match (&inbound.context.to, &inbound.context.from) {
                    (Some(f), Some(t)) => (f.clone(), t.clone()),
                    _ => return Ok(None),
                };

                tracing::info!(
                    "Template '{}' not found locally, sending fetch-template to sender",
                    start_msg.template_id
                );

                let fetch_msg = FetchTemplateMessage {
                    template_id: start_msg.template_id,
                    template_version: start_msg.template_version,
                    prefer_hash: false,
                };

                let body = serde_json::to_value(&fetch_msg)
                    .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

                let response_msg = Message::new(
                    uuid::Uuid::new_v4().to_string(),
                    FetchTemplateMessage::TYPE.to_string(),
                    body,
                );

                return Ok(Some(OutboundMessage {
                    message: response_msg,
                    to,
                    from,
                    connection_id: inbound.context.connection_id,
                }));
            }
        }

        Ok(None)
    }
}
