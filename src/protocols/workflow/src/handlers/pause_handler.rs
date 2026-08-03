use std::sync::Arc;

use async_trait::async_trait;

use crate::messages::PauseMessage;
use crate::queue::command_queue::PersistentCommandQueue;
use crate::repository::command_record::CommandType;
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage,
};

pub struct PauseHandler {
    command_queue: Arc<PersistentCommandQueue>,
}

impl PauseHandler {
    pub fn new(command_queue: Arc<PersistentCommandQueue>) -> Self {
        Self { command_queue }
    }
}

#[async_trait]
impl MessageHandler for PauseHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![PauseMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> std::result::Result<Option<OutboundMessage>, MessageHandlerError> {
        let pause_msg: PauseMessage = serde_json::from_value(inbound.message.body.clone())
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        self.command_queue
            .enqueue(
                CommandType::Pause,
                &pause_msg.instance_id,
                inbound.context.connection_id.as_deref(),
                None,
                serde_json::to_value(&pause_msg)
                    .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?,
            )
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        Ok(None)
    }
}
