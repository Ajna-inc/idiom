use std::sync::Arc;

use async_trait::async_trait;

use crate::messages::AdvanceMessage;
use crate::queue::command_queue::PersistentCommandQueue;
use crate::repository::command_record::CommandType;
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage,
};

pub struct AdvanceHandler {
    command_queue: Arc<PersistentCommandQueue>,
}

impl AdvanceHandler {
    pub fn new(command_queue: Arc<PersistentCommandQueue>) -> Self {
        Self { command_queue }
    }
}

#[async_trait]
impl MessageHandler for AdvanceHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![AdvanceMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> std::result::Result<Option<OutboundMessage>, MessageHandlerError> {
        let advance_msg: AdvanceMessage = serde_json::from_value(inbound.message.body.clone())
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        let connection_id = inbound.context.connection_id.clone();

        self.command_queue
            .enqueue(
                CommandType::Advance,
                &advance_msg.instance_id,
                connection_id.as_deref(),
                advance_msg.idempotency_key.as_deref(),
                serde_json::to_value(&advance_msg)
                    .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?,
            )
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        Ok(None)
    }
}
