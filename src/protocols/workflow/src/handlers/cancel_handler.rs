use std::sync::Arc;

use async_trait::async_trait;

use crate::messages::CancelMessage;
use crate::queue::command_queue::PersistentCommandQueue;
use crate::repository::command_record::CommandType;
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage,
};

pub struct CancelHandler {
    command_queue: Arc<PersistentCommandQueue>,
}

impl CancelHandler {
    pub fn new(command_queue: Arc<PersistentCommandQueue>) -> Self {
        Self { command_queue }
    }
}

#[async_trait]
impl MessageHandler for CancelHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![CancelMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> std::result::Result<Option<OutboundMessage>, MessageHandlerError> {
        let cancel_msg: CancelMessage = serde_json::from_value(inbound.message.body.clone())
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        self.command_queue
            .enqueue(
                CommandType::Cancel,
                &cancel_msg.instance_id,
                inbound.context.connection_id.as_deref(),
                None,
                serde_json::to_value(&cancel_msg)
                    .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?,
            )
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        Ok(None)
    }
}
