//! Live Delivery Change Handler
//!
//! Handles live-delivery-change messages (RFC 0685).
//! When a recipient requests live delivery, messages are pushed
//! directly via WebSocket instead of being queued for polling.

use crate::messages::{LiveDeliveryChangeMessage, StatusMessage};
use crate::repository::MessageQueueRepositoryTrait;
use crate::services::PickupMediatorService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for live-delivery-change messages (mediator side).
///
/// When a recipient sends `live_delivery: true`, this handler returns
/// a status message with `live_delivery: true` and the current queue count.
/// The actual WebSocket session registration is handled by the WS connection layer.
pub struct LiveDeliveryChangeHandler<R: MessageQueueRepositoryTrait + 'static> {
    service: Arc<PickupMediatorService<R>>,
}

impl<R: MessageQueueRepositoryTrait + 'static> LiveDeliveryChangeHandler<R> {
    pub fn new(service: Arc<PickupMediatorService<R>>) -> Self {
        Self { service }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<R: MessageQueueRepositoryTrait + 'static> MessageHandler for LiveDeliveryChangeHandler<R> {
    fn supported_types(&self) -> Vec<String> {
        vec![LiveDeliveryChangeMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        message: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        // Parse live_delivery flag
        let live_delivery = message
            .message
            .body
            .get("live_delivery")
            .or_else(|| message.message.extra.get("live_delivery"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let connection_id = message
            .context
            .connection_id
            .ok_or_else(|| MessageHandlerError::InvalidMessage("Missing connection ID".into()))?;

        tracing::info!(
            connection_id = connection_id,
            live_delivery = live_delivery,
            "Live delivery change request"
        );

        // Get current queue count for the status response
        let message_count = self
            .service
            .get_queue_count(&connection_id)
            .await
            .unwrap_or(0);

        // Build status response with live_delivery flag
        let response = StatusMessage::new(message.message.id.clone(), message_count)
            .with_live_delivery(live_delivery);

        let didcomm_msg =
            build_status_response(&response).map_err(MessageHandlerError::ProcessingFailed)?;

        Ok(Some(OutboundMessage {
            message: didcomm_msg,
            to: message.context.from.clone().unwrap_or_default(),
            from: message.context.to.clone().unwrap_or_default(),
            connection_id: Some(connection_id),
        }))
    }
}

fn build_status_response(response: &StatusMessage) -> Result<didcomm::core::Message, String> {
    let mut body = serde_json::json!({
        "message_count": response.message_count,
    });

    if let Some(key) = &response.recipient_key {
        body["recipient_key"] = serde_json::json!(key);
    }
    if let Some(seconds) = response.longest_waited_seconds {
        body["longest_waited_seconds"] = serde_json::json!(seconds);
    }
    if let Some(bytes) = response.total_bytes {
        body["total_bytes"] = serde_json::json!(bytes);
    }
    if let Some(live) = response.live_delivery {
        body["live_delivery"] = serde_json::json!(live);
    }

    let msg = didcomm::core::MessageBuilder::new(StatusMessage::TYPE)
        .id(response.id.clone())
        .body(body);

    Ok(msg.build())
}
