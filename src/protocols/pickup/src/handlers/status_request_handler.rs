//! Status Request Handler
//!
//! Handles incoming status request messages (mediator side).

use crate::messages::{StatusMessage, StatusRequestMessage};
use crate::repository::MessageQueueRepositoryTrait;
use crate::services::PickupMediatorService;
use async_trait::async_trait;
use didcomm::core::MessageBuilder;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for status request messages
///
/// This handler:
/// 1. Receives a status request from a recipient
/// 2. Returns the count of queued messages
pub struct StatusRequestHandler<R: MessageQueueRepositoryTrait + 'static> {
    service: Arc<PickupMediatorService<R>>,
}

impl<R: MessageQueueRepositoryTrait + 'static> StatusRequestHandler<R> {
    /// Create a new handler
    pub fn new(service: Arc<PickupMediatorService<R>>) -> Self {
        Self { service }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<R: MessageQueueRepositoryTrait + 'static> MessageHandler for StatusRequestHandler<R> {
    fn supported_types(&self) -> Vec<String> {
        vec![StatusRequestMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        message: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        // Parse the request from the DIDComm message body/extra
        let request =
            parse_status_request(&message.message).map_err(MessageHandlerError::InvalidMessage)?;

        // Get connection ID
        let connection_id = message
            .context
            .connection_id
            .ok_or_else(|| MessageHandlerError::InvalidMessage("Missing connection ID".into()))?;

        tracing::debug!(
            "Processing status request from connection {}, recipient_key: {:?}",
            connection_id,
            request.recipient_key
        );

        // Process the request
        let response = self
            .service
            .process_status_request(request, &connection_id)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        tracing::info!(
            "Status response: {} messages queued for connection {}",
            response.message_count,
            connection_id
        );

        // Build DIDComm response message
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

/// Parse a StatusRequestMessage from a DIDComm Message
fn parse_status_request(msg: &didcomm::core::Message) -> Result<StatusRequestMessage, String> {
    // The request may have recipient_key in the body or extra
    let recipient_key = msg
        .body
        .get("recipient_key")
        .or_else(|| msg.extra.get("recipient_key"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(StatusRequestMessage {
        msg_type: msg.msg_type.clone(),
        id: msg.id.clone(),
        recipient_key,
    })
}

/// Build a DIDComm Message from a StatusMessage
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

    let mut builder = MessageBuilder::new(StatusMessage::TYPE)
        .id(response.id.clone())
        .body(body);

    // Add thread decorator - use thread ID from response
    if let Some(thid) = response.thread.thid.as_ref() {
        builder = builder.thread(thid.clone());
    }

    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::InMemoryMessageQueueRepository;
    use didcomm::core::MessageBuilder;

    #[tokio::test]
    async fn test_handle_status_request() {
        let repo = Arc::new(InMemoryMessageQueueRepository::new());
        let service = Arc::new(PickupMediatorService::new(repo.clone()));

        // Queue some messages
        service
            .queue_message("conn-123", vec![], "msg1")
            .await
            .unwrap();
        service
            .queue_message("conn-123", vec![], "msg2")
            .await
            .unwrap();

        let handler = StatusRequestHandler::new(service);

        // Create a proper DIDComm message for the request
        let didcomm_msg = MessageBuilder::new(StatusRequestMessage::TYPE)
            .body(serde_json::json!({}))
            .build();

        let inbound = InboundMessage {
            message: didcomm_msg.clone(),
            context: didcomm::messaging::MessageContext {
                from: Some("did:peer:recipient".to_string()),
                to: Some("did:peer:mediator".to_string()),
                thread_id: Some(didcomm_msg.id.clone()),
                parent_thread_id: None,
                connection_id: Some("conn-123".to_string()),
                encrypted: true,
                authenticated: true,
                sender_endpoint: None,
                raw_plaintext: None,
            },
        };

        let result = handler.handle(inbound).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.is_some());

        // Verify response has correct message count
        let outbound = response.unwrap();
        assert_eq!(outbound.message.msg_type, StatusMessage::TYPE);
        let count = outbound
            .message
            .body
            .get("message_count")
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(count, 2);
    }
}
