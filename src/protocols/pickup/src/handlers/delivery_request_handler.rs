//! Delivery Request Handler
//!
//! Handles incoming delivery request messages (mediator side).

use crate::messages::{DeliveryRequestMessage, MessageDeliveryMessage};
use crate::repository::MessageQueueRepositoryTrait;
use crate::services::PickupMediatorService;
use async_trait::async_trait;
use didcomm::core::MessageBuilder;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for delivery request messages
///
/// This handler:
/// 1. Receives a delivery request from a recipient
/// 2. Returns queued messages as attachments
pub struct DeliveryRequestHandler<R: MessageQueueRepositoryTrait + 'static> {
    service: Arc<PickupMediatorService<R>>,
}

impl<R: MessageQueueRepositoryTrait + 'static> DeliveryRequestHandler<R> {
    /// Create a new handler
    pub fn new(service: Arc<PickupMediatorService<R>>) -> Self {
        Self { service }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<R: MessageQueueRepositoryTrait + 'static> MessageHandler for DeliveryRequestHandler<R> {
    fn supported_types(&self) -> Vec<String> {
        vec![DeliveryRequestMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        message: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        // Parse the request from the DIDComm message
        let request = parse_delivery_request(&message.message)
            .map_err(MessageHandlerError::InvalidMessage)?;

        // Get connection ID
        let connection_id = message
            .context
            .connection_id
            .ok_or_else(|| MessageHandlerError::InvalidMessage("Missing connection ID".into()))?;

        tracing::debug!(
            "Processing delivery request from connection {}, limit: {}, recipient_key: {:?}",
            connection_id,
            request.limit,
            request.recipient_key
        );

        // Process the request
        let response = self
            .service
            .process_delivery_request(request, &connection_id)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let attachment_count = response.attachments.len();
        tracing::info!(
            "Delivery response: {} messages delivered to connection {}",
            attachment_count,
            connection_id
        );

        // Build DIDComm response message
        let didcomm_msg = build_delivery_response(&response, &message.message.id)
            .map_err(MessageHandlerError::ProcessingFailed)?;

        Ok(Some(OutboundMessage {
            message: didcomm_msg,
            to: message.context.from.clone().unwrap_or_default(),
            from: message.context.to.clone().unwrap_or_default(),
            connection_id: Some(connection_id),
        }))
    }
}

/// Parse a DeliveryRequestMessage from a DIDComm Message
fn parse_delivery_request(msg: &didcomm::core::Message) -> Result<DeliveryRequestMessage, String> {
    let limit = msg
        .body
        .get("limit")
        .or_else(|| msg.extra.get("limit"))
        .and_then(|v| v.as_u64())
        .map(|l| l as u32)
        .unwrap_or(10); // Default to 10 if not specified

    let recipient_key = msg
        .body
        .get("recipient_key")
        .or_else(|| msg.extra.get("recipient_key"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(DeliveryRequestMessage {
        msg_type: msg.msg_type.clone(),
        id: msg.id.clone(),
        limit,
        recipient_key,
    })
}

/// Build a DIDComm Message from a MessageDeliveryMessage
fn build_delivery_response(
    response: &MessageDeliveryMessage,
    thread_id: &str,
) -> Result<didcomm::core::Message, String> {
    let mut body = serde_json::json!({});

    if let Some(key) = &response.recipient_key {
        body["recipient_key"] = serde_json::json!(key);
    }

    let mut builder = MessageBuilder::new(MessageDeliveryMessage::TYPE)
        .id(response.id.clone())
        .body(body)
        .thread(thread_id.to_string());

    // Add attachments
    for attachment in &response.attachments {
        builder = builder.add_attachment(attachment.clone());
    }

    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::InMemoryMessageQueueRepository;
    use didcomm::core::MessageBuilder;

    #[tokio::test]
    async fn test_handle_delivery_request() {
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

        let handler = DeliveryRequestHandler::new(service);

        // Create a proper DIDComm message for the request
        let didcomm_msg = MessageBuilder::new(DeliveryRequestMessage::TYPE)
            .body(serde_json::json!({"limit": 10}))
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

        // Verify response has attachments
        let outbound = response.unwrap();
        assert_eq!(outbound.message.msg_type, MessageDeliveryMessage::TYPE);
        assert!(outbound.message.attachments.is_some());
        assert_eq!(outbound.message.attachments.as_ref().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_handle_delivery_with_limit() {
        let repo = Arc::new(InMemoryMessageQueueRepository::new());
        let service = Arc::new(PickupMediatorService::new(repo.clone()));

        // Queue 5 messages
        for i in 0..5 {
            service
                .queue_message("conn-123", vec![], &format!("msg{}", i))
                .await
                .unwrap();
        }

        let handler = DeliveryRequestHandler::new(service);

        // Request only 2
        let didcomm_msg = MessageBuilder::new(DeliveryRequestMessage::TYPE)
            .body(serde_json::json!({"limit": 2}))
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
        let outbound = result.unwrap().unwrap();
        assert_eq!(outbound.message.attachments.as_ref().unwrap().len(), 2);
    }
}
