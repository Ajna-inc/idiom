use crate::messages::{DeviceInfoMessage, GET_DEVICE_INFO_TYPE};
use crate::service::PushNotificationService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Placeholder DID used when the inbound message lacks an authcrypt-verified
/// `to`/`from`. The reply still carries a well-formed (if unroutable) DID.
const UNKNOWN_DID: &str = "did:unknown";

/// Handles `get-device-info`. Replies with a `device-info` message in the
/// same thread carrying whatever is currently stored (or both fields null
/// when nothing is registered).
pub struct GetDeviceInfoHandler {
    service: Arc<PushNotificationService>,
}

impl GetDeviceInfoHandler {
    pub fn new(service: Arc<PushNotificationService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl MessageHandler for GetDeviceInfoHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![GET_DEVICE_INFO_TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        let connection_id = inbound.context.connection_id.clone().ok_or_else(|| {
            MessageHandlerError::InvalidMessage(
                "get-device-info: no connection_id on inbound".into(),
            )
        })?;

        let (token, platform) = self
            .service
            .get_device_info(&connection_id)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let resp = DeviceInfoMessage::new(inbound.message.id.clone(), token, platform);
        let body = serde_json::to_value(&resp)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let our_did = inbound
            .context
            .to
            .clone()
            .unwrap_or_else(|| UNKNOWN_DID.to_string());
        let their_did = inbound
            .context
            .from
            .clone()
            .unwrap_or_else(|| UNKNOWN_DID.to_string());

        let mut message = didcomm::core::Message {
            id: resp.id.clone(),
            msg_type: resp.msg_type.clone(),
            body,
            from: Some(our_did.clone()),
            to: Some(vec![their_did.clone()]),
            thread: Some(didcomm::core::models::Thread {
                thid: Some(inbound.message.id.clone()),
                pthid: None,
                sender_order: None,
                received_orders: None,
            }),
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: Default::default(),
        };
        // Encourage inline response for behind-NAT wallets.
        message.extra.insert(
            "~transport".to_string(),
            serde_json::json!({"return_route": "all"}),
        );

        Ok(Some(OutboundMessage {
            message,
            to: their_did,
            from: our_did,
            connection_id: Some(connection_id),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::DeviceInfoRepository;
    use didcomm::messaging::MessageContext;

    fn inbound(connection_id: Option<String>) -> InboundMessage {
        InboundMessage {
            message: didcomm::core::Message {
                id: "get-1".to_string(),
                msg_type: GET_DEVICE_INFO_TYPE.to_string(),
                body: serde_json::json!({}),
                from: Some("did:wallet".to_string()),
                to: Some(vec!["did:med".to_string()]),
                thread: None,
                pthid: None,
                created_time: None,
                expires_time: None,
                attachments: None,
                extra: Default::default(),
            },
            context: MessageContext {
                from: Some("did:wallet".to_string()),
                to: Some("did:med".to_string()),
                thread_id: None,
                parent_thread_id: None,
                connection_id,
                encrypted: true,
                authenticated: true,
                sender_endpoint: None,
            },
        }
    }

    #[tokio::test]
    async fn requires_connection_id() {
        let svc = Arc::new(PushNotificationService::new(Arc::new(
            DeviceInfoRepository::new(),
        )));
        let h = GetDeviceInfoHandler::new(svc);
        assert!(h.handle(inbound(None)).await.is_err());
    }

    #[tokio::test]
    async fn returns_nulls_when_unregistered() {
        let svc = Arc::new(PushNotificationService::new(Arc::new(
            DeviceInfoRepository::new(),
        )));
        let h = GetDeviceInfoHandler::new(svc);
        let out = h
            .handle(inbound(Some("c".to_string())))
            .await
            .unwrap()
            .unwrap();
        let parsed: DeviceInfoMessage = serde_json::from_value(out.message.body).unwrap();
        assert!(parsed.device_token.is_none());
        assert!(parsed.device_platform.is_none());
        assert_eq!(parsed.thread.thid.as_deref(), Some("get-1"));
    }

    #[tokio::test]
    async fn returns_stored_registration() {
        let svc = Arc::new(PushNotificationService::new(Arc::new(
            DeviceInfoRepository::new(),
        )));
        svc.set_device_info("c", Some("tok".to_string()), Some("ios".to_string()))
            .await
            .unwrap();
        let h = GetDeviceInfoHandler::new(svc);
        let out = h
            .handle(inbound(Some("c".to_string())))
            .await
            .unwrap()
            .unwrap();
        let parsed: DeviceInfoMessage = serde_json::from_value(out.message.body).unwrap();
        assert_eq!(parsed.device_token.as_deref(), Some("tok"));
        assert_eq!(parsed.device_platform.as_deref(), Some("ios"));
    }

    #[tokio::test]
    async fn response_carries_return_route_decorator() {
        let svc = Arc::new(PushNotificationService::new(Arc::new(
            DeviceInfoRepository::new(),
        )));
        let h = GetDeviceInfoHandler::new(svc);
        let out = h
            .handle(inbound(Some("c".to_string())))
            .await
            .unwrap()
            .unwrap();
        let transport = out.message.extra.get("~transport").unwrap();
        assert_eq!(transport["return_route"], "all");
    }
}
