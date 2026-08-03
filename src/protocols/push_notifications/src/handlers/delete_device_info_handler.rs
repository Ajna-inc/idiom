use crate::messages::DELETE_DEVICE_INFO_TYPE;
use crate::service::PushNotificationService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handles `delete-device-info`. Idempotent — no error if the connection
/// has no registration. No response message.
pub struct DeleteDeviceInfoHandler {
    service: Arc<PushNotificationService>,
}

impl DeleteDeviceInfoHandler {
    pub fn new(service: Arc<PushNotificationService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl MessageHandler for DeleteDeviceInfoHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![DELETE_DEVICE_INFO_TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        let connection_id = inbound.context.connection_id.clone().ok_or_else(|| {
            MessageHandlerError::InvalidMessage(
                "delete-device-info: no connection_id on inbound".into(),
            )
        })?;

        if let Err(e) = self.service.delete_device_info(&connection_id).await {
            tracing::warn!(
                connection_id = connection_id,
                error = %e,
                "delete-device-info: persist failed"
            );
        } else {
            tracing::info!(
                connection_id = connection_id,
                "delete-device-info: cleared registration"
            );
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::DeviceInfoRepository;
    use didcomm::core::Message as DidcommMessage;
    use didcomm::messaging::MessageContext;

    fn inbound(connection_id: Option<String>) -> InboundMessage {
        InboundMessage {
            message: DidcommMessage {
                id: "m".to_string(),
                msg_type: DELETE_DEVICE_INFO_TYPE.to_string(),
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
        let h = DeleteDeviceInfoHandler::new(svc);
        assert!(h.handle(inbound(None)).await.is_err());
    }

    #[tokio::test]
    async fn clears_registration() {
        let repo = Arc::new(DeviceInfoRepository::new());
        let svc = Arc::new(PushNotificationService::new(repo.clone()));
        svc.set_device_info("c", Some("t".to_string()), Some("ios".to_string()))
            .await
            .unwrap();
        let h = DeleteDeviceInfoHandler::new(svc.clone());
        h.handle(inbound(Some("c".to_string()))).await.unwrap();
        assert!(svc.find_record("c").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn idempotent_when_no_record() {
        let svc = Arc::new(PushNotificationService::new(Arc::new(
            DeviceInfoRepository::new(),
        )));
        let h = DeleteDeviceInfoHandler::new(svc);
        let r = h.handle(inbound(Some("c".to_string()))).await.unwrap();
        assert!(r.is_none());
    }
}
