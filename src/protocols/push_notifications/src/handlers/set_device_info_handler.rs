use crate::messages::{SetDeviceInfoMessage, SET_DEVICE_INFO_TYPE};
use crate::service::{PushNotificationService, SetOutcome};
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handles `https://didcomm.org/push-notifications-fcm/1.0/set-device-info`.
///
/// Fire-and-forget from the wallet's perspective — no response. Errors are
/// logged and swallowed so a bad `set` doesn't tear down the existing
/// connection.
pub struct SetDeviceInfoHandler {
    service: Arc<PushNotificationService>,
}

impl SetDeviceInfoHandler {
    pub fn new(service: Arc<PushNotificationService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl MessageHandler for SetDeviceInfoHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![SET_DEVICE_INFO_TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        let connection_id = inbound.context.connection_id.clone().ok_or_else(|| {
            MessageHandlerError::InvalidMessage(
                "set-device-info: no connection_id on inbound (must be over an active connection)"
                    .into(),
            )
        })?;

        let msg: SetDeviceInfoMessage = serde_json::from_value(serde_json::json!({
            "@type": inbound.message.msg_type,
            "@id": inbound.message.id,
            "device_token": inbound.message.body.get("device_token"),
            "device_platform": inbound.message.body.get("device_platform"),
        }))
        .map_err(|e| {
            MessageHandlerError::InvalidMessage(format!("set-device-info parse: {}", e))
        })?;

        match self
            .service
            .set_device_info(&connection_id, msg.device_token, msg.device_platform)
            .await
        {
            Ok(SetOutcome::Created(r)) => {
                tracing::info!(
                    connection_id = connection_id,
                    platform = %r.device_platform,
                    "set-device-info: created"
                );
            }
            Ok(SetOutcome::Updated(r)) => {
                tracing::info!(
                    connection_id = connection_id,
                    platform = %r.device_platform,
                    "set-device-info: token rotated"
                );
            }
            Ok(SetOutcome::Removed) => {
                tracing::info!(
                    connection_id = connection_id,
                    "set-device-info: both fields null → unregister"
                );
            }
            Ok(SetOutcome::NoChange) => {
                tracing::debug!(
                    connection_id = connection_id,
                    "set-device-info: no-op (both null on unregistered connection)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    connection_id = connection_id,
                    error = %e,
                    "set-device-info: persist failed"
                );
            }
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
    use serde_json::json;

    fn make_inbound(connection_id: Option<String>, body: serde_json::Value) -> InboundMessage {
        InboundMessage {
            message: DidcommMessage {
                id: "msg-1".to_string(),
                msg_type: SET_DEVICE_INFO_TYPE.to_string(),
                body,
                from: Some("did:peer:1zWallet".to_string()),
                to: Some(vec!["did:peer:1zMediator".to_string()]),
                thread: None,
                pthid: None,
                created_time: None,
                expires_time: None,
                attachments: None,
                extra: Default::default(),
            },
            context: MessageContext {
                from: Some("did:peer:1zWallet".to_string()),
                to: Some("did:peer:1zMediator".to_string()),
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
    async fn missing_connection_id_errors() {
        let svc = Arc::new(PushNotificationService::new(Arc::new(
            DeviceInfoRepository::new(),
        )));
        let h = SetDeviceInfoHandler::new(svc);
        let r = h
            .handle(make_inbound(
                None,
                json!({
                    "device_token": "t",
                    "device_platform": "ios"
                }),
            ))
            .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn registers_a_token() {
        let repo = Arc::new(DeviceInfoRepository::new());
        let svc = Arc::new(PushNotificationService::new(repo.clone()));
        let h = SetDeviceInfoHandler::new(svc.clone());

        h.handle(make_inbound(
            Some("conn-1".to_string()),
            json!({
                "device_token": "tok-A",
                "device_platform": "android"
            }),
        ))
        .await
        .unwrap();

        let stored = svc.find_record("conn-1").await.unwrap().unwrap();
        assert_eq!(stored.device_token, "tok-A");
    }

    #[tokio::test]
    async fn both_null_clears_registration() {
        let repo = Arc::new(DeviceInfoRepository::new());
        let svc = Arc::new(PushNotificationService::new(repo));
        let h = SetDeviceInfoHandler::new(svc.clone());

        h.handle(make_inbound(
            Some("c".to_string()),
            json!({
                "device_token": "t",
                "device_platform": "ios"
            }),
        ))
        .await
        .unwrap();
        h.handle(make_inbound(
            Some("c".to_string()),
            json!({
                "device_token": null,
                "device_platform": null
            }),
        ))
        .await
        .unwrap();

        assert!(svc.find_record("c").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn invalid_platform_swallowed_no_response() {
        let svc = Arc::new(PushNotificationService::new(Arc::new(
            DeviceInfoRepository::new(),
        )));
        let h = SetDeviceInfoHandler::new(svc);
        let r = h
            .handle(make_inbound(
                Some("c".to_string()),
                json!({
                    "device_token": "t",
                    "device_platform": "symbian"
                }),
            ))
            .await
            .unwrap();
        // Errors are logged + swallowed; no auto-response.
        assert!(r.is_none());
    }
}
