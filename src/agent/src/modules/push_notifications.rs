//! Wallet-side push-notifications module.
//!
//! Sends the three wallet-originated DIDComm messages of the
//! `push-notifications-fcm/1.0` protocol — `set-device-info`,
//! `delete-device-info`, `get-device-info` — over the granted mediator
//! connection. Provides the wallet-side API for the FCM push-notifications
//! protocol.

use crate::error::{AgentError, Result};
use crate::messaging::DidCommSender;
use protocol_connections::ConnectionRepositoryTrait;
use protocol_coordinate_mediation::MediationRepositoryTrait;
use protocol_push_notifications::{
    DeleteDeviceInfoMessage, GetDeviceInfoMessage, SetDeviceInfoMessage,
};
use std::sync::Arc;

/// Wallet API for push notifications.
#[derive(Clone)]
pub struct PushNotificationsModule {
    connection_repository: Arc<dyn ConnectionRepositoryTrait>,
    mediation_repository: Arc<dyn MediationRepositoryTrait>,
    sender: Arc<DidCommSender>,
}

impl PushNotificationsModule {
    pub fn new(
        connection_repository: Arc<dyn ConnectionRepositoryTrait>,
        mediation_repository: Arc<dyn MediationRepositoryTrait>,
        sender: Arc<DidCommSender>,
    ) -> Self {
        Self {
            connection_repository,
            mediation_repository,
            sender,
        }
    }

    /// Register a device token + platform with the active mediator.
    ///
    /// `platform` should be `"ios"` or `"android"`. Validation happens
    /// server-side; on parse error the mediator silently drops the update.
    pub async fn set_device_token(
        &self,
        device_token: impl Into<String>,
        platform: impl Into<String>,
    ) -> Result<()> {
        let msg = SetDeviceInfoMessage::new(device_token.into(), platform.into());
        self.send_to_mediator(&msg).await
    }

    /// Unregister the wallet from push notifications.
    pub async fn delete_device_token(&self) -> Result<()> {
        let msg = DeleteDeviceInfoMessage::new();
        self.send_to_mediator(&msg).await
    }

    /// Send a `get-device-info` query. The mediator replies in the same
    /// thread with a `device-info` message (the wallet's inbound handler
    /// would normally route it).
    pub async fn get_device_info(&self) -> Result<String> {
        let msg = GetDeviceInfoMessage::new();
        let id = msg.id.clone();
        self.send_to_mediator(&msg).await?;
        Ok(id)
    }

    /// Resolve the mediator connection id from the granted mediation record
    /// and send `msg` over it via the canonical sender. Returns
    /// `AgentError::Mediation` when no granted mediation exists.
    async fn send_to_mediator<M: serde::Serialize>(&self, msg: &M) -> Result<()> {
        let conn = self.mediator_connection().await?;
        self.sender
            .send_via_connection(&conn, msg)
            .await
            .map(|_| ())
    }

    async fn mediator_connection(&self) -> Result<protocol_connections::ConnectionRecord> {
        use protocol_coordinate_mediation::MediationState;
        let granted = self
            .mediation_repository
            .get_all()
            .await
            .map_err(|e| AgentError::Mediation(format!("get_all mediations: {}", e)))?;
        let m = granted
            .into_iter()
            .find(|r| r.state == MediationState::Granted)
            .ok_or_else(|| {
                AgentError::Mediation(
                    "No granted mediation — call setup_mediation first".to_string(),
                )
            })?;
        let conn = self
            .connection_repository
            .find_by_id(&m.connection_id)
            .await
            .map_err(|e| AgentError::Connections(e.to_string()))?
            .ok_or_else(|| {
                AgentError::Connections(format!(
                    "Mediator connection {} not found",
                    m.connection_id
                ))
            })?;
        Ok(conn)
    }
}
