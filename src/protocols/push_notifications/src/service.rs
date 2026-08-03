use crate::domain::DevicePlatform;
use crate::error::{PushNotificationError, Result};
use crate::repository::{DeviceInfoRecord, DeviceInfoRepositoryTrait};
use std::str::FromStr;
use std::sync::Arc;

/// Outcome of applying a `set-device-info` message — used by the wallet API
/// and the handler so callers can tell whether something was actually
/// changed vs no-op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetOutcome {
    /// First registration for this connection.
    Created(DeviceInfoRecord),
    /// Pre-existing registration was overwritten (different token / platform).
    Updated(DeviceInfoRecord),
    /// `set` payload with both fields null — same as `delete`.
    Removed,
    /// Connection had no registration, and the payload was a no-op delete.
    NoChange,
}

/// Service layer for the mediator-side push-notifications protocol. Wraps a
/// `DeviceInfoRepositoryTrait` and applies the message-level state rules
/// (mismatched fields, "both null = delete", platform parsing).
#[derive(Clone)]
pub struct PushNotificationService {
    repo: Arc<dyn DeviceInfoRepositoryTrait>,
}

impl PushNotificationService {
    pub fn new(repo: Arc<dyn DeviceInfoRepositoryTrait>) -> Self {
        Self { repo }
    }

    /// Apply a `set-device-info` payload. `device_token` and `device_platform`
    /// must both be Some or both be None per the protocol.
    pub async fn set_device_info(
        &self,
        connection_id: &str,
        device_token: Option<String>,
        device_platform: Option<String>,
    ) -> Result<SetOutcome> {
        match (device_token, device_platform) {
            (Some(tok), Some(plat)) => {
                let plat_parsed = DevicePlatform::from_str(&plat)
                    .map_err(PushNotificationError::InvalidPlatform)?;
                let existing = self.repo.find_by_connection_id(connection_id).await?;
                let record = DeviceInfoRecord::new(connection_id.to_string(), tok, plat_parsed);
                let stored = self.repo.upsert(record).await?;
                Ok(if existing.is_some() {
                    SetOutcome::Updated(stored)
                } else {
                    SetOutcome::Created(stored)
                })
            }
            (None, None) => {
                let existing = self.repo.find_by_connection_id(connection_id).await?;
                if existing.is_some() {
                    self.repo.delete_by_connection_id(connection_id).await?;
                    Ok(SetOutcome::Removed)
                } else {
                    Ok(SetOutcome::NoChange)
                }
            }
            _ => Err(PushNotificationError::MismatchedFields),
        }
    }

    /// Explicit `delete-device-info`. Idempotent — silently succeeds when
    /// the connection has no registration.
    pub async fn delete_device_info(&self, connection_id: &str) -> Result<()> {
        self.repo.delete_by_connection_id(connection_id).await
    }

    /// `get-device-info` lookup. Returns `(token, platform)` or `(None, None)`.
    pub async fn get_device_info(
        &self,
        connection_id: &str,
    ) -> Result<(Option<String>, Option<String>)> {
        Ok(self
            .repo
            .find_by_connection_id(connection_id)
            .await?
            .map(|r| (Some(r.device_token), Some(r.device_platform.to_string())))
            .unwrap_or((None, None)))
    }

    /// Lookup the full record (used by the mediator's push notifier when
    /// it needs the project ID alongside the token).
    pub async fn find_record(&self, connection_id: &str) -> Result<Option<DeviceInfoRecord>> {
        self.repo.find_by_connection_id(connection_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::DeviceInfoRepository;

    fn fresh_service() -> PushNotificationService {
        let repo: Arc<dyn DeviceInfoRepositoryTrait> = Arc::new(DeviceInfoRepository::new());
        PushNotificationService::new(repo)
    }

    #[tokio::test]
    async fn set_creates_then_updates() {
        let svc = fresh_service();
        let outcome = svc
            .set_device_info("c1", Some("t1".to_string()), Some("ios".to_string()))
            .await
            .unwrap();
        assert!(matches!(outcome, SetOutcome::Created(_)));

        let outcome = svc
            .set_device_info("c1", Some("t2".to_string()), Some("android".to_string()))
            .await
            .unwrap();
        match outcome {
            SetOutcome::Updated(r) => {
                assert_eq!(r.device_token, "t2");
                assert_eq!(r.device_platform, DevicePlatform::Android);
            }
            _ => panic!("expected Updated"),
        }
    }

    #[tokio::test]
    async fn set_with_both_null_removes() {
        let svc = fresh_service();
        svc.set_device_info("c1", Some("t".to_string()), Some("ios".to_string()))
            .await
            .unwrap();

        let outcome = svc.set_device_info("c1", None, None).await.unwrap();
        assert_eq!(outcome, SetOutcome::Removed);

        let outcome = svc.set_device_info("c1", None, None).await.unwrap();
        assert_eq!(outcome, SetOutcome::NoChange);
    }

    #[tokio::test]
    async fn mismatched_fields_rejected() {
        let svc = fresh_service();
        let err = svc
            .set_device_info("c1", Some("t".to_string()), None)
            .await
            .unwrap_err();
        assert!(matches!(err, PushNotificationError::MismatchedFields));

        let err = svc
            .set_device_info("c1", None, Some("ios".to_string()))
            .await
            .unwrap_err();
        assert!(matches!(err, PushNotificationError::MismatchedFields));
    }

    #[tokio::test]
    async fn invalid_platform_rejected() {
        let svc = fresh_service();
        let err = svc
            .set_device_info("c1", Some("t".to_string()), Some("symbian".to_string()))
            .await
            .unwrap_err();
        assert!(matches!(err, PushNotificationError::InvalidPlatform(_)));
    }

    #[tokio::test]
    async fn delete_idempotent() {
        let svc = fresh_service();
        svc.delete_device_info("c1").await.unwrap();
        svc.set_device_info("c1", Some("t".to_string()), Some("ios".to_string()))
            .await
            .unwrap();
        svc.delete_device_info("c1").await.unwrap();
        svc.delete_device_info("c1").await.unwrap();
        let (tok, plat) = svc.get_device_info("c1").await.unwrap();
        assert!(tok.is_none() && plat.is_none());
    }

    #[tokio::test]
    async fn get_returns_platform_lowercase() {
        let svc = fresh_service();
        svc.set_device_info("c1", Some("t".to_string()), Some("iOS".to_string()))
            .await
            .unwrap();
        let (tok, plat) = svc.get_device_info("c1").await.unwrap();
        assert_eq!(tok.as_deref(), Some("t"));
        assert_eq!(plat.as_deref(), Some("ios"));
    }
}
