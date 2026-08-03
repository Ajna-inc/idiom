use crate::domain::DevicePlatform;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Per-connection device-token registration. One row per `connection_id` —
/// later `set-device-info` from the same connection overwrites the prior
/// row (one row per connection).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceInfoRecord {
    pub id: String,
    pub connection_id: String,
    pub device_token: String,
    pub device_platform: DevicePlatform,
    /// Optional Firebase project ID, useful when the mediator is configured
    /// with multiple Firebase apps (e.g. dev + prod). When empty, the
    /// mediator tries every configured project until one accepts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firebase_project_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl DeviceInfoRecord {
    pub fn new(
        connection_id: String,
        device_token: String,
        device_platform: DevicePlatform,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            connection_id,
            device_token,
            device_platform,
            firebase_project_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_project_id(mut self, project_id: String) -> Self {
        self.firebase_project_id = Some(project_id);
        self
    }
}

/// Tag keys used by the storage-backed repository to support
/// `find_by_connection_id` without a full scan.
pub struct DeviceInfoTags;

impl DeviceInfoTags {
    pub const CONNECTION_ID: &'static str = "connection_id";
    pub const DEVICE_PLATFORM: &'static str = "device_platform";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_assigns_fresh_id_and_timestamps() {
        let r = DeviceInfoRecord::new("conn".to_string(), "tok".to_string(), DevicePlatform::Ios);
        assert!(!r.id.is_empty());
        assert_eq!(r.created_at, r.updated_at);
        assert!(r.firebase_project_id.is_none());
    }

    #[test]
    fn project_id_optional() {
        let r = DeviceInfoRecord::new("c".to_string(), "t".to_string(), DevicePlatform::Android)
            .with_project_id("proj-1".to_string());
        assert_eq!(r.firebase_project_id.as_deref(), Some("proj-1"));
    }

    #[test]
    fn roundtrip_serde() {
        let r = DeviceInfoRecord::new("c".to_string(), "t".to_string(), DevicePlatform::Ios);
        let j = serde_json::to_string(&r).unwrap();
        let back: DeviceInfoRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
