use didcomm::core::models::Thread;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const GET_DEVICE_INFO_TYPE: &str =
    "https://didcomm.org/push-notifications-fcm/1.0/get-device-info";

/// `get-device-info` — wallet asks the mediator what it has stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetDeviceInfoMessage {
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,
    #[serde(rename = "@id", alias = "id")]
    pub id: String,
}

impl GetDeviceInfoMessage {
    pub fn new() -> Self {
        Self {
            msg_type: GET_DEVICE_INFO_TYPE.to_string(),
            id: Uuid::new_v4().to_string(),
        }
    }
}

impl Default for GetDeviceInfoMessage {
    fn default() -> Self {
        Self::new()
    }
}

pub const DEVICE_INFO_TYPE: &str = "https://didcomm.org/push-notifications-fcm/1.0/device-info";

/// `device-info` — mediator's response to `get-device-info`. `device_token`
/// and `device_platform` are null if no registration is stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceInfoMessage {
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,
    #[serde(rename = "@id", alias = "id")]
    pub id: String,
    #[serde(rename = "~thread")]
    pub thread: Thread,
    pub device_token: Option<String>,
    pub device_platform: Option<String>,
}

impl DeviceInfoMessage {
    pub fn new(thread_id: String, token: Option<String>, platform: Option<String>) -> Self {
        Self {
            msg_type: DEVICE_INFO_TYPE.to_string(),
            id: Uuid::new_v4().to_string(),
            thread: Thread {
                thid: Some(thread_id),
                pthid: None,
                sender_order: None,
                received_orders: None,
            },
            device_token: token,
            device_platform: platform,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_roundtrip() {
        let g = GetDeviceInfoMessage::new();
        let j = serde_json::to_string(&g).unwrap();
        let back: GetDeviceInfoMessage = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn device_info_with_registration() {
        let m = DeviceInfoMessage::new(
            "thr-1".to_string(),
            Some("tok".to_string()),
            Some("android".to_string()),
        );
        assert_eq!(m.thread.thid.as_deref(), Some("thr-1"));
        assert_eq!(m.device_token.as_deref(), Some("tok"));
        let j = serde_json::to_string(&m).unwrap();
        let back: DeviceInfoMessage = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn device_info_when_unregistered() {
        let m = DeviceInfoMessage::new("thr-1".to_string(), None, None);
        assert!(m.device_token.is_none());
        assert!(m.device_platform.is_none());
    }
}
