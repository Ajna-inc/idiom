use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// DIDComm message type for FCM push notification device registration.
///
/// Aries RFC 0734. iOS and Android both use the **same**
/// `push-notifications-fcm/1.0` URI — the `device_platform` field tells the
/// mediator which APS / Android payload to attach to the outbound FCM v1
/// request. iOS apps use Firebase's APNS bridge (one FCM token per device).
pub const SET_DEVICE_INFO_TYPE: &str =
    "https://didcomm.org/push-notifications-fcm/1.0/set-device-info";

/// SetDeviceInfo message for registering FCM push notification tokens.
///
/// Per the protocol, both `device_token` and `device_platform` must
/// either both be set, or both be null (for unregistration via this same
/// message). A dedicated `delete-device-info` message also exists for
/// clarity — both flows are honoured by the mediator service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetDeviceInfoMessage {
    /// Message type URI
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Unique message identifier
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// FCM device token (null to unregister)
    pub device_token: Option<String>,

    /// Device platform: `"ios"` or `"android"` (null to unregister).
    pub device_platform: Option<String>,
}

impl SetDeviceInfoMessage {
    /// Register a device token for push notifications.
    pub fn new(device_token: String, device_platform: String) -> Self {
        Self {
            msg_type: SET_DEVICE_INFO_TYPE.to_string(),
            id: Uuid::new_v4().to_string(),
            device_token: Some(device_token),
            device_platform: Some(device_platform),
        }
    }

    /// Unregister — both fields null.
    pub fn unregister() -> Self {
        Self {
            msg_type: SET_DEVICE_INFO_TYPE.to_string(),
            id: Uuid::new_v4().to_string(),
            device_token: None,
            device_platform: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_unregister() {
        let msg = SetDeviceInfoMessage::new("tok".to_string(), "ios".to_string());
        assert_eq!(msg.msg_type, SET_DEVICE_INFO_TYPE);
        assert_eq!(msg.device_token.as_deref(), Some("tok"));
        assert_eq!(msg.device_platform.as_deref(), Some("ios"));

        let u = SetDeviceInfoMessage::unregister();
        assert!(u.device_token.is_none());
        assert!(u.device_platform.is_none());
    }

    #[test]
    fn roundtrip_serialization() {
        let msg = SetDeviceInfoMessage::new("tok".to_string(), "android".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        let back: SetDeviceInfoMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn parses_set_device_info_payload() {
        let json = r#"{
            "@type": "https://didcomm.org/push-notifications-fcm/1.0/set-device-info",
            "@id": "abc-123",
            "device_token": "fcm-token",
            "device_platform": "ios"
        }"#;
        let msg: SetDeviceInfoMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "abc-123");
        assert_eq!(msg.device_token.as_deref(), Some("fcm-token"));
    }
}
