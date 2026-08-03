use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DELETE_DEVICE_INFO_TYPE: &str =
    "https://didcomm.org/push-notifications-fcm/1.0/delete-device-info";

/// Explicit "remove my device" message. Functionally equivalent to
/// `SetDeviceInfoMessage::unregister()` but the dedicated type makes intent
/// readable in logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteDeviceInfoMessage {
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,
    #[serde(rename = "@id", alias = "id")]
    pub id: String,
}

impl DeleteDeviceInfoMessage {
    pub fn new() -> Self {
        Self {
            msg_type: DELETE_DEVICE_INFO_TYPE.to_string(),
            id: Uuid::new_v4().to_string(),
        }
    }
}

impl Default for DeleteDeviceInfoMessage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let m = DeleteDeviceInfoMessage::new();
        let j = serde_json::to_string(&m).unwrap();
        let back: DeleteDeviceInfoMessage = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
        assert_eq!(m.msg_type, DELETE_DEVICE_INFO_TYPE);
    }
}
