//! Live Delivery Change message for Message Pickup Protocol V2 (RFC 0685)

use serde::{Deserialize, Serialize};

/// Live Delivery Change Message (RFC 0685)
///
/// Sent by the recipient to enable or disable live delivery mode.
/// When live delivery is enabled, the mediator pushes messages over the
/// existing WebSocket connection instead of queuing them for polling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveDeliveryChangeMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// Whether to enable or disable live delivery
    pub live_delivery: bool,
}

impl LiveDeliveryChangeMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/messagepickup/2.0/live-delivery-change";

    /// Create a live-delivery-change message to enable live delivery
    pub fn enable() -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            live_delivery: true,
        }
    }

    /// Create a live-delivery-change message to disable live delivery
    pub fn disable() -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            live_delivery: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enable() {
        let msg = LiveDeliveryChangeMessage::enable();
        assert_eq!(msg.msg_type, LiveDeliveryChangeMessage::TYPE);
        assert!(msg.live_delivery);
        assert!(!msg.id.is_empty());
    }

    #[test]
    fn test_disable() {
        let msg = LiveDeliveryChangeMessage::disable();
        assert!(!msg.live_delivery);
    }

    #[test]
    fn test_serialization() {
        let msg = LiveDeliveryChangeMessage::enable();
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("live-delivery-change"));
        assert!(json.contains("\"live_delivery\":true"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/messagepickup/2.0/live-delivery-change",
            "@id": "test-id",
            "live_delivery": true
        }"#;
        let msg: LiveDeliveryChangeMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
        assert!(msg.live_delivery);
    }
}
