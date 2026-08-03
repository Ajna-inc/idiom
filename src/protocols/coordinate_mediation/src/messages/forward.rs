use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Deserialize a `to` field that may be a string or an array of strings.
/// DIDComm v1 uses `"to": "did:..."` while v2 uses `"to": ["did:..."]`.
/// Takes the first element when given an array.
fn deserialize_string_or_first<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        Single(String),
        Vec(Vec<String>),
    }

    match StringOrVec::deserialize(deserializer)? {
        StringOrVec::Single(s) => Ok(s),
        StringOrVec::Vec(v) => v
            .into_iter()
            .next()
            .ok_or_else(|| serde::de::Error::custom("empty 'to' array")),
    }
}

/// Forward Message (RFC 0094)
///
/// Used by a mediator to forward a message to the intended recipient.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// The DID of the recipient
    #[serde(deserialize_with = "deserialize_string_or_first")]
    pub to: String,

    /// The encrypted message to forward
    #[serde(rename = "msg")]
    pub message: Value,
}

impl ForwardMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/routing/1.0/forward";

    /// Create a new forward message
    pub fn new(to: String, message: Value) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            to,
            message,
        }
    }

    /// Create with custom message ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_new_forward() {
        let encrypted_msg = json!({
            "protected": "...",
            "ciphertext": "..."
        });
        let msg = ForwardMessage::new("did:key:z6Mkk...".to_string(), encrypted_msg);
        assert_eq!(msg.msg_type, ForwardMessage::TYPE);
        assert_eq!(msg.to, "did:key:z6Mkk...");
    }

    #[test]
    fn test_serialization() {
        let encrypted_msg = json!({
            "protected": "...",
            "ciphertext": "..."
        });
        let msg = ForwardMessage::new("did:key:z6Mkk...".to_string(), encrypted_msg)
            .with_id("test-id".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("routing/1.0/forward"));
        assert!(json.contains("did:key:z6Mkk..."));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/routing/1.0/forward",
            "@id": "test-id",
            "to": "did:key:z6Mkk...",
            "msg": {
                "protected": "...",
                "ciphertext": "..."
            }
        }"#;
        let msg: ForwardMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
        assert_eq!(msg.to, "did:key:z6Mkk...");
    }
}
