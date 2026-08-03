use crate::domain::KeylistAction;
use serde::{Deserialize, Serialize};

/// A single keylist update
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeylistUpdate {
    /// The recipient key to add or remove
    pub recipient_key: String,

    /// The action to perform
    pub action: KeylistAction,
}

impl KeylistUpdate {
    /// Create a new keylist update
    pub fn new(recipient_key: String, action: KeylistAction) -> Self {
        Self {
            recipient_key,
            action,
        }
    }

    /// Create an "add" update
    pub fn add(recipient_key: String) -> Self {
        Self::new(recipient_key, KeylistAction::Add)
    }

    /// Create a "remove" update
    pub fn remove(recipient_key: String) -> Self {
        Self::new(recipient_key, KeylistAction::Remove)
    }
}

/// Keylist Update Message (RFC 0211)
///
/// Sent by the recipient to update the keylist at the mediator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeylistUpdateMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// List of updates to apply
    pub updates: Vec<KeylistUpdate>,
}

impl KeylistUpdateMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/coordinate-mediation/1.0/keylist-update";

    /// Create a new keylist update message
    pub fn new(updates: Vec<KeylistUpdate>) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            updates,
        }
    }

    /// Create with custom message ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Add an update to the message
    pub fn add_update(mut self, update: KeylistUpdate) -> Self {
        self.updates.push(update);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keylist_update_helpers() {
        let add = KeylistUpdate::add("did:key:z6Mkk...".to_string());
        assert_eq!(add.action, KeylistAction::Add);

        let remove = KeylistUpdate::remove("did:key:z6Mkk...".to_string());
        assert_eq!(remove.action, KeylistAction::Remove);
    }

    #[test]
    fn test_new_keylist_update_message() {
        let updates = vec![
            KeylistUpdate::add("did:key:z6Mkk1...".to_string()),
            KeylistUpdate::remove("did:key:z6Mkk2...".to_string()),
        ];
        let msg = KeylistUpdateMessage::new(updates);
        assert_eq!(msg.msg_type, KeylistUpdateMessage::TYPE);
        assert_eq!(msg.updates.len(), 2);
    }

    #[test]
    fn test_serialization() {
        let updates = vec![KeylistUpdate::add("did:key:z6Mkk...".to_string())];
        let msg = KeylistUpdateMessage::new(updates).with_id("test-id".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("keylist-update"));
        assert!(json.contains("did:key:z6Mkk..."));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/coordinate-mediation/1.0/keylist-update",
            "@id": "test-id",
            "updates": [
                {
                    "recipient_key": "did:key:z6Mkk...",
                    "action": "add"
                }
            ]
        }"#;
        let msg: KeylistUpdateMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
        assert_eq!(msg.updates.len(), 1);
    }
}
