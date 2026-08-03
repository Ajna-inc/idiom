//! Queued message domain types for Message Pickup Protocol V2

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// State of a queued message
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum QueuedMessageState {
    /// Message is waiting to be delivered
    #[default]
    Pending,
    /// Message is currently being delivered (prevents duplicate delivery)
    Sending,
}

impl std::fmt::Display for QueuedMessageState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Sending => write!(f, "sending"),
        }
    }
}

/// A message queued at the mediator for later pickup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    /// Unique ID for this queue entry
    pub id: String,

    /// Connection ID this message is for (mediator's connection to recipient)
    pub connection_id: String,

    /// Recipient keys this message is addressed to
    /// Used to filter which messages a recipient can pick up
    pub recipient_keys: Vec<String>,

    /// The encrypted/packed DIDComm message
    /// This is the raw JSON string that was forwarded
    pub encrypted_message: String,

    /// When the message was received at the mediator
    pub received_at: DateTime<Utc>,

    /// Current state of the message
    pub state: QueuedMessageState,
}

impl QueuedMessage {
    /// Create a new queued message
    pub fn new(
        connection_id: String,
        recipient_keys: Vec<String>,
        encrypted_message: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            connection_id,
            recipient_keys,
            encrypted_message,
            received_at: Utc::now(),
            state: QueuedMessageState::Pending,
        }
    }

    /// Create with a specific ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Mark as sending (being delivered)
    pub fn mark_sending(&mut self) {
        self.state = QueuedMessageState::Sending;
    }

    /// Reset to pending (delivery failed)
    pub fn mark_pending(&mut self) {
        self.state = QueuedMessageState::Pending;
    }

    /// Check if message matches a recipient key filter
    pub fn matches_recipient_key(&self, key: Option<&str>) -> bool {
        match key {
            Some(k) => self.recipient_keys.iter().any(|rk| rk == k),
            None => true, // No filter means match all
        }
    }

    /// Get the age of this message in seconds
    pub fn age_seconds(&self) -> u64 {
        let now = Utc::now();
        let duration = now.signed_duration_since(self.received_at);
        duration.num_seconds().max(0) as u64
    }

    /// Get the byte size of the encrypted message
    pub fn byte_size(&self) -> usize {
        self.encrypted_message.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_queued_message() {
        let msg = QueuedMessage::new(
            "conn-123".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
            r#"{"encrypted": "data"}"#.to_string(),
        );

        assert_eq!(msg.connection_id, "conn-123");
        assert_eq!(msg.recipient_keys.len(), 1);
        assert_eq!(msg.state, QueuedMessageState::Pending);
        assert!(!msg.id.is_empty());
    }

    #[test]
    fn test_matches_recipient_key() {
        let msg = QueuedMessage::new(
            "conn-123".to_string(),
            vec!["key1".to_string(), "key2".to_string()],
            "{}".to_string(),
        );

        assert!(msg.matches_recipient_key(None));
        assert!(msg.matches_recipient_key(Some("key1")));
        assert!(msg.matches_recipient_key(Some("key2")));
        assert!(!msg.matches_recipient_key(Some("key3")));
    }

    #[test]
    fn test_state_transitions() {
        let mut msg = QueuedMessage::new("conn-123".to_string(), vec![], "{}".to_string());

        assert_eq!(msg.state, QueuedMessageState::Pending);

        msg.mark_sending();
        assert_eq!(msg.state, QueuedMessageState::Sending);

        msg.mark_pending();
        assert_eq!(msg.state, QueuedMessageState::Pending);
    }

    #[test]
    fn test_byte_size() {
        let msg = QueuedMessage::new("conn-123".to_string(), vec![], "12345678".to_string());
        assert_eq!(msg.byte_size(), 8);
    }

    #[test]
    fn test_serialization() {
        let msg = QueuedMessage::new(
            "conn-123".to_string(),
            vec!["key1".to_string()],
            "{}".to_string(),
        );
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("conn-123"));
        assert!(json.contains("pending"));
    }
}
