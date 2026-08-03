//! Basic Message Record
//!
//! Storage model for basic messages

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Role in a basic message exchange
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BasicMessageRole {
    /// Message sender
    Sender,
    /// Message receiver
    Receiver,
}

/// Basic Message Record
///
/// Persistent storage model for basic messages.
/// Records are stored with connection ID for querying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicMessageRecord {
    /// Record ID (same as message ID)
    pub id: String,

    /// Connection ID this message belongs to
    pub connection_id: String,

    /// Role (sender or receiver)
    pub role: BasicMessageRole,

    /// Message content
    pub content: String,

    /// When the message was sent (ISO 8601)
    pub sent_time: String,

    /// Thread ID (for threading messages)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,

    /// Parent thread ID (for replies)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_thread_id: Option<String>,

    /// When this record was created
    pub created_at: String,

    /// Storage tags for querying
    #[serde(default)]
    pub tags: BasicMessageTags,
}

/// Tags for querying basic message records
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BasicMessageTags {
    /// Connection ID tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,

    /// Role tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,

    /// Thread ID tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,

    /// Parent thread ID tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_thread_id: Option<String>,
}

impl BasicMessageRecord {
    /// Create a new basic message record
    pub fn new(
        id: impl Into<String>,
        connection_id: impl Into<String>,
        role: BasicMessageRole,
        content: impl Into<String>,
        sent_time: impl Into<String>,
    ) -> Self {
        let connection_id = connection_id.into();
        let role_str = match role {
            BasicMessageRole::Sender => "sender".to_string(),
            BasicMessageRole::Receiver => "receiver".to_string(),
        };

        Self {
            id: id.into(),
            connection_id: connection_id.clone(),
            role,
            content: content.into(),
            sent_time: sent_time.into(),
            thread_id: None,
            parent_thread_id: None,
            created_at: Utc::now().to_rfc3339(),
            tags: BasicMessageTags {
                connection_id: Some(connection_id),
                role: Some(role_str),
                thread_id: None,
                parent_thread_id: None,
            },
        }
    }

    /// Set thread information
    pub fn with_thread(
        mut self,
        thread_id: impl Into<String>,
        parent_thread_id: Option<String>,
    ) -> Self {
        let tid = thread_id.into();
        self.thread_id = Some(tid.clone());
        self.parent_thread_id = parent_thread_id.clone();
        self.tags.thread_id = Some(tid);
        self.tags.parent_thread_id = parent_thread_id;
        self
    }

    /// Get the record type for storage
    pub fn record_type() -> &'static str {
        "BasicMessageRecord"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_record() {
        let record = BasicMessageRecord::new(
            "msg-123",
            "conn-456",
            BasicMessageRole::Sender,
            "Hello",
            "2024-01-01T00:00:00Z",
        );

        assert_eq!(record.id, "msg-123");
        assert_eq!(record.connection_id, "conn-456");
        assert!(matches!(record.role, BasicMessageRole::Sender));
        assert_eq!(record.content, "Hello");
        assert!(record.thread_id.is_none());
    }

    #[test]
    fn test_record_with_thread() {
        let record = BasicMessageRecord::new(
            "msg-123",
            "conn-456",
            BasicMessageRole::Receiver,
            "Reply",
            "2024-01-01T00:00:00Z",
        )
        .with_thread("thread-789", Some("parent-000".to_string()));

        assert_eq!(record.thread_id, Some("thread-789".to_string()));
        assert_eq!(record.parent_thread_id, Some("parent-000".to_string()));
        assert_eq!(record.tags.thread_id, Some("thread-789".to_string()));
    }

    #[test]
    fn test_serialization() {
        let record = BasicMessageRecord::new(
            "msg-123",
            "conn-456",
            BasicMessageRole::Sender,
            "Test",
            "2024-01-01T00:00:00Z",
        );

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("msg-123"));
        assert!(json.contains("conn-456"));
        assert!(json.contains("sender"));
    }
}
