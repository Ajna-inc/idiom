use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Deserialize a field that can be either a single string or an array of strings,
/// wrapped in Option. Handles the DIDComm v1 (`"to": "did:..."`) vs v2 (`"to": ["did:..."]`) mismatch.
fn deserialize_string_or_vec_opt<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        Vec(Vec<String>),
        Single(String),
    }

    let result: Option<StringOrVec> = Option::deserialize(deserializer)?;
    Ok(result.map(|v| match v {
        StringOrVec::Vec(vec) => vec,
        StringOrVec::Single(s) => vec![s],
    }))
}

/// DIDComm Message (plaintext)
///
/// Represents a DIDComm message before encryption or after decryption.
/// Follows DIDComm v2 specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    /// Unique message identifier
    #[serde(alias = "@id")]
    pub id: String,

    /// Message type (e.g., "https://didcomm.org/basicmessage/2.0/message")
    #[serde(rename = "type", alias = "@type")]
    pub msg_type: String,

    /// Message body (protocol-specific content)
    #[serde(default)]
    pub body: serde_json::Value,

    /// Sender DID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,

    /// Recipient DIDs (optional)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_string_or_vec_opt"
    )]
    pub to: Option<Vec<String>>,

    /// Thread decorator for correlation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread: Option<Thread>,

    /// Parent thread ID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pthid: Option<String>,

    /// Created timestamp (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<i64>,

    /// Expires timestamp (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_time: Option<i64>,

    /// Attachments (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<Attachment>>,

    /// Additional fields (decorators, etc.)
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Thread decorator for message correlation
///
/// In DIDComm, when thid is not present, the message @id
/// should be used as the implicit thread ID. This is common in the first
/// message of a protocol exchange (e.g., DID Exchange request).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Thread {
    /// Thread ID (optional - if not present, use message @id)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thid: Option<String>,

    /// Parent thread ID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pthid: Option<String>,

    /// Sender order (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_order: Option<u32>,

    /// Received orders (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_orders: Option<HashMap<String, u32>>,
}

/// Attachment in a DIDComm message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Attachment {
    /// Attachment ID. Emitted as `@id` on the wire;
    /// we deserialize either `id` or `@id` (RFC 0044 attachment decorator
    /// uses `@id` in v1, plain `id` in v2). Serializing always uses `id`.
    #[serde(rename = "id", alias = "@id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Filename
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,

    /// Media type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Last modified time. Emitted as an ISO 8601 string on the wire.
    /// We keep this as a free-form string so we don't tie ourselves to a
    /// specific date library on the wire side; callers that need a
    /// `DateTime` parse it themselves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lastmod_time: Option<String>,

    /// Byte count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_count: Option<usize>,

    /// Data
    pub data: AttachmentData,
}

/// Attachment data formats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum AttachmentData {
    /// Base64-encoded data
    Base64 { base64: String },
    /// JSON data
    Json { json: serde_json::Value },
    /// External link
    Links { links: Vec<String> },
}

impl Message {
    /// Create a new message with minimal required fields
    pub fn new(id: String, msg_type: String, body: serde_json::Value) -> Self {
        Self {
            id,
            msg_type,
            body,
            from: None,
            to: None,
            thread: None,
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: HashMap::new(),
        }
    }

    /// Builder pattern for constructing messages
    pub fn builder(msg_type: impl Into<String>) -> MessageBuilder {
        MessageBuilder::new(msg_type)
    }

    /// Get thread ID (from thread decorator or message ID)
    ///
    /// Returns the thread ID in this order:
    /// 1. If thread.thid is present, use it
    /// 2. Otherwise, use the message @id (implicit thread ID)
    pub fn thread_id(&self) -> &str {
        self.thread
            .as_ref()
            .and_then(|t| t.thid.as_deref())
            .unwrap_or(&self.id)
    }

    /// Check if this message is part of a thread
    pub fn has_thread(&self) -> bool {
        self.thread.is_some()
    }
}

/// Builder for constructing DIDComm messages
pub struct MessageBuilder {
    id: String,
    msg_type: String,
    body: serde_json::Value,
    from: Option<String>,
    to: Option<Vec<String>>,
    thread: Option<Thread>,
    pthid: Option<String>,
    created_time: Option<i64>,
    expires_time: Option<i64>,
    attachments: Option<Vec<Attachment>>,
    extra: HashMap<String, serde_json::Value>,
}

impl MessageBuilder {
    /// Create a new message builder
    pub fn new(msg_type: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            msg_type: msg_type.into(),
            body: serde_json::Value::Object(serde_json::Map::new()),
            from: None,
            to: None,
            thread: None,
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: HashMap::new(),
        }
    }

    /// Set message ID
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Set message body
    pub fn body(mut self, body: serde_json::Value) -> Self {
        self.body = body;
        self
    }

    /// Set sender DID
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Set recipient DIDs
    pub fn to(mut self, to: Vec<String>) -> Self {
        self.to = Some(to);
        self
    }

    /// Add a single recipient
    pub fn add_recipient(mut self, recipient: impl Into<String>) -> Self {
        self.to.get_or_insert_with(Vec::new).push(recipient.into());
        self
    }

    /// Set thread
    pub fn thread(mut self, thid: impl Into<String>) -> Self {
        self.thread = Some(Thread {
            thid: Some(thid.into()),
            pthid: None,
            sender_order: None,
            received_orders: None,
        });
        self
    }

    /// Set thread with parent thread ID
    pub fn thread_with_parent(mut self, thid: impl Into<String>, pthid: impl Into<String>) -> Self {
        self.thread = Some(Thread {
            thid: Some(thid.into()),
            pthid: Some(pthid.into()),
            sender_order: None,
            received_orders: None,
        });
        self
    }

    /// Set parent thread ID
    pub fn pthid(mut self, pthid: impl Into<String>) -> Self {
        self.pthid = Some(pthid.into());
        self
    }

    /// Set created time (Unix timestamp)
    pub fn created_time(mut self, time: i64) -> Self {
        self.created_time = Some(time);
        self
    }

    /// Set expires time (Unix timestamp)
    pub fn expires_time(mut self, time: i64) -> Self {
        self.expires_time = Some(time);
        self
    }

    /// Add an attachment
    pub fn add_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments
            .get_or_insert_with(Vec::new)
            .push(attachment);
        self
    }

    /// Add extra field (decorator)
    pub fn add_extra(mut self, key: String, value: serde_json::Value) -> Self {
        self.extra.insert(key, value);
        self
    }

    /// Build the message
    pub fn build(self) -> Message {
        Message {
            id: self.id,
            msg_type: self.msg_type,
            body: self.body,
            from: self.from,
            to: self.to,
            thread: self.thread,
            pthid: self.pthid,
            created_time: self.created_time,
            expires_time: self.expires_time,
            attachments: self.attachments,
            extra: self.extra,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_new() {
        let msg = Message::new(
            "test-id".to_string(),
            "https://didcomm.org/test/1.0/message".to_string(),
            serde_json::json!({"key": "value"}),
        );

        assert_eq!(msg.id, "test-id");
        assert_eq!(msg.msg_type, "https://didcomm.org/test/1.0/message");
        assert_eq!(msg.body, serde_json::json!({"key": "value"}));
        assert!(msg.from.is_none());
        assert!(msg.to.is_none());
    }

    #[test]
    fn test_message_builder() {
        let msg = Message::builder("https://didcomm.org/basicmessage/2.0/message")
            .id("msg-123")
            .body(serde_json::json!({"content": "Hello"}))
            .from("did:key:alice")
            .add_recipient("did:key:bob")
            .thread("thread-456")
            .build();

        assert_eq!(msg.id, "msg-123");
        assert_eq!(msg.from, Some("did:key:alice".to_string()));
        assert_eq!(msg.to, Some(vec!["did:key:bob".to_string()]));
        assert!(msg.thread.is_some());
        assert_eq!(
            msg.thread.as_ref().unwrap().thid,
            Some("thread-456".to_string())
        );
    }

    #[test]
    fn test_thread_id() {
        let msg_no_thread = Message::new(
            "msg-1".to_string(),
            "test".to_string(),
            serde_json::json!({}),
        );
        assert_eq!(msg_no_thread.thread_id(), "msg-1");

        let msg_with_thread = Message::builder("test")
            .id("msg-2")
            .thread("thread-abc")
            .build();
        assert_eq!(msg_with_thread.thread_id(), "thread-abc");
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message::builder("https://didcomm.org/test/1.0/message")
            .id("test-id")
            .body(serde_json::json!({"data": "value"}))
            .from("did:key:sender")
            .add_recipient("did:key:receiver")
            .build();

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: Message = serde_json::from_str(&json).unwrap();

        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_attachment_base64() {
        let attachment = Attachment {
            id: Some("attach-1".to_string()),
            description: Some("Test attachment".to_string()),
            filename: None,
            media_type: Some("text/plain".to_string()),
            format: None,
            lastmod_time: None,
            byte_count: None,
            data: AttachmentData::Base64 {
                base64: "SGVsbG8gV29ybGQ=".to_string(),
            },
        };

        let json = serde_json::to_string(&attachment).unwrap();
        let deserialized: Attachment = serde_json::from_str(&json).unwrap();

        assert_eq!(attachment, deserialized);
    }
}
