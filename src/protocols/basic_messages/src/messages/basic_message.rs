//! Basic Message Type
//!
//! DIDComm Basic Message protocol (https://didcomm.org/basicmessage/1.0/message)
//! For sending simple text messages between agents

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Basic Message protocol version
pub const BASIC_MESSAGE_TYPE: &str = "https://didcomm.org/basicmessage/1.0/message";

/// DIDComm Basic Message
///
/// A simple text message that can be sent between agents.
/// Supports threading for conversations and localization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BasicMessage {
    /// Message ID
    #[serde(rename = "@id")]
    pub id: String,

    /// Message type (always "https://didcomm.org/basicmessage/1.0/message")
    #[serde(rename = "@type")]
    pub msg_type: String,

    /// Message content (the actual text)
    pub content: String,

    /// When the message was sent (ISO 8601 timestamp)
    #[serde(rename = "sent_time")]
    pub sent_time: String,

    /// Localization decorator (optional)
    #[serde(rename = "~l10n", skip_serializing_if = "Option::is_none")]
    pub locale: Option<L10n>,

    /// Thread decorator for message threading (optional)
    #[serde(rename = "~thread", skip_serializing_if = "Option::is_none")]
    pub thread: Option<Thread>,
}

/// Localization decorator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct L10n {
    /// Locale code (e.g., "en", "es", "fr")
    pub locale: String,
}

/// Thread decorator for message threading
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Thread {
    /// Thread ID (for this message in the thread)
    #[serde(rename = "thid", skip_serializing_if = "Option::is_none")]
    pub thid: Option<String>,

    /// Parent thread ID (for replies)
    #[serde(rename = "pthid", skip_serializing_if = "Option::is_none")]
    pub pthid: Option<String>,
}

impl BasicMessage {
    /// Create a new basic message
    ///
    /// # Arguments
    /// * `content` - The message text
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            msg_type: BASIC_MESSAGE_TYPE.to_string(),
            content: content.into(),
            sent_time: Utc::now().to_rfc3339(),
            locale: Some(L10n {
                locale: "en".to_string(),
            }),
            thread: None,
        }
    }

    /// Create a new basic message with a specific ID
    pub fn with_id(id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            msg_type: BASIC_MESSAGE_TYPE.to_string(),
            content: content.into(),
            sent_time: Utc::now().to_rfc3339(),
            locale: Some(L10n {
                locale: "en".to_string(),
            }),
            thread: None,
        }
    }

    /// Set the locale for this message
    pub fn with_locale(mut self, locale: impl Into<String>) -> Self {
        self.locale = Some(L10n {
            locale: locale.into(),
        });
        self
    }

    /// Set threading information (for replies)
    pub fn with_thread(mut self, parent_thread_id: impl Into<String>) -> Self {
        let thread_id = Uuid::new_v4().to_string();
        self.thread = Some(Thread {
            thid: Some(thread_id),
            pthid: Some(parent_thread_id.into()),
        });
        self
    }

    /// Get the thread ID
    pub fn thread_id(&self) -> Option<&str> {
        self.thread.as_ref().and_then(|t| t.thid.as_deref())
    }

    /// Get the parent thread ID
    pub fn parent_thread_id(&self) -> Option<&str> {
        self.thread.as_ref().and_then(|t| t.pthid.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_basic_message() {
        let msg = BasicMessage::new("Hello, world!");

        assert_eq!(msg.msg_type, BASIC_MESSAGE_TYPE);
        assert_eq!(msg.content, "Hello, world!");
        assert!(msg.locale.is_some());
        assert_eq!(msg.locale.as_ref().unwrap().locale, "en");
        assert!(msg.thread.is_none());
    }

    #[test]
    fn test_message_with_thread() {
        let parent_id = "parent-thread-123";
        let msg = BasicMessage::new("Reply").with_thread(parent_id);

        assert_eq!(msg.content, "Reply");
        assert!(msg.thread.is_some());
        assert_eq!(msg.parent_thread_id(), Some(parent_id));
        assert!(msg.thread_id().is_some());
    }

    #[test]
    fn test_message_with_locale() {
        let msg = BasicMessage::new("Hola").with_locale("es");

        assert_eq!(msg.locale.as_ref().unwrap().locale, "es");
    }

    #[test]
    fn test_serialization() {
        let msg = BasicMessage::new("Test message");
        let json = serde_json::to_string(&msg).unwrap();

        assert!(json.contains("@id"));
        assert!(json.contains("@type"));
        assert!(json.contains("content"));
        assert!(json.contains("sent_time"));
        assert!(json.contains("~l10n"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@id": "test-123",
            "@type": "https://didcomm.org/basicmessage/1.0/message",
            "content": "Hello",
            "sent_time": "2024-01-01T00:00:00Z",
            "~l10n": { "locale": "en" }
        }"#;

        let msg: BasicMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-123");
        assert_eq!(msg.content, "Hello");
    }
}
