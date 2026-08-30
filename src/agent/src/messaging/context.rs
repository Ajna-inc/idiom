use didcomm::core::Message as DidcommMessage;
use didcomm::messaging::MessageContext;

/// Builder for MessageContext
///
/// Provides a fluent API for creating MessageContext with different configurations.
/// Supports both plaintext (test) and encrypted (production) message contexts.
pub struct MessageContextBuilder {
    from: Option<String>,
    to: Option<String>,
    thread_id: Option<String>,
    parent_thread_id: Option<String>,
    connection_id: Option<String>,
    encrypted: bool,
    authenticated: bool,
    sender_endpoint: Option<String>,
    raw_plaintext: Option<String>,
}

impl MessageContextBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            from: None,
            to: None,
            thread_id: None,
            parent_thread_id: None,
            connection_id: None,
            encrypted: false,
            authenticated: false,
            sender_endpoint: None,
            raw_plaintext: None,
        }
    }

    /// Create a builder for plaintext messages (test mode)
    pub fn from_plaintext_message(msg: &DidcommMessage) -> Self {
        Self {
            from: None,
            to: None,
            thread_id: msg.thread.as_ref().and_then(|t| t.thid.clone()),
            parent_thread_id: msg.pthid.clone(),
            connection_id: None,
            encrypted: false,     // Plaintext message
            authenticated: false, // No authentication
            sender_endpoint: None,
            raw_plaintext: None,
        }
    }

    /// Create a builder for decrypted messages (production mode)
    pub fn from_decrypted_message(msg: &DidcommMessage) -> Self {
        Self {
            from: None, // Can be set later from metadata
            to: None,   // Can be set later from metadata
            thread_id: msg.thread.as_ref().and_then(|t| t.thid.clone()),
            parent_thread_id: msg.pthid.clone(),
            connection_id: None,
            encrypted: true,     // Was encrypted before decryption
            authenticated: true, // Authcrypt provides authentication
            sender_endpoint: None,
            raw_plaintext: None,
        }
    }

    /// Set the sender DID
    pub fn with_from(mut self, from: Option<String>) -> Self {
        self.from = from;
        self
    }

    /// Set the recipient DID
    pub fn with_to(mut self, to: Option<String>) -> Self {
        self.to = to;
        self
    }

    /// Set the thread ID
    pub fn with_thread_id(mut self, thread_id: Option<String>) -> Self {
        self.thread_id = thread_id;
        self
    }

    /// Set the parent thread ID
    pub fn with_parent_thread_id(mut self, parent_thread_id: Option<String>) -> Self {
        self.parent_thread_id = parent_thread_id;
        self
    }

    /// Set the connection ID
    pub fn with_connection_id(mut self, connection_id: Option<String>) -> Self {
        self.connection_id = connection_id;
        self
    }

    /// Set whether the message was encrypted
    pub fn with_encrypted(mut self, encrypted: bool) -> Self {
        self.encrypted = encrypted;
        self
    }

    /// Set whether the message was authenticated
    pub fn with_authenticated(mut self, authenticated: bool) -> Self {
        self.authenticated = authenticated;
        self
    }

    /// Set the sender endpoint for return routing
    pub fn with_sender_endpoint(mut self, endpoint: Option<String>) -> Self {
        self.sender_endpoint = endpoint;
        self
    }

    /// Set the raw (pre-normalization) decrypted plaintext
    pub fn with_raw_plaintext(mut self, raw_plaintext: Option<String>) -> Self {
        self.raw_plaintext = raw_plaintext;
        self
    }

    /// Build the MessageContext
    pub fn build(self) -> MessageContext {
        MessageContext {
            from: self.from,
            to: self.to,
            thread_id: self.thread_id,
            parent_thread_id: self.parent_thread_id,
            connection_id: self.connection_id,
            encrypted: self.encrypted,
            authenticated: self.authenticated,
            sender_endpoint: self.sender_endpoint,
            raw_plaintext: self.raw_plaintext,
        }
    }
}

impl Default for MessageContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use didcomm::core::{Message, Thread};

    #[test]
    fn test_builder_new() {
        let context = MessageContextBuilder::new()
            .with_encrypted(true)
            .with_authenticated(true)
            .build();

        assert!(context.encrypted);
        assert!(context.authenticated);
        assert!(context.from.is_none());
    }

    #[test]
    fn test_from_plaintext_message() {
        let msg = Message {
            id: "test-123".to_string(),
            msg_type: "test".to_string(),
            body: serde_json::json!({}),
            from: None,
            to: None,
            thread: Some(Thread {
                thid: Some("thread-123".to_string()),
                pthid: None,
                ..Default::default()
            }),
            pthid: Some("parent-123".to_string()),
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: std::collections::HashMap::new(),
        };

        let context = MessageContextBuilder::from_plaintext_message(&msg)
            .with_sender_endpoint(Some("http://localhost".to_string()))
            .build();

        assert!(!context.encrypted);
        assert!(!context.authenticated);
        assert_eq!(context.thread_id, Some("thread-123".to_string()));
        assert_eq!(context.parent_thread_id, Some("parent-123".to_string()));
        assert_eq!(
            context.sender_endpoint,
            Some("http://localhost".to_string())
        );
    }

    #[test]
    fn test_from_decrypted_message() {
        let msg = Message {
            id: "test-456".to_string(),
            msg_type: "test".to_string(),
            body: serde_json::json!({}),
            from: None,
            to: None,
            thread: Some(Thread {
                thid: Some("thread-456".to_string()),
                pthid: None,
                ..Default::default()
            }),
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: std::collections::HashMap::new(),
        };

        let context = MessageContextBuilder::from_decrypted_message(&msg).build();

        assert!(context.encrypted);
        assert!(context.authenticated);
        assert_eq!(context.thread_id, Some("thread-456".to_string()));
    }
}
