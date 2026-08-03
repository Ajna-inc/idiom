//! Basic Message Events
//!
//! Typed event payloads for the basic-message protocol. Each payload binds to
//! a `(topic, name)` pair via `agent_events::TypedEvent` so producers can't
//! typo the strings and consumers decode without guessing JSON keys.

use crate::messages::BasicMessage;
use crate::repository::BasicMessageRecord;
use serde::{Deserialize, Serialize};

/// Event topics for basic-message events.
pub mod topics {
    /// Top-level topic for every basic-message event variant.
    pub const BASIC_MESSAGE: &str = "basic_message";
}

/// Event names (event-variant discriminants under `BASIC_MESSAGE`).
pub mod types {
    /// A new basic message landed (created locally or received over DIDComm).
    pub const STATE_CHANGED: &str = "state_changed";

    /// An existing message was edited via `basic_message.edit`.
    pub const EDITED: &str = "edited";

    /// An existing message was deleted via `basic_message.delete`.
    pub const DELETED: &str = "deleted";
}

/// Payload for a new-or-received basic message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicMessageStateChangedPayload {
    /// The persisted record (id, role, sent_time, content, thread, …).
    pub record: BasicMessageRecord,
    /// The wire message that produced the record.
    pub message: BasicMessage,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for BasicMessageStateChangedPayload {
    const TOPIC: &'static str = topics::BASIC_MESSAGE;
    const NAME: &'static str = types::STATE_CHANGED;
}

/// Payload for an edit-message event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicMessageEditedPayload {
    /// ID of the message that was edited.
    pub message_id: String,
    /// New content after the edit.
    pub new_content: String,
    /// ISO-8601 timestamp of the edit (sender clock).
    pub edited_time: String,
    /// Connection on which the edit arrived (or was issued).
    pub connection_id: String,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for BasicMessageEditedPayload {
    const TOPIC: &'static str = topics::BASIC_MESSAGE;
    const NAME: &'static str = types::EDITED;
}

/// Payload for a delete-message event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicMessageDeletedPayload {
    /// ID of the message that was deleted.
    pub message_id: String,
    /// ISO-8601 timestamp of the deletion (sender clock).
    pub deleted_time: String,
    /// Connection on which the delete arrived (or was issued).
    pub connection_id: String,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for BasicMessageDeletedPayload {
    const TOPIC: &'static str = topics::BASIC_MESSAGE;
    const NAME: &'static str = types::DELETED;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "events")]
    use agent_events::TypedEvent;

    #[test]
    fn test_event_constants() {
        assert_eq!(topics::BASIC_MESSAGE, "basic_message");
        assert_eq!(types::STATE_CHANGED, "state_changed");
        assert_eq!(types::EDITED, "edited");
        assert_eq!(types::DELETED, "deleted");
    }

    #[cfg(feature = "events")]
    #[test]
    fn test_typed_event_bindings() {
        assert_eq!(
            <BasicMessageStateChangedPayload as TypedEvent>::TOPIC,
            topics::BASIC_MESSAGE
        );
        assert_eq!(
            <BasicMessageStateChangedPayload as TypedEvent>::NAME,
            types::STATE_CHANGED
        );
        assert_eq!(
            <BasicMessageEditedPayload as TypedEvent>::NAME,
            types::EDITED
        );
        assert_eq!(
            <BasicMessageDeletedPayload as TypedEvent>::NAME,
            types::DELETED
        );
    }

    #[cfg(feature = "events")]
    #[tokio::test]
    async fn state_changed_round_trip() {
        use crate::repository::BasicMessageRole;
        use agent_events::{EventBus, EventMetadata};
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        let message = BasicMessage::new("hello");
        let record = BasicMessageRecord::new(
            message.id.clone(),
            "conn-1",
            BasicMessageRole::Receiver,
            message.content.clone(),
            message.sent_time.clone(),
        );
        bus.emit(
            &EventMetadata::for_tenant("test-tenant"),
            BasicMessageStateChangedPayload { record, message },
        )
        .await
        .unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: BasicMessageStateChangedPayload = env.payload().unwrap();
        assert_eq!(decoded.record.content, "hello");
        assert_eq!(env.topic, topics::BASIC_MESSAGE);
    }

    #[cfg(feature = "events")]
    #[tokio::test]
    async fn edited_round_trip() {
        use agent_events::{EventBus, EventMetadata};
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &EventMetadata::for_tenant("test-tenant"),
            BasicMessageEditedPayload {
                message_id: "msg-1".into(),
                new_content: "edited!".into(),
                edited_time: "2026-05-10T00:00:00Z".into(),
                connection_id: "conn-1".into(),
            },
        )
        .await
        .unwrap();
        let decoded: BasicMessageEditedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.new_content, "edited!");
    }

    #[cfg(feature = "events")]
    #[tokio::test]
    async fn deleted_round_trip() {
        use agent_events::{EventBus, EventMetadata};
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &EventMetadata::for_tenant("test-tenant"),
            BasicMessageDeletedPayload {
                message_id: "msg-2".into(),
                deleted_time: "2026-05-10T00:00:00Z".into(),
                connection_id: "conn-1".into(),
            },
        )
        .await
        .unwrap();
        let decoded: BasicMessageDeletedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.message_id, "msg-2");
    }
}
