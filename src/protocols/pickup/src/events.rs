//! Events for Message Pickup Protocol V2

use serde::{Deserialize, Serialize};

/// Event topics for pickup protocol
pub mod topics {
    /// Topic for message queued events
    pub const MESSAGE_QUEUED: &str = "pickup.message.queued";
    /// Topic for messages delivered events
    pub const MESSAGES_DELIVERED: &str = "pickup.messages.delivered";
    /// Topic for messages received (acknowledged) events
    pub const MESSAGES_RECEIVED: &str = "pickup.messages.received";
    /// Topic for live-session lifecycle events (saved / removed) and the
    /// per-cycle "this poll drained N messages" event.
    pub const PICKUP: &str = "pickup";
}

/// Event types for pickup protocol
pub mod types {
    /// Event type for message queued
    pub const MESSAGE_QUEUED: &str = "MessageQueuedEvent";
    /// Event type for messages delivered
    pub const MESSAGES_DELIVERED: &str = "MessagesDeliveredEvent";
    /// Event type for messages received
    pub const MESSAGES_RECEIVED: &str = "MessagesReceivedEvent";
    /// A long-lived pickup session was saved (e.g. WebSocket pickup loop
    /// established its keylist + began polling).
    pub const LIVE_SESSION_SAVED: &str = "live_session_saved";
    /// A long-lived pickup session was removed (WS disconnect, key rejection,
    /// idle timeout).
    pub const LIVE_SESSION_REMOVED: &str = "live_session_removed";
    /// One pickup cycle drained ≥1 message and ACKed it. Distinct from
    /// `MessagesReceivedEvent` — that fires per ACK round-trip; this fires
    /// once per *cycle* with the aggregate count.
    pub const PICKUP_COMPLETED: &str = "pickup_completed";
}

/// Payload for message queued event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageQueuedPayload {
    /// Queue message ID
    pub message_id: String,
    /// Connection ID
    pub connection_id: String,
    /// Recipient keys
    pub recipient_keys: Vec<String>,
}

/// Payload for messages delivered event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesDeliveredPayload {
    /// Connection ID
    pub connection_id: String,
    /// Message IDs that were delivered
    pub message_ids: Vec<String>,
}

/// Payload for messages received (acknowledged) event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesReceivedPayload {
    /// Connection ID
    pub connection_id: String,
    /// Message IDs that were acknowledged
    pub message_ids: Vec<String>,
    /// Remaining message count
    pub remaining_count: u64,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for MessageQueuedPayload {
    const TOPIC: &'static str = topics::MESSAGE_QUEUED;
    const NAME: &'static str = types::MESSAGE_QUEUED;
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for MessagesDeliveredPayload {
    const TOPIC: &'static str = topics::MESSAGES_DELIVERED;
    const NAME: &'static str = types::MESSAGES_DELIVERED;
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for MessagesReceivedPayload {
    const TOPIC: &'static str = topics::MESSAGES_RECEIVED;
    const NAME: &'static str = types::MESSAGES_RECEIVED;
}

/// Payload for `(pickup, live_session_saved)` — fired when a long-lived
/// pickup session opens (the WS pickup loop in
/// `agent_tenants/src/pickup_loop.rs` is the canonical source).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PickupLiveSessionSavedPayload {
    pub session_id: String,
    pub connection_id: String,
    /// `"ws"` / `"http"` / `"mesh"` — drives transport-aware UI.
    pub transport: String,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for PickupLiveSessionSavedPayload {
    const TOPIC: &'static str = topics::PICKUP;
    const NAME: &'static str = types::LIVE_SESSION_SAVED;
}

/// Payload for `(pickup, live_session_removed)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PickupLiveSessionRemovedPayload {
    pub session_id: String,
    pub connection_id: String,
    /// Optional reason — `"disconnect"`, `"key_rejected"`, `"idle"`, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for PickupLiveSessionRemovedPayload {
    const TOPIC: &'static str = topics::PICKUP;
    const NAME: &'static str = types::LIVE_SESSION_REMOVED;
}

/// Payload for `(pickup, pickup_completed)` — fires once per pickup cycle
/// that successfully drained ≥1 message and ACKed it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePickupCompletedPayload {
    pub connection_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    pub message_count: u32,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for MessagePickupCompletedPayload {
    const TOPIC: &'static str = topics::PICKUP;
    const NAME: &'static str = types::PICKUP_COMPLETED;
}

#[cfg(all(test, feature = "events"))]
mod tests {
    use super::*;
    use agent_events::{EventBus, EventMetadata, TypedEvent};

    fn meta() -> EventMetadata {
        EventMetadata::for_tenant("test-tenant")
    }

    /// Every TypedEvent impl must reference the canonical `topics::*` /
    /// `types::*` constants. Catches typos that would silently disconnect
    /// producers from consumers.
    #[test]
    fn typed_event_bindings_match_constants() {
        assert_eq!(
            <MessageQueuedPayload as TypedEvent>::TOPIC,
            topics::MESSAGE_QUEUED
        );
        assert_eq!(
            <MessageQueuedPayload as TypedEvent>::NAME,
            types::MESSAGE_QUEUED
        );
        assert_eq!(
            <MessagesDeliveredPayload as TypedEvent>::TOPIC,
            topics::MESSAGES_DELIVERED
        );
        assert_eq!(
            <MessagesReceivedPayload as TypedEvent>::TOPIC,
            topics::MESSAGES_RECEIVED
        );
        assert_eq!(
            <PickupLiveSessionSavedPayload as TypedEvent>::TOPIC,
            topics::PICKUP
        );
        assert_eq!(
            <PickupLiveSessionSavedPayload as TypedEvent>::NAME,
            types::LIVE_SESSION_SAVED
        );
        assert_eq!(
            <PickupLiveSessionRemovedPayload as TypedEvent>::NAME,
            types::LIVE_SESSION_REMOVED
        );
        assert_eq!(
            <MessagePickupCompletedPayload as TypedEvent>::NAME,
            types::PICKUP_COMPLETED
        );
    }

    /// Publish→subscribe round-trip on the typed bus.
    #[tokio::test]
    async fn live_session_saved_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        let payload = PickupLiveSessionSavedPayload {
            session_id: "sess-1".into(),
            connection_id: "conn-abc".into(),
            transport: "ws".into(),
        };
        bus.emit(&meta(), payload.clone()).await.unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: PickupLiveSessionSavedPayload = env.payload().unwrap();
        assert_eq!(decoded.session_id, payload.session_id);
        assert_eq!(decoded.transport, "ws");
        assert_eq!(env.topic, topics::PICKUP);
        assert_eq!(env.name, types::LIVE_SESSION_SAVED);
        assert_eq!(env.agent_id, "test-tenant");
    }

    #[tokio::test]
    async fn live_session_removed_carries_reason() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            PickupLiveSessionRemovedPayload {
                session_id: "sess-1".into(),
                connection_id: "conn-abc".into(),
                reason: Some("disconnect".into()),
            },
        )
        .await
        .unwrap();
        let decoded: PickupLiveSessionRemovedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.reason.as_deref(), Some("disconnect"));
    }

    #[tokio::test]
    async fn pickup_completed_carries_count() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            MessagePickupCompletedPayload {
                connection_id: "conn-abc".into(),
                thread_id: None,
                message_count: 3,
            },
        )
        .await
        .unwrap();
        let decoded: MessagePickupCompletedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.message_count, 3);
        assert!(decoded.thread_id.is_none());
    }
}
