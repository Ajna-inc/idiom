//! Connection Events
//!
//! Defines event topics, types, and payloads for the DID Exchange protocol.
//! These events are published to the agent's event bus when connection state changes.

use crate::domain::DidExchangeState;
use crate::repository::ConnectionRecord;
use serde::{Deserialize, Serialize};

/// Event topics for connection events
pub mod topics {
    /// Topic for all connection-related events
    pub const CONNECTION: &str = "connection";
}

/// Event types for connection events
pub mod types {
    /// Connection state changed (most important for testing)
    pub const STATE_CHANGED: &str = "state_changed";

    /// New connection was created
    pub const CREATED: &str = "created";

    /// Connection was deleted
    pub const DELETED: &str = "deleted";
}

/// Payload for ConnectionStateChanged event
///
/// This is emitted whenever a connection transitions to a new state.
/// Consumers can subscribe to these events to react to state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStateChangedPayload {
    /// The connection record after the state change
    pub connection_record: ConnectionRecord,

    /// The previous state (None if this is the initial state)
    pub previous_state: Option<DidExchangeState>,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for ConnectionStateChangedPayload {
    const TOPIC: &'static str = topics::CONNECTION;
    const NAME: &'static str = types::STATE_CHANGED;
}

#[cfg(all(test, feature = "events"))]
mod tests {
    use super::*;
    use agent_events::TypedEvent;

    #[test]
    fn test_event_constants() {
        assert_eq!(topics::CONNECTION, "connection");
        assert_eq!(types::STATE_CHANGED, "state_changed");
        assert_eq!(types::CREATED, "created");
        assert_eq!(types::DELETED, "deleted");
    }

    /// The TypedEvent constants must reference the same strings the constants
    /// module exposes — otherwise consumers filtering by `topics::CONNECTION`
    /// (e.g. `agent/tests/helpers/events.rs`) silently miss every event.
    #[test]
    fn test_typed_event_bindings() {
        assert_eq!(
            <ConnectionStateChangedPayload as TypedEvent>::TOPIC,
            topics::CONNECTION
        );
        assert_eq!(
            <ConnectionStateChangedPayload as TypedEvent>::NAME,
            types::STATE_CHANGED
        );
    }

    #[tokio::test]
    async fn state_changed_round_trip() {
        use crate::domain::DidExchangeRole;
        use agent_events::{EventBus, EventMetadata};
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        let record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
            "thread-1".into(),
            "oob-1".into(),
            "did:peer:test".into(),
        );
        bus.emit(
            &EventMetadata::for_tenant("test-tenant"),
            ConnectionStateChangedPayload {
                connection_record: record,
                previous_state: Some(DidExchangeState::Start),
            },
        )
        .await
        .unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: ConnectionStateChangedPayload = env.payload().unwrap();
        assert_eq!(decoded.connection_record.thread_id, "thread-1");
        assert_eq!(
            decoded.connection_record.state,
            DidExchangeState::RequestSent
        );
        assert_eq!(decoded.previous_state, Some(DidExchangeState::Start));
        assert_eq!(env.topic, topics::CONNECTION);
    }
}
