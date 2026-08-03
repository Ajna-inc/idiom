//! Mediation Events
//!
//! Defines event topics, types, and payloads for the Coordinate Mediation protocol.
//! These events are published to the agent's event bus when mediation state changes.

use crate::{MediationRecord, MediationState};
use serde::{Deserialize, Serialize};

/// Event topics for mediation events (following connection events pattern)
pub mod topics {
    /// Topic for all mediation-related events
    pub const MEDIATION: &str = "mediation";

    /// Topic for keylist-related events
    pub const KEYLIST: &str = "keylist";

    /// Topic for routing-creation events — fires when the recipient
    /// establishes initial routing through a mediator (i.e., right after
    /// `process_grant` returns successfully and the recipient now has a
    /// `routing_keys` / `endpoint` pair to hand out in DIDs).
    pub const ROUTING: &str = "routing";
}

/// Event types for mediation events
pub mod types {
    /// Mediation state changed (most important for E2E testing)
    pub const STATE_CHANGED: &str = "state_changed";

    /// Mediation request created
    pub const REQUEST_CREATED: &str = "request_created";

    /// Mediation was granted
    pub const GRANTED: &str = "granted";

    /// Mediation was denied
    pub const DENIED: &str = "denied";

    /// Keylist was updated
    pub const KEYLIST_UPDATED: &str = "keylist_updated";

    /// Routing was created (recipient established mediator routing).
    pub const CREATED: &str = "created";
}

/// Payload for MediationStateChanged event
///
/// This is emitted whenever a mediation record transitions to a new state.
/// Consumers can subscribe to these events to react to state changes.
///
/// Pattern matches ConnectionStateChangedPayload for consistency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediationStateChangedPayload {
    /// The mediation record after the state change
    pub mediation_record: MediationRecord,

    /// The previous state (None if this is the initial state)
    pub previous_state: Option<MediationState>,
}

/// Payload for KeylistUpdated event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeylistUpdatedPayload {
    /// The mediation record ID
    pub mediation_id: String,

    /// Keys that were added
    pub keys_added: Vec<String>,

    /// Keys that were removed
    pub keys_removed: Vec<String>,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for MediationStateChangedPayload {
    const TOPIC: &'static str = topics::MEDIATION;
    const NAME: &'static str = types::STATE_CHANGED;
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for KeylistUpdatedPayload {
    const TOPIC: &'static str = topics::KEYLIST;
    const NAME: &'static str = types::KEYLIST_UPDATED;
}

/// Payload for `(routing, created)` — emitted on the recipient side once
/// `process_grant` has stored the granted MediationRecord and the recipient
/// can now hand `endpoint` + `routing_keys` to peers in their DIDs.
///
/// Emitted once routing is created — we surface the granted MediationRecord
/// directly so consumers don't have to look up the record again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingCreatedPayload {
    pub mediation_record: MediationRecord,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for RoutingCreatedPayload {
    const TOPIC: &'static str = topics::ROUTING;
    const NAME: &'static str = types::CREATED;
}

#[cfg(all(test, feature = "events"))]
mod tests {
    use super::*;
    use agent_events::TypedEvent;

    #[test]
    fn test_event_constants() {
        assert_eq!(topics::MEDIATION, "mediation");
        assert_eq!(topics::KEYLIST, "keylist");
        assert_eq!(types::STATE_CHANGED, "state_changed");
        assert_eq!(types::REQUEST_CREATED, "request_created");
        assert_eq!(types::GRANTED, "granted");
        assert_eq!(types::DENIED, "denied");
        assert_eq!(types::KEYLIST_UPDATED, "keylist_updated");
    }

    #[test]
    fn test_typed_event_bindings() {
        assert_eq!(
            <MediationStateChangedPayload as TypedEvent>::TOPIC,
            topics::MEDIATION
        );
        assert_eq!(
            <MediationStateChangedPayload as TypedEvent>::NAME,
            types::STATE_CHANGED
        );
        assert_eq!(
            <KeylistUpdatedPayload as TypedEvent>::TOPIC,
            topics::KEYLIST
        );
        assert_eq!(
            <KeylistUpdatedPayload as TypedEvent>::NAME,
            types::KEYLIST_UPDATED
        );
        assert_eq!(
            <RoutingCreatedPayload as TypedEvent>::TOPIC,
            topics::ROUTING
        );
        assert_eq!(<RoutingCreatedPayload as TypedEvent>::NAME, types::CREATED);
    }

    fn sample_record() -> MediationRecord {
        use crate::domain::MediationRole;
        use crate::MediationRecordBuilder;
        MediationRecordBuilder::new("conn-1".into(), MediationRole::Recipient)
            .id("med-1".into())
            .build()
    }

    #[tokio::test]
    async fn mediation_state_changed_round_trip() {
        use agent_events::{EventBus, EventMetadata};
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &EventMetadata::for_tenant("test-tenant"),
            MediationStateChangedPayload {
                mediation_record: sample_record(),
                previous_state: Some(MediationState::Requested),
            },
        )
        .await
        .unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: MediationStateChangedPayload = env.payload().unwrap();
        assert_eq!(decoded.mediation_record.connection_id, "conn-1");
        assert_eq!(decoded.previous_state, Some(MediationState::Requested));
        assert_eq!(env.topic, topics::MEDIATION);
    }

    #[tokio::test]
    async fn keylist_updated_round_trip() {
        use agent_events::{EventBus, EventMetadata};
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &EventMetadata::for_tenant("test-tenant"),
            KeylistUpdatedPayload {
                mediation_id: "med-1".into(),
                keys_added: vec!["did:key:zABC".into()],
                keys_removed: vec![],
            },
        )
        .await
        .unwrap();
        let decoded: KeylistUpdatedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.keys_added.len(), 1);
        assert_eq!(decoded.keys_added[0], "did:key:zABC");
    }

    #[tokio::test]
    async fn routing_created_round_trip() {
        use agent_events::{EventBus, EventMetadata};
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &EventMetadata::for_tenant("test-tenant"),
            RoutingCreatedPayload {
                mediation_record: sample_record(),
            },
        )
        .await
        .unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: RoutingCreatedPayload = env.payload().unwrap();
        assert_eq!(decoded.mediation_record.id, "med-1");
        assert_eq!(env.topic, topics::ROUTING);
        assert_eq!(env.name, types::CREATED);
    }
}
