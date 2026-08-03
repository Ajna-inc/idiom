//! Proof Exchange Events
//!
//! Defines event topics, types, and payloads for the Present Proof protocol.
//! These events are published to the agent's event bus when proof exchange state changes.

use crate::domain::ProofExchangeState;
use crate::repository::ProofExchangeRecord;
use serde::{Deserialize, Serialize};

/// Event topics for proof exchange events
pub mod topics {
    /// Topic for all proof-related events
    pub const PROOF: &str = "proof";
}

/// Event types for proof exchange events
pub mod types {
    /// Proof exchange state changed
    pub const STATE_CHANGED: &str = "state_changed";

    /// New proof exchange was created
    pub const CREATED: &str = "created";

    /// Proof exchange was deleted
    pub const DELETED: &str = "deleted";
}

/// Payload for ProofStateChanged event
///
/// This is emitted whenever a proof exchange transitions to a new state.
/// Consumers can subscribe to these events to react to state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStateChangedPayload {
    /// The proof exchange record after the state change
    pub proof_record: ProofExchangeRecord,

    /// The previous state (None if this is the initial state)
    pub previous_state: Option<ProofExchangeState>,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for ProofStateChangedPayload {
    const TOPIC: &'static str = topics::PROOF;
    const NAME: &'static str = types::STATE_CHANGED;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ProofExchangeRole;

    #[test]
    fn test_event_constants() {
        assert_eq!(topics::PROOF, "proof");
        assert_eq!(types::STATE_CHANGED, "state_changed");
        assert_eq!(types::CREATED, "created");
        assert_eq!(types::DELETED, "deleted");
    }

    #[cfg(feature = "events")]
    #[test]
    fn typed_event_bindings_match_constants() {
        use agent_events::TypedEvent;
        assert_eq!(
            <ProofStateChangedPayload as TypedEvent>::TOPIC,
            topics::PROOF
        );
        assert_eq!(
            <ProofStateChangedPayload as TypedEvent>::NAME,
            types::STATE_CHANGED
        );
    }

    #[cfg(feature = "events")]
    #[tokio::test]
    async fn state_changed_round_trip() {
        use agent_events::{EventBus, EventMetadata};
        let meta = EventMetadata::for_tenant("test-tenant");
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        let record = ProofExchangeRecord::new(
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
            "thread-1".into(),
        );
        bus.emit(
            &meta,
            ProofStateChangedPayload {
                proof_record: record,
                previous_state: None,
            },
        )
        .await
        .unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: ProofStateChangedPayload = env.payload().unwrap();
        assert_eq!(decoded.proof_record.thread_id, "thread-1");
        assert_eq!(decoded.proof_record.state, ProofExchangeState::RequestSent);
        assert_eq!(env.topic, topics::PROOF);
    }
}
