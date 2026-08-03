//! Credential Exchange Events
//!
//! Defines event topics, types, and payloads for the Issue Credential v3 protocol.
//! These events are published to the agent's event bus when credential exchange state changes.

use crate::domain::CredentialExchangeState;
use crate::repository::CredentialExchangeRecord;
use serde::{Deserialize, Serialize};

/// Event topics for credential exchange events
pub mod topics {
    /// Topic for all credential exchange events
    pub const CREDENTIAL_EXCHANGE: &str = "credential_exchange";
}

/// Event types for credential exchange events
pub mod types {
    /// Credential exchange state changed
    pub const STATE_CHANGED: &str = "state_changed";

    /// New credential exchange was created
    pub const CREATED: &str = "created";

    /// Credential exchange was deleted
    pub const DELETED: &str = "deleted";
}

/// Payload for CredentialStateChanged event
///
/// This is emitted whenever a credential exchange transitions to a new state.
/// Consumers can subscribe to these events to react to state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStateChangedPayload {
    /// The credential exchange record after the state change
    pub credential_exchange_record: CredentialExchangeRecord,

    /// The previous state (None if this is the initial state)
    pub previous_state: Option<CredentialExchangeState>,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for CredentialStateChangedPayload {
    const TOPIC: &'static str = topics::CREDENTIAL_EXCHANGE;
    const NAME: &'static str = types::STATE_CHANGED;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::CredentialExchangeRole;

    #[test]
    fn test_event_constants() {
        assert_eq!(topics::CREDENTIAL_EXCHANGE, "credential_exchange");
        assert_eq!(types::STATE_CHANGED, "state_changed");
        assert_eq!(types::CREATED, "created");
        assert_eq!(types::DELETED, "deleted");
    }

    #[cfg(feature = "events")]
    #[test]
    fn typed_event_bindings_match_constants() {
        use agent_events::TypedEvent;
        assert_eq!(
            <CredentialStateChangedPayload as TypedEvent>::TOPIC,
            topics::CREDENTIAL_EXCHANGE
        );
        assert_eq!(
            <CredentialStateChangedPayload as TypedEvent>::NAME,
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
        let record = CredentialExchangeRecord::new(
            CredentialExchangeRole::Holder,
            CredentialExchangeState::OfferReceived,
            "thread-1".into(),
        );
        bus.emit(
            &meta,
            CredentialStateChangedPayload {
                credential_exchange_record: record,
                previous_state: None,
            },
        )
        .await
        .unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: CredentialStateChangedPayload = env.payload().unwrap();
        assert_eq!(decoded.credential_exchange_record.thread_id, "thread-1");
        assert_eq!(
            decoded.credential_exchange_record.state,
            CredentialExchangeState::OfferReceived
        );
        assert_eq!(env.topic, topics::CREDENTIAL_EXCHANGE);
    }
}
