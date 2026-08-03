//! Out-of-Band Events
//!
//! The out-of-band events:
//! - `OutOfBandStateChanged` fires on every transition through the OOB
//!   lifecycle (`Initial → AwaitResponse | PrepareResponse → Done`).
//! - `HandshakeReused` fires when an inbound `~thread.pthid` resolves to an
//!   existing connection and the recipient short-circuits the handshake.

use crate::domain::OutOfBandState;
use crate::repository::OutOfBandRecord;
use serde::{Deserialize, Serialize};

pub mod topics {
    pub const OOB: &str = "oob";
}

pub mod types {
    pub const STATE_CHANGED: &str = "state_changed";
    pub const HANDSHAKE_REUSED: &str = "handshake_reused";
}

/// Payload for `(oob, state_changed)` — emitted whenever an `OutOfBandRecord`
/// transitions between `OutOfBandState` variants. `previous_state` is `None`
/// for the initial save (record creation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutOfBandStateChangedPayload {
    pub oob_record: OutOfBandRecord,
    pub previous_state: Option<OutOfBandState>,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for OutOfBandStateChangedPayload {
    const TOPIC: &'static str = topics::OOB;
    const NAME: &'static str = types::STATE_CHANGED;
}

/// Payload for `(oob, handshake_reused)` — emitted when the recipient resolves
/// an incoming OOB invitation's `~thread.pthid` to an existing connection
/// (RFC 0434 handshake-reuse). The connection isn't carried as a full record
/// here because `protocol_oob` doesn't depend on `protocol_connections`;
/// consumers look it up by `connection_id` if needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeReusedPayload {
    pub reuse_thread_id: String,
    pub oob_record: OutOfBandRecord,
    pub connection_id: String,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for HandshakeReusedPayload {
    const TOPIC: &'static str = topics::OOB;
    const NAME: &'static str = types::HANDSHAKE_REUSED;
}

#[cfg(all(test, feature = "events"))]
mod tests {
    use super::*;
    use crate::domain::OutOfBandRole;
    use crate::messages::{InlineService, OutOfBandInvitation, OutOfBandService};
    use agent_events::{EventBus, EventMetadata, TypedEvent};

    fn meta() -> EventMetadata {
        EventMetadata::for_tenant("test-tenant")
    }

    fn sample_record(state: OutOfBandState) -> OutOfBandRecord {
        let service = OutOfBandService::Inline(InlineService::new(
            "#inline-0".into(),
            vec!["did:key:zABC".into()],
            vec![],
            "https://example.com".into(),
        ));
        let invitation = OutOfBandInvitation::new(vec![service]);
        let mut rec = OutOfBandRecord::new(invitation, OutOfBandRole::Sender);
        rec.state = state;
        rec
    }

    #[test]
    fn typed_event_bindings_match_constants() {
        assert_eq!(
            <OutOfBandStateChangedPayload as TypedEvent>::TOPIC,
            topics::OOB
        );
        assert_eq!(
            <OutOfBandStateChangedPayload as TypedEvent>::NAME,
            types::STATE_CHANGED
        );
        assert_eq!(
            <HandshakeReusedPayload as TypedEvent>::NAME,
            types::HANDSHAKE_REUSED
        );
    }

    #[tokio::test]
    async fn state_changed_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            OutOfBandStateChangedPayload {
                oob_record: sample_record(OutOfBandState::AwaitResponse),
                previous_state: Some(OutOfBandState::Initial),
            },
        )
        .await
        .unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: OutOfBandStateChangedPayload = env.payload().unwrap();
        assert_eq!(decoded.oob_record.state, OutOfBandState::AwaitResponse);
        assert_eq!(decoded.previous_state, Some(OutOfBandState::Initial));
        assert_eq!(env.topic, topics::OOB);
    }

    #[tokio::test]
    async fn handshake_reused_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            HandshakeReusedPayload {
                reuse_thread_id: "th-1".into(),
                oob_record: sample_record(OutOfBandState::Done),
                connection_id: "conn-1".into(),
            },
        )
        .await
        .unwrap();
        let decoded: HandshakeReusedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.connection_id, "conn-1");
        assert_eq!(decoded.reuse_thread_id, "th-1");
    }
}
