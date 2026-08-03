//! Threshold-signing events.
//!
//! The signing-session events:
//! - `state_changed` — fires on every `transition_state` in `coordinator.rs`.
//! - `partial_signature_received` — fires when a counter's
//!   `accept_partial_signature` lands a new partial.
//! - `consent_received` — fires when `accept_consent` records a participant's
//!   consent message.
//! - `session_completed` — fires after `combine_signatures` lands a
//!   final signature and the session reaches `Completed`.
//! - `threshold_met` — fires when the number of received partial signatures
//!   first equals or exceeds the configured threshold.

use crate::models::SigningSession;
use crate::state::SigningSessionState;
use serde::{Deserialize, Serialize};

pub mod topics {
    pub const SIGNING: &str = "signing";
}

pub mod types {
    pub const STATE_CHANGED: &str = "state_changed";
    pub const PARTIAL_SIGNATURE_RECEIVED: &str = "partial_signature_received";
    pub const CONSENT_RECEIVED: &str = "consent_received";
    pub const SESSION_COMPLETED: &str = "session_completed";
    pub const THRESHOLD_MET: &str = "threshold_met";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningStateChangedPayload {
    pub session: SigningSession,
    pub previous_state: Option<SigningSessionState>,
}

impl agent_events::TypedEvent for SigningStateChangedPayload {
    const TOPIC: &'static str = topics::SIGNING;
    const NAME: &'static str = types::STATE_CHANGED;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignatureReceivedPayload {
    pub session_id: String,
    pub signer_did: String,
    /// 0-indexed round number for multi-round suites; `None` for
    /// single-round (Schnorr/Ed25519).
    pub round: Option<u32>,
}

impl agent_events::TypedEvent for PartialSignatureReceivedPayload {
    const TOPIC: &'static str = topics::SIGNING;
    const NAME: &'static str = types::PARTIAL_SIGNATURE_RECEIVED;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentReceivedPayload {
    pub session_id: String,
    pub signer_did: String,
}

impl agent_events::TypedEvent for ConsentReceivedPayload {
    const TOPIC: &'static str = topics::SIGNING;
    const NAME: &'static str = types::CONSENT_RECEIVED;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCompletedPayload {
    pub session: SigningSession,
    /// Hex-encoded final signature.
    pub final_signature: String,
}

impl agent_events::TypedEvent for SessionCompletedPayload {
    const TOPIC: &'static str = topics::SIGNING;
    const NAME: &'static str = types::SESSION_COMPLETED;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdMetPayload {
    pub session_id: String,
    pub required_signatures: u32,
    pub received_signatures: u32,
}

impl agent_events::TypedEvent for ThresholdMetPayload {
    const TOPIC: &'static str = topics::SIGNING;
    const NAME: &'static str = types::THRESHOLD_MET;
}

#[cfg(test)]
mod events_tests {
    use super::*;
    use agent_events::{EventBus, EventMetadata, TypedEvent};

    fn meta() -> EventMetadata {
        EventMetadata::for_tenant("test-tenant")
    }

    #[test]
    fn typed_event_bindings_match_constants() {
        assert_eq!(
            <SigningStateChangedPayload as TypedEvent>::TOPIC,
            topics::SIGNING
        );
        assert_eq!(
            <SigningStateChangedPayload as TypedEvent>::NAME,
            types::STATE_CHANGED
        );
        assert_eq!(
            <PartialSignatureReceivedPayload as TypedEvent>::NAME,
            types::PARTIAL_SIGNATURE_RECEIVED
        );
        assert_eq!(
            <ConsentReceivedPayload as TypedEvent>::NAME,
            types::CONSENT_RECEIVED
        );
        assert_eq!(
            <SessionCompletedPayload as TypedEvent>::NAME,
            types::SESSION_COMPLETED
        );
        assert_eq!(
            <ThresholdMetPayload as TypedEvent>::NAME,
            types::THRESHOLD_MET
        );
    }

    #[tokio::test]
    async fn partial_signature_received_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            PartialSignatureReceivedPayload {
                session_id: "sess-9".into(),
                signer_did: "did:key:zABC".into(),
                round: Some(2),
            },
        )
        .await
        .unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: PartialSignatureReceivedPayload = env.payload().unwrap();
        assert_eq!(decoded.session_id, "sess-9");
        assert_eq!(decoded.round, Some(2));
        assert_eq!(env.topic, topics::SIGNING);
        assert_eq!(env.name, types::PARTIAL_SIGNATURE_RECEIVED);
    }

    #[tokio::test]
    async fn consent_received_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            ConsentReceivedPayload {
                session_id: "sess-9".into(),
                signer_did: "did:key:zABC".into(),
            },
        )
        .await
        .unwrap();
        let decoded: ConsentReceivedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.signer_did, "did:key:zABC");
    }

    #[tokio::test]
    async fn threshold_met_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            ThresholdMetPayload {
                session_id: "sess-9".into(),
                required_signatures: 3,
                received_signatures: 3,
            },
        )
        .await
        .unwrap();
        let decoded: ThresholdMetPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.required_signatures, decoded.received_signatures);
    }
}
