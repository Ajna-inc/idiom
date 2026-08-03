//! Typed in-tree agent events.
//!
//! Events emitted by the `agent` crate itself — consensus block production
//! and any non-protocol-crate event source.

use serde::{Deserialize, Serialize};

pub mod topics {
    pub const CONSENSUS: &str = "consensus";
    /// Transport-layer DIDComm events: `(didcomm, message_received)` etc.
    pub const DIDCOMM: &str = "didcomm";
}

pub mod types {
    pub const PROPOSAL_CREATED: &str = "proposal_created";
    pub const VOTE_CAST: &str = "vote_cast";
    pub const MESSAGE_RECEIVED: &str = "message_received";
    pub const MESSAGE_PROCESSED: &str = "message_processed";
    pub const MESSAGE_SENT: &str = "message_sent";
}

/// Payload for `(didcomm, message_received)` — fires after a JWE inbound
/// envelope is unpacked or after a plaintext inbound message is parsed.
/// Use this for transport-level instrumentation (audit logs, latency
/// metrics, "show last received message" UI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidCommMessageReceivedPayload {
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_did: Option<String>,
    pub encrypted: bool,
    pub authenticated: bool,
}

impl agent_events::TypedEvent for DidCommMessageReceivedPayload {
    const TOPIC: &'static str = topics::DIDCOMM;
    const NAME: &'static str = types::MESSAGE_RECEIVED;
}

/// Payload for `(didcomm, message_processed)` — fires after the registered
/// handler returns from processing the inbound message. `success` is `false`
/// for handler errors; `processed_at_ms` is a Unix-epoch millis timestamp
/// for latency calculations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidCommMessageProcessedPayload {
    pub message_type: String,
    pub processed_at_ms: u64,
    pub success: bool,
}

impl agent_events::TypedEvent for DidCommMessageProcessedPayload {
    const TOPIC: &'static str = topics::DIDCOMM;
    const NAME: &'static str = types::MESSAGE_PROCESSED;
}

/// Payload for `(didcomm, message_sent)` — fires after an outbound packed
/// message lands on its transport (HTTP/WS/mesh). `transport` distinguishes
/// the path; `status` is `"ok"` / `"error: ..."` so consumers don't need to
/// model a separate failure event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidCommMessageSentPayload {
    pub message_type: String,
    pub recipient_endpoint: String,
    pub transport: String,
    pub status: String,
}

impl agent_events::TypedEvent for DidCommMessageSentPayload {
    const TOPIC: &'static str = topics::DIDCOMM;
    const NAME: &'static str = types::MESSAGE_SENT;
}

/// Payload for `(consensus, proposal_created)` — emitted when the local
/// validator produces a block proposal. View / hash / count are surfaced for
/// observability dashboards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProposalCreatedPayload {
    pub view: u64,
    pub block_hash: String,
    pub transactions_count: usize,
}

impl agent_events::TypedEvent for ConsensusProposalCreatedPayload {
    const TOPIC: &'static str = topics::CONSENSUS;
    const NAME: &'static str = types::PROPOSAL_CREATED;
}

/// Payload for `(consensus, vote_cast)` — emitted when the local validator
/// casts a vote on a proposed block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVoteCastPayload {
    pub view: u64,
    pub block_hash: String,
    /// Validator identifier — formatted via Debug today; Phase 4 deprecation
    /// will switch this to a typed `Validator` once the consensus layer
    /// exposes a stable string representation.
    pub validator: String,
}

impl agent_events::TypedEvent for ConsensusVoteCastPayload {
    const TOPIC: &'static str = topics::CONSENSUS;
    const NAME: &'static str = types::VOTE_CAST;
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_events::{EventBus, EventMetadata, TypedEvent};

    fn meta() -> EventMetadata {
        EventMetadata::for_tenant("test-tenant")
    }

    #[test]
    fn typed_event_bindings_match_constants() {
        assert_eq!(
            <DidCommMessageReceivedPayload as TypedEvent>::TOPIC,
            topics::DIDCOMM
        );
        assert_eq!(
            <DidCommMessageReceivedPayload as TypedEvent>::NAME,
            types::MESSAGE_RECEIVED
        );
        assert_eq!(
            <DidCommMessageProcessedPayload as TypedEvent>::NAME,
            types::MESSAGE_PROCESSED
        );
        assert_eq!(
            <DidCommMessageSentPayload as TypedEvent>::NAME,
            types::MESSAGE_SENT
        );
        assert_eq!(
            <ConsensusProposalCreatedPayload as TypedEvent>::TOPIC,
            topics::CONSENSUS
        );
        assert_eq!(
            <ConsensusProposalCreatedPayload as TypedEvent>::NAME,
            types::PROPOSAL_CREATED
        );
        assert_eq!(
            <ConsensusVoteCastPayload as TypedEvent>::NAME,
            types::VOTE_CAST
        );
    }

    #[tokio::test]
    async fn didcomm_message_received_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            DidCommMessageReceivedPayload {
                message_type: "https://didcomm.org/basicmessage/1.0/message".into(),
                sender_did: Some("did:key:zABC".into()),
                encrypted: true,
                authenticated: true,
            },
        )
        .await
        .unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: DidCommMessageReceivedPayload = env.payload().unwrap();
        assert_eq!(decoded.sender_did.as_deref(), Some("did:key:zABC"));
        assert!(decoded.encrypted);
        assert_eq!(env.topic, topics::DIDCOMM);
    }

    #[tokio::test]
    async fn didcomm_message_processed_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            DidCommMessageProcessedPayload {
                message_type: "msg".into(),
                processed_at_ms: 1_700_000_000_000,
                success: true,
            },
        )
        .await
        .unwrap();
        let decoded: DidCommMessageProcessedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert!(decoded.success);
        assert_eq!(decoded.processed_at_ms, 1_700_000_000_000);
    }

    #[tokio::test]
    async fn didcomm_message_sent_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            DidCommMessageSentPayload {
                message_type: "msg".into(),
                recipient_endpoint: "https://example.com/inbox".into(),
                transport: "http".into(),
                status: "ok".into(),
            },
        )
        .await
        .unwrap();
        let decoded: DidCommMessageSentPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.transport, "http");
        assert_eq!(decoded.status, "ok");
    }

    #[tokio::test]
    async fn consensus_proposal_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            ConsensusProposalCreatedPayload {
                view: 42,
                block_hash: "0xabcdef".into(),
                transactions_count: 3,
            },
        )
        .await
        .unwrap();
        let decoded: ConsensusProposalCreatedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.view, 42);
        assert_eq!(decoded.transactions_count, 3);
    }

    #[tokio::test]
    async fn consensus_vote_cast_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            ConsensusVoteCastPayload {
                view: 42,
                block_hash: "0xabcdef".into(),
                validator: "v1".into(),
            },
        )
        .await
        .unwrap();
        let decoded: ConsensusVoteCastPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.validator, "v1");
    }
}
