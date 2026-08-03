//! Workflow Events
//!
//! Typed payloads for the workflow protocol. Three events:
//! - `state_changed` — FSM state transition (driven by an internal `event` token)
//! - `status_changed` — instance lifecycle status (Active/Paused/Completed/...)
//! - `completed` — terminal-state convenience event
//!
//! Payload field shapes match the prior hand-built JSON exactly so external
//! consumers (the workflow UI in vilko, integration tests) stay backward
//! compatible.

use crate::InstanceStatus;
use serde::{Deserialize, Serialize};

pub mod topics {
    pub const WORKFLOW: &str = "workflow";
}

pub mod types {
    pub const STATE_CHANGED: &str = "state_changed";
    pub const STATUS_CHANGED: &str = "status_changed";
    pub const COMPLETED: &str = "completed";
}

/// Payload for an FSM state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStateChangedPayload {
    pub instance_id: String,
    pub previous_state: Option<String>,
    pub new_state: String,
    /// The internal event token that triggered the transition.
    pub event: String,
    pub template_id: String,
    pub connection_id: Option<String>,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for WorkflowStateChangedPayload {
    const TOPIC: &'static str = topics::WORKFLOW;
    const NAME: &'static str = types::STATE_CHANGED;
}

/// Payload for an instance lifecycle status change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStatusChangedPayload {
    pub instance_id: String,
    pub previous_status: InstanceStatus,
    pub new_status: InstanceStatus,
    pub template_id: String,
    pub connection_id: Option<String>,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for WorkflowStatusChangedPayload {
    const TOPIC: &'static str = topics::WORKFLOW;
    const NAME: &'static str = types::STATUS_CHANGED;
}

/// Payload for a terminal-state completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowCompletedPayload {
    pub instance_id: String,
    pub state: String,
    pub section: Option<String>,
    pub template_id: String,
    pub connection_id: Option<String>,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for WorkflowCompletedPayload {
    const TOPIC: &'static str = topics::WORKFLOW;
    const NAME: &'static str = types::COMPLETED;
}

#[cfg(all(test, feature = "events"))]
mod tests {
    use super::*;
    use agent_events::{EventBus, EventMetadata, TypedEvent};

    fn meta() -> EventMetadata {
        EventMetadata::for_tenant("test-tenant")
    }

    #[test]
    fn typed_event_bindings_match_constants() {
        assert_eq!(
            <WorkflowStateChangedPayload as TypedEvent>::TOPIC,
            topics::WORKFLOW
        );
        assert_eq!(
            <WorkflowStateChangedPayload as TypedEvent>::NAME,
            types::STATE_CHANGED
        );
        assert_eq!(
            <WorkflowStatusChangedPayload as TypedEvent>::NAME,
            types::STATUS_CHANGED
        );
        assert_eq!(
            <WorkflowCompletedPayload as TypedEvent>::NAME,
            types::COMPLETED
        );
    }

    #[tokio::test]
    async fn state_changed_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            WorkflowStateChangedPayload {
                instance_id: "inst-1".into(),
                previous_state: Some("Draft".into()),
                new_state: "Submitted".into(),
                event: "submit".into(),
                template_id: "tpl-1".into(),
                connection_id: Some("conn-1".into()),
            },
        )
        .await
        .unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: WorkflowStateChangedPayload = env.payload().unwrap();
        assert_eq!(decoded.new_state, "Submitted");
        assert_eq!(decoded.previous_state.as_deref(), Some("Draft"));
        assert_eq!(env.topic, topics::WORKFLOW);
    }

    #[tokio::test]
    async fn status_changed_carries_enum() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            WorkflowStatusChangedPayload {
                instance_id: "inst-2".into(),
                previous_status: InstanceStatus::Active,
                new_status: InstanceStatus::Paused,
                template_id: "tpl-1".into(),
                connection_id: None,
            },
        )
        .await
        .unwrap();
        let decoded: WorkflowStatusChangedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.new_status, InstanceStatus::Paused);
        assert_eq!(decoded.previous_status, InstanceStatus::Active);
    }

    #[tokio::test]
    async fn completed_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            WorkflowCompletedPayload {
                instance_id: "inst-3".into(),
                state: "Done".into(),
                section: Some("final".into()),
                template_id: "tpl-1".into(),
                connection_id: None,
            },
        )
        .await
        .unwrap();
        let decoded: WorkflowCompletedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.state, "Done");
        assert_eq!(decoded.section.as_deref(), Some("final"));
    }
}
