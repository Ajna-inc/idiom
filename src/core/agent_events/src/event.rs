//! Event types and builders

use crate::typed::{EventMetadata, TypedEvent, TypedEventError};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// An event published on the event bus
///
/// Events contain:
/// - `id`: Unique event identifier
/// - `agent_id`: Agent that emitted the event
/// - `topic`: Full topic path (e.g., "consensus.proposal_created", "peer.discovered")
/// - `name`: Event name (e.g., "proposal_created", "discovered")
/// - `data`: Event payload (arbitrary JSON)
/// - `timestamp`: When the event was created
/// - `trace_id`: For tracing related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event ID
    pub id: String,

    /// Agent that emitted the event
    pub agent_id: String,

    /// Full topic path (e.g., "consensus.proposal_created")
    pub topic: String,

    /// Event name (e.g., "proposal_created")
    pub name: String,

    /// Event data (arbitrary JSON)
    pub data: serde_json::Value,

    /// Unix timestamp (milliseconds)
    pub timestamp: u64,

    /// Trace ID for correlation
    pub trace_id: Option<String>,
}

impl Event {
    /// Create a new event
    ///
    /// # Example
    ///
    /// ```rust
    /// use agent_events::Event;
    ///
    /// let event = Event::new(
    ///     "validator0",
    ///     "consensus.proposal_created",
    ///     "proposal_created",
    ///     serde_json::json!({
    ///         "view": 1,
    ///         "block_hash": "0x..."
    ///     })
    /// );
    /// ```
    pub fn new(
        agent_id: impl Into<String>,
        topic: impl Into<String>,
        name: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: agent_id.into(),
            topic: topic.into(),
            name: name.into(),
            data,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_id: None,
        }
    }

    /// Create an event with trace ID
    pub fn with_trace(
        agent_id: impl Into<String>,
        topic: impl Into<String>,
        name: impl Into<String>,
        data: serde_json::Value,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: agent_id.into(),
            topic: topic.into(),
            name: name.into(),
            data,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_id: Some(trace_id.into()),
        }
    }

    /// Builder pattern for creating events
    pub fn builder(
        agent_id: impl Into<String>,
        topic: impl Into<String>,
        name: impl Into<String>,
    ) -> EventBuilder {
        EventBuilder {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: agent_id.into(),
            topic: topic.into(),
            name: name.into(),
            data: serde_json::Value::Null,
            trace_id: None,
        }
    }

    /// Check if event matches a topic
    pub fn matches_topic(&self, topic: &str) -> bool {
        self.topic == topic
    }

    /// Check if event matches a name
    pub fn matches_name(&self, name: &str) -> bool {
        self.name == name
    }

    /// Build a wire envelope from a typed payload.
    ///
    /// Sets `topic` / `name` from the type's `TypedEvent` constants and
    /// serializes `payload` into `data`. This is the canonical way to publish
    /// once the producer has migrated off `Event::new`.
    pub fn from_typed<E: TypedEvent>(
        meta: &EventMetadata,
        payload: &E,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: meta.tenant_id.clone(),
            topic: E::TOPIC.to_string(),
            name: E::NAME.to_string(),
            data: serde_json::to_value(payload)?,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_id: meta.trace_id.clone(),
        })
    }

    /// Decode the wire envelope back into the typed payload.
    ///
    /// Returns `TopicMismatch` / `NameMismatch` when the caller asked for the
    /// wrong type, and `Json` when producer/consumer schemas have drifted.
    pub fn payload<E: TypedEvent>(&self) -> Result<E, TypedEventError> {
        if self.topic != E::TOPIC {
            return Err(TypedEventError::TopicMismatch {
                expected: E::TOPIC,
                actual: self.topic.clone(),
            });
        }
        if self.name != E::NAME {
            return Err(TypedEventError::NameMismatch {
                expected: E::NAME,
                actual: self.name.clone(),
            });
        }
        Ok(serde_json::from_value(self.data.clone())?)
    }
}

/// Builder for creating events
pub struct EventBuilder {
    id: String,
    agent_id: String,
    topic: String,
    name: String,
    data: serde_json::Value,
    trace_id: Option<String>,
}

impl EventBuilder {
    /// Set the data
    pub fn data(mut self, data: serde_json::Value) -> Self {
        self.data = data;
        self
    }

    /// Set the trace ID
    pub fn trace_id(mut self, id: impl Into<String>) -> Self {
        self.trace_id = Some(id.into());
        self
    }

    /// Build the event
    pub fn build(self) -> Event {
        Event {
            id: self.id,
            agent_id: self.agent_id,
            topic: self.topic,
            name: self.name,
            data: self.data,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_id: self.trace_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = Event::new(
            "validator0",
            "consensus.proposal_created",
            "proposal_created",
            serde_json::json!({"view": 1}),
        );
        assert_eq!(event.agent_id, "validator0");
        assert_eq!(event.topic, "consensus.proposal_created");
        assert_eq!(event.name, "proposal_created");
        assert_eq!(event.data["view"], 1);
        assert!(event.timestamp > 0);
        assert!(event.trace_id.is_none());
        assert!(!event.id.is_empty());
    }

    #[test]
    fn test_event_with_trace() {
        let event = Event::with_trace(
            "validator0",
            "consensus.vote_cast",
            "vote_cast",
            serde_json::json!({}),
            "trace-123",
        );
        assert_eq!(event.trace_id, Some("trace-123".to_string()));
    }

    #[test]
    fn test_event_builder() {
        let event = Event::builder("validator0", "peer.discovered", "discovered")
            .data(serde_json::json!({"peer_did": "did:ajna:peer1"}))
            .trace_id("trace-id")
            .build();

        assert_eq!(event.agent_id, "validator0");
        assert_eq!(event.topic, "peer.discovered");
        assert_eq!(event.name, "discovered");
        assert_eq!(event.trace_id, Some("trace-id".to_string()));
    }

    #[test]
    fn test_event_matches() {
        let event = Event::new(
            "validator0",
            "consensus.proposal_created",
            "proposal_created",
            serde_json::json!({}),
        );
        assert!(event.matches_topic("consensus.proposal_created"));
        assert!(!event.matches_topic("peer.discovered"));
        assert!(event.matches_name("proposal_created"));
        assert!(!event.matches_name("vote_cast"));
    }

    #[test]
    fn test_event_serialization() {
        let event = Event::new(
            "validator0",
            "test.event",
            "event",
            serde_json::json!({"key": "value"}),
        );
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: Event = serde_json::from_str(&json).unwrap();

        assert_eq!(event.agent_id, deserialized.agent_id);
        assert_eq!(event.topic, deserialized.topic);
        assert_eq!(event.name, deserialized.name);
        assert_eq!(event.data, deserialized.data);
    }
}
