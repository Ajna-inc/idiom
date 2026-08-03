//! Event filtering utilities

use crate::Event;

/// Filter for subscribing to specific events
///
/// # Example
///
/// ```rust
/// use agent_events::EventFilter;
///
/// // Filter for connection events
/// let filter = EventFilter::new()
///     .with_topic("connection")
///     .with_name("state_changed");
///
/// // Match all events on a topic
/// let filter = EventFilter::topic("consensus.proposal_created");
/// ```
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// Topics to match (empty = match all)
    topics: Vec<String>,

    /// Event names to match (empty = match all)
    names: Vec<String>,

    /// Trace IDs to match (empty = match all)
    trace_ids: Vec<String>,

    /// Agent (tenant) IDs to match (empty = match all). Multi-tenant
    /// consumers (e.g. the per-WS-connection forwarder in vilko_api) build
    /// this once at subscribe time instead of comparing `event.agent_id ==
    /// ws_user_id` in their hot path.
    agent_ids: Vec<String>,
}

impl EventFilter {
    /// Create an empty filter (matches all events)
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a filter for a specific topic
    pub fn topic(topic: impl Into<String>) -> Self {
        Self {
            topics: vec![topic.into()],
            ..Self::default()
        }
    }

    /// Create a filter for a specific event name
    pub fn name(name: impl Into<String>) -> Self {
        Self {
            names: vec![name.into()],
            ..Self::default()
        }
    }

    /// Create a filter for events emitted by a specific agent / tenant.
    pub fn agent_id(agent_id: impl Into<String>) -> Self {
        Self {
            agent_ids: vec![agent_id.into()],
            ..Self::default()
        }
    }

    /// Alias for `agent_id` — reads better at WS-subscription sites where
    /// the value is conceptually a tenant id.
    pub fn tenant(tenant_id: impl Into<String>) -> Self {
        Self::agent_id(tenant_id)
    }

    /// Add a topic to the filter
    pub fn with_topic(mut self, topic: impl Into<String>) -> Self {
        self.topics.push(topic.into());
        self
    }

    /// Add an event name to the filter
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.names.push(name.into());
        self
    }

    /// Add a trace ID to the filter
    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_ids.push(trace_id.into());
        self
    }

    /// Add an agent / tenant id to the filter (`OR` against any others).
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_ids.push(agent_id.into());
        self
    }

    /// Check if an event matches this filter
    ///
    /// An event matches if:
    /// - All topic filters match (OR logic within topics)
    /// - All name filters match (OR logic within names)
    /// - All trace_id filters match (OR logic within IDs)
    /// - Empty filter lists match all events
    pub fn matches(&self, event: &Event) -> bool {
        // Check topic filter
        if !self.topics.is_empty() && !self.topics.iter().any(|t| event.matches_topic(t)) {
            return false;
        }

        // Check event name filter
        if !self.names.is_empty() && !self.names.iter().any(|t| event.matches_name(t)) {
            return false;
        }

        // Check trace ID filter
        if !self.trace_ids.is_empty() {
            match &event.trace_id {
                Some(id) => {
                    if !self.trace_ids.iter().any(|c| c == id) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Check agent_id (tenant) filter
        if !self.agent_ids.is_empty() && !self.agent_ids.iter().any(|a| a == &event.agent_id) {
            return false;
        }

        true
    }

    /// Check if this is an empty filter (matches all)
    pub fn is_empty(&self) -> bool {
        self.topics.is_empty()
            && self.names.is_empty()
            && self.trace_ids.is_empty()
            && self.agent_ids.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_filter_matches_all() {
        let filter = EventFilter::new();
        let event = Event::new(
            "validator0",
            "consensus.proposal_created",
            "proposal_created",
            serde_json::json!({}),
        );
        assert!(filter.matches(&event));
    }

    #[test]
    fn test_topic_filter() {
        let filter = EventFilter::topic("consensus.proposal_created");
        let event1 = Event::new(
            "validator0",
            "consensus.proposal_created",
            "proposal_created",
            serde_json::json!({}),
        );
        let event2 = Event::new(
            "validator0",
            "peer.discovered",
            "discovered",
            serde_json::json!({}),
        );

        assert!(filter.matches(&event1));
        assert!(!filter.matches(&event2));
    }

    #[test]
    fn test_name_filter() {
        let filter = EventFilter::name("proposal_created");
        let event1 = Event::new(
            "validator0",
            "consensus.proposal_created",
            "proposal_created",
            serde_json::json!({}),
        );
        let event2 = Event::new(
            "validator0",
            "consensus.vote_cast",
            "vote_cast",
            serde_json::json!({}),
        );

        assert!(filter.matches(&event1));
        assert!(!filter.matches(&event2));
    }

    #[test]
    fn test_multiple_topics() {
        let filter = EventFilter::new()
            .with_topic("consensus.proposal_created")
            .with_topic("peer.discovered");

        let event1 = Event::new(
            "validator0",
            "consensus.proposal_created",
            "proposal_created",
            serde_json::json!({}),
        );
        let event2 = Event::new(
            "validator0",
            "peer.discovered",
            "discovered",
            serde_json::json!({}),
        );
        let event3 = Event::new(
            "validator0",
            "consensus.vote_cast",
            "vote_cast",
            serde_json::json!({}),
        );

        assert!(filter.matches(&event1));
        assert!(filter.matches(&event2));
        assert!(!filter.matches(&event3));
    }

    #[test]
    fn test_combined_filter() {
        let filter = EventFilter::new()
            .with_topic("consensus.proposal_created")
            .with_name("proposal_created");

        let event1 = Event::new(
            "validator0",
            "consensus.proposal_created",
            "proposal_created",
            serde_json::json!({}),
        );
        let event2 = Event::new(
            "validator0",
            "consensus.proposal_created",
            "vote_cast",
            serde_json::json!({}),
        );
        let event3 = Event::new(
            "validator0",
            "peer.discovered",
            "proposal_created",
            serde_json::json!({}),
        );

        assert!(filter.matches(&event1));
        assert!(!filter.matches(&event2));
        assert!(!filter.matches(&event3));
    }

    #[test]
    fn test_trace_id_filter() {
        let filter = EventFilter::new().with_trace_id("trace-123");

        let event1 = Event::with_trace(
            "validator0",
            "consensus.proposal_created",
            "proposal_created",
            serde_json::json!({}),
            "trace-123",
        );
        let event2 = Event::with_trace(
            "validator0",
            "consensus.proposal_created",
            "proposal_created",
            serde_json::json!({}),
            "trace-456",
        );
        let event3 = Event::new(
            "validator0",
            "consensus.proposal_created",
            "proposal_created",
            serde_json::json!({}),
        );

        assert!(filter.matches(&event1));
        assert!(!filter.matches(&event2));
        assert!(!filter.matches(&event3));
    }

    #[test]
    fn test_is_empty() {
        let empty = EventFilter::new();
        assert!(empty.is_empty());

        let not_empty = EventFilter::topic("consensus.proposal_created");
        assert!(!not_empty.is_empty());
    }
}
