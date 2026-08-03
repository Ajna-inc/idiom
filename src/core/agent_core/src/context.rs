//! Agent context for runtime state and configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Agent label (human-readable name)
    pub label: String,

    /// Agent endpoints (for DID documents)
    pub endpoints: Vec<String>,

    /// Inbound transport host
    pub inbound_host: Option<String>,

    /// Inbound transport port
    pub inbound_port: Option<u16>,

    /// Mediator invitation URL (optional)
    pub mediator_invitation_url: Option<String>,

    /// Auto-accept connections
    pub auto_accept_connections: bool,

    /// Auto-accept credentials
    pub auto_accept_credentials: bool,

    /// Extra configuration (module-specific)
    #[serde(default)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            label: "Idiom Agent".to_string(),
            endpoints: vec![],
            inbound_host: Some("127.0.0.1".to_string()),
            inbound_port: Some(9002),
            mediator_invitation_url: None,
            auto_accept_connections: false,
            auto_accept_credentials: false,
            extra: HashMap::new(),
        }
    }
}

impl AgentConfig {
    /// Create a new agent configuration
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            ..Default::default()
        }
    }

    /// Set endpoints
    pub fn with_endpoints(mut self, endpoints: Vec<String>) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// Set inbound transport
    pub fn with_inbound(mut self, host: impl Into<String>, port: u16) -> Self {
        self.inbound_host = Some(host.into());
        self.inbound_port = Some(port);
        self
    }

    /// Set mediator
    pub fn with_mediator(mut self, invitation_url: impl Into<String>) -> Self {
        self.mediator_invitation_url = Some(invitation_url.into());
        self
    }

    /// Enable auto-accept for connections
    pub fn auto_accept_connections(mut self) -> Self {
        self.auto_accept_connections = true;
        self
    }

    /// Enable auto-accept for credentials
    pub fn auto_accept_credentials(mut self) -> Self {
        self.auto_accept_credentials = true;
        self
    }

    /// Add extra configuration
    pub fn with_extra(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    /// Get extra configuration value
    pub fn get_extra(&self, key: &str) -> Option<&serde_json::Value> {
        self.extra.get(key)
    }
}

/// Agent context holds runtime state and configuration.
///
/// The context is created during agent initialization and is passed to
/// all modules and services. It provides access to:
/// - Agent configuration
/// - Correlation ID for tracing
/// - Shared state across modules
#[derive(Clone)]
pub struct AgentContext {
    /// Agent configuration
    config: Arc<AgentConfig>,

    /// Correlation ID for this context
    correlation_id: String,

    /// Whether this is the root context
    is_root: bool,

    /// Shared state (thread-safe)
    state: Arc<tokio::sync::RwLock<HashMap<String, serde_json::Value>>>,
}

impl AgentContext {
    /// Create a new root agent context
    pub fn new(config: AgentConfig) -> Self {
        Self {
            config: Arc::new(config),
            correlation_id: Uuid::new_v4().to_string(),
            is_root: true,
            state: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Create a new child context with its own correlation ID
    pub fn child(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            correlation_id: Uuid::new_v4().to_string(),
            is_root: false,
            state: Arc::clone(&self.state),
        }
    }

    /// Get the agent configuration
    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    /// Get the correlation ID
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// Check if this is the root context
    pub fn is_root(&self) -> bool {
        self.is_root
    }

    /// Set a value in the shared state
    pub async fn set_state(&self, key: impl Into<String>, value: serde_json::Value) {
        let mut state = self.state.write().await;
        state.insert(key.into(), value);
    }

    /// Get a value from the shared state
    pub async fn get_state(&self, key: &str) -> Option<serde_json::Value> {
        let state = self.state.read().await;
        state.get(key).cloned()
    }

    /// Remove a value from the shared state
    pub async fn remove_state(&self, key: &str) -> Option<serde_json::Value> {
        let mut state = self.state.write().await;
        state.remove(key)
    }

    /// Clear all state
    pub async fn clear_state(&self) {
        let mut state = self.state.write().await;
        state.clear();
    }
}

impl std::fmt::Debug for AgentContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentContext")
            .field("correlation_id", &self.correlation_id)
            .field("is_root", &self.is_root)
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_config_builder() {
        let config = AgentConfig::new("Test Agent")
            .with_endpoints(vec!["http://localhost:9002".to_string()])
            .with_inbound("0.0.0.0", 8080)
            .auto_accept_connections()
            .with_extra("custom_key", serde_json::json!({"value": 42}));

        assert_eq!(config.label, "Test Agent");
        assert_eq!(config.endpoints.len(), 1);
        assert_eq!(config.inbound_port, Some(8080));
        assert!(config.auto_accept_connections);
        assert!(config.get_extra("custom_key").is_some());
    }

    #[tokio::test]
    async fn test_agent_context() {
        let config = AgentConfig::default();
        let ctx = AgentContext::new(config);

        assert!(ctx.is_root());
        assert!(!ctx.correlation_id().is_empty());

        // Test state management
        ctx.set_state("test_key", serde_json::json!({"foo": "bar"}))
            .await;
        let value = ctx.get_state("test_key").await;
        assert!(value.is_some());

        // Test child context
        let child = ctx.child();
        assert!(!child.is_root());
        assert_ne!(ctx.correlation_id(), child.correlation_id());

        // Child shares state with parent
        let child_value = child.get_state("test_key").await;
        assert!(child_value.is_some());
    }
}
