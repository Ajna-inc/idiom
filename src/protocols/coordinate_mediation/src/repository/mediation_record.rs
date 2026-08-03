use crate::{MediationRole, MediationState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Mediation record stored in the repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediationRecord {
    pub id: String,
    pub connection_id: String,
    pub state: MediationState,
    pub role: MediationRole,
    pub endpoint: Option<String>,
    pub routing_keys: Vec<String>,
    /// The recipient key (did:key format) registered with the mediator via keylist-update.
    /// This is the key that peers should use to route messages to this agent through the mediator.
    /// Persisted across restarts to ensure continuity.
    #[serde(default)]
    pub registered_recipient_key: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Builder for MediationRecord
pub struct MediationRecordBuilder {
    id: Option<String>,
    connection_id: String,
    state: MediationState,
    role: MediationRole,
    endpoint: Option<String>,
    routing_keys: Vec<String>,
    registered_recipient_key: Option<String>,
}

impl MediationRecordBuilder {
    pub fn new(connection_id: String, role: MediationRole) -> Self {
        Self {
            id: None,
            connection_id,
            state: MediationState::Requested,
            role,
            endpoint: None,
            routing_keys: Vec::new(),
            registered_recipient_key: None,
        }
    }

    pub fn id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    pub fn state(mut self, state: MediationState) -> Self {
        self.state = state;
        self
    }

    pub fn endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn routing_keys(mut self, keys: Vec<String>) -> Self {
        self.routing_keys = keys;
        self
    }

    pub fn registered_recipient_key(mut self, key: String) -> Self {
        self.registered_recipient_key = Some(key);
        self
    }

    pub fn build(self) -> MediationRecord {
        let now = Utc::now();
        MediationRecord {
            id: self.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            connection_id: self.connection_id,
            state: self.state,
            role: self.role,
            endpoint: self.endpoint,
            routing_keys: self.routing_keys,
            registered_recipient_key: self.registered_recipient_key,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Tags for querying mediation records
pub struct MediationTags;

impl MediationTags {
    pub const CONNECTION_ID: &'static str = "connection_id";
    pub const STATE: &'static str = "state";
    pub const ROLE: &'static str = "role";
}
