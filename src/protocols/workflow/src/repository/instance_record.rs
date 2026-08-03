use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::instance::WorkflowInstanceData;
use crate::domain::role::WorkflowRole;

pub const WORKFLOW_INSTANCE_CATEGORY: &str = "workflow_instance";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInstanceRecord {
    pub id: String,
    pub data: WorkflowInstanceData,
    pub role: WorkflowRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl WorkflowInstanceRecord {
    pub fn new(data: WorkflowInstanceData, role: WorkflowRole) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            data,
            role,
            created_at: now,
            updated_at: now,
        }
    }

    /// Convenience: get the instance_id from inner data.
    pub fn instance_id(&self) -> &str {
        &self.data.instance_id
    }

    /// Convenience: get the current state.
    pub fn state(&self) -> &str {
        &self.data.state
    }

    /// Convenience: get the connection_id.
    pub fn connection_id(&self) -> Option<&str> {
        self.data.connection_id.as_deref()
    }
}
