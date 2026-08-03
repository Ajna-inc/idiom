use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const WORKFLOW_COMMAND_CATEGORY: &str = "workflow_command";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowCommandRecord {
    pub id: String,
    pub cmd: CommandType,
    pub thid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub payload: serde_json::Value,
    pub status: CommandStatus,
    pub attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl WorkflowCommandRecord {
    pub fn new(
        cmd: CommandType,
        thid: String,
        connection_id: Option<String>,
        idempotency_key: Option<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            cmd,
            thid,
            connection_id,
            idempotency_key,
            payload,
            status: CommandStatus::Pending,
            attempts: 0,
            last_attempt_at: None,
            error: None,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommandType {
    Start,
    Advance,
    Pause,
    Resume,
    Cancel,
    Complete,
}

impl std::fmt::Display for CommandType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandType::Start => write!(f, "start"),
            CommandType::Advance => write!(f, "advance"),
            CommandType::Pause => write!(f, "pause"),
            CommandType::Resume => write!(f, "resume"),
            CommandType::Cancel => write!(f, "cancel"),
            CommandType::Complete => write!(f, "complete"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommandStatus {
    Pending,
    Processing,
    Completed,
    Failed,
}

impl std::fmt::Display for CommandStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandStatus::Pending => write!(f, "pending"),
            CommandStatus::Processing => write!(f, "processing"),
            CommandStatus::Completed => write!(f, "completed"),
            CommandStatus::Failed => write!(f, "failed"),
        }
    }
}
