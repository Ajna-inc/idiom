//! Problem report message body
use serde::{Deserialize, Serialize};

/// Problem report - error notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemReport {
    pub session_id: String,
    pub reporter_did: String,
    /// Structured error code (e.g., "e.p.signing.timeout")
    pub code: String,
    /// Human-readable description
    pub description: String,
    /// Optional additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}
