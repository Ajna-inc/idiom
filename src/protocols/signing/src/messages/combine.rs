//! Combine message body - aggregation status from coordinator
use crate::models::Suite;
use serde::{Deserialize, Serialize};

/// Combine - sent by coordinator after threshold is reached
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Combine {
    pub session_id: String,
    /// Base64-encoded combined/aggregated signature
    pub combined_signature: String,
    pub suite: Suite,
    pub object_digest: String,
    /// Number of partial signatures that were combined
    pub participant_count: u32,
}
