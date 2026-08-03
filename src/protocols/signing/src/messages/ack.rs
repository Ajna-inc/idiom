//! Acknowledgment message body
use serde::{Deserialize, Serialize};

/// Acknowledgment of a received message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ack {
    pub session_id: String,
    /// Status (e.g., "OK")
    pub status: String,
}
