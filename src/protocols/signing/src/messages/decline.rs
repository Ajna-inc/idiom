//! Decline message body
use serde::{Deserialize, Serialize};

/// Decline - signer or coordinator refuses the signing request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decline {
    pub session_id: String,
    pub decliner_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
