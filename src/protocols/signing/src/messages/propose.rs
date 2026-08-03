//! Propose signing message body
use crate::models::{Constraints, KeyBinding, SessionMode, SignableObject, Suite, ThresholdConfig};
use serde::{Deserialize, Serialize};

/// Propose signing - initial capability discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeSigning {
    pub session_id: String,
    pub object: SignableObject,
    pub suite: Suite,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_binding: Option<KeyBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<SessionMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ThresholdConfig>,
}
