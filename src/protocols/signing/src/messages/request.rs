//! Request signing message body
use crate::models::{
    Constraints, KeyBinding, SealedSecret, SessionMode, SignableObject, Suite, ThresholdConfig,
};
use serde::{Deserialize, Serialize};

/// Request signing - initiate a signing session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSigning {
    pub session_id: String,
    pub object: SignableObject,
    pub suite: Suite,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_binding: Option<KeyBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    pub mode: SessionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ThresholdConfig>,
    /// Optional sealed secret for the signer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_secret: Option<SealedSecret>,
}
