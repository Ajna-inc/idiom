//! Provide artifacts message body
use crate::models::SealedSecret;
use serde::{Deserialize, Serialize};

/// Provide artifacts - deliver signed outputs or sealed secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvideArtifacts {
    pub session_id: String,
    /// Base64-encoded combined signature
    pub combined_signature: String,
    /// Per-recipient sealed secrets
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sealed_secrets: Vec<SealedSecret>,
}
