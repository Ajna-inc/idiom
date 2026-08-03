//! Signing session types

use serde::{Deserialize, Serialize};

use crate::state::SigningSessionState;

use super::signable_object::{Constraints, KeyBinding, SignableObject, Suite};

/// Threshold configuration for N-of-M signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Scheme identifier (e.g., "n-of-m")
    pub scheme: String,
    /// Required number of signatures
    pub n: u32,
    /// Total number of signers
    pub m: u32,
    /// DIDs of all authorized signers
    pub signers: Vec<String>,
    /// Aggregation method (e.g., "none", "math-aggregate@1")
    #[serde(default = "default_aggregation")]
    pub aggregation: String,
}

fn default_aggregation() -> String {
    "none".to_string()
}

/// Session mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMode {
    /// Mode type (e.g., "single", "threshold", "cryptographic-aggregation")
    #[serde(rename = "type")]
    pub mode_type: String,
}

/// A participant in a signing session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionParticipant {
    /// Participant's DID
    pub did: String,
    /// Key binding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_binding: Option<KeyBinding>,
    /// Connection ID for DIDComm routing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    /// Whether consent has been received
    #[serde(default)]
    pub consented: bool,
    /// Whether signature has been received
    #[serde(default)]
    pub signed: bool,
    /// Partial signature data (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A signing session managed by the coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningSession {
    /// Unique session ID
    pub session_id: String,
    /// DIDComm thread ID
    pub thread_id: String,
    /// The object being signed
    pub object: SignableObject,
    /// Cryptographic suite to use
    pub suite: Suite,
    /// Constraints on the signing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    /// Session mode
    pub mode: SessionMode,
    /// Threshold config (for multi-sig)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ThresholdConfig>,
    /// Current session state
    pub state: SigningSessionState,
    /// Participating signers
    pub participants: Vec<SessionParticipant>,
    /// Coordinator's DID
    pub coordinator_did: String,
    /// Creation timestamp (ISO 8601)
    pub created_at: String,
    /// Last updated timestamp (ISO 8601)
    pub updated_at: String,
    /// Expiry timestamp (ISO 8601, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Combined signature after aggregation (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub combined_signature: Option<String>,
}
