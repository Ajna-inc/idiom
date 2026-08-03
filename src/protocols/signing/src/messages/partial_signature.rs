//! Partial signature message body
use crate::models::Suite;
use serde::{Deserialize, Serialize};

/// Partial signature submitted by a signer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    pub session_id: String,
    pub signer_did: String,
    /// 1-based signer index (for threshold ordering)
    pub signer_index: u32,
    /// Base64-encoded signature data
    pub signature: String,
    pub suite: Suite,
    /// Hex-encoded digest of the signed content (must match object.digest)
    pub object_digest: String,
}
