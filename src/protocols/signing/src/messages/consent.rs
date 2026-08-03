//! Consent message body
use crate::models::{KeyBinding, Suite};
use serde::{Deserialize, Serialize};

/// Consent - signer agrees to participate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consent {
    pub session_id: String,
    pub signer_did: String,
    pub key_binding: KeyBinding,
    pub accepted_suite: Suite,
}
