//! Issue token message body
use crate::models::{SealedSecret, SignedAuthorizationToken};
use serde::{Deserialize, Serialize};

/// Issue token - deliver authorization token after successful signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueToken {
    pub session_id: String,
    pub token: SignedAuthorizationToken,
    /// Optional sealed secret bound to the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_secret: Option<SealedSecret>,
}
