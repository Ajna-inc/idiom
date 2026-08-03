//! Authorization token types with monotonic counter replay protection

use serde::{Deserialize, Serialize};

/// Authorization token issued after successful signing
///
/// Contains a monotonic counter for replay protection per the
/// DIDComm Signing Protocol 1.0 specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationToken {
    /// Token type identifier
    pub typ: String,
    /// Session ID this token was issued for
    pub session_id: String,
    /// Scope of authorization (e.g., "unlock")
    pub scope: String,
    /// Device DID this token is bound to
    pub device: String,
    /// Monotonic counter value (must be strictly increasing per device)
    pub ctr: u64,
    /// Expiry timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
    /// Single-use capability count
    #[serde(default = "default_cap")]
    pub cap: u32,
}

fn default_cap() -> u32 {
    1
}

/// Signature over the authorization token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSignature {
    /// Signature suite used
    pub suite: String,
    /// Key ID of the signer
    pub kid: String,
    /// Signature value (base64-encoded)
    pub value: String,
}

/// A signed authorization token (token + signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAuthorizationToken {
    /// The token payload
    pub token: AuthorizationToken,
    /// Coordinator's signature over the token
    pub sig: TokenSignature,
}
