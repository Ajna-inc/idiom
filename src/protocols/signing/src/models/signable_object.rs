//! Signable object and cryptographic constraint types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An object to be signed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignableObject {
    /// Unique identifier for the signable object
    pub id: String,
    /// MIME type (e.g., "application/json", "application/pdf")
    pub media_type: String,
    /// Canonicalization method and parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonicalization: Option<Canonicalization>,
    /// Digest of the content
    pub digest: Digest,
    /// Human-readable display hints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_hints: Option<DisplayHints>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canonicalization {
    pub method: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub parameters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    /// Hash algorithm (e.g., "sha-256")
    pub alg: String,
    /// Base64-encoded hash value
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayHints {
    /// Human-readable title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Preview links
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preview_links: Vec<String>,
}

/// Cryptographic suite identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suite {
    /// Suite identifier (e.g., "jws-ed25519@1", "evm-eip712@1")
    pub id: String,
}

/// Key binding for a signer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBinding {
    /// DID controller of the key
    pub controller: String,
    /// Proof purpose (e.g., "assertionMethod", "authentication")
    pub proof_purpose: String,
}

/// Signing constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    /// Not-before timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Expiry timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_time: Option<String>,
    /// Maximum number of uses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_limit: Option<u32>,
    /// Policy URI for reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
}
