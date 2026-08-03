/// Common types for SD-JWT implementation
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// SD-JWT Verifiable Credential
#[derive(Debug, Clone)]
pub struct SdJwtVc {
    /// The main JWT containing _sd claims
    pub jwt: String,
    /// List of disclosures for selective disclosure
    pub disclosures: Vec<String>,
    /// Optional key binding JWT for holder binding
    pub key_binding_jwt: Option<String>,
}

impl SdJwtVc {
    /// Convert to compact format (tilde-separated)
    pub fn to_compact(&self) -> String {
        let mut parts = vec![self.jwt.clone()];
        parts.extend(self.disclosures.clone());

        if let Some(kb_jwt) = &self.key_binding_jwt {
            parts.push(kb_jwt.clone());
        } else {
            parts.push(String::new());
        }

        parts.join("~")
    }

    /// KB-JWT hash input for SD-JWT: `<jwt>~<d1>~…~<dn>~` — the
    /// presented credential up to and including the final `~`, EXCLUDING the
    /// KB-JWT itself. Holder (when minting `sd_hash`) and verifier (when
    /// checking it) must both hash exactly this string.
    pub fn kb_hash_input(&self) -> String {
        let mut input = self.jwt.clone();
        for disclosure in &self.disclosures {
            input.push('~');
            input.push_str(disclosure);
        }
        input.push('~');
        input
    }

    /// Parse from compact format
    pub fn from_compact(compact: &str) -> Result<Self, SdJwtError> {
        let parts: Vec<&str> = compact.split('~').collect();

        if parts.is_empty() {
            return Err(SdJwtError::InvalidFormat("Empty SD-JWT".to_string()));
        }

        let jwt = parts[0].to_string();

        // Last part is key binding JWT or empty
        let kb_jwt = parts.last().and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        });

        // Middle parts are disclosures
        let disclosures = if parts.len() > 2 {
            parts[1..parts.len() - 1]
                .iter()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        } else {
            Vec::new()
        };

        Ok(Self {
            jwt,
            disclosures,
            key_binding_jwt: kb_jwt,
        })
    }
}

/// Claims structure for SD-JWT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtClaims {
    /// Standard JWT claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Selective disclosure digests
    #[serde(rename = "_sd", skip_serializing_if = "Option::is_none")]
    pub sd: Option<Vec<String>>,

    /// Hash algorithm used (default: sha-256)
    #[serde(rename = "_sd_alg", skip_serializing_if = "Option::is_none")]
    pub sd_alg: Option<String>,

    /// Confirmation claim for holder binding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Value>,

    /// Verifiable Credential claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vc: Option<Value>,

    /// Additional claims
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

/// Key Binding JWT for holder binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBindingJwt {
    /// Nonce for freshness
    pub nonce: String,

    /// Audience (verifier)
    pub aud: String,

    /// Issued at timestamp
    pub iat: i64,

    /// Hash of the SD-JWT
    #[serde(rename = "_sd_hash")]
    pub sd_hash: String,

    /// Additional claims
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

/// SD-JWT Error types
#[derive(Debug, Clone)]
pub enum SdJwtError {
    /// Invalid format
    InvalidFormat(String),

    /// Signature verification failed
    InvalidSignature(String),

    /// Disclosure verification failed
    InvalidDisclosure(String),

    /// Key binding verification failed
    InvalidKeyBinding(String),

    /// Missing required claim
    MissingClaim(String),

    /// Serialization error
    SerializationError(String),

    /// Other error
    Other(String),
}

impl std::fmt::Display for SdJwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdJwtError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            SdJwtError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            SdJwtError::InvalidDisclosure(msg) => write!(f, "Invalid disclosure: {}", msg),
            SdJwtError::InvalidKeyBinding(msg) => write!(f, "Invalid key binding: {}", msg),
            SdJwtError::MissingClaim(msg) => write!(f, "Missing claim: {}", msg),
            SdJwtError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            SdJwtError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for SdJwtError {}

impl From<serde_json::Error> for SdJwtError {
    fn from(err: serde_json::Error) -> Self {
        SdJwtError::SerializationError(err.to_string())
    }
}
