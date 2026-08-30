//! DIDComm v1 message types and JWE structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DIDComm v1 encrypted message (JWE format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Base64URL-encoded protected header
    pub protected: String,

    /// Base64URL-encoded ciphertext
    pub ciphertext: String,

    /// Base64URL-encoded initialization vector
    pub iv: String,

    /// Base64URL-encoded authentication tag
    pub tag: String,
}

/// DIDComm v1 plaintext message
pub type PlaintextMessage = HashMap<String, serde_json::Value>;

/// Protected header structure (decoded from protected field)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedHeader {
    /// Encryption algorithm (should be "xchacha20poly1305_ietf")
    pub enc: String,

    /// Message type (should be "JWM/1.0")
    pub typ: String,

    /// Packing algorithm ("Authcrypt" or "Anoncrypt")
    pub alg: String,

    /// Recipients array
    pub recipients: Vec<Recipient>,
}

/// Recipient information in the protected header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    /// Base64URL-encoded encrypted content encryption key
    pub encrypted_key: String,

    /// Recipient-specific header
    pub header: RecipientHeader,
}

/// Recipient header containing key ID and authcrypt-specific fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientHeader {
    /// Key ID (base58-encoded public key)
    pub kid: String,

    /// Optional sender public key (encrypted, for authcrypt)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,

    /// Optional IV for encrypted sender (for authcrypt)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,

    // ── Post-quantum hybrid fields (Phase 3) ──
    /// ML-KEM-768 ciphertext (base64url, 1088 bytes). Present when hybrid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kem: Option<String>,

    /// ML-KEM kid (base64url SHA-256 of peer's KEM public key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kem_kid: Option<String>,

    /// X25519 ephemeral public key (base64url, 32 bytes). For hybrid ECDH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x25519_eph: Option<String>,
}

/// Algorithm types for DIDComm v1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackAlgorithm {
    /// Authenticated encryption (with sender authentication)
    Authcrypt,
    /// Anonymous encryption (no sender authentication)
    Anoncrypt,
    /// Hybrid: X25519 ECDH + ML-KEM-768 (quantum-safe, authenticated)
    AuthcryptHybrid,
}

impl PackAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            PackAlgorithm::Authcrypt => "Authcrypt",
            PackAlgorithm::Anoncrypt => "Anoncrypt",
            PackAlgorithm::AuthcryptHybrid => "Authcrypt-Hybrid",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Authcrypt" => Some(PackAlgorithm::Authcrypt),
            "Anoncrypt" => Some(PackAlgorithm::Anoncrypt),
            "Authcrypt-Hybrid" => Some(PackAlgorithm::AuthcryptHybrid),
            _ => None,
        }
    }

    pub fn is_hybrid(&self) -> bool {
        matches!(self, PackAlgorithm::AuthcryptHybrid)
    }
}

/// Metadata from unpacking a DIDComm v1 message
#[derive(Debug, Clone)]
pub struct UnpackMetadata {
    /// Recipient key (base58-encoded public key)
    pub recipient_key: String,

    /// Sender key (base58-encoded public key, only for authcrypt)
    pub sender_key: Option<String>,

    /// Whether the message was authenticated
    pub authenticated: bool,

    /// Whether the message was anonymous
    pub anonymous: bool,

    /// The exact decrypted plaintext as it came off the wire, before any
    /// parsing or v1→v2 normalization. Byte-faithful except for being UTF-8.
    pub raw_plaintext: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_algorithm() {
        assert_eq!(PackAlgorithm::Authcrypt.as_str(), "Authcrypt");
        assert_eq!(PackAlgorithm::Anoncrypt.as_str(), "Anoncrypt");

        assert_eq!(
            PackAlgorithm::from_str("Authcrypt"),
            Some(PackAlgorithm::Authcrypt)
        );
        assert_eq!(
            PackAlgorithm::from_str("Anoncrypt"),
            Some(PackAlgorithm::Anoncrypt)
        );
        assert_eq!(PackAlgorithm::from_str("Invalid"), None);
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let msg = EncryptedMessage {
            protected: "eyJ0eXAiOiJKV00vMS4wIn0".to_string(),
            ciphertext: "abc123".to_string(),
            iv: "iv123".to_string(),
            tag: "tag123".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: EncryptedMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(msg.protected, deserialized.protected);
        assert_eq!(msg.ciphertext, deserialized.ciphertext);
    }
}
