//! HPKE sealed secret types
//!
//! Implements the sealed-secret envelope format from the DIDComm Signing Protocol 1.0.
//! Uses DHKEM(X25519, HKDF-SHA256) + AES-256-GCM (RFC 9180 compatible).

use serde::{Deserialize, Serialize};

/// HPKE encryption parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeEncParams {
    /// KEM algorithm (e.g., "X25519")
    pub kem: String,
    /// KDF algorithm (e.g., "HKDF-SHA256")
    pub kdf: String,
    /// AEAD algorithm (e.g., "AES-256-GCM")
    pub aead: String,
    /// Ephemeral public key (base64-encoded)
    pub ek_pub: String,
}

impl Default for HpkeEncParams {
    fn default() -> Self {
        Self {
            kem: "X25519".to_string(),
            kdf: "HKDF-SHA256".to_string(),
            aead: "AES-256-GCM".to_string(),
            ek_pub: String::new(),
        }
    }
}

/// Additional authenticated data for binding the envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeAad {
    /// SHA-256 hash of the bound authorization token
    pub ticket_digest: String,
    /// Session ID for binding
    pub session_id: String,
    /// Device DID for binding
    pub device: String,
}

/// HPKE sealed secret envelope
///
/// Contains an encrypted payload that can only be decrypted by the
/// intended recipient using their X25519 private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSecret {
    /// Envelope type identifier
    #[serde(rename = "type")]
    pub envelope_type: String,
    /// Suite identifier (e.g., "envelope-hpke@1")
    pub suite: String,
    /// Additional authenticated data
    pub aad: HpkeAad,
    /// Encrypted ciphertext (base64-encoded)
    pub ciphertext: String,
    /// HPKE encryption parameters
    pub enc: HpkeEncParams,
}

impl SealedSecret {
    /// Default envelope type
    pub const TYPE: &'static str = "sealed-secret@1";
    /// Default suite
    pub const SUITE: &'static str = "envelope-hpke@1";
}
