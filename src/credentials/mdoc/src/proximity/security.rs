//! Security parameters for proximity presentations

use crate::cose::CoseKey;
use serde::{Deserialize, Serialize};

/// Security parameters for DeviceEngagement
///
/// Contains the cipher suite identifier and the device's ephemeral public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security {
    /// Cipher suite identifier
    /// - 1: ECDH-ES + AES-128-GCM
    /// - 2: ECDH-ES + AES-256-GCM
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: i32,

    /// Device's ephemeral public key
    #[serde(rename = "eDeviceKey")]
    pub device_key: EDeviceKey,

    /// Optional additional security parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl Security {
    /// Create new Security with cipher suite and device key
    pub fn new(cipher_suite: i32, device_key: EDeviceKey) -> Self {
        Self {
            cipher_suite,
            device_key,
            extensions: None,
        }
    }

    /// Builder pattern: set cipher suite
    pub fn with_cipher_suite(mut self, cipher_suite: i32) -> Self {
        self.cipher_suite = cipher_suite;
        self
    }

    /// Builder pattern: add extensions
    pub fn with_extensions(mut self, extensions: serde_json::Value) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Get the cipher suite name
    pub fn cipher_suite_name(&self) -> &str {
        match self.cipher_suite {
            1 => "ECDH-ES + AES-128-GCM",
            2 => "ECDH-ES + AES-256-GCM",
            _ => "Unknown",
        }
    }
}

/// Ephemeral Device Key wrapper
///
/// Contains the device's ephemeral public key used for session establishment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EDeviceKey {
    /// The actual COSE key
    #[serde(flatten)]
    pub key: CoseKey,

    /// Optional key agreement parameters
    #[serde(rename = "keyAgreement", skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<serde_json::Value>,
}

impl EDeviceKey {
    /// Create a new EDeviceKey from a COSE key
    pub fn new(key: CoseKey) -> Self {
        Self {
            key,
            key_agreement: None,
        }
    }

    /// Builder pattern: set key agreement parameters
    pub fn with_key_agreement(mut self, params: serde_json::Value) -> Self {
        self.key_agreement = Some(params);
        self
    }

    /// Get the key type
    pub fn key_type(&self) -> i32 {
        self.key.kty
    }

    /// Check if this is an EC2 (Elliptic Curve) key
    pub fn is_ec2(&self) -> bool {
        self.key.kty == 2
    }

    /// Check if this is an OKP (Octet Key Pair) key
    pub fn is_okp(&self) -> bool {
        self.key.kty == 1
    }
}

impl From<CoseKey> for EDeviceKey {
    fn from(key: CoseKey) -> Self {
        Self::new(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_creation() {
        let key = CoseKey::new(2); // EC2 key
        let edevice_key = EDeviceKey::new(key);
        let security = Security::new(1, edevice_key);

        assert_eq!(security.cipher_suite, 1);
        assert_eq!(security.cipher_suite_name(), "ECDH-ES + AES-128-GCM");
    }

    #[test]
    fn test_security_builder() {
        let key = CoseKey::new(2);
        let edevice_key = EDeviceKey::new(key);
        let security = Security::new(1, edevice_key).with_cipher_suite(2);

        assert_eq!(security.cipher_suite, 2);
        assert_eq!(security.cipher_suite_name(), "ECDH-ES + AES-256-GCM");
    }

    #[test]
    fn test_edevice_key_types() {
        let ec2_key = CoseKey::new(2);
        let edevice_key = EDeviceKey::new(ec2_key);

        assert!(edevice_key.is_ec2());
        assert!(!edevice_key.is_okp());
        assert_eq!(edevice_key.key_type(), 2);
    }

    #[test]
    fn test_edevice_key_from_cose_key() {
        let key = CoseKey::new(1); // OKP key
        let edevice_key: EDeviceKey = key.into();

        assert!(edevice_key.is_okp());
    }
}
