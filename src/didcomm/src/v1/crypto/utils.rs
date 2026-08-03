//! Cryptographic utility functions

use crate::v1::error::{DIDCommV1Error, Result};
use aries_askar::kms::{KeyAlg, LocalKey};

/// Convert Ed25519 key to X25519 key for key agreement
///
/// DIDComm v1 uses Ed25519 keys for identity but X25519 keys for encryption.
/// This function converts an Ed25519 key to its corresponding X25519 key.
pub fn ed25519_to_x25519(ed25519_key: &LocalKey) -> Result<LocalKey> {
    // Convert Ed25519 to X25519 using Askar's built-in conversion
    let x25519_key = ed25519_key.convert_key(KeyAlg::X25519).map_err(|e| {
        DIDCommV1Error::Crypto(format!("Failed to convert Ed25519 to X25519: {}", e))
    })?;

    Ok(x25519_key)
}

/// Convert X25519 public key bytes to LocalKey for recipient operations
pub fn x25519_public_key_from_bytes(public_key: &[u8]) -> Result<LocalKey> {
    if public_key.len() != 32 {
        return Err(DIDCommV1Error::InvalidKeyFormat(format!(
            "X25519 public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }

    LocalKey::from_public_bytes(KeyAlg::X25519, public_key)
        .map_err(|e| DIDCommV1Error::Crypto(format!("Failed to create X25519 public key: {}", e)))
}

/// Create X25519 ephemeral keypair for anonymous encryption
pub fn generate_x25519_keypair() -> Result<LocalKey> {
    LocalKey::generate_with_rng(KeyAlg::X25519, false)
        .map_err(|e| DIDCommV1Error::Crypto(format!("Failed to generate X25519 keypair: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_to_x25519_conversion() {
        // Generate an Ed25519 key
        let ed_key = LocalKey::generate_with_rng(KeyAlg::Ed25519, false).unwrap();

        // Convert to X25519
        let x_key = ed25519_to_x25519(&ed_key).unwrap();

        // Verify it's an X25519 key
        assert_eq!(x_key.algorithm(), KeyAlg::X25519);
    }

    #[test]
    fn test_x25519_public_key_from_bytes() {
        // Generate a key and extract public bytes
        let keypair = LocalKey::generate_with_rng(KeyAlg::X25519, false).unwrap();
        let pub_bytes = keypair.to_public_bytes().unwrap();

        // Create public key from bytes
        let pub_key = x25519_public_key_from_bytes(&pub_bytes).unwrap();

        assert_eq!(pub_key.algorithm(), KeyAlg::X25519);
    }

    #[test]
    fn test_x25519_public_key_invalid_length() {
        let invalid_bytes = vec![0u8; 16]; // Wrong length
        let result = x25519_public_key_from_bytes(&invalid_bytes);

        assert!(result.is_err());
    }

    #[test]
    fn test_generate_x25519_keypair() {
        let keypair = generate_x25519_keypair().unwrap();
        assert_eq!(keypair.algorithm(), KeyAlg::X25519);

        // Verify we can get public bytes
        let pub_bytes = keypair.to_public_bytes().unwrap();
        assert_eq!(pub_bytes.len(), 32);
    }
}
