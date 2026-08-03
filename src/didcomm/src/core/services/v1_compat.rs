/// V1 compatibility utilities for DIDComm v1/v2 interop
///
/// This module provides utilities for converting between DIDComm v1 and v2 formats,
/// particularly for key material representation.
use crate::core::error::{DidcommError, Result};

/// Convert multibase-encoded key to base58
///
/// DIDComm v1 expects base58-encoded keys, while DIDComm v2 uses multibase.
/// This function converts between the two formats.
///
/// # Arguments
/// * `multibase` - Multibase-encoded key (e.g., "z6Mk...")
///
/// # Returns
/// Base58-encoded key string
pub fn multibase_to_base58(multibase: &str) -> Result<String> {
    // Check for empty string
    if multibase.is_empty() {
        return Err(DidcommError::InvalidKey(
            "Empty multibase string".to_string(),
        ));
    }

    // Multibase format for base58btc starts with 'z'
    if let Some(rest) = multibase.strip_prefix('z') {
        // For base58btc encoding, the 'z' prefix indicates the encoding,
        // and the rest is already base58-encoded data
        Ok(rest.to_string())
    } else {
        // For other multibase encodings, we need to decode and re-encode
        match multibase::decode(multibase) {
            Ok((_base, bytes)) => Ok(bs58::encode(&bytes).into_string()),
            Err(e) => Err(DidcommError::InvalidKey(format!(
                "Failed to decode multibase key: {}",
                e
            ))),
        }
    }
}

/// Convert base58-encoded key to multibase
///
/// This is the reverse operation, converting base58 to multibase format.
///
/// # Arguments
/// * `base58` - Base58-encoded key
///
/// # Returns
/// Multibase-encoded key with 'z' prefix (base58btc)
pub fn base58_to_multibase(base58: &str) -> Result<String> {
    // Simply prepend 'z' for base58btc encoding
    Ok(format!("z{}", base58))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multibase_to_base58() {
        // Example Ed25519 key in multibase format (z6Mk... = base58btc)
        let multibase = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let base58 = multibase_to_base58(multibase).unwrap();

        // Should strip the 'z' prefix
        assert_eq!(base58, "6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert!(!base58.starts_with('z'));
    }

    #[test]
    fn test_base58_to_multibase() {
        let base58 = "6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let multibase = base58_to_multibase(base58).unwrap();

        // Should add 'z' prefix
        assert_eq!(
            multibase,
            "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        assert!(multibase.starts_with('z'));
    }

    #[test]
    fn test_round_trip() {
        let original = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let base58 = multibase_to_base58(original).unwrap();
        let multibase = base58_to_multibase(&base58).unwrap();

        assert_eq!(original, multibase);
    }

    #[test]
    fn test_x25519_key_conversion() {
        // Example X25519 key (z6LS... format)
        let multibase = "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc";
        let base58 = multibase_to_base58(multibase).unwrap();

        assert_eq!(base58, "6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc");
        assert!(!base58.starts_with('z'));

        // Round trip
        let recovered = base58_to_multibase(&base58).unwrap();
        assert_eq!(recovered, multibase);
    }

    #[test]
    fn test_empty_string_error() {
        let result = multibase_to_base58("");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_multibase_format() {
        // Non-z prefix should trigger decode path
        let result = multibase_to_base58("invalid");
        assert!(result.is_err());
    }
}
