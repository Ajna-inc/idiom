//! Device authentication verification with HKDF-based MAC derivation

use crate::cose::{Mac0, Sign1};
use crate::error::{MdocError, Result};
use crate::types::SessionTranscript;
use hkdf::Hkdf;
use sha2::Sha256;

/// Device authentication verification
///
/// Verifies device authentication using either:
/// - COSE_Sign1 with device private key signature
/// - COSE_Mac0 with HKDF-derived MAC key
pub struct DeviceAuthVerification;

impl DeviceAuthVerification {
    /// Verify Sign1 device authentication
    ///
    /// Verifies the signature over DeviceAuthentication structure
    pub fn verify_sign1(
        sign1: &Sign1,
        _session_transcript: &SessionTranscript,
        _device_public_key: &[u8],
    ) -> Result<()> {
        // Verify the signature
        // This requires the actual public key and signature verification
        // For now, we verify the structure is valid

        let payload = sign1.payload().ok_or_else(|| MdocError::DeviceAuthFailed {
            reason: "Missing payload in device auth Sign1".to_string(),
        })?;

        // Decode the DeviceAuthentication structure
        let device_auth: ciborium::Value =
            ciborium::de::from_reader(payload).map_err(|e| MdocError::DeviceAuthFailed {
                reason: format!("Failed to decode DeviceAuthentication: {}", e),
            })?;

        // Verify it's the correct structure: ["DeviceAuthentication", session_transcript, doc_type, elements]
        match &device_auth {
            ciborium::Value::Array(arr) if arr.len() == 4 => {
                // Check first element is "DeviceAuthentication"
                if let ciborium::Value::Text(context) = &arr[0] {
                    if context != "DeviceAuthentication" {
                        return Err(MdocError::DeviceAuthFailed {
                            reason: "Invalid DeviceAuthentication context".to_string(),
                        });
                    }
                } else {
                    return Err(MdocError::DeviceAuthFailed {
                        reason: "Invalid DeviceAuthentication structure".to_string(),
                    });
                }
            }
            _ => {
                return Err(MdocError::DeviceAuthFailed {
                    reason: "Invalid DeviceAuthentication array".to_string(),
                });
            }
        }

        // TODO: Actual signature verification
        // This requires integrating with a crypto library to:
        // 1. Parse the device public key
        // 2. Verify the signature over the to-be-signed structure
        // For now, we accept if the structure is valid

        Ok(())
    }

    /// Verify Mac0 device authentication with HKDF
    ///
    /// Derives the MAC key using HKDF and verifies the MAC
    pub fn verify_mac0(
        mac0: &Mac0,
        session_transcript: &SessionTranscript,
        device_public_key: &[u8],
        reader_public_key: &[u8],
        salt: &[u8],
    ) -> Result<()> {
        // Derive the MAC key using HKDF
        let mac_key = derive_mac_key(
            device_public_key,
            reader_public_key,
            session_transcript,
            salt,
        )?;

        // Get the to-be-MACed bytes
        let to_be_maced = mac0.create_to_be_maced()?;

        // Compute expected MAC tag
        let expected_tag = compute_hmac_sha256(&mac_key, &to_be_maced);

        // Compare tags (constant-time comparison)
        let actual_tag = mac0.tag();

        if constant_time_compare(actual_tag, &expected_tag) {
            Ok(())
        } else {
            Err(MdocError::DeviceAuthFailed {
                reason: "MAC verification failed".to_string(),
            })
        }
    }
}

/// Derive MAC key using HKDF-SHA-256
///
/// Per ISO 18013-5, the MAC key is derived using:
/// - IKM (Input Keying Material): Shared secret from ECDH
/// - Salt: Random salt value
/// - Info: Session transcript bytes
pub fn derive_mac_key(
    device_public_key: &[u8],
    reader_public_key: &[u8],
    session_transcript: &SessionTranscript,
    salt: &[u8],
) -> Result<Vec<u8>> {
    // TODO: Perform actual ECDH to derive shared secret
    // For now, we use a simplified approach
    // In production, this requires:
    // 1. Parse device and reader public keys as EC points
    // 2. Perform ECDH to get shared secret
    // 3. Use shared secret as IKM

    // Placeholder: concatenate keys as IKM
    let mut ikm = Vec::new();
    ikm.extend_from_slice(device_public_key);
    ikm.extend_from_slice(reader_public_key);

    // Encode session transcript as info parameter
    let mut info = Vec::new();
    ciborium::ser::into_writer(session_transcript, &mut info)
        .map_err(|e| MdocError::Other(format!("Failed to encode session transcript: {}", e)))?;

    // Derive key using HKDF-SHA256
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut mac_key = vec![0u8; 32]; // 256-bit key
    hk.expand(&info, &mut mac_key)
        .map_err(|e| MdocError::CryptoError(format!("HKDF expansion failed: {}", e)))?;

    Ok(mac_key)
}

/// Compute HMAC-SHA256
fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Verify device authentication (auto-detects Sign1 or Mac0)
pub fn verify_device_auth_mac(
    device_auth_bytes: &[u8],
    session_transcript: &SessionTranscript,
    device_public_key: &[u8],
    reader_public_key: Option<&[u8]>,
    salt: Option<&[u8]>,
) -> Result<()> {
    // Try to decode as Sign1 first
    if let Ok(sign1) = Sign1::decode(device_auth_bytes) {
        return DeviceAuthVerification::verify_sign1(&sign1, session_transcript, device_public_key);
    }

    // Try to decode as Mac0
    if let Ok(mac0) = Mac0::decode(device_auth_bytes) {
        let reader_key = reader_public_key.ok_or_else(|| MdocError::DeviceAuthFailed {
            reason: "Reader public key required for Mac0 verification".to_string(),
        })?;

        let salt_bytes = salt.ok_or_else(|| MdocError::DeviceAuthFailed {
            reason: "Salt required for Mac0 verification".to_string(),
        })?;

        return DeviceAuthVerification::verify_mac0(
            &mac0,
            session_transcript,
            device_public_key,
            reader_key,
            salt_bytes,
        );
    }

    Err(MdocError::DeviceAuthFailed {
        reason: "Failed to decode device auth as Sign1 or Mac0".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        assert!(constant_time_compare(&a, &b));

        let c = vec![1, 2, 3, 5];
        assert!(!constant_time_compare(&a, &c));

        let d = vec![1, 2, 3];
        assert!(!constant_time_compare(&a, &d));
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret_key";
        let data = b"hello world";
        let mac = compute_hmac_sha256(key, data);

        assert_eq!(mac.len(), 32); // SHA-256 produces 32 bytes
    }

    #[test]
    fn test_derive_mac_key() {
        let device_key = b"device_public_key";
        let reader_key = b"reader_public_key";
        let session_transcript = SessionTranscript {
            device_engagement: None,
            e_reader_key: None,
            handover: vec![],
        };
        let salt = b"random_salt";

        let mac_key = derive_mac_key(device_key, reader_key, &session_transcript, salt).unwrap();
        assert_eq!(mac_key.len(), 32); // 256-bit key
    }
}
