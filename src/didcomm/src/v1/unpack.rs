//! DIDComm v1 message unpacking (decryption)
//!
//! This module implements the DIDComm v1 message decryption flow,

use crate::v1::{
    crypto::{content::decrypt_content, utils::ed25519_to_x25519},
    error::{DIDCommV1Error, Result},
    types::{EncryptedMessage, PackAlgorithm, PlaintextMessage, ProtectedHeader, UnpackMetadata},
};
use agent_core::traits::{KeyType, WalletProvider};
use base64::Engine;
use std::sync::Arc;

/// Unpack (decrypt) a DIDComm v1 encrypted message
///
/// This function implements the full DIDComm v1 decryption flow:
/// 1. Parse and validate the JWE structure
/// 2. Find the matching recipient by key ID
/// 3. Decrypt the content encryption key
/// 4. If authcrypt, decrypt and verify the sender
/// 5. Decrypt the message content
///
/// # Arguments
/// * `encrypted` - The encrypted JWE message
/// * `wallet` - Wallet provider for key access
///
/// # Returns
/// Tuple of (decrypted message, metadata about the unpacking)
pub async fn unpack_message(
    encrypted: &EncryptedMessage,
    wallet: Arc<dyn WalletProvider>,
) -> Result<(PlaintextMessage, UnpackMetadata)> {
    unpack_message_with_kem(encrypted, wallet, None).await
}

/// Unpack with optional ML-KEM secret key for hybrid decryption.
pub async fn unpack_message_with_kem(
    encrypted: &EncryptedMessage,
    wallet: Arc<dyn WalletProvider>,
    kem_secret_key: Option<&[u8]>,
) -> Result<(PlaintextMessage, UnpackMetadata)> {
    tracing::debug!("Unpacking DIDComm v1 message");

    // 1. Parse protected header
    let protected = parse_protected_header(&encrypted.protected)?;

    // 2. Validate encryption algorithm
    validate_encryption_algorithm(&protected)?;

    // 3. Find our recipient and key
    let (recipient, our_key) = find_our_recipient(&protected, wallet.clone()).await?;

    tracing::debug!(
        "Found matching recipient with kid: {}",
        recipient.header.kid
    );

    // 4. Convert Ed25519 to X25519 for key agreement
    let our_x25519 = ed25519_to_x25519(&our_key)?;

    // 5. Determine if authcrypt or anoncrypt
    let alg = PackAlgorithm::from_str(&protected.alg)
        .ok_or_else(|| DIDCommV1Error::UnsupportedAlgorithm(protected.alg.clone()))?;

    // 6. Decrypt sender if authcrypt
    let sender_key = if alg == PackAlgorithm::Authcrypt {
        // Authcrypt is a security boundary: if the sender cannot be
        // authenticated, the envelope must not be processed as anoncrypt.
        // Compatibility fallbacks here turn an attacker-controlled `alg`
        // header into a false `authenticated = true` result.
        Some(decrypt_sender(&recipient, &our_x25519, &our_key).await?)
    } else {
        None
    };

    // 7. Decrypt the content encryption key (CEK)
    let cek = decrypt_cek(&recipient, &our_x25519, sender_key.as_ref(), kem_secret_key).await?;

    tracing::debug!("Decrypted content encryption key ({} bytes)", cek.len());

    // 8. Decrypt the message content
    let plaintext = decrypt_message_content(encrypted, &cek)?;

    // 9. Parse plaintext as JSON
    let message: PlaintextMessage = serde_json::from_slice(&plaintext)?;

    tracing::debug!("Successfully unpacked DIDComm v1 message");

    // 10. Create metadata
    let metadata = UnpackMetadata {
        recipient_key: recipient.header.kid.clone(),
        sender_key,
        authenticated: alg == PackAlgorithm::Authcrypt,
        anonymous: alg == PackAlgorithm::Anoncrypt,
    };

    Ok((message, metadata))
}

/// Parse the base64url-encoded protected header
fn parse_protected_header(protected_b64: &str) -> Result<ProtectedHeader> {
    // Decode from base64url
    let protected_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(protected_b64)
        .map_err(|e| {
            DIDCommV1Error::InvalidJWE(format!("Failed to decode protected header: {}", e))
        })?;

    // Parse JSON
    let protected: ProtectedHeader = serde_json::from_slice(&protected_bytes).map_err(|e| {
        DIDCommV1Error::InvalidJWE(format!("Failed to parse protected header: {}", e))
    })?;

    Ok(protected)
}

/// Validate that we support the encryption algorithm
fn validate_encryption_algorithm(protected: &ProtectedHeader) -> Result<()> {
    // Check encryption algorithm
    if protected.enc != "xchacha20poly1305_ietf" {
        return Err(DIDCommV1Error::UnsupportedAlgorithm(format!(
            "Unsupported enc algorithm: {}",
            protected.enc
        )));
    }

    // Check message type
    if protected.typ != "JWM/1.0" {
        return Err(DIDCommV1Error::UnsupportedAlgorithm(format!(
            "Unsupported message type: {}",
            protected.typ
        )));
    }

    // Check pack algorithm
    if protected.alg != "Authcrypt"
        && protected.alg != "Anoncrypt"
        && protected.alg != "Authcrypt-Hybrid"
    {
        return Err(DIDCommV1Error::UnsupportedAlgorithm(format!(
            "Unsupported alg: {}",
            protected.alg
        )));
    }

    Ok(())
}

/// Find our recipient in the recipients list and load the corresponding key
async fn find_our_recipient(
    protected: &ProtectedHeader,
    wallet: Arc<dyn WalletProvider>,
) -> Result<(crate::v1::types::Recipient, aries_askar::kms::LocalKey)> {
    // List all our keys
    let our_keys = wallet
        .list_keys()
        .await
        .map_err(|e| DIDCommV1Error::KeyNotFound(format!("Failed to list keys: {}", e)))?;

    // Try each recipient
    for recipient in &protected.recipients {
        // The kid is a base58-encoded X25519 public key (as of DIDComm v1)
        let kid_bytes = bs58::decode(&recipient.header.kid)
            .into_vec()
            .map_err(|e| DIDCommV1Error::InvalidKeyFormat(format!("Invalid base58 kid: {}", e)))?;

        tracing::debug!(
            "[DIDComm v1 unpack] Looking for recipient kid: {} ({} bytes), {} keys in wallet",
            recipient.header.kid,
            kid_bytes.len(),
            our_keys.len()
        );

        for our_key in our_keys.iter() {
            if our_key.key_type == KeyType::Ed25519 {
                // Get the private key from wallet
                let secret_bytes = wallet.get_secret_bytes(&our_key.id).await?;

                // Create LocalKey from secret bytes
                let ed25519_key = aries_askar::kms::LocalKey::from_secret_bytes(
                    aries_askar::kms::KeyAlg::Ed25519,
                    &secret_bytes,
                )
                .map_err(|e| DIDCommV1Error::Crypto(format!("Failed to create LocalKey: {}", e)))?;

                // Get Ed25519 public key for checking
                let ed25519_public_bytes = ed25519_key.to_public_bytes().map_err(|e| {
                    DIDCommV1Error::Crypto(format!("Failed to get Ed25519 public bytes: {}", e))
                })?;

                // Convert to X25519 to compare with kid
                let x25519_key = ed25519_to_x25519(&ed25519_key)?;
                let x25519_public_bytes = x25519_key.to_public_bytes().map_err(|e| {
                    DIDCommV1Error::Crypto(format!("Failed to get X25519 public bytes: {}", e))
                })?;

                // Check BOTH Ed25519 and X25519 public keys against kid
                // Some agents may use either depending on configuration
                if ed25519_public_bytes.as_ref() == kid_bytes.as_slice() {
                    tracing::debug!(
                        "Found matching key: {} (matched via Ed25519 public key)",
                        our_key.id
                    );
                    return Ok((recipient.clone(), ed25519_key));
                } else if x25519_public_bytes.as_ref() == kid_bytes.as_slice() {
                    tracing::debug!(
                        "Found matching key: {} (matched via X25519 public key)",
                        our_key.id
                    );
                    return Ok((recipient.clone(), ed25519_key));
                }
            }
        }
    }

    Err(DIDCommV1Error::KeyNotFound(
        "No matching recipient key found in wallet".to_string(),
    ))
}

/// Decrypt the sender's public key (authcrypt only)
async fn decrypt_sender(
    recipient: &crate::v1::types::Recipient,
    _our_x25519: &aries_askar::kms::LocalKey,
    recipient_ed25519_key: &aries_askar::kms::LocalKey,
) -> Result<String> {
    let encrypted_sender = recipient.header.sender.as_ref().ok_or_else(|| {
        DIDCommV1Error::DecryptionFailed("Sender field missing for authcrypt".to_string())
    })?;

    // Decode base64url
    let encrypted_sender_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encrypted_sender)
        .map_err(DIDCommV1Error::Base64Decode)?;

    tracing::debug!(
        "Attempting to decrypt sender field: {} bytes",
        encrypted_sender_bytes.len()
    );

    // Decrypt using crypto_box_seal_open (anonymous decryption)
    // Uses ECDH-HSALSA20 with no external public key
    use aries_askar::kms::crypto_box_seal_open;

    // crypto_box_seal adds 48 bytes overhead (32 for ephemeral public key + 16 for MAC)
    if encrypted_sender_bytes.len() < 48 {
        return Err(DIDCommV1Error::DecryptionFailed(format!(
            "Encrypted sender too short for crypto_box_seal format: {} bytes",
            encrypted_sender_bytes.len()
        )));
    }

    // Try using a fresh X25519 key created directly from the Ed25519 secret
    // This ensures we're using the exact same conversion method
    let recipient_ed25519_secret = recipient_ed25519_key.to_secret_bytes().map_err(|e| {
        DIDCommV1Error::DecryptionFailed(format!("Failed to get Ed25519 secret: {}", e))
    })?;

    // Create X25519 key using Askar's conversion
    use aries_askar::kms::KeyAlg;
    let x25519_from_secret = aries_askar::kms::LocalKey::from_secret_bytes(
        KeyAlg::Ed25519,
        recipient_ed25519_secret.as_ref(),
    )
    .map_err(|e| DIDCommV1Error::Crypto(format!("Failed to recreate Ed25519 key: {}", e)))?
    .convert_key(KeyAlg::X25519)
    .map_err(|e| DIDCommV1Error::Crypto(format!("Failed to convert to X25519: {}", e)))?;

    // Try crypto_box_seal_open
    let decrypted =
        crypto_box_seal_open(&x25519_from_secret, &encrypted_sender_bytes).map_err(|e| {
            DIDCommV1Error::DecryptionFailed(format!("Failed to decrypt sender: {}", e))
        })?;

    // Convert to string (should be base58-encoded Ed25519 public key)
    let sender_key_base58 = String::from_utf8(decrypted.to_vec()).map_err(|e| {
        DIDCommV1Error::DecryptionFailed(format!("Invalid sender key UTF-8: {}", e))
    })?;

    tracing::debug!("Decrypted sender key: {}", sender_key_base58);

    Ok(sender_key_base58)
}

/// Decrypt the content encryption key (CEK)
///
/// For hybrid: Uses X25519 ECDH + ML-KEM-768 combined shared secret
/// For authcrypt: Uses crypto_box_open with sender's public key and IV from header
/// For anoncrypt: Uses crypto_box_seal_open with no sender key and no IV
async fn decrypt_cek(
    recipient: &crate::v1::types::Recipient,
    our_x25519: &aries_askar::kms::LocalKey,
    sender_key_base58: Option<&String>,
    kem_secret_key: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Decode encrypted key from base64url
    let encrypted_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&recipient.encrypted_key)
        .map_err(DIDCommV1Error::Base64Decode)?;

    // HYBRID: If recipient header has `kem` field, use hybrid unwrap
    if let (Some(kem_b64), Some(x25519_eph_b64), Some(iv_b64)) = (
        &recipient.header.kem,
        &recipient.header.x25519_eph,
        &recipient.header.iv,
    ) {
        tracing::debug!("Decrypting CEK via hybrid (X25519 + ML-KEM-768)");

        let kem_sk = kem_secret_key.ok_or_else(|| {
            DIDCommV1Error::DecryptionFailed("Hybrid message requires ML-KEM secret key".into())
        })?;

        let kem_ct = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(kem_b64)
            .map_err(DIDCommV1Error::Base64Decode)?;
        let x25519_eph = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x25519_eph_b64)
            .map_err(DIDCommV1Error::Base64Decode)?;
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(iv_b64)
            .map_err(DIDCommV1Error::Base64Decode)?;

        if x25519_eph.len() != 32 {
            return Err(DIDCommV1Error::InvalidKeyFormat(
                "Hybrid x25519_eph must be 32 bytes".into(),
            ));
        }

        let our_x25519_secret = our_x25519
            .to_secret_bytes()
            .map_err(|e| DIDCommV1Error::Crypto(format!("Get X25519 secret: {}", e)))?;

        let mut eph_pk = [0u8; 32];
        eph_pk.copy_from_slice(&x25519_eph);
        let mut our_sk = [0u8; 32];
        // X25519 secret from Askar is 32 bytes
        if our_x25519_secret.len() >= 32 {
            our_sk.copy_from_slice(&our_x25519_secret[..32]);
        }

        let cek = crate::v1::crypto::key_wrap::unwrap_key_hybrid(
            &encrypted_key,
            &nonce,
            &eph_pk,
            &kem_ct,
            &our_sk,
            kem_sk,
        )?;

        return Ok(cek);
    }

    // Check if this is authcrypt (has sender) or anoncrypt (no sender)
    if let Some(sender_base58) = sender_key_base58 {
        // AUTHCRYPT: Decrypt CEK using crypto_box_open with sender's public key and IV

        // Decode IV from base64url (required for authcrypt)
        let iv = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(recipient.header.iv.as_ref().ok_or_else(|| {
                DIDCommV1Error::DecryptionFailed(
                    "IV missing for authcrypt CEK decryption".to_string(),
                )
            })?)
            .map_err(DIDCommV1Error::Base64Decode)?;

        // Decode sender's Ed25519 public key from base58
        let sender_ed25519_bytes = bs58::decode(sender_base58).into_vec().map_err(|e| {
            DIDCommV1Error::InvalidKeyFormat(format!("Invalid sender base58: {}", e))
        })?;

        // Create Ed25519 public key
        let sender_ed25519 = aries_askar::kms::LocalKey::from_public_bytes(
            aries_askar::kms::KeyAlg::Ed25519,
            &sender_ed25519_bytes,
        )
        .map_err(|e| {
            DIDCommV1Error::Crypto(format!("Failed to create sender Ed25519 key: {}", e))
        })?;

        // Convert to X25519
        let sender_x25519 = ed25519_to_x25519(&sender_ed25519)?;

        // Decrypt CEK using crypto_box_open (authenticated encryption)
        use aries_askar::kms::crypto_box_open;

        if iv.len() != 24 {
            return Err(DIDCommV1Error::InvalidKeyFormat(format!(
                "Nonce must be 24 bytes, got {}",
                iv.len()
            )));
        }

        let cek =
            crypto_box_open(our_x25519, &sender_x25519, &encrypted_key, &iv).map_err(|e| {
                DIDCommV1Error::DecryptionFailed(format!(
                    "Failed to decrypt CEK (authcrypt): {}",
                    e
                ))
            })?;

        Ok(cek.to_vec())
    } else {
        // ANONCRYPT: Decrypt CEK using crypto_box_seal_open (no sender, no IV)
        use aries_askar::kms::crypto_box_seal_open;

        let cek = crypto_box_seal_open(our_x25519, &encrypted_key).map_err(|e| {
            DIDCommV1Error::DecryptionFailed(format!("Failed to decrypt CEK (anoncrypt): {}", e))
        })?;

        Ok(cek.to_vec())
    }
}

/// Decrypt the message content using the CEK
fn decrypt_message_content(encrypted: &EncryptedMessage, cek: &[u8]) -> Result<Vec<u8>> {
    // Decode ciphertext, IV, and tag from base64url
    let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .map_err(DIDCommV1Error::Base64Decode)?;

    let iv = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encrypted.iv)
        .map_err(DIDCommV1Error::Base64Decode)?;

    let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encrypted.tag)
        .map_err(DIDCommV1Error::Base64Decode)?;

    // The AAD is the protected header (base64url-encoded)
    let aad = encrypted.protected.as_bytes();

    // Decrypt content
    let plaintext = decrypt_content(&ciphertext, &iv, &tag, cek, aad)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_protected_header() {
        // Example protected header
        let protected_b64 = "eyJlbmMiOiJ4Y2hhY2hhMjBwb2x5MTMwNV9pZXRmIiwidHlwIjoiSldNLzEuMCIsImFsZyI6IkF1dGhjcnlwdCIsInJlY2lwaWVudHMiOlt7ImVuY3J5cHRlZF9rZXkiOiJfWm5YYkdYLVFwTG8xVEllY1BnbDFFZUhiZEpyMUMteWNvc25fWWVDZm9BeUlzUVk4UmFBTG1IMFZlcEhQcnMwIiwiaGVhZGVyIjp7ImtpZCI6IkJUZk5WSDFDSzVHN29HRmRwbkFFUjNaaTRzd3Jrc2J1RWsxZjNXTVV4cWhmIiwic2VuZGVyIjoiWjBBZXZVYkRsand4YzJsdVhpYWI5M1Z2OUw1YzBGdm4tV3ljaUpHc0RYcWlobVdtTEg1R1JtQjVaN2FTRVNfQXFsMDByUllQMDRkaWg1YjVSTG9ydEg1N2JIRER3QnhGallZTElMSE9ValI4NUZJeHdsSnNhM1NKUXY0IiwiaXYiOiJjYjJlaDdYRHdFSVU0WFNrWDduOFl6cVVNSXRMUWlUbyJ9fV19";

        let protected = parse_protected_header(protected_b64).unwrap();

        assert_eq!(protected.enc, "xchacha20poly1305_ietf");
        assert_eq!(protected.typ, "JWM/1.0");
        assert_eq!(protected.alg, "Authcrypt");
        assert_eq!(protected.recipients.len(), 1);
        assert_eq!(
            protected.recipients[0].header.kid,
            "BTfNVH1CK5G7oGFdpnAER3Zi4swrksbuEk1f3WMUxqhf"
        );
    }

    #[test]
    fn test_validate_encryption_algorithm() {
        let mut protected = ProtectedHeader {
            enc: "xchacha20poly1305_ietf".to_string(),
            typ: "JWM/1.0".to_string(),
            alg: "Authcrypt".to_string(),
            recipients: vec![],
        };

        // Valid
        assert!(validate_encryption_algorithm(&protected).is_ok());

        // Invalid enc
        protected.enc = "aes256gcm".to_string();
        assert!(validate_encryption_algorithm(&protected).is_err());

        // Invalid alg
        protected.enc = "xchacha20poly1305_ietf".to_string();
        protected.alg = "InvalidAlg".to_string();
        assert!(validate_encryption_algorithm(&protected).is_err());
    }
}
