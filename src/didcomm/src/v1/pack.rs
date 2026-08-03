//! DIDComm v1 message packing (encryption)
//!
//! This module implements the DIDComm v1 message encryption flow,

use crate::v1::{
    crypto::{
        content::encrypt_content,
        key_wrap::{encrypt_sender_key, wrap_key},
        utils::{ed25519_to_x25519, generate_x25519_keypair},
    },
    error::{DIDCommV1Error, Result},
    types::{
        EncryptedMessage, PackAlgorithm, PlaintextMessage, ProtectedHeader, Recipient,
        RecipientHeader,
    },
};
use agent_core::traits::{KeyType, WalletProvider};
use base64::Engine;
use std::sync::Arc;

/// Pack (encrypt) a DIDComm v1 message
///
/// This function implements the full DIDComm v1 encryption flow:
/// 1. Generate a random content encryption key (CEK)
/// 2. For each recipient:
///    - If authcrypt: Encrypt sender's public key
///    - Encrypt CEK for the recipient
/// 3. Create protected header with recipients
/// 4. Encrypt message content with CEK
///
/// # Arguments
/// * `message` - The plaintext message to encrypt
/// * `recipient_keys` - List of (kid, encryption_key) tuples where:
///   - kid: Ed25519 public key (base58) for wallet lookup (used as `kid` in JWE)
///   - encryption_key: X25519 public key (base58) for ECDH encryption
/// * `sender_key_id` - Optional sender key ID from wallet (for authcrypt, None for anoncrypt)
/// * `wallet` - Wallet provider for key access
///
/// # Returns
/// Encrypted JWE message
pub async fn pack_message(
    message: &PlaintextMessage,
    recipient_keys: &[(String, String)],
    sender_key_id: Option<&str>,
    wallet: Arc<dyn WalletProvider>,
) -> Result<EncryptedMessage> {
    if recipient_keys.is_empty() {
        return Err(DIDCommV1Error::Other(
            "At least one recipient required".to_string(),
        ));
    }

    tracing::debug!(
        "🔒 Packing DIDComm v1 message for {} recipient(s)",
        recipient_keys.len()
    );

    // 1. Determine algorithm (authcrypt or anoncrypt)
    let alg = if sender_key_id.is_some() {
        PackAlgorithm::Authcrypt
    } else {
        PackAlgorithm::Anoncrypt
    };

    // 2. Get sender key if authcrypt
    let sender_key = if let Some(key_id) = sender_key_id {
        Some(get_sender_key(wallet.clone(), key_id).await?)
    } else {
        None
    };

    // 3. Generate ephemeral key for anoncrypt
    let ephemeral_x25519 = if alg == PackAlgorithm::Anoncrypt {
        Some(generate_x25519_keypair()?)
    } else {
        None
    };

    // 4. Generate random content encryption key (CEK)
    let cek = generate_cek()?;

    tracing::debug!("Generated content encryption key ({} bytes)", cek.len());

    // 5. Build recipients array
    let recipients = build_recipients(
        recipient_keys,
        &cek,
        sender_key.as_ref(),
        ephemeral_x25519.as_ref(),
        alg,
    )
    .await?;

    tracing::debug!("Built {} recipient(s)", recipients.len());

    // 6. Create protected header
    let protected_header = ProtectedHeader {
        enc: "xchacha20poly1305_ietf".to_string(),
        typ: "JWM/1.0".to_string(),
        alg: alg.as_str().to_string(),
        recipients,
    };

    // 7. Serialize and encode protected header
    let protected_json = serde_json::to_vec(&protected_header)?;
    let protected_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&protected_json);

    // 8. Encrypt message content
    let message_json = serde_json::to_vec(message)?;
    let (ciphertext, iv, tag) = encrypt_content(&message_json, &cek, protected_b64.as_bytes())?;

    tracing::debug!("Encrypted message content");

    // 9. Encode to base64url
    let encrypted = EncryptedMessage {
        protected: protected_b64,
        ciphertext: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&ciphertext),
        iv: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&iv),
        tag: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&tag),
    };

    tracing::debug!("Successfully packed DIDComm v1 message");

    Ok(encrypted)
}

/// Generate a random 32-byte content encryption key
fn generate_cek() -> Result<Vec<u8>> {
    let mut cek = vec![0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut cek);
    Ok(cek)
}

/// Get sender key from wallet and convert to necessary formats
async fn get_sender_key(wallet: Arc<dyn WalletProvider>, key_id: &str) -> Result<SenderKeyInfo> {
    // Get the key from wallet
    let key = wallet
        .get_key(key_id)
        .await?
        .ok_or_else(|| DIDCommV1Error::KeyNotFound(format!("Sender key not found: {}", key_id)))?;

    if key.key_type != KeyType::Ed25519 {
        return Err(DIDCommV1Error::InvalidKeyFormat(
            "Sender key must be Ed25519".to_string(),
        ));
    }

    // Get secret bytes
    let secret_bytes = wallet.get_secret_bytes(key_id).await?;

    // Create LocalKey
    let ed25519_key = aries_askar::kms::LocalKey::from_secret_bytes(
        aries_askar::kms::KeyAlg::Ed25519,
        &secret_bytes,
    )
    .map_err(|e| DIDCommV1Error::Crypto(format!("Failed to create LocalKey: {}", e)))?;

    // Convert to X25519
    let x25519_key = ed25519_to_x25519(&ed25519_key)?;

    // Encode public key as base58
    let public_key_base58 = bs58::encode(&key.public_key).into_string();

    Ok(SenderKeyInfo {
        x25519_key,
        public_key_base58,
    })
}

/// Helper struct for sender key information
struct SenderKeyInfo {
    x25519_key: aries_askar::kms::LocalKey,
    public_key_base58: String,
}

/// Build recipients array with encrypted CEKs
async fn build_recipients(
    recipient_keys: &[(String, String)],
    cek: &[u8],
    sender: Option<&SenderKeyInfo>,
    ephemeral_x25519: Option<&aries_askar::kms::LocalKey>,
    alg: PackAlgorithm,
) -> Result<Vec<Recipient>> {
    let mut recipients = Vec::new();

    for (kid_base58, encryption_key_base58) in recipient_keys {
        // Decode recipient encryption key from base58
        let recipient_key_bytes = bs58::decode(encryption_key_base58)
            .into_vec()
            .map_err(|e| {
                DIDCommV1Error::InvalidKeyFormat(format!("Invalid recipient base58: {}", e))
            })?;

        // Try to create the key as X25519 first (for keyAgreement keys from did_doc~attach)
        // If that fails, try Ed25519 and convert (for traditional did:key DIDs)
        let recipient_x25519 = match aries_askar::kms::LocalKey::from_public_bytes(
            aries_askar::kms::KeyAlg::X25519,
            &recipient_key_bytes,
        ) {
            Ok(x25519_key) => {
                tracing::debug!(
                    "Recipient encryption key is X25519 (keyAgreement key from did_doc~attach)"
                );
                x25519_key
            }
            Err(_) => {
                // Not X25519, try Ed25519 and convert
                tracing::debug!("  Encryption key is not X25519, trying Ed25519 conversion...");
                let recipient_ed25519 = aries_askar::kms::LocalKey::from_public_bytes(
                    aries_askar::kms::KeyAlg::Ed25519,
                    &recipient_key_bytes,
                )
                .map_err(|e| {
                    DIDCommV1Error::Crypto(format!(
                        "Failed to create recipient key (tried both X25519 and Ed25519): {}",
                        e
                    ))
                })?;

                // Convert to X25519 for encryption
                ed25519_to_x25519(&recipient_ed25519)?
            }
        };

        // Build recipient based on algorithm
        // Use kid_base58 (Ed25519 authentication key) for the `kid` field
        // Use recipient_x25519 (X25519 keyAgreement) for ECDH encryption
        let recipient = if alg == PackAlgorithm::Authcrypt {
            build_authcrypt_recipient(&recipient_x25519, cek, sender.unwrap(), kid_base58)?
        } else {
            build_anoncrypt_recipient(
                &recipient_x25519,
                cek,
                ephemeral_x25519.unwrap(),
                kid_base58,
            )?
        };

        recipients.push(recipient);
    }

    Ok(recipients)
}

/// Build recipient for authcrypt (with sender authentication)
fn build_authcrypt_recipient(
    recipient_x25519: &aries_askar::kms::LocalKey,
    cek: &[u8],
    sender: &SenderKeyInfo,
    recipient_key_base58: &str,
) -> Result<Recipient> {
    // 1. Encrypt sender's public key (using crypto_box_seal - no external nonce)
    let (encrypted_sender, _sender_iv) = encrypt_sender_key(
        &sender.public_key_base58,
        recipient_x25519,
        &sender.x25519_key,
    )?;

    // 2. Wrap CEK with sender authentication
    let (encrypted_key, cek_iv) = wrap_key(cek, recipient_x25519, Some(&sender.x25519_key))?;

    // 3. Encode to base64url
    let recipient = Recipient {
        encrypted_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&encrypted_key),
        header: RecipientHeader {
            kid: recipient_key_base58.to_string(),
            sender: Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&encrypted_sender),
            ),
            iv: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cek_iv)),
            kem: None,
            kem_kid: None,
            x25519_eph: None,
        },
    };

    Ok(recipient)
}

/// Build recipient for anoncrypt (anonymous)
fn build_anoncrypt_recipient(
    recipient_x25519: &aries_askar::kms::LocalKey,
    cek: &[u8],
    _ephemeral_x25519: &aries_askar::kms::LocalKey,
    recipient_key_base58: &str,
) -> Result<Recipient> {
    use aries_askar::kms::crypto_box_seal;

    let sealed = crypto_box_seal(recipient_x25519, cek)
        .map_err(|e| DIDCommV1Error::EncryptionFailed(format!("crypto_box_seal failed: {}", e)))?;

    let recipient = Recipient {
        encrypted_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sealed),
        header: RecipientHeader {
            kid: recipient_key_base58.to_string(),
            sender: None,
            iv: None,
            kem: None,
            kem_kid: None,
            x25519_eph: None,
        },
    };

    Ok(recipient)
}

/// Build recipient for hybrid authcrypt: X25519 + ML-KEM-768.
///
/// Uses raw x25519-dalek ECDH + ML-KEM-768 encapsulate → combined shared secret
/// → AES-256-GCM key wrap. Both classical and quantum must be broken.
fn build_hybrid_recipient(
    recipient_x25519_pk_bytes: &[u8; 32],
    recipient_kem_pk: &[u8],
    recipient_kem_kid: &str,
    cek: &[u8],
    recipient_key_base58: &str,
) -> Result<Recipient> {
    use crate::v1::crypto::key_wrap::{wrap_key_hybrid, HybridWrappedKey};

    let HybridWrappedKey {
        encrypted_key,
        nonce,
        x25519_eph_pk,
        kem_ciphertext,
        kem_kid,
    } = wrap_key_hybrid(
        cek,
        recipient_x25519_pk_bytes,
        recipient_kem_pk,
        recipient_kem_kid,
    )?;

    Ok(Recipient {
        encrypted_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&encrypted_key),
        header: RecipientHeader {
            kid: recipient_key_base58.to_string(),
            sender: None,
            iv: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&nonce)),
            kem: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&kem_ciphertext)),
            kem_kid: Some(kem_kid),
            x25519_eph: Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x25519_eph_pk),
            ),
        },
    })
}

/// KEM key info for a recipient (for hybrid pack).
pub struct RecipientKemInfo {
    /// ML-KEM-768 public key (1184 bytes).
    pub kem_pk: Vec<u8>,
    /// ML-KEM kid.
    pub kem_kid: String,
    /// X25519 public key (32 bytes) — raw, for hybrid ECDH.
    pub x25519_pk: [u8; 32],
}

/// Pack a DIDComm v1 message with hybrid encryption for recipients that have KEM keys.
///
/// Same as `pack_message` but checks `kem_keys` map: if a recipient's kid has a KEM key,
/// uses hybrid (X25519 + ML-KEM-768). Otherwise falls back to standard authcrypt/anoncrypt.
pub async fn pack_message_hybrid(
    message: &PlaintextMessage,
    recipient_keys: &[(String, String)],
    sender_key_id: Option<&str>,
    wallet: Arc<dyn WalletProvider>,
    kem_keys: &std::collections::HashMap<String, RecipientKemInfo>,
) -> Result<EncryptedMessage> {
    if recipient_keys.is_empty() {
        return Err(DIDCommV1Error::Other(
            "At least one recipient required".to_string(),
        ));
    }

    // Determine if any recipients have KEM keys
    let has_any_kem = recipient_keys
        .iter()
        .any(|(kid, _)| kem_keys.contains_key(kid));

    // If no KEM keys, use standard pack
    if !has_any_kem {
        return pack_message(message, recipient_keys, sender_key_id, wallet).await;
    }

    tracing::debug!(
        "Packing hybrid DIDComm v1 message ({} recipients, {} with KEM)",
        recipient_keys.len(),
        kem_keys.len()
    );

    // Generate CEK
    let cek = generate_cek()?;

    // Get sender key if authcrypt
    let sender = if let Some(key_id) = sender_key_id {
        Some(get_sender_key(wallet.clone(), key_id).await?)
    } else {
        None
    };

    // Build recipients — hybrid for those with KEM, standard for others
    let mut recipients = Vec::new();
    for (kid_base58, encryption_key_base58) in recipient_keys {
        if let Some(kem_info) = kem_keys.get(kid_base58) {
            // Hybrid path
            recipients.push(build_hybrid_recipient(
                &kem_info.x25519_pk,
                &kem_info.kem_pk,
                &kem_info.kem_kid,
                &cek,
                kid_base58,
            )?);
        } else {
            // Standard path
            let recipient_key_bytes = bs58::decode(encryption_key_base58)
                .into_vec()
                .map_err(|e| DIDCommV1Error::InvalidKeyFormat(format!("Invalid base58: {}", e)))?;

            let recipient_x25519 = match aries_askar::kms::LocalKey::from_public_bytes(
                aries_askar::kms::KeyAlg::X25519,
                &recipient_key_bytes,
            ) {
                Ok(k) => k,
                Err(_) => {
                    let ed = aries_askar::kms::LocalKey::from_public_bytes(
                        aries_askar::kms::KeyAlg::Ed25519,
                        &recipient_key_bytes,
                    )
                    .map_err(|e| DIDCommV1Error::Crypto(format!("Invalid key: {}", e)))?;
                    ed25519_to_x25519(&ed)?
                }
            };

            if let Some(s) = &sender {
                recipients.push(build_authcrypt_recipient(
                    &recipient_x25519,
                    &cek,
                    s,
                    kid_base58,
                )?);
            } else {
                let eph = generate_x25519_keypair()?;
                recipients.push(build_anoncrypt_recipient(
                    &recipient_x25519,
                    &cek,
                    &eph,
                    kid_base58,
                )?);
            }
        }
    }

    // Use Authcrypt-Hybrid alg if any recipient is hybrid
    let alg = if has_any_kem {
        PackAlgorithm::AuthcryptHybrid
    } else if sender.is_some() {
        PackAlgorithm::Authcrypt
    } else {
        PackAlgorithm::Anoncrypt
    };

    let protected_header = ProtectedHeader {
        enc: "xchacha20poly1305_ietf".to_string(),
        typ: "JWM/1.0".to_string(),
        alg: alg.as_str().to_string(),
        recipients,
    };

    let protected_json = serde_json::to_vec(&protected_header)?;
    let protected_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&protected_json);

    let message_json = serde_json::to_vec(message)?;
    let (ciphertext, iv, tag) = encrypt_content(&message_json, &cek, protected_b64.as_bytes())?;

    Ok(EncryptedMessage {
        protected: protected_b64,
        ciphertext: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&ciphertext),
        iv: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&iv),
        tag: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&tag),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_cek() {
        let cek1 = generate_cek().unwrap();
        let cek2 = generate_cek().unwrap();

        assert_eq!(cek1.len(), 32);
        assert_eq!(cek2.len(), 32);
        assert_ne!(cek1, cek2); // Should be random
    }

    #[test]
    fn test_pack_algorithm_determination() {
        let alg_authcrypt = if Some("key-id").is_some() {
            PackAlgorithm::Authcrypt
        } else {
            PackAlgorithm::Anoncrypt
        };

        let alg_anoncrypt = if Option::<&str>::None.is_some() {
            PackAlgorithm::Authcrypt
        } else {
            PackAlgorithm::Anoncrypt
        };

        assert_eq!(alg_authcrypt, PackAlgorithm::Authcrypt);
        assert_eq!(alg_anoncrypt, PackAlgorithm::Anoncrypt);
    }
}
