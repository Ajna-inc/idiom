//! Key wrapping using XSalsa20-Poly1305 (NaCl crypto_box)
//!
//! This implements the key wrapping mechanism used in DIDComm v1, which uses
//! ECDH for key agreement and XSalsa20-Poly1305 for encryption.

use crate::v1::error::{DIDCommV1Error, Result};
use aries_askar::kms::{
    crypto_box, crypto_box_open, crypto_box_random_nonce, crypto_box_seal_open, LocalKey,
};

/// Wrap (encrypt) a content encryption key using ECDH + XSalsa20-Poly1305
///
/// For Authcrypt: Uses authenticated encryption with both sender and recipient keys
/// For Anoncrypt: Uses ephemeral key with recipient key only
///
/// # Arguments
/// * `cek` - Content encryption key to wrap (32 bytes)
/// * `recipient_x25519` - Recipient's X25519 public key
/// * `sender_x25519` - Sender's X25519 private key (None for anoncrypt)
///
/// # Returns
/// Tuple of (encrypted_key, nonce/iv)
pub fn wrap_key(
    cek: &[u8],
    recipient_x25519: &LocalKey,
    sender_x25519: Option<&LocalKey>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Generate random nonce for crypto_box
    let nonce = crypto_box_random_nonce()
        .map_err(|e| DIDCommV1Error::Crypto(format!("Failed to generate nonce: {}", e)))?;

    let encrypted = if let Some(sender) = sender_x25519 {
        // Authcrypt: Use sender key for authenticated encryption
        crypto_box(recipient_x25519, sender, cek, &nonce)
            .map_err(|e| DIDCommV1Error::EncryptionFailed(format!("crypto_box failed: {}", e)))?
    } else {
        // Anoncrypt: Use anonymous encryption (crypto_box_seal)
        // Note: crypto_box_seal doesn't use an external nonce, it generates one internally
        // But DIDComm v1 still uses crypto_box with an ephemeral key for anoncrypt
        // We'll need to handle this differently
        return Err(DIDCommV1Error::Other(
            "Anonymous key wrapping should use ephemeral key".to_string(),
        ));
    };

    Ok((encrypted, nonce.to_vec()))
}

/// Wrap a key for anonymous encryption using an ephemeral keypair
///
/// # Arguments
/// * `cek` - Content encryption key to wrap (32 bytes)
/// * `recipient_x25519` - Recipient's X25519 public key
/// * `ephemeral_x25519` - Ephemeral X25519 keypair for this encryption
///
/// # Returns
/// Tuple of (encrypted_key, nonce/iv)
pub fn wrap_key_anon(
    cek: &[u8],
    recipient_x25519: &LocalKey,
    ephemeral_x25519: &LocalKey,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Generate random nonce
    let nonce = crypto_box_random_nonce()
        .map_err(|e| DIDCommV1Error::Crypto(format!("Failed to generate nonce: {}", e)))?;

    // Use crypto_box with ephemeral sender key
    let encrypted = crypto_box(recipient_x25519, ephemeral_x25519, cek, &nonce)
        .map_err(|e| DIDCommV1Error::EncryptionFailed(format!("crypto_box failed: {}", e)))?;

    Ok((encrypted, nonce.to_vec()))
}

/// Unwrap (decrypt) a content encryption key using ECDH + XSalsa20-Poly1305
///
/// # Arguments
/// * `encrypted_key` - Encrypted content encryption key
/// * `nonce` - Nonce/IV used for encryption
/// * `recipient_x25519` - Recipient's X25519 private key
/// * `sender_x25519` - Sender's X25519 public key (None for anoncrypt with ephemeral)
///
/// # Returns
/// Decrypted content encryption key (32 bytes)
pub fn unwrap_key(
    encrypted_key: &[u8],
    nonce: &[u8],
    recipient_x25519: &LocalKey,
    sender_x25519: Option<&LocalKey>,
) -> Result<Vec<u8>> {
    if nonce.len() != 24 {
        return Err(DIDCommV1Error::InvalidKeyFormat(format!(
            "Nonce must be 24 bytes, got {}",
            nonce.len()
        )));
    }

    let decrypted = if let Some(sender) = sender_x25519 {
        // Authcrypt: Decrypt using sender's public key
        crypto_box_open(recipient_x25519, sender, encrypted_key, nonce).map_err(|e| {
            DIDCommV1Error::DecryptionFailed(format!("crypto_box_open failed: {}", e))
        })?
    } else {
        return Err(DIDCommV1Error::Other(
            "Anonymous key unwrapping requires sender key".to_string(),
        ));
    };

    Ok(decrypted.to_vec())
}

/// Encrypt sender's public key for authcrypt
///
/// In authcrypt, the sender's public key is encrypted using crypto_box_seal (anonymous encryption)
/// so the recipient can decrypt it using only their private key, without needing to know the sender first.
///
/// # Arguments
/// * `sender_public_key` - Sender's Ed25519 public key bytes (base58-encoded string)
/// * `recipient_x25519` - Recipient's X25519 public key
/// * `sender_x25519` - Sender's X25519 private key (unused - kept for API compatibility)
///
/// # Returns
/// Tuple of (encrypted_sender, empty_nonce)
/// Note: crypto_box_seal doesn't use an external nonce, so we return an empty vec
pub fn encrypt_sender_key(
    sender_public_key: &str,
    recipient_x25519: &LocalKey,
    _sender_x25519: &LocalKey,
) -> Result<(Vec<u8>, Vec<u8>)> {
    use aries_askar::kms::crypto_box_seal;

    // Encrypt the sender's public key using anonymous encryption (crypto_box_seal)
    // This only requires the recipient's public key
    let sender_bytes = sender_public_key.as_bytes();
    let encrypted = crypto_box_seal(recipient_x25519, sender_bytes).map_err(|e| {
        DIDCommV1Error::EncryptionFailed(format!("Failed to encrypt sender key: {}", e))
    })?;

    // crypto_box_seal doesn't use an external nonce (it generates one internally)
    // Return empty nonce for compatibility with the API
    Ok((encrypted, vec![]))
}

/// Decrypt sender's public key from authcrypt
///
/// Uses crypto_box_seal_open (anonymous decryption) which only requires the recipient's private key.
/// The sender field is encrypted with crypto_box_seal, not crypto_box, so no nonce is used.
///
/// # Arguments
/// * `encrypted_sender` - Encrypted sender public key
/// * `nonce` - Nonce/IV (unused for crypto_box_seal, but kept for API compatibility)
/// * `recipient_x25519` - Recipient's X25519 private key
///
/// # Returns
/// Sender's Ed25519 public key (base58-encoded string)
pub fn decrypt_sender_key(
    encrypted_sender: &[u8],
    _nonce: &[u8],
    recipient_x25519: &LocalKey,
) -> Result<String> {
    // Decrypt using crypto_box_seal_open (anonymous decryption)
    // This only requires the recipient's private key
    let decrypted = crypto_box_seal_open(recipient_x25519, encrypted_sender).map_err(|e| {
        DIDCommV1Error::DecryptionFailed(format!("crypto_box_seal_open failed: {}", e))
    })?;

    // Convert decrypted bytes to UTF-8 string (the sender's base58-encoded public key)
    let sender_key = String::from_utf8(decrypted.to_vec()).map_err(|e| {
        DIDCommV1Error::InvalidKeyFormat(format!("Invalid UTF-8 in sender key: {}", e))
    })?;

    Ok(sender_key)
}

// ── Post-Quantum Hybrid Key Wrap (X25519 + ML-KEM-768) ──
//
// Combined shared secret: HKDF(X25519_ss || ML-KEM_ss) → both must be broken.
// Uses x25519-dalek directly (not aries-askar crypto_box) to get the raw ECDH
// shared secret for combination with ML-KEM.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce as AesNonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit};
use ml_kem::{
    array::Array, DecapsulationKey768, EncapsulationKey768, ExpandedDecapsulationKey,
    ExpandedKeyEncoding, MlKem768,
};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};

const HYBRID_INFO: &[u8] = b"didcomm/v1/hybrid/1.0";

/// Result of hybrid key wrapping.
pub struct HybridWrappedKey {
    /// AES-256-GCM encrypted CEK (combined_key as key).
    pub encrypted_key: Vec<u8>,
    /// 12-byte AES-GCM nonce.
    pub nonce: Vec<u8>,
    /// 32-byte X25519 ephemeral public key.
    pub x25519_eph_pk: Vec<u8>,
    /// 1088-byte ML-KEM-768 ciphertext.
    pub kem_ciphertext: Vec<u8>,
    /// ML-KEM kid for the recipient.
    pub kem_kid: String,
}

/// Hybrid key wrap: X25519 ECDH + ML-KEM-768 → combined shared secret → AES-256-GCM wrap.
///
/// Both the classical X25519 ECDH and quantum-safe ML-KEM-768 must be broken
/// to recover the CEK.
pub fn wrap_key_hybrid(
    cek: &[u8],
    recipient_x25519_pk: &[u8; 32],
    recipient_kem_pk: &[u8],
    kem_kid: &str,
) -> Result<HybridWrappedKey> {
    // 1. X25519 ECDH with ephemeral key
    let eph_secret = EphemeralSecret::random_from_rng(aes_gcm::aead::OsRng);
    let eph_public = X25519Public::from(&eph_secret);
    let recipient_public = X25519Public::from(*recipient_x25519_pk);
    let x25519_ss = eph_secret.diffie_hellman(&recipient_public);

    // 2. ML-KEM-768 encapsulate (ml-kem 0.3: fallible parse, infallible encapsulate)
    let ek = EncapsulationKey768::new_from_slice(recipient_kem_pk)
        .map_err(|_| DIDCommV1Error::Crypto("Invalid ML-KEM-768 PK length".into()))?;
    let (ct, kem_ss) = ek.encapsulate();

    // 3. Combine: HKDF(X25519_ss || KEM_ss) → 32-byte combined key
    let mut combined_ikm = Vec::with_capacity(64);
    combined_ikm.extend_from_slice(x25519_ss.as_bytes());
    combined_ikm.extend_from_slice(&kem_ss);

    let hkdf = Hkdf::<Sha256>::new(None, &combined_ikm);
    let mut combined_key = [0u8; 32];
    hkdf.expand(HYBRID_INFO, &mut combined_key)
        .map_err(|e| DIDCommV1Error::Crypto(format!("Hybrid HKDF: {}", e)))?;

    // 4. AES-256-GCM wrap CEK with combined key
    let cipher = Aes256Gcm::new_from_slice(&combined_key)
        .map_err(|e| DIDCommV1Error::Crypto(format!("AES init: {}", e)))?;
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce = AesNonce::from_slice(&nonce_bytes);
    let encrypted_cek = cipher
        .encrypt(nonce, cek)
        .map_err(|e| DIDCommV1Error::EncryptionFailed(format!("Hybrid wrap: {}", e)))?;

    Ok(HybridWrappedKey {
        encrypted_key: encrypted_cek,
        nonce: nonce_bytes.to_vec(),
        x25519_eph_pk: eph_public.as_bytes().to_vec(),
        kem_ciphertext: ct.to_vec(),
        kem_kid: kem_kid.to_string(),
    })
}

/// Hybrid key unwrap: X25519 ECDH + ML-KEM-768 → combined shared secret → AES-256-GCM unwrap.
pub fn unwrap_key_hybrid(
    encrypted_key: &[u8],
    nonce: &[u8],
    x25519_eph_pk: &[u8; 32],
    kem_ciphertext: &[u8],
    our_x25519_sk: &[u8; 32],
    our_kem_sk: &[u8],
) -> Result<Vec<u8>> {
    // 1. X25519 ECDH
    let our_secret = StaticSecret::from(*our_x25519_sk);
    let eph_public = X25519Public::from(*x25519_eph_pk);
    let x25519_ss = our_secret.diffie_hellman(&eph_public);

    // 2. ML-KEM-768 decapsulate (ml-kem 0.3). `our_kem_sk` is the 2400-byte
    //    EXPANDED decapsulation key — the on-disk/wire format is unchanged from
    //    ml-kem 0.2, so existing persisted keys stay valid; we read it via the
    //    expanded encoding (`from_expanded_bytes`) rather than the new 64-byte seed.
    #[allow(deprecated)]
    let dk = {
        let sk_exp: ExpandedDecapsulationKey<MlKem768> = Array::try_from(our_kem_sk)
            .map_err(|_| DIDCommV1Error::Crypto("Invalid ML-KEM-768 SK length".into()))?;
        DecapsulationKey768::from_expanded_bytes(&sk_exp)
            .map_err(|_| DIDCommV1Error::Crypto("Invalid ML-KEM-768 SK".into()))?
    };
    let kem_ss = dk
        .decapsulate_slice(kem_ciphertext)
        .map_err(|_| DIDCommV1Error::Crypto("Invalid ML-KEM-768 CT length".into()))?;

    // 3. Combine: same HKDF as wrapping
    let mut combined_ikm = Vec::with_capacity(64);
    combined_ikm.extend_from_slice(x25519_ss.as_bytes());
    combined_ikm.extend_from_slice(&kem_ss);

    let hkdf = Hkdf::<Sha256>::new(None, &combined_ikm);
    let mut combined_key = [0u8; 32];
    hkdf.expand(HYBRID_INFO, &mut combined_key)
        .map_err(|e| DIDCommV1Error::Crypto(format!("Hybrid HKDF: {}", e)))?;

    // 4. AES-256-GCM unwrap
    if nonce.len() != 12 {
        return Err(DIDCommV1Error::InvalidKeyFormat(format!(
            "Hybrid nonce must be 12 bytes, got {}",
            nonce.len()
        )));
    }
    let cipher = Aes256Gcm::new_from_slice(&combined_key)
        .map_err(|e| DIDCommV1Error::Crypto(format!("AES init: {}", e)))?;
    let aes_nonce = AesNonce::from_slice(nonce);
    let cek = cipher
        .decrypt(aes_nonce, encrypted_key)
        .map_err(|e| DIDCommV1Error::DecryptionFailed(format!("Hybrid unwrap: {}", e)))?;

    Ok(cek)
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)] // to_expanded_bytes: intentional 2400-byte format preservation
    use super::*;
    use crate::v1::crypto::utils::generate_x25519_keypair;

    #[test]
    fn test_wrap_unwrap_key_authcrypt() {
        // Generate keys
        let recipient = generate_x25519_keypair().unwrap();
        let sender = generate_x25519_keypair().unwrap();

        // Content encryption key
        let cek = vec![0u8; 32];

        // Wrap the key
        let (encrypted_key, nonce) = wrap_key(&cek, &recipient, Some(&sender)).unwrap();

        assert!(encrypted_key.len() > 32); // Should include authentication tag
        assert_eq!(nonce.len(), 24); // XSalsa20 nonce is 24 bytes

        // Unwrap the key
        // For decryption, we need the sender's public key
        let sender_public = LocalKey::from_public_bytes(
            aries_askar::kms::KeyAlg::X25519,
            &sender.to_public_bytes().unwrap(),
        )
        .unwrap();

        let decrypted_cek =
            unwrap_key(&encrypted_key, &nonce, &recipient, Some(&sender_public)).unwrap();

        assert_eq!(decrypted_cek, cek);
    }

    #[test]
    fn test_wrap_key_anon() {
        let recipient = generate_x25519_keypair().unwrap();
        let ephemeral = generate_x25519_keypair().unwrap();

        let cek = vec![1u8; 32];

        let (encrypted_key, nonce) = wrap_key_anon(&cek, &recipient, &ephemeral).unwrap();

        assert!(encrypted_key.len() > 32);
        assert_eq!(nonce.len(), 24);

        // Decrypt using ephemeral public key
        let ephemeral_public = LocalKey::from_public_bytes(
            aries_askar::kms::KeyAlg::X25519,
            &ephemeral.to_public_bytes().unwrap(),
        )
        .unwrap();

        let decrypted_cek =
            unwrap_key(&encrypted_key, &nonce, &recipient, Some(&ephemeral_public)).unwrap();

        assert_eq!(decrypted_cek, cek);
    }

    #[test]
    fn test_encrypt_sender_key() {
        let recipient = generate_x25519_keypair().unwrap();
        let sender = generate_x25519_keypair().unwrap();

        let sender_key_base58 = "SomeBase58EncodedKey";

        let (encrypted, nonce) =
            encrypt_sender_key(sender_key_base58, &recipient, &sender).unwrap();

        assert!(!encrypted.is_empty());
        // crypto_box_seal doesn't use an external nonce — returns empty vec
        assert!(nonce.is_empty());
    }

    #[test]
    fn test_hybrid_wrap_unwrap_roundtrip() {
        // Generate X25519 keypair
        let x25519_sk = x25519_dalek::StaticSecret::random_from_rng(aes_gcm::aead::OsRng);
        let x25519_pk = x25519_dalek::PublicKey::from(&x25519_sk);

        // Generate ML-KEM-768 keypair
        let (dk, ek) = MlKem768::generate_keypair();
        let kem_pk = ek.to_bytes().to_vec();
        let kem_sk = dk.to_expanded_bytes().to_vec();
        let kem_kid = "test-kid-123";

        // CEK to wrap
        let cek = vec![42u8; 32];

        // Wrap
        let wrapped = wrap_key_hybrid(&cek, x25519_pk.as_bytes(), &kem_pk, kem_kid).unwrap();

        assert_eq!(wrapped.x25519_eph_pk.len(), 32);
        assert_eq!(wrapped.kem_ciphertext.len(), 1088);
        assert_eq!(wrapped.nonce.len(), 12);
        assert_eq!(wrapped.kem_kid, kem_kid);

        // Unwrap
        let mut x25519_eph = [0u8; 32];
        x25519_eph.copy_from_slice(&wrapped.x25519_eph_pk);

        let decrypted_cek = unwrap_key_hybrid(
            &wrapped.encrypted_key,
            &wrapped.nonce,
            &x25519_eph,
            &wrapped.kem_ciphertext,
            &x25519_sk.to_bytes(),
            &kem_sk,
        )
        .unwrap();

        assert_eq!(decrypted_cek, cek);
    }

    #[test]
    fn test_hybrid_wrong_x25519_fails() {
        let x25519_sk = x25519_dalek::StaticSecret::random_from_rng(aes_gcm::aead::OsRng);
        let x25519_pk = x25519_dalek::PublicKey::from(&x25519_sk);

        let (dk, ek) = MlKem768::generate_keypair();
        let kem_pk = ek.to_bytes().to_vec();
        let kem_sk = dk.to_expanded_bytes().to_vec();

        let cek = vec![7u8; 32];
        let wrapped = wrap_key_hybrid(&cek, x25519_pk.as_bytes(), &kem_pk, "kid").unwrap();

        // Wrong X25519 secret key
        let wrong_sk = x25519_dalek::StaticSecret::random_from_rng(aes_gcm::aead::OsRng);
        let mut x25519_eph = [0u8; 32];
        x25519_eph.copy_from_slice(&wrapped.x25519_eph_pk);

        let result = unwrap_key_hybrid(
            &wrapped.encrypted_key,
            &wrapped.nonce,
            &x25519_eph,
            &wrapped.kem_ciphertext,
            &wrong_sk.to_bytes(),
            &kem_sk,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_wrong_kem_fails() {
        let x25519_sk = x25519_dalek::StaticSecret::random_from_rng(aes_gcm::aead::OsRng);
        let x25519_pk = x25519_dalek::PublicKey::from(&x25519_sk);

        let (_dk, ek) = MlKem768::generate_keypair();
        let kem_pk = ek.to_bytes().to_vec();

        // Different KEM keypair for unwrap
        let (wrong_dk, _) = MlKem768::generate_keypair();
        let wrong_kem_sk = wrong_dk.to_expanded_bytes().to_vec();

        let cek = vec![7u8; 32];
        let wrapped = wrap_key_hybrid(&cek, x25519_pk.as_bytes(), &kem_pk, "kid").unwrap();

        let mut x25519_eph = [0u8; 32];
        x25519_eph.copy_from_slice(&wrapped.x25519_eph_pk);

        let result = unwrap_key_hybrid(
            &wrapped.encrypted_key,
            &wrapped.nonce,
            &x25519_eph,
            &wrapped.kem_ciphertext,
            &x25519_sk.to_bytes(),
            &wrong_kem_sk,
        );
        assert!(result.is_err());
    }
}
