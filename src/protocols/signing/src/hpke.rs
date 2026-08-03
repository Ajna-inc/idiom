//! HPKE Base mode implementation
//!
//! Implements DHKEM(X25519, HKDF-SHA256) + AES-256-GCM following RFC 9180.
//! Uses primitives already in the workspace lockfile via aries-askar.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::errors::{Result, SigningProtocolError};

/// Default info parameter for HPKE key derivation
const HPKE_INFO: &[u8] = b"didcomm.org/signing/1.0/sealed-secret";

/// Default info parameter for nonce derivation
const HPKE_NONCE_INFO: &[u8] = b"didcomm.org/signing/1.0/nonce";

/// HPKE Base mode: DHKEM(X25519, HKDF-SHA256) + AES-256-GCM
pub struct HpkeBase;

impl HpkeBase {
    /// Seal (encrypt) plaintext for a recipient's X25519 public key.
    ///
    /// # Arguments
    /// * `recipient_pk` - Recipient's X25519 public key (32 bytes)
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data (binds ciphertext to context)
    ///
    /// # Returns
    /// * `(ephemeral_pk, ciphertext)` - Ephemeral public key (32 bytes) and AES-256-GCM ciphertext with tag
    pub fn seal(
        recipient_pk: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        Self::seal_with_info(recipient_pk, plaintext, aad, HPKE_INFO)
    }

    /// Seal with custom info parameter for HKDF.
    pub fn seal_with_info(
        recipient_pk: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // 1. Generate ephemeral X25519 key pair
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);
        let eph_public = PublicKey::from(&eph_secret);

        // 2. ECDH: shared_secret = X25519(eph_secret, recipient_pk)
        let recipient_public = PublicKey::from(*recipient_pk);
        let shared_secret = eph_secret.diffie_hellman(&recipient_public);

        // 3. Derive AES-256 key and nonce via HKDF-SHA256
        let (aes_key, nonce_bytes) = Self::derive_key_and_nonce(
            shared_secret.as_bytes(),
            eph_public.as_bytes(),
            recipient_pk,
            info,
        )?;

        // 4. Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| SigningProtocolError::HpkeError(format!("AES key init: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| SigningProtocolError::HpkeError(format!("AES encrypt: {}", e)))?;

        Ok((eph_public.as_bytes().to_vec(), ciphertext))
    }

    /// Unseal (decrypt) ciphertext using recipient's X25519 secret key.
    ///
    /// # Arguments
    /// * `recipient_sk` - Recipient's X25519 secret key (32 bytes)
    /// * `ephemeral_pk` - Ephemeral public key from the sender (32 bytes)
    /// * `ciphertext` - AES-256-GCM ciphertext with tag
    /// * `aad` - Additional authenticated data (must match what was used during seal)
    ///
    /// # Returns
    /// * Decrypted plaintext bytes
    pub fn unseal(
        recipient_sk: &[u8; 32],
        ephemeral_pk: &[u8; 32],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        Self::unseal_with_info(recipient_sk, ephemeral_pk, ciphertext, aad, HPKE_INFO)
    }

    /// Unseal with custom info parameter for HKDF.
    pub fn unseal_with_info(
        recipient_sk: &[u8; 32],
        ephemeral_pk: &[u8; 32],
        ciphertext: &[u8],
        aad: &[u8],
        info: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. Reconstruct shared secret: ECDH(recipient_sk, ephemeral_pk)
        let secret = StaticSecret::from(*recipient_sk);
        let eph_public = PublicKey::from(*ephemeral_pk);
        let shared_secret = secret.diffie_hellman(&eph_public);

        // Recipient public key is needed for IKM construction
        let recipient_public = PublicKey::from(&secret);
        let recipient_pk = recipient_public.as_bytes();

        // 2. Derive same AES-256 key and nonce
        let (aes_key, nonce_bytes) =
            Self::derive_key_and_nonce(shared_secret.as_bytes(), ephemeral_pk, recipient_pk, info)?;

        // 3. Decrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| SigningProtocolError::HpkeError(format!("AES key init: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|e| SigningProtocolError::HpkeError(format!("AES decrypt: {}", e)))?;

        Ok(plaintext)
    }

    /// Derive AES-256 key and 12-byte nonce from shared secret via HKDF-SHA256.
    ///
    /// IKM = shared_secret || ephemeral_pk || recipient_pk
    /// Key = HKDF-Expand(IKM, info, 32)
    /// Nonce = HKDF-Expand(IKM, nonce_info, 12)
    fn derive_key_and_nonce(
        shared_secret: &[u8],
        ephemeral_pk: &[u8],
        recipient_pk: &[u8],
        info: &[u8],
    ) -> Result<([u8; 32], [u8; 12])> {
        // Construct IKM: shared_secret || ephemeral_pk || recipient_pk
        let mut ikm =
            Vec::with_capacity(shared_secret.len() + ephemeral_pk.len() + recipient_pk.len());
        ikm.extend_from_slice(shared_secret);
        ikm.extend_from_slice(ephemeral_pk);
        ikm.extend_from_slice(recipient_pk);

        // Derive AES-256 key
        let hkdf = Hkdf::<Sha256>::new(None, &ikm);
        let mut aes_key = [0u8; 32];
        hkdf.expand(info, &mut aes_key)
            .map_err(|e| SigningProtocolError::HpkeError(format!("HKDF key expand: {}", e)))?;

        // Derive 12-byte nonce with separate info
        let mut nonce_bytes = [0u8; 12];
        hkdf.expand(HPKE_NONCE_INFO, &mut nonce_bytes)
            .map_err(|e| SigningProtocolError::HpkeError(format!("HKDF nonce expand: {}", e)))?;

        Ok((aes_key, nonce_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal_roundtrip() {
        // Generate recipient key pair
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let plaintext = b"This is a secret database encryption key";
        let aad = b"session:abc123:device:did:key:z6Mk";

        // Seal
        let (eph_pk, ciphertext) =
            HpkeBase::seal(recipient_public.as_bytes(), plaintext, aad).unwrap();

        // Unseal
        let decrypted = HpkeBase::unseal(
            recipient_secret.as_bytes(),
            eph_pk.as_slice().try_into().unwrap(),
            &ciphertext,
            aad,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);
        let wrong_secret = StaticSecret::random_from_rng(OsRng);

        let plaintext = b"secret data";
        let aad = b"context";

        let (eph_pk, ciphertext) =
            HpkeBase::seal(recipient_public.as_bytes(), plaintext, aad).unwrap();

        let result = HpkeBase::unseal(
            wrong_secret.as_bytes(),
            eph_pk.as_slice().try_into().unwrap(),
            &ciphertext,
            aad,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let plaintext = b"secret data";
        let aad = b"correct context";

        let (eph_pk, ciphertext) =
            HpkeBase::seal(recipient_public.as_bytes(), plaintext, aad).unwrap();

        let result = HpkeBase::unseal(
            recipient_secret.as_bytes(),
            eph_pk.as_slice().try_into().unwrap(),
            &ciphertext,
            b"wrong context",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let plaintext = b"";
        let aad = b"";

        let (eph_pk, ciphertext) =
            HpkeBase::seal(recipient_public.as_bytes(), plaintext, aad).unwrap();

        let decrypted = HpkeBase::unseal(
            recipient_secret.as_bytes(),
            eph_pk.as_slice().try_into().unwrap(),
            &ciphertext,
            aad,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let plaintext = vec![0xABu8; 1024 * 64]; // 64 KB
        let aad = b"large payload test";

        let (eph_pk, ciphertext) =
            HpkeBase::seal(recipient_public.as_bytes(), &plaintext, aad).unwrap();

        let decrypted = HpkeBase::unseal(
            recipient_secret.as_bytes(),
            eph_pk.as_slice().try_into().unwrap(),
            &ciphertext,
            aad,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
