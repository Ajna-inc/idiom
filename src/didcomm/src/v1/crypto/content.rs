//! Content encryption using ChaCha20-Poly1305 (C20P)
//!
//! This implements the actual message content encryption for DIDComm v1.
//! Despite the "xchacha20poly1305_ietf" name in the JWE, DIDComm v1 uses
//! regular ChaCha20-Poly1305 with 12-byte nonces.

use crate::v1::error::{DIDCommV1Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};

/// Encrypt message content using ChaCha20-Poly1305
///
/// # Arguments
/// * `plaintext` - The message content to encrypt
/// * `cek` - Content encryption key (32 bytes)
/// * `aad` - Additional authenticated data (the protected header)
///
/// # Returns
/// Tuple of (ciphertext, iv, tag)
pub fn encrypt_content(
    plaintext: &[u8],
    cek: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if cek.len() != 32 {
        return Err(DIDCommV1Error::InvalidKeyFormat(format!(
            "Content encryption key must be 32 bytes, got {}",
            cek.len()
        )));
    }

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(cek)
        .map_err(|e| DIDCommV1Error::Crypto(format!("Failed to create cipher: {}", e)))?;

    // Generate random nonce (ChaCha20 uses 12-byte nonces)
    let mut nonce = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);

    // Create payload with AAD
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    // Encrypt
    let ciphertext_with_tag = cipher
        .encrypt(&nonce.into(), payload)
        .map_err(|e| DIDCommV1Error::EncryptionFailed(format!("Encryption failed: {}", e)))?;

    // ChaCha20Poly1305 appends the 16-byte tag to the ciphertext
    // Split them apart
    let tag_len = 16;
    if ciphertext_with_tag.len() < tag_len {
        return Err(DIDCommV1Error::EncryptionFailed(
            "Ciphertext too short".to_string(),
        ));
    }

    let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - tag_len);

    Ok((ciphertext.to_vec(), nonce.to_vec(), tag.to_vec()))
}

/// Decrypt message content using ChaCha20-Poly1305
///
/// # Arguments
/// * `ciphertext` - The encrypted message content
/// * `iv` - Initialization vector / nonce (12 bytes for ChaCha20)
/// * `tag` - Authentication tag (16 bytes)
/// * `cek` - Content encryption key (32 bytes)
/// * `aad` - Additional authenticated data (the protected header)
///
/// # Returns
/// Decrypted plaintext
pub fn decrypt_content(
    ciphertext: &[u8],
    iv: &[u8],
    tag: &[u8],
    cek: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if cek.len() != 32 {
        return Err(DIDCommV1Error::InvalidKeyFormat(format!(
            "Content encryption key must be 32 bytes, got {}",
            cek.len()
        )));
    }

    if iv.len() != 12 {
        return Err(DIDCommV1Error::InvalidKeyFormat(format!(
            "IV must be 12 bytes for ChaCha20, got {}",
            iv.len()
        )));
    }

    if tag.len() != 16 {
        return Err(DIDCommV1Error::InvalidKeyFormat(format!(
            "Tag must be 16 bytes, got {}",
            tag.len()
        )));
    }

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(cek)
        .map_err(|e| DIDCommV1Error::Crypto(format!("Failed to create cipher: {}", e)))?;

    // Combine ciphertext and tag (ChaCha20Poly1305 expects them together)
    let mut ciphertext_with_tag = ciphertext.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);

    // Convert IV to nonce (12 bytes for ChaCha20)
    let nonce = chacha20poly1305::Nonce::from_slice(iv);

    // Create payload with AAD
    let payload = Payload {
        msg: &ciphertext_with_tag,
        aad,
    };

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| DIDCommV1Error::DecryptionFailed(format!("Decryption failed: {}", e)))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_content() {
        let plaintext = b"Hello, DIDComm v1!";
        let cek = [0u8; 32]; // In real use, this would be a random key
        let aad = b"protected_header_data";

        // Encrypt
        let (ciphertext, iv, tag) = encrypt_content(plaintext, &cek, aad).unwrap();

        assert_ne!(ciphertext, plaintext); // Should be encrypted
        assert_eq!(iv.len(), 12); // ChaCha20 nonce
        assert_eq!(tag.len(), 16); // Poly1305 tag

        // Decrypt
        let decrypted = decrypt_content(&ciphertext, &iv, &tag, &cek, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_aad() {
        let plaintext = b"Secret message";
        let cek = [1u8; 32];
        let aad = b"correct_aad";

        let (ciphertext, iv, tag) = encrypt_content(plaintext, &cek, aad).unwrap();

        // Try to decrypt with wrong AAD
        let wrong_aad = b"wrong_aad";
        let result = decrypt_content(&ciphertext, &iv, &tag, &cek, wrong_aad);

        assert!(result.is_err()); // Should fail authentication
    }

    #[test]
    fn test_decrypt_with_wrong_tag() {
        let plaintext = b"Secret message";
        let cek = [2u8; 32];
        let aad = b"aad";

        let (ciphertext, iv, _tag) = encrypt_content(plaintext, &cek, aad).unwrap();

        // Try with wrong tag
        let wrong_tag = vec![0u8; 16];
        let result = decrypt_content(&ciphertext, &iv, &wrong_tag, &cek, aad);

        assert!(result.is_err()); // Should fail authentication
    }

    #[test]
    fn test_invalid_cek_length() {
        let plaintext = b"test";
        let wrong_cek = [0u8; 16]; // Wrong length
        let aad = b"aad";

        let result = encrypt_content(plaintext, &wrong_cek, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_iv_length() {
        let ciphertext = b"encrypted";
        let cek = [0u8; 32];
        let tag = [0u8; 16];
        let wrong_iv = [0u8; 12]; // Wrong length
        let aad = b"aad";

        let result = decrypt_content(ciphertext, &wrong_iv, &tag, &cek, aad);
        assert!(result.is_err());
    }
}
