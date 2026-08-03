//! ChaCha20-Poly1305 AEAD wrapper.
//!
//! DCX uses a single AEAD suite for all frame payloads. The header is
//! the AAD; the nonce is derived deterministically from `msg_id` (see
//! [`crate::dcx::crypto::nonce`]).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use thiserror::Error;

/// Errors from AEAD operations. We keep these distinct from
/// [`crate::dcx::FrameError`] so callers above the codec can tell whether a
/// failure was structural or cryptographic.
#[derive(Debug, Error)]
pub enum AeadError {
    /// Encryption failed. ChaCha20-Poly1305 itself doesn't fail in
    /// realistic conditions; this variant exists for completeness.
    #[error("AEAD encryption failed")]
    EncryptFailed,

    /// Decryption failed — typically a tampered ciphertext or wrong key.
    /// Implementations MUST treat this as a security signal, not a
    /// transient failure.
    #[error("AEAD decryption failed (bad tag or tampered ciphertext)")]
    DecryptFailed,
}

/// Encrypt `plaintext` under `key` with `nonce` and `aad`.
///
/// Returns `ciphertext || tag` (the 16-byte Poly1305 tag is appended
/// to the ciphertext per RFC 8439).
pub fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AeadError::EncryptFailed)
}

/// Decrypt and verify `ciphertext_with_tag` under `key` with `nonce`
/// and `aad`.
///
/// Returns the plaintext on success. On AEAD verification failure
/// returns [`AeadError::DecryptFailed`] — the caller MUST drop the
/// frame and SHOULD close the channel.
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext_with_tag,
                aad,
            },
        )
        .map_err(|_| AeadError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let aad = b"some-aad";
        let pt = b"hello, dcx!";

        let ct = aead_seal(&key, &nonce, aad, pt).unwrap();
        // ChaCha20-Poly1305 appends a 16-byte tag.
        assert_eq!(ct.len(), pt.len() + 16);

        let dec = aead_open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn aad_mismatch_fails() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let pt = b"hello";

        let ct = aead_seal(&key, &nonce, b"aad-1", pt).unwrap();
        let err = aead_open(&key, &nonce, b"aad-2", &ct);
        assert!(matches!(err, Err(AeadError::DecryptFailed)));
    }

    #[test]
    fn key_mismatch_fails() {
        let nonce = [0u8; 12];
        let aad = b"";
        let pt = b"hello";

        let ct = aead_seal(&[1u8; 32], &nonce, aad, pt).unwrap();
        let err = aead_open(&[2u8; 32], &nonce, aad, &ct);
        assert!(matches!(err, Err(AeadError::DecryptFailed)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let aad = b"";
        let pt = b"hello";

        let mut ct = aead_seal(&key, &nonce, aad, pt).unwrap();
        ct[0] ^= 0x01; // flip a single bit
        let err = aead_open(&key, &nonce, aad, &ct);
        assert!(matches!(err, Err(AeadError::DecryptFailed)));
    }
}
