//! Counter-based AEAD nonce derivation.
//!
//! ```text
//! nonce = 0x00000000 || msg_id_be(8)
//! ```
//!
//! `msg_id` is monotonic per direction; per-direction keys differ; so
//! nonce reuse is structurally impossible within a key's lifetime.

/// AEAD nonce length (ChaCha20-Poly1305).
pub const NONCE_LEN: usize = 12;

/// Build the deterministic nonce for the given `msg_id`.
///
/// 12 bytes total: 4 leading zero bytes followed by `msg_id` in big-endian.
#[inline]
pub fn nonce_for_msg_id(msg_id: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&msg_id.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_msg_id() {
        let a = nonce_for_msg_id(42);
        let b = nonce_for_msg_id(42);
        assert_eq!(a, b);
    }

    #[test]
    fn unique_for_different_msg_ids() {
        let a = nonce_for_msg_id(0);
        let b = nonce_for_msg_id(1);
        let c = nonce_for_msg_id(u64::MAX);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn first_four_bytes_are_zero() {
        let nonce = nonce_for_msg_id(0xDEAD_BEEF);
        assert_eq!(&nonce[0..4], &[0u8; 4]);
    }

    #[test]
    fn msg_id_encoded_big_endian() {
        let nonce = nonce_for_msg_id(0x01_02_03_04_05_06_07_08);
        assert_eq!(
            &nonce[4..],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }
}
