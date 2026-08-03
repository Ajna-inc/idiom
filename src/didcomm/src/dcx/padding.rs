//! Padding helpers.
//!
//! Default policy: pad such that the total frame size is a multiple of
//! 64 bytes. Padding bytes are inside the AEAD ciphertext so the
//! mediator cannot distinguish payload from padding.

/// Default padding boundary in bytes.
pub const DEFAULT_PADDING_BOUNDARY: usize = 64;

/// Frame-overhead constants used to compute padding size.
///
/// `header(42) + nonce(12) + payload_len_field(2) + padding_len_field(2) + tag(16)`
const FRAME_OVERHEAD_BYTES: usize = 42 + 12 + 2 + 2 + 16;

/// Compute the padding length to align a frame of `payload_length`
/// bytes to the next multiple of `boundary`.
///
/// Returns the number of padding bytes to append.
#[inline]
pub fn padding_length(payload_length: usize, boundary: usize) -> usize {
    let total = FRAME_OVERHEAD_BYTES + payload_length;
    let remainder = total % boundary;
    if remainder == 0 {
        0
    } else {
        boundary - remainder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_zero_byte_payload_to_64() {
        // overhead = 70 bytes; pad to 128 (next multiple of 64).
        let pad = padding_length(0, DEFAULT_PADDING_BOUNDARY);
        assert_eq!((FRAME_OVERHEAD_BYTES + pad) % 64, 0);
    }

    #[test]
    fn align_arbitrary_payload_to_64() {
        for payload in [1, 100, 1000, 65000] {
            let pad = padding_length(payload, DEFAULT_PADDING_BOUNDARY);
            assert_eq!((FRAME_OVERHEAD_BYTES + payload + pad) % 64, 0);
            assert!(pad < 64);
        }
    }

    #[test]
    fn align_exact_multiple_yields_zero_padding() {
        // Find a payload that makes (overhead + payload) exactly 64-aligned.
        let payload = 64 - FRAME_OVERHEAD_BYTES % 64;
        let pad = padding_length(payload, DEFAULT_PADDING_BOUNDARY);
        assert_eq!(pad, 0);
    }
}
