use crate::sid::error::{Result, SIDError};
use crate::sid::wordlist::{index_to_word, word_to_index};
/// English Mnemonic (AEM) Encoding for Ajna SIDs
///
/// Encodes 128-bit SID as 12 English words (BIP-39 style) with 4-bit checksum.
///
/// Format:
/// - 128 bits of data (sid_int)
/// - 4 bits of checksum (Blake3-based)
/// - Total: 132 bits = 12 words × 11 bits/word
use blake3;

/// Encode sid_int as 12 English words
///
/// Algorithm:
/// 1. Serialize sid_int as 16 bytes (big-endian)
/// 2. Compute 4-bit checksum: blake3("AJNA/AEM/V1" || bytes)[0] >> 4
/// 3. Concatenate: 128 bits (data) + 4 bits (checksum) = 132 bits
/// 4. Split into 12 chunks of 11 bits each
/// 5. Map each chunk to word index (0-2047)
///
/// # Example
///
/// ```
/// use crypto::sid::english::encode_english;
///
/// let sid_int: u128 = 123456789012345678901234567890;
/// let words = encode_english(sid_int);
/// assert_eq!(words.len(), 12);
/// ```
pub fn encode_english(sid_int: u128) -> [&'static str; 12] {
    // 1. Serialize sid_int as 16 bytes (big-endian)
    let bytes = sid_int.to_be_bytes();

    // 2. Compute 4-bit checksum
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AJNA/AEM/V1");
    hasher.update(&bytes);
    let hash = hasher.finalize();
    let checksum_bits = hash.as_bytes()[0] >> 4; // Top 4 bits (0-15)

    // 3. Build 132-bit value (128 data + 4 checksum)
    // We need 17 bytes to store 132 bits
    let mut bits = [0u8; 17];
    bits[0..16].copy_from_slice(&bytes);
    bits[16] = checksum_bits << 4; // Store checksum in upper 4 bits of byte 16

    // 4. Extract 12 chunks of 11 bits each
    // Total: 12 × 11 = 132 bits
    let mut words = [""; 12];
    for (i, word) in words.iter_mut().enumerate() {
        let bit_offset = i * 11; // Starting bit position (0, 11, 22, 33, ...)

        // Extract 11 bits starting at bit_offset
        // We'll read enough bytes and use bit manipulation
        let byte_idx = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        // Read 24 bits (3 bytes) to ensure we have enough
        let bytes_available = bits.len() - byte_idx;
        let chunk = if bytes_available >= 3 {
            let b0 = bits[byte_idx] as u32;
            let b1 = bits[byte_idx + 1] as u32;
            let b2 = bits[byte_idx + 2] as u32;
            let combined = (b0 << 16) | (b1 << 8) | b2;
            // Extract 11 bits starting at bit_shift
            ((combined >> (24 - bit_shift - 11)) & 0x7FF) as u16
        } else if bytes_available >= 2 {
            let b0 = bits[byte_idx] as u16;
            let b1 = bits[byte_idx + 1] as u16;
            let combined = (b0 << 8) | b1;
            (combined >> (16 - bit_shift - 11)) & 0x7FF
        } else {
            // Last word - pad with zeros if needed
            let b0 = bits[byte_idx] as u16;
            ((b0 << bit_shift) >> 5) & 0x7FF
        };

        *word = index_to_word(chunk).expect("Index must be valid (0-2047)");
    }

    words
}

/// Decode 12 English words to sid_int
///
/// Validates checksum and returns error if mnemonic is invalid.
///
/// # Errors
///
/// Returns error if:
/// - Wrong number of words (not 12)
/// - Invalid word (not in BIP-39 list)
/// - Checksum validation fails
///
/// # Example
///
/// ```
/// use crypto::sid::english::{encode_english, decode_english};
///
/// let sid_int: u128 = 123456789012345678901234567890;
/// let words = encode_english(sid_int);
/// let decoded = decode_english(&words).unwrap();
/// assert_eq!(sid_int, decoded);
/// ```
pub fn decode_english(words: &[&str]) -> Result<u128> {
    if words.len() != 12 {
        return Err(SIDError::InvalidLength {
            expected: 12,
            got: words.len(),
        });
    }

    // 1. Map words to indices (0-2047)
    let mut indices = [0u16; 12];
    for (i, &word) in words.iter().enumerate() {
        indices[i] = word_to_index(word).ok_or_else(|| SIDError::InvalidWord(word.to_string()))?;
    }

    // 2. Combine indices into 132 bits
    let mut bits = [0u8; 17];
    for (i, &index) in indices.iter().enumerate() {
        let bit_offset = i * 11;
        let byte_idx = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        // Write 11 bits starting at bit_offset
        // Convert index to 32-bit for easier manipulation
        let value = (index as u32) & 0x7FF; // Ensure it's 11 bits

        // We need to write these 11 bits across potentially 2-3 bytes
        // Position the value and write to bytes
        let shifted_value = value << (24 - bit_shift - 11);

        // Write to up to 3 bytes
        if byte_idx < bits.len() {
            bits[byte_idx] |= ((shifted_value >> 16) & 0xFF) as u8;
        }
        if byte_idx + 1 < bits.len() {
            bits[byte_idx + 1] |= ((shifted_value >> 8) & 0xFF) as u8;
        }
        if byte_idx + 2 < bits.len() {
            bits[byte_idx + 2] |= (shifted_value & 0xFF) as u8;
        }
    }

    // 3. Split into data (128 bits) + checksum (4 bits)
    let mut data_bytes = [0u8; 16];
    data_bytes.copy_from_slice(&bits[0..16]);
    let checksum_given = bits[16] >> 4;

    // 4. Verify checksum
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AJNA/AEM/V1");
    hasher.update(&data_bytes);
    let hash = hasher.finalize();
    let checksum_expected = hash.as_bytes()[0] >> 4;

    if checksum_given != checksum_expected {
        return Err(SIDError::InvalidChecksum);
    }

    // 5. Convert to sid_int
    let sid_int = u128::from_be_bytes(data_bytes);

    Ok(sid_int)
}

/// Validate English mnemonic (checksum only, doesn't check Sanskrit checksum)
pub fn validate_english(words: &[&str]) -> Result<()> {
    decode_english(words).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let sid_int: u128 = 123456789012345678901234567890;

        let words = encode_english(sid_int);
        assert_eq!(words.len(), 12);

        // All words should be valid
        for word in &words {
            assert!(
                word_to_index(word).is_some(),
                "Word not in dictionary: {}",
                word
            );
        }

        let decoded = decode_english(&words).unwrap();
        assert_eq!(sid_int, decoded);
    }

    #[test]
    fn test_zero() {
        let sid_int: u128 = 0;

        let words = encode_english(sid_int);
        let decoded = decode_english(&words).unwrap();
        assert_eq!(sid_int, decoded);
    }

    #[test]
    fn test_max_value() {
        let sid_int: u128 = u128::MAX;

        let words = encode_english(sid_int);
        let decoded = decode_english(&words).unwrap();
        assert_eq!(sid_int, decoded);
    }

    #[test]
    fn test_invalid_checksum() {
        let sid_int: u128 = 123456789012345678901234567890;
        let mut words = encode_english(sid_int);

        // Corrupt the last word (which contains the checksum)
        // This guarantees checksum mismatch
        let original_last = words[11];
        words[11] = if original_last == "abandon" {
            "ability"
        } else {
            "abandon"
        };

        let result = decode_english(&words);
        assert!(result.is_err(), "Should fail with corrupted checksum");
        assert!(matches!(result, Err(SIDError::InvalidChecksum)));
    }

    #[test]
    fn test_invalid_word() {
        let words = [
            "river",
            "mango",
            "invalid_word_xyz",
            "temple",
            "orbit",
            "sunset",
            "anchor",
            "forest",
            "crystal",
            "meadow",
            "beacon",
            "harbor",
        ];

        let result = decode_english(&words);
        assert!(result.is_err());
        assert!(matches!(result, Err(SIDError::InvalidWord(_))));
    }

    #[test]
    fn test_wrong_word_count() {
        let words = ["abandon", "ability", "able"]; // Only 3 words

        let result = decode_english(&words);
        assert!(result.is_err());
        assert!(matches!(result, Err(SIDError::InvalidLength { .. })));
    }

    #[test]
    fn test_multiple_values() {
        let test_values = vec![
            0u128,
            1,
            42,
            1000,
            u128::MAX / 2,
            u128::MAX / 1000,
            123456789012345678901234567890,
        ];

        for value in test_values {
            let words = encode_english(value);
            let decoded = decode_english(&words).unwrap();
            assert_eq!(value, decoded, "Roundtrip failed for value: {}", value);
        }
    }

    #[test]
    fn test_deterministic() {
        let sid_int: u128 = 123456789012345678901234567890;

        let words1 = encode_english(sid_int);
        let words2 = encode_english(sid_int);

        assert_eq!(words1, words2, "Encoding should be deterministic");
    }
}
