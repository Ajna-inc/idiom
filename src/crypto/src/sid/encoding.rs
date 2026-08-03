/// Sanskrit base-125 encoding/decoding
///
/// Encodes u128 values as 18 Sanskrit syllables using base-125 encoding.
use crate::sid::constants::{index_to_syllable, syllable_to_index};
use crate::sid::error::{Result, SIDError};

/// Number of syllables in a complete SID
pub const SID_SYLLABLE_COUNT: usize = 18;

/// Encode u128 as 18 Sanskrit syllables (base-125)
pub fn encode_sanskrit(mut value: u128) -> String {
    let mut syllables = Vec::with_capacity(SID_SYLLABLE_COUNT);

    // Encode 18 syllables from least to most significant
    for _ in 0..SID_SYLLABLE_COUNT {
        let syllable_index = (value % 125) as usize;
        syllables.push(index_to_syllable(syllable_index));
        value /= 125;
    }

    // Concatenate syllables
    syllables.join("")
}

/// Decode Sanskrit syllables to u128 (base-125)
pub fn decode_sanskrit(sanskrit: &str) -> Result<u128> {
    let mut value: u128 = 0;
    let mut multiplier: u128 = 1;
    let mut syllable_count = 0;
    let bytes = sanskrit.as_bytes();
    let mut pos = 0;

    // Parse and decode syllables in one pass
    while pos < bytes.len() {
        let mut found = false;

        // Try different syllable lengths (2-6 bytes for UTF-8)
        for len in [6, 5, 4, 3, 2] {
            if pos + len <= bytes.len() {
                if let Ok(candidate) = std::str::from_utf8(&bytes[pos..pos + len]) {
                    if let Some(index) = syllable_to_index(candidate) {
                        // Found valid syllable, decode it
                        let term = (index as u128)
                            .checked_mul(multiplier)
                            .ok_or(SIDError::Overflow)?;

                        value = value.checked_add(term).ok_or(SIDError::Overflow)?;
                        multiplier = multiplier.checked_mul(125).ok_or(SIDError::Overflow)?;

                        syllable_count += 1;
                        pos += len;
                        found = true;
                        break;
                    }
                }
            }
        }

        if !found {
            // Extract invalid syllable for error message
            let invalid = std::str::from_utf8(&bytes[pos..std::cmp::min(pos + 6, bytes.len())])
                .unwrap_or("???");
            return Err(SIDError::InvalidSyllable(invalid.to_string()));
        }
    }

    // Verify syllable count
    if syllable_count != SID_SYLLABLE_COUNT {
        return Err(SIDError::InvalidLength {
            expected: SID_SYLLABLE_COUNT,
            got: syllable_count,
        });
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_zero() {
        let encoded = encode_sanskrit(0);
        assert_eq!(encoded, "ka".repeat(SID_SYLLABLE_COUNT));
    }

    #[test]
    fn test_encode_small_value() {
        let encoded = encode_sanskrit(5);
        // 5 in base-125: 5 % 125 = 5, which is "ga" (index 5)
        // Then 17 more "ka" syllables for the remaining positions
        // The first syllable is encoded first, so it should start with "ga"
        assert!(encoded.starts_with("ga"), "Encoded: {}", encoded);
    }

    #[test]
    fn test_roundtrip() {
        let original: u128 = 123456789012345678901234567890;
        let encoded = encode_sanskrit(original);
        let decoded = decode_sanskrit(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_max_value() {
        // Maximum value representable in 18 base-125 syllables
        let max_value = 125u128.pow(18) - 1;

        let encoded = encode_sanskrit(max_value);
        let decoded = decode_sanskrit(&encoded).unwrap();

        assert_eq!(max_value, decoded);
    }

    #[test]
    fn test_decode_invalid_syllable() {
        let invalid = "kakizzzz"; // "zz" is invalid

        let result = decode_sanskrit(invalid);
        assert!(result.is_err());
        assert!(matches!(result, Err(SIDError::InvalidSyllable(_))));
    }

    #[test]
    fn test_decode_wrong_length() {
        let too_short = "kakikukeko"; // Only 5 syllables

        let result = decode_sanskrit(too_short);
        assert!(result.is_err());
        assert!(matches!(result, Err(SIDError::InvalidLength { .. })));
    }

    #[test]
    fn test_multiple_values_roundtrip() {
        // Maximum value that fits in 18 base-125 syllables
        let max_representable = 125u128.pow(18) - 1;

        let test_values = vec![
            0u128,
            1,
            125,
            125 * 125,
            max_representable / 2,
            max_representable / 1000,
            max_representable,
        ];

        for value in test_values {
            let encoded = encode_sanskrit(value);
            let decoded = decode_sanskrit(&encoded).unwrap();
            assert_eq!(value, decoded, "Roundtrip failed for value: {}", value);
        }
    }
}
