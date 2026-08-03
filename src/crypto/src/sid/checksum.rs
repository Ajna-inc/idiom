/// Checksum validation for Sanskrit SIDs using Blake3
///
/// The checksum is stored in the last syllable (position 18) and computed
/// from the first 17 syllables using Blake3 hashing.
///
/// Since each syllable can represent 0-124 (125 values), and 125^18 bits fit in u128,
/// we use a simple positional encoding where the last syllable is the checksum.
use blake3;

/// Base for syllable encoding
const BASE: u128 = 125;

/// Compute checksum for a SID value
///
/// Takes the first 17 syllables and computes a Blake3 hash,
/// then maps the result to a syllable index (0-124).
pub fn compute_checksum(value: u128) -> u8 {
    // The last syllable is at position 17 (0-indexed)
    // Remove it by dividing by BASE
    let data_without_checksum = value / BASE;

    // Compute Blake3 hash
    let hash = blake3::hash(&data_without_checksum.to_be_bytes());

    // Map first byte to syllable index (0-124)
    let checksum_byte = hash.as_bytes()[0];
    (checksum_byte % 125) as u8
}

/// Verify checksum of a SID value
pub fn verify(value: u128) -> bool {
    // Extract stored checksum (last syllable)
    let stored_checksum = (value % BASE) as u8;

    // Recompute expected checksum from first 17 syllables
    let expected_checksum = compute_checksum(value);

    stored_checksum == expected_checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_deterministic() {
        let value: u128 = 0x123456789abcdef0123456789abcdef0;

        let checksum1 = compute_checksum(value);
        let checksum2 = compute_checksum(value);

        assert_eq!(checksum1, checksum2);
        assert!(checksum1 < 125);
    }

    #[test]
    fn test_checksum_range() {
        // Test multiple values to ensure checksum stays in range
        for i in 0..1000 {
            let value = (i as u128) << 50;
            let checksum = compute_checksum(value);
            assert!(checksum < 125, "Checksum out of range: {}", checksum);
        }
    }

    #[test]
    fn test_checksum_different_for_different_values() {
        let value1: u128 = 0x111111111111111;
        let value2: u128 = 0x222222222222222;

        let checksum1 = compute_checksum(value1);
        let checksum2 = compute_checksum(value2);

        // Different values should (usually) produce different checksums
        // This is probabilistic but very likely to pass
        assert_ne!(checksum1, checksum2);
    }
}
