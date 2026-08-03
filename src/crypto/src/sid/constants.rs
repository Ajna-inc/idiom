//! Sanskrit SID Constants
//!
//! This module defines the syllable tables for Sanskrit base-125 encoding.
//! Each syllable is a consonant + vowel pair from the Sanskrit alphabet.

/// Pre-computed syllable lookup table (25 × 5 = 125 syllables)
/// All syllables are ASCII-only for maximum compatibility.
pub const SYLLABLES: [&str; 125] = [
    // k-group (0-4)
    "ka", "ki", "ku", "ke", "ko", // g-group (5-9)
    "ga", "gi", "gu", "ge", "go", // c-group (10-14)
    "ca", "ci", "cu", "ce", "co", // j-group (15-19)
    "ja", "ji", "ju", "je", "jo", // t-group (20-24)
    "ta", "ti", "tu", "te", "to", // d-group (25-29)
    "da", "di", "du", "de", "do", // n-group (30-34)
    "na", "ni", "nu", "ne", "no", // p-group (35-39)
    "pa", "pi", "pu", "pe", "po", // b-group (40-44)
    "ba", "bi", "bu", "be", "bo", // m-group (45-49)
    "ma", "mi", "mu", "me", "mo", // y-group (50-54)
    "ya", "yi", "yu", "ye", "yo", // r-group (55-59)
    "ra", "ri", "ru", "re", "ro", // l-group (60-64)
    "la", "li", "lu", "le", "lo", // v-group (65-69)
    "va", "vi", "vu", "ve", "vo", // s-group (70-74)
    "sa", "si", "su", "se", "so", // h-group (75-79)
    "ha", "hi", "hu", "he", "ho", // q-group (80-84)
    "qa", "qi", "qu", "qe", "qo", // w-group (85-89)
    "wa", "wi", "wu", "we", "wo", // x-group (90-94)
    "xa", "xi", "xu", "xe", "xo", // z-group (95-99)
    "za", "zi", "zu", "ze", "zo", // f-group (100-104)
    "fa", "fi", "fu", "fe", "fo", // th-group (105-109) - replaces ñ (aspirated t)
    "tha", "thi", "thu", "the", "tho",
    // dh-group (110-114) - replaces ṭ (aspirated d)
    "dha", "dhi", "dhu", "dhe", "dho",
    // ng-group (115-119) - replaces ḍ (velar nasal)
    "nga", "ngi", "ngu", "nge", "ngo",
    // sh-group (120-124) - replaces ṇ (palatal sibilant)
    "sha", "shi", "shu", "she", "sho",
];

/// Get syllable by index (0-124)
#[inline]
pub fn index_to_syllable(index: usize) -> &'static str {
    debug_assert!(index < 125, "Syllable index out of range: {}", index);
    SYLLABLES[index]
}

/// Get index from syllable (returns None if invalid)
pub fn syllable_to_index(syllable: &str) -> Option<usize> {
    SYLLABLES.iter().position(|&s| s == syllable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syllable_count() {
        assert_eq!(SYLLABLES.len(), 125);
    }

    #[test]
    fn test_roundtrip() {
        for i in 0..125 {
            let syllable = index_to_syllable(i);
            let index = syllable_to_index(syllable).unwrap();
            assert_eq!(i, index, "Roundtrip failed for syllable: {}", syllable);
        }
    }

    #[test]
    fn test_first_and_last() {
        assert_eq!(index_to_syllable(0), "ka");
        assert_eq!(index_to_syllable(124), "sho");
        assert_eq!(syllable_to_index("ka"), Some(0));
        assert_eq!(syllable_to_index("sho"), Some(124));
    }

    #[test]
    fn test_invalid_syllable() {
        assert_eq!(syllable_to_index("zz"), None);
        assert_eq!(syllable_to_index("invalid"), None);
    }
}
