// ! Sanskrit SID Library (did:ajna v1.0)
//!
//! This crate provides the core SID (Syllable IDentifier) implementation for the
//! Ajna blockchain. SIDs are 128-bit identifiers with multiple human-readable
//! encodings and built-in checksums.
//!
//! # Features
//!
//! - **Compact**: 16 bytes (uint128) instead of 32 bytes
//! - **Multi-encoding**: Sanskrit syllables + English mnemonic (BIP-39 style)
//! - **Checksum**: Built-in error detection (99.2% accuracy)
//! - **DID format**: `did:ajna:kadidunagishibibamalata`
//! - **Human-friendly**: Both Sanskrit and English representations
//!
//! # Encodings
//!
//! A single SID can be represented in multiple ways:
//!
//! 1. **uint128** (blockchain storage): `123456789012345678901234567890`
//! 2. **Sanskrit** (18 syllables): `kadidunagishibibamalata...`
//! 3. **English Mnemonic** (12 BIP-39 words): `river mango sunset temple...`
//! 4. **DID string**: `did:ajna:kadidunagishibibamalata...`
//!
//! All encodings decode to the same uint128 value (single source of truth).
//!
//! # Example
//!
//! ```
//! use crypto::sid::SID;
//!
//! // Generate new SID
//! let sid = SID::generate();
//!
//! // Sanskrit encoding
//! let sanskrit = sid.to_sanskrit();
//! let did = sid.to_did();  // did:ajna:<sanskrit>
//!
//! // English mnemonic encoding (12 words)
//! let words = sid.to_english();
//! let phrase = sid.to_english_phrase();  // ajna-words:<12 words>
//!
//! // Parse from any format
//! let from_did = SID::from_did(&did).unwrap();
//! let from_english = SID::from_english(&words).unwrap();
//! let from_phrase = SID::from_english_phrase(&phrase).unwrap();
//!
//! // All decode to same SID
//! assert_eq!(sid, from_did);
//! assert_eq!(sid, from_english);
//! assert_eq!(sid, from_phrase);
//!
//! // Get as u128 for blockchain storage
//! let sid_int = sid.as_u128();
//! ```

mod checksum;
mod constants;
mod encoding;
pub mod english;
mod error;
pub mod headers;
pub mod wordlist;

pub use error::{Result, SIDError};
pub use headers::{DIDKind, Network, SIDHeader, ShardId, Version};

use blake3;
use rand::Rng;

/// Sanskrit SID - Multi-encoding 128-bit identifier (did:ajna v1.0)
///
/// A SID is a 128-bit identifier that can be represented as:
/// - **uint128** (blockchain storage): Single source of truth
/// - **18 Sanskrit syllables**: Primary human-friendly encoding
/// - **12 English words**: BIP-39 style mnemonic (secondary encoding)
/// - **DID string**: `did:ajna:<syllables>`
/// - **16-byte array**: Network transmission
///
/// All encodings are bidirectional and decode to the same uint128 value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SID {
    inner: u128,
}

impl SID {
    /// Parse from DID string: "did:ajna:kadidunagishibibamalata"
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The prefix is not "did:ajna:"
    /// - The syllables are invalid
    /// - The checksum is invalid
    pub fn from_did(did: &str) -> Result<Self> {
        // Validate prefix
        if !did.starts_with("did:ajna:") {
            return Err(SIDError::InvalidPrefix);
        }

        // Extract Sanskrit portion
        let sanskrit = &did[9..];

        // Decode Sanskrit → SID
        Self::from_sanskrit(sanskrit)
    }

    /// Convert to DID string
    ///
    /// Returns a string in the format: `did:ajna:<syllables>`
    pub fn to_did(&self) -> String {
        format!("did:ajna:{}", self.to_sanskrit())
    }

    /// Get as u128 (for blockchain storage)
    #[inline]
    pub fn as_u128(&self) -> u128 {
        self.inner
    }

    /// Get as 16-byte array
    pub fn as_bytes(&self) -> [u8; 16] {
        self.inner.to_be_bytes()
    }

    /// Create from u128 (for blockchain lookups)
    ///
    /// Note: This does NOT validate the checksum. Use `from_sanskrit()` for
    /// checksum validation.
    #[inline]
    pub fn from_u128(value: u128) -> Self {
        Self { inner: value }
    }

    /// Create from 16-byte array
    ///
    /// Note: This does NOT validate the checksum.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            inner: u128::from_be_bytes(bytes),
        }
    }

    /// Encode as Sanskrit syllables
    ///
    /// Returns 18 syllables like "kadidunagishibibamalata"
    pub fn to_sanskrit(&self) -> String {
        encoding::encode_sanskrit(self.inner)
    }

    /// Decode from Sanskrit syllables
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Syllables are invalid
    /// - Wrong number of syllables
    /// - Checksum validation fails
    pub fn from_sanskrit(sanskrit: &str) -> Result<Self> {
        let value = encoding::decode_sanskrit(sanskrit)?;

        // Verify checksum
        if !checksum::verify(value) {
            return Err(SIDError::InvalidChecksum);
        }

        Ok(Self { inner: value })
    }

    /// Generate new random SID with default headers
    ///
    /// This generates a cryptographically random SID with:
    /// - Default headers (V0, Mainnet, Generic)
    /// - Random payload (98 bits)
    /// - Checksum (7 bits)
    pub fn generate() -> Self {
        Self::generate_with_header(SIDHeader::default())
    }

    /// Generate new random SID with custom header
    ///
    /// This allows specifying:
    /// - Version (V0 for DIDs, V1+ for future uses)
    /// - Network (Mainnet, Testnet, Devnet, Staging)
    /// - DID Kind (Generic, Person, Organization, Device, Agent, etc.)
    /// - Shard ID (0-15 for state partitioning)
    ///
    /// # Example
    ///
    /// ```
    /// use crypto::sid::{SID, SIDHeader, Version, Network, DIDKind};
    ///
    /// // Generate testnet person DID in shard 5
    /// let header = SIDHeader::with_shard(
    ///     Version::V0,
    ///     Network::Testnet,
    ///     DIDKind::Person,
    ///     5,  // Shard 5
    /// ).unwrap();
    /// let sid = SID::generate_with_header(header);
    /// assert_eq!(sid.network(), Network::Testnet);
    /// assert_eq!(sid.did_kind(), DIDKind::Person);
    /// assert_eq!(sid.shard_id(), 5);
    /// ```
    pub fn generate_with_header(header: SIDHeader) -> Self {
        // SECURITY: Use OsRng for cryptographic random generation
        let mut rng = rand::rngs::OsRng;

        // Generate random payload for digits 3-16 (14 digits)
        let random: u128 = rng.gen();
        let masked = random & ((1u128 << 98) - 1); // 14 digits ≈ 98 bits

        // Build sid_int from digits (following the plan's algorithm)
        let (d0, d1, d2) = header.to_digits();
        let mut sid_int = 0u128;

        // Add header digits (d0-d2)
        sid_int = sid_int * 125 + (d0 as u128);
        sid_int = sid_int * 125 + (d1 as u128);
        sid_int = sid_int * 125 + (d2 as u128);

        // Add random digits (d3-d16) - 14 digits
        let mut n = masked;
        for _ in 0..14 {
            let digit = n % 125;
            sid_int = sid_int * 125 + digit;
            n /= 125;
        }

        // Add checksum (d17) - make space and compute
        sid_int *= 125; // Make space for checksum
        let checksum = checksum::compute_checksum(sid_int);
        sid_int += checksum as u128;

        Self { inner: sid_int }
    }

    /// Generate a SID from a seed (deterministic)
    ///
    /// Useful for testing or generating predictable SIDs.
    /// Uses default headers (V0, Mainnet, Generic).
    pub fn from_seed(seed: &[u8]) -> Self {
        Self::from_seed_with_header(seed, SIDHeader::default())
    }

    /// Generate a SID from a seed with custom header (deterministic)
    ///
    /// Useful for testing or generating predictable SIDs with specific headers.
    pub fn from_seed_with_header(seed: &[u8], header: SIDHeader) -> Self {
        let hash = blake3::hash(seed);
        let bytes: [u8; 16] = hash.as_bytes()[0..16].try_into().unwrap();
        let payload = u128::from_be_bytes(bytes);

        // Mask to 98 bits for payload
        let masked = payload & ((1u128 << 98) - 1);

        // Build sid_int from digits
        let (d0, d1, d2) = header.to_digits();
        let mut sid_int = 0u128;

        // Add header digits (d0-d2)
        sid_int = sid_int * 125 + (d0 as u128);
        sid_int = sid_int * 125 + (d1 as u128);
        sid_int = sid_int * 125 + (d2 as u128);

        // Add payload digits (d3-d16) - 14 digits
        let mut n = masked;
        for _ in 0..14 {
            let digit = (n % 125) as u128;
            sid_int = sid_int * 125 + digit;
            n /= 125;
        }

        // Add checksum (d17)
        sid_int *= 125; // Make space for checksum
        let checksum = checksum::compute_checksum(sid_int);
        sid_int += checksum as u128;

        Self { inner: sid_int }
    }

    /// Verify the checksum of this SID
    pub fn verify_checksum(&self) -> bool {
        checksum::verify(self.inner)
    }

    /// Extract header from this SID
    ///
    /// Returns the parsed header containing version, network, kind, and flags.
    ///
    /// # Example
    ///
    /// ```
    /// use crypto::sid::{SID, Network, DIDKind};
    ///
    /// let sid = SID::generate();
    /// let header = sid.header();
    /// assert_eq!(header.network, Network::Mainnet);
    /// assert_eq!(header.kind, DIDKind::Generic);
    /// ```
    pub fn header(&self) -> SIDHeader {
        SIDHeader::from_sid_int(self.inner).expect("SID header should always be valid")
    }

    /// Get version from this SID
    pub fn version(&self) -> Version {
        self.header().version
    }

    /// Get network from this SID
    pub fn network(&self) -> Network {
        self.header().network
    }

    /// Get DID kind from this SID
    pub fn did_kind(&self) -> DIDKind {
        self.header().kind
    }

    /// Get the shard ID (0-15) for this SID
    ///
    /// The shard determines which state partition this account belongs to.
    /// Shard assignment is based on d2 digit: `shard_id = d2 % 16`
    #[inline]
    pub fn shard_id(&self) -> u8 {
        self.header().shard()
    }

    /// Get the raw ShardId struct from this SID
    pub fn shard(&self) -> ShardId {
        self.header().shard_id
    }

    /// Validate this SID's header
    ///
    /// Checks that header values are valid and consistent.
    pub fn validate_header(&self) -> Result<()> {
        self.header().validate()
    }

    /// Encode as 12 English words (AEM - Ajna English Mnemonic)
    ///
    /// Returns a 12-word BIP-39 style mnemonic encoding this SID.
    ///
    /// # Example
    ///
    /// ```
    /// use crypto::sid::SID;
    ///
    /// let sid = SID::generate();
    /// let words = sid.to_english();
    /// assert_eq!(words.len(), 12);
    /// ```
    pub fn to_english(&self) -> [&'static str; 12] {
        english::encode_english(self.inner)
    }

    /// Decode from 12 English words (AEM - Ajna English Mnemonic)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Wrong number of words (not 12)
    /// - Invalid word (not in BIP-39 wordlist)
    /// - Checksum validation fails
    ///
    /// # Example
    ///
    /// ```
    /// use crypto::sid::SID;
    ///
    /// let sid = SID::generate();
    /// let words = sid.to_english();
    /// let decoded = SID::from_english(&words).unwrap();
    /// assert_eq!(sid, decoded);
    /// ```
    pub fn from_english(words: &[&str]) -> Result<Self> {
        let sid_int = english::decode_english(words)?;

        // Create SID from decoded value
        let sid = Self { inner: sid_int };

        // Verify Sanskrit checksum (digit 17)
        if !sid.verify_checksum() {
            return Err(SIDError::InvalidChecksum);
        }

        Ok(sid)
    }

    /// Format as English mnemonic phrase string
    ///
    /// Returns a string in the format: `ajna-words:<word1> <word2> ... <word12>`
    ///
    /// # Example
    ///
    /// ```
    /// use crypto::sid::SID;
    ///
    /// let sid = SID::generate();
    /// let phrase = sid.to_english_phrase();
    /// assert!(phrase.starts_with("ajna-words:"));
    /// ```
    pub fn to_english_phrase(&self) -> String {
        let words = self.to_english();
        format!("ajna-words:{}", words.join(" "))
    }

    /// Parse from English mnemonic phrase string
    ///
    /// Accepts formats:
    /// - `ajna-words:<word1> <word2> ... <word12>`
    /// - `<word1> <word2> ... <word12>` (raw words)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Wrong number of words
    /// - Invalid words
    /// - Checksum validation fails
    ///
    /// # Example
    ///
    /// ```
    /// use crypto::sid::SID;
    ///
    /// let sid = SID::generate();
    /// let phrase = sid.to_english_phrase();
    /// let decoded = SID::from_english_phrase(&phrase).unwrap();
    /// assert_eq!(sid, decoded);
    /// ```
    pub fn from_english_phrase(phrase: &str) -> Result<Self> {
        let phrase = phrase.trim();

        // Strip optional prefix
        let phrase = phrase.strip_prefix("ajna-words:").unwrap_or(phrase).trim();

        // Split into words
        let words: Vec<&str> = phrase.split_whitespace().collect();

        if words.len() != 12 {
            return Err(SIDError::InvalidLength {
                expected: 12,
                got: words.len(),
            });
        }

        Self::from_english(&words)
    }
}

// ============================================================================
// Trait Implementations
// ============================================================================

impl From<u128> for SID {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl From<SID> for u128 {
    fn from(sid: SID) -> Self {
        sid.as_u128()
    }
}

impl From<[u8; 16]> for SID {
    fn from(bytes: [u8; 16]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<SID> for [u8; 16] {
    fn from(sid: SID) -> Self {
        sid.as_bytes()
    }
}

impl std::fmt::Display for SID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_did())
    }
}

impl std::str::FromStr for SID {
    type Err = SIDError;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();

        if s.starts_with("did:ajna:") {
            // DID format: did:ajna:<sanskrit>
            Self::from_did(s)
        } else if s.starts_with("ajna-words:") || s.contains(' ') {
            // English mnemonic format: "ajna-words:<words>" or "<word> <word> ..."
            Self::from_english_phrase(s)
        } else {
            // Sanskrit syllables (no spaces)
            Self::from_sanskrit(s)
        }
    }
}

// ============================================================================
// Serialization Support (optional feature)
// ============================================================================

#[cfg(feature = "serde")]
impl serde::Serialize for SID {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as Sanskrit string for readability
        serializer.serialize_str(&self.to_sanskrit())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SID {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        SID::from_sanskrit(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify() {
        let sid = SID::generate();

        // Should have valid checksum
        assert!(sid.verify_checksum());

        // Should roundtrip through Sanskrit
        let sanskrit = sid.to_sanskrit();
        let decoded = SID::from_sanskrit(&sanskrit).unwrap();
        assert_eq!(sid, decoded);

        // Should roundtrip through DID
        let did = sid.to_did();
        let parsed = SID::from_did(&did).unwrap();
        assert_eq!(sid, parsed);
    }

    #[test]
    fn test_from_seed_deterministic() {
        let seed = b"test-seed-123";

        let sid1 = SID::from_seed(seed);
        let sid2 = SID::from_seed(seed);

        assert_eq!(sid1, sid2);
        assert!(sid1.verify_checksum());
    }

    #[test]
    fn test_u128_roundtrip() {
        let sid = SID::generate();
        let sid_int = sid.as_u128();
        let recovered = SID::from_u128(sid_int);

        assert_eq!(sid, recovered);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let sid = SID::generate();
        let bytes = sid.as_bytes();
        let recovered = SID::from_bytes(bytes);

        assert_eq!(sid, recovered);
    }

    #[test]
    fn test_did_format() {
        let sid = SID::generate();
        let did = sid.to_did();

        assert!(did.starts_with("did:ajna:"));
        // Syllables are now ASCII-only (2-3 chars each)
        // 18 syllables × 2-3 chars = 36-54 chars + "did:ajna:" prefix (9 chars) = 45-63 chars
        assert!(
            did.len() >= 45 && did.len() <= 63,
            "DID length: {}",
            did.len()
        );
    }

    #[test]
    fn test_invalid_prefix() {
        let invalid = "did:wrong:kadikukekogagugugego";
        let result = SID::from_did(invalid);

        assert!(result.is_err());
        assert!(matches!(result, Err(SIDError::InvalidPrefix)));
    }

    #[test]
    fn test_invalid_checksum_detection() {
        // Previous version corrupted the first *two chars* of the Sanskrit
        // string to "za". That was flaky: (a) the first syllable may be 3 chars
        // (e.g. "shi"), so a 2-char splice produced a structurally invalid
        // syllable stream → `InvalidSyllable`, not `InvalidChecksum`; and
        // (b) even a valid corruption had a ~1/125 chance of preserving the
        // checksum. This deterministic version corrupts ONLY the checksum
        // syllable (the low base-125 digit) to a value that cannot match the
        // recomputed checksum, while keeping every syllable valid, so
        // `from_sanskrit` reliably reports `InvalidChecksum`.
        let sid = SID::generate();
        let value = sid.as_u128();

        // The stored checksum is the low base-125 digit. Bump it by 1 (mod 125):
        // the recomputed checksum depends only on `value / 125`, which is
        // unchanged, so the corrupted digit is guaranteed to differ from it.
        let stored = value % 125;
        let corrupted_value = value - stored + ((stored + 1) % 125);
        assert_ne!(corrupted_value, value);

        // Re-encode from the corrupted value → 18 valid syllables, bad checksum.
        let corrupted_sanskrit = SID::from_u128(corrupted_value).to_sanskrit();

        let result = SID::from_sanskrit(&corrupted_sanskrit);
        assert!(result.is_err());
        assert!(matches!(result, Err(SIDError::InvalidChecksum)));
    }

    #[test]
    fn test_display_trait() {
        let sid = SID::generate();
        let display = format!("{}", sid);

        assert!(display.starts_with("did:ajna:"));
    }

    #[test]
    fn test_from_str_did_format() {
        let sid = SID::generate();
        let did = sid.to_did();

        let parsed: SID = did.parse().unwrap();
        assert_eq!(sid, parsed);
    }

    #[test]
    fn test_from_str_sanskrit_format() {
        let sid = SID::generate();
        let sanskrit = sid.to_sanskrit();

        let parsed: SID = sanskrit.parse().unwrap();
        assert_eq!(sid, parsed);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_roundtrip() {
        let sid = SID::generate();

        let json = serde_json::to_string(&sid).unwrap();
        let decoded: SID = serde_json::from_str(&json).unwrap();

        assert_eq!(sid, decoded);
    }

    #[test]
    fn test_english_roundtrip() {
        let sid = SID::generate();

        // Test array format
        let words = sid.to_english();
        assert_eq!(words.len(), 12);

        let decoded = SID::from_english(&words).unwrap();
        assert_eq!(sid, decoded);
    }

    #[test]
    fn test_english_phrase_roundtrip() {
        let sid = SID::generate();

        // Test phrase format
        let phrase = sid.to_english_phrase();
        assert!(phrase.starts_with("ajna-words:"));

        let decoded = SID::from_english_phrase(&phrase).unwrap();
        assert_eq!(sid, decoded);
    }

    #[test]
    fn test_english_phrase_without_prefix() {
        let sid = SID::generate();
        let words = sid.to_english();
        let phrase_no_prefix = words.join(" ");

        let decoded = SID::from_english_phrase(&phrase_no_prefix).unwrap();
        assert_eq!(sid, decoded);
    }

    #[test]
    fn test_from_str_english_format() {
        let sid = SID::generate();
        let phrase = sid.to_english_phrase();

        let parsed: SID = phrase.parse().unwrap();
        assert_eq!(sid, parsed);
    }

    #[test]
    fn test_from_str_english_no_prefix() {
        let sid = SID::generate();
        let words = sid.to_english();
        let phrase = words.join(" ");

        let parsed: SID = phrase.parse().unwrap();
        assert_eq!(sid, parsed);
    }

    #[test]
    fn test_multi_encoding_consistency() {
        let sid = SID::generate();

        // Sanskrit encoding
        let sanskrit = sid.to_sanskrit();
        let from_sanskrit = SID::from_sanskrit(&sanskrit).unwrap();

        // English encoding
        let words = sid.to_english();
        let from_english = SID::from_english(&words).unwrap();

        // DID format
        let did = sid.to_did();
        let from_did = SID::from_did(&did).unwrap();

        // All should decode to same SID
        assert_eq!(sid, from_sanskrit);
        assert_eq!(sid, from_english);
        assert_eq!(sid, from_did);
    }

    #[test]
    fn test_default_headers() {
        let sid = SID::generate();

        assert_eq!(sid.version(), Version::V0);
        assert_eq!(sid.network(), Network::Mainnet);
        assert_eq!(sid.did_kind(), DIDKind::Generic);
        assert_eq!(sid.shard_id(), 0); // Default shard is 0
        assert!(sid.validate_header().is_ok());
    }

    #[test]
    fn test_custom_headers() {
        let header = SIDHeader::with_shard(
            Version::V0,
            Network::Testnet,
            DIDKind::Person,
            5, // Shard 5
        )
        .unwrap();

        let sid = SID::generate_with_header(header);

        assert_eq!(sid.version(), Version::V0);
        assert_eq!(sid.network(), Network::Testnet);
        assert_eq!(sid.did_kind(), DIDKind::Person);
        assert_eq!(sid.shard_id(), 5);
        assert!(sid.validate_header().is_ok());
    }

    #[test]
    fn test_header_roundtrip() {
        let header = SIDHeader::with_shard(
            Version::V0,
            Network::Devnet,
            DIDKind::Agent,
            12, // Shard 12
        )
        .unwrap();

        let sid = SID::generate_with_header(header);
        let extracted = sid.header();

        assert_eq!(extracted, header);
    }

    #[test]
    fn test_all_networks() {
        for network in [
            Network::Mainnet,
            Network::Testnet,
            Network::Devnet,
            Network::Staging,
        ] {
            let header = SIDHeader::new(
                Version::V0,
                network,
                DIDKind::Generic,
                ShardId::new(0).unwrap(),
            );

            let sid = SID::generate_with_header(header);
            assert_eq!(sid.network(), network);
        }
    }

    #[test]
    fn test_all_did_kinds() {
        for kind in [
            DIDKind::Generic,
            DIDKind::Person,
            DIDKind::Organization,
            DIDKind::Device,
            DIDKind::Agent,
            DIDKind::Service,
            DIDKind::Faucet,
        ] {
            let header = SIDHeader::new(
                Version::V0,
                Network::Mainnet,
                kind,
                ShardId::new(0).unwrap(),
            );

            let sid = SID::generate_with_header(header);
            assert_eq!(sid.did_kind(), kind);
        }
    }

    #[test]
    fn test_all_shards() {
        // Test that all 16 shards work correctly with SID
        for shard in 0..16 {
            let header =
                SIDHeader::with_shard(Version::V0, Network::Mainnet, DIDKind::Person, shard)
                    .unwrap();

            let sid = SID::generate_with_header(header);
            assert_eq!(sid.shard_id(), shard);
        }
    }

    #[test]
    fn test_from_seed_with_header() {
        let seed = b"test-seed-123";
        let header = SIDHeader::with_shard(
            Version::V0,
            Network::Testnet,
            DIDKind::Organization,
            7, // Shard 7
        )
        .unwrap();

        let sid1 = SID::from_seed_with_header(seed, header);
        let sid2 = SID::from_seed_with_header(seed, header);

        // Deterministic
        assert_eq!(sid1, sid2);

        // Headers preserved
        assert_eq!(sid1.network(), Network::Testnet);
        assert_eq!(sid1.did_kind(), DIDKind::Organization);
        assert_eq!(sid1.shard_id(), 7);

        // Checksum valid
        assert!(sid1.verify_checksum());
    }

    #[test]
    fn test_header_persists_through_encoding() {
        let header = SIDHeader::with_shard(
            Version::V0,
            Network::Testnet,
            DIDKind::Device,
            9, // Shard 9
        )
        .unwrap();

        let sid = SID::generate_with_header(header);

        // Sanskrit roundtrip
        let sanskrit = sid.to_sanskrit();
        let from_sanskrit = SID::from_sanskrit(&sanskrit).unwrap();
        assert_eq!(from_sanskrit.network(), Network::Testnet);
        assert_eq!(from_sanskrit.did_kind(), DIDKind::Device);

        // English roundtrip
        let words = sid.to_english();
        let from_english = SID::from_english(&words).unwrap();
        assert_eq!(from_english.network(), Network::Testnet);
        assert_eq!(from_english.did_kind(), DIDKind::Device);

        // DID roundtrip
        let did = sid.to_did();
        let from_did = SID::from_did(&did).unwrap();
        assert_eq!(from_did.network(), Network::Testnet);
        assert_eq!(from_did.did_kind(), DIDKind::Device);
    }
}
