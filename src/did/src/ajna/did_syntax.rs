//! DID Syntax for did:ajna (Updated to Sanskrit SID v1.0)
//!
//! Implements DID syntax with Sanskrit Systematic Identifiers (SID):
//! ```text
//! did:ajna:<sanskrit-sid>[#<fragment>]
//! ```
//!
//! Where:
//! - `<sanskrit-sid>` = 18 Sanskrit syllables encoding a uint128
//! - `#<fragment>` = optional fragment for VM/service references
//!
//! This replaces the old 32-byte random NSID with human-readable Sanskrit SIDs
//! that are compatible with the Ajna blockchain.

use crate::ajna::{AjnaError, Result};
use ::crypto::sid::{DIDKind, Network, SIDHeader, ShardId, Version, SID};
use serde::{Deserialize, Serialize};

/// DID method name
pub const DID_METHOD: &str = "ajna";

/// DID method prefix
pub const DID_PREFIX: &str = "did:ajna:";

/// A parsed did:ajna identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AjnaDid {
    /// The Sanskrit SID (uint128)
    pub sid: SID,

    /// Optional fragment (for referencing VMs, services, etc.)
    pub fragment: Option<String>,
}

impl AjnaDid {
    /// Generate a new random DID with Sanskrit SID
    ///
    /// # Arguments
    /// * `network` - Network (Mainnet, Testnet, etc.)
    /// * `kind` - DID kind (Person, Organization, Device, Service)
    ///
    /// # Returns
    /// A new randomly generated DID with Sanskrit SID
    pub fn generate(network: Network, kind: DIDKind) -> Self {
        let header = SIDHeader::new(Version::V0, network, kind, ShardId::new(0).unwrap());
        let sid = SID::generate_with_header(header);

        Self {
            sid,
            fragment: None,
        }
    }

    /// Create a DID from a SID
    pub fn from_sid(sid: SID) -> Self {
        Self {
            sid,
            fragment: None,
        }
    }

    /// Create a DID from Sanskrit string
    ///
    /// # Arguments
    /// * `sanskrit` - Sanskrit SID string (18 syllables)
    ///
    /// # Returns
    /// Parsed DID
    pub fn from_sanskrit(sanskrit: &str) -> Result<Self> {
        let sid = SID::from_sanskrit(sanskrit)
            .map_err(|e| AjnaError::InvalidDid(format!("Invalid Sanskrit SID: {}", e)))?;

        Ok(Self {
            sid,
            fragment: None,
        })
    }

    /// Create a DID from English mnemonic
    ///
    /// # Arguments
    /// * `words` - 12 BIP-39 words
    ///
    /// # Returns
    /// Parsed DID
    pub fn from_english(words: &[&str]) -> Result<Self> {
        let sid = SID::from_english(words)
            .map_err(|e| AjnaError::InvalidDid(format!("Invalid English mnemonic: {}", e)))?;

        Ok(Self {
            sid,
            fragment: None,
        })
    }

    /// Create a DID from uint128
    pub fn from_u128(value: u128) -> Self {
        Self {
            sid: SID::from_u128(value),
            fragment: None,
        }
    }

    /// Parse a DID string into components
    ///
    /// # Arguments
    /// * `did_string` - The DID string to parse (e.g., "did:ajna:qegelonufa...")
    ///
    /// # Returns
    /// Parsed DID components
    ///
    /// # Errors
    /// Returns error if the DID string is invalid
    pub fn parse(did_string: &str) -> Result<Self> {
        // Check prefix
        if !did_string.starts_with(DID_PREFIX) {
            return Err(AjnaError::InvalidDid(format!(
                "DID must start with '{}': {}",
                DID_PREFIX, did_string
            )));
        }

        // Remove prefix
        let remainder = &did_string[DID_PREFIX.len()..];

        // Split by fragment
        let (sanskrit_str, fragment) = if let Some(idx) = remainder.find('#') {
            let frag = remainder[idx + 1..].to_string();
            (&remainder[..idx], Some(frag))
        } else {
            (remainder, None)
        };

        // Parse Sanskrit SID
        let sid = SID::from_sanskrit(sanskrit_str)
            .map_err(|e| AjnaError::InvalidDid(format!("Invalid Sanskrit SID: {}", e)))?;

        Ok(Self { sid, fragment })
    }

    /// Get Sanskrit representation
    pub fn to_sanskrit(&self) -> String {
        self.sid.to_sanskrit()
    }

    /// Get English mnemonic representation
    pub fn to_english(&self) -> [&'static str; 12] {
        self.sid.to_english()
    }

    /// Get uint128 value
    pub fn as_u128(&self) -> u128 {
        self.sid.as_u128()
    }

    /// Get SID metadata
    pub fn metadata(&self) -> (Version, Network, DIDKind) {
        (self.sid.version(), self.sid.network(), self.sid.did_kind())
    }

    /// Add a fragment to the DID
    pub fn with_fragment(mut self, fragment: String) -> Self {
        self.fragment = Some(fragment);
        self
    }
}

impl std::fmt::Display for AjnaDid {
    /// Formats the canonical DID string (e.g., "did:ajna:qegelonufa...").
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.sid.to_did())?;
        if let Some(ref frag) = self.fragment {
            write!(f, "#{}", frag)?;
        }
        Ok(())
    }
}

impl Serialize for AjnaDid {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AjnaDid {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_did() {
        let did = AjnaDid::generate(Network::Mainnet, DIDKind::Person);
        assert!(did.to_string().starts_with("did:ajna:"));
        // A SID is always 18 Sanskrit syllables, but each syllable is either 2
        // chars (e.g. "ka") or 3 chars (e.g. "shi"/"dha"), so the total char
        // count is not fixed — it ranges from 36 (all 2-char) to 54 (all 3-char).
        // The stale `== 36` assertion wrongly assumed every syllable was 2 chars.
        let sanskrit = did.to_sanskrit();
        let char_count = sanskrit.chars().count();
        assert!(
            (36..=54).contains(&char_count),
            "18 syllables must be 36..=54 chars, got {char_count}: {sanskrit}"
        );
        // Confirm it really is a valid 18-syllable SID by round-tripping.
        let reparsed = AjnaDid::from_sanskrit(&sanskrit).unwrap();
        assert_eq!(reparsed.as_u128(), did.as_u128());
    }

    #[test]
    fn test_parse_did() {
        // Generate a valid DID and test roundtrip parsing
        let original = AjnaDid::generate(Network::Mainnet, DIDKind::Person);
        let did_str = original.to_string();
        let parsed = AjnaDid::parse(&did_str).unwrap();
        assert_eq!(parsed.to_string(), did_str);
    }

    #[test]
    fn test_parse_did_with_fragment() {
        // Generate a valid DID and add a fragment
        let original = AjnaDid::generate(Network::Mainnet, DIDKind::Person);
        let did_str = format!("{}#key-1", original);
        let parsed = AjnaDid::parse(&did_str).unwrap();
        assert_eq!(parsed.fragment, Some("key-1".to_string()));
        assert_eq!(parsed.to_string(), did_str);
    }

    #[test]
    fn test_english_mnemonic() {
        let did = AjnaDid::generate(Network::Mainnet, DIDKind::Person);
        let words = did.to_english();
        assert_eq!(words.len(), 12);

        // Round-trip test
        let did2 = AjnaDid::from_english(&words).unwrap();
        assert_eq!(did.sid.as_u128(), did2.sid.as_u128());
    }

    #[test]
    fn test_u128_conversion() {
        let value = 123456789012345678901234567890u128;
        let did = AjnaDid::from_u128(value);
        assert_eq!(did.as_u128(), value);
    }

    #[test]
    fn test_metadata() {
        let did = AjnaDid::generate(Network::Mainnet, DIDKind::Person);
        let (version, network, kind) = did.metadata();
        assert_eq!(version, Version::V0);
        assert_eq!(network, Network::Mainnet);
        assert_eq!(kind, DIDKind::Person);
    }

    #[test]
    fn test_invalid_did() {
        assert!(AjnaDid::parse("did:example:123").is_err());
        assert!(AjnaDid::parse("did:ajna:invalid-sanskrit").is_err());
    }
}
