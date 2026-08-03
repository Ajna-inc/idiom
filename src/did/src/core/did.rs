//! DID (Decentralized Identifier) type and parsing
//!
//! Implements W3C DID specification parsing and validation.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// DID parsing and validation errors
#[derive(Debug, Error)]
pub enum DidError {
    #[error("Invalid DID format: {0}")]
    InvalidFormat(String),

    #[error("Missing DID method: {0}")]
    MissingMethod(String),

    #[error("Missing method-specific ID: {0}")]
    MissingMethodSpecificId(String),

    #[error("Invalid DID URL: {0}")]
    InvalidUrl(String),
}

/// A DID (Decentralized Identifier)
///
/// Format: `did:method:method-specific-id`
///
/// # Examples
///
/// ```
/// use did::core::DID;
///
/// let did = DID::parse("did:peer:2.Ez6LSms...Vf4D")?;
/// assert_eq!(did.method(), "peer");
/// assert_eq!(did.method_specific_id(), "2.Ez6LSms...Vf4D");
/// # Ok::<(), did::core::DidError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DID(String);

impl DID {
    /// Parse a DID from a string
    ///
    /// # Format
    ///
    /// `did:method:method-specific-id`
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - DID doesn't start with "did:"
    /// - Method is missing
    /// - Method-specific ID is missing
    pub fn parse(did: &str) -> Result<Self, DidError> {
        // Must start with "did:"
        if !did.starts_with("did:") {
            return Err(DidError::InvalidFormat(format!(
                "DID must start with 'did:', got: {}",
                did
            )));
        }

        // Split into parts
        let parts: Vec<&str> = did.splitn(3, ':').collect();

        // Must have at least 3 parts: "did", method, method-specific-id
        if parts.len() < 3 {
            return Err(DidError::InvalidFormat(format!(
                "DID must have format 'did:method:id', got: {}",
                did
            )));
        }

        // Validate method is not empty
        if parts[1].is_empty() {
            return Err(DidError::MissingMethod(did.to_string()));
        }

        // Validate method-specific ID is not empty
        if parts[2].is_empty() {
            return Err(DidError::MissingMethodSpecificId(did.to_string()));
        }

        Ok(Self(did.to_string()))
    }

    /// Create a DID from parts (unchecked)
    ///
    /// This skips validation. Use `parse()` for validation.
    pub fn new_unchecked(did: String) -> Self {
        Self(did)
    }

    /// Get the DID method
    ///
    /// # Examples
    ///
    /// ```
    /// # use did::core::DID;
    /// let did = DID::parse("did:peer:2.Ez6LSms")?;
    /// assert_eq!(did.method(), "peer");
    /// # Ok::<(), did::core::DidError>(())
    /// ```
    pub fn method(&self) -> &str {
        let parts: Vec<&str> = self.0.splitn(3, ':').collect();
        parts.get(1).unwrap_or(&"")
    }

    /// Get the method-specific ID
    ///
    /// # Examples
    ///
    /// ```
    /// # use did::core::DID;
    /// let did = DID::parse("did:key:z6MkpTHz")?;
    /// assert_eq!(did.method_specific_id(), "z6MkpTHz");
    /// # Ok::<(), did::core::DidError>(())
    /// ```
    pub fn method_specific_id(&self) -> &str {
        let parts: Vec<&str> = self.0.splitn(3, ':').collect();
        parts.get(2).unwrap_or(&"")
    }

    /// Get the full DID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for DID {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<DID> for String {
    fn from(did: DID) -> Self {
        did.0
    }
}

impl TryFrom<String> for DID {
    type Error = DidError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl TryFrom<&str> for DID {
    type Error = DidError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_did() {
        let did = DID::parse("did:peer:2.Ez6LSms").unwrap();
        assert_eq!(did.method(), "peer");
        assert_eq!(did.method_specific_id(), "2.Ez6LSms");
        assert_eq!(did.as_str(), "did:peer:2.Ez6LSms");
    }

    #[test]
    fn test_parse_did_key() {
        let did = DID::parse("did:key:z6MkpTHz").unwrap();
        assert_eq!(did.method(), "key");
        assert_eq!(did.method_specific_id(), "z6MkpTHz");
    }

    #[test]
    fn test_parse_did_web() {
        let did = DID::parse("did:web:example.com").unwrap();
        assert_eq!(did.method(), "web");
        assert_eq!(did.method_specific_id(), "example.com");
    }

    #[test]
    fn test_parse_invalid_no_prefix() {
        let result = DID::parse("peer:2.Ez6LSms");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DidError::InvalidFormat(_)));
    }

    #[test]
    fn test_parse_invalid_no_method() {
        let result = DID::parse("did::2.Ez6LSms");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DidError::MissingMethod(_)));
    }

    #[test]
    fn test_parse_invalid_no_id() {
        let result = DID::parse("did:peer:");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DidError::MissingMethodSpecificId(_)
        ));
    }

    #[test]
    fn test_parse_invalid_incomplete() {
        let result = DID::parse("did:peer");
        assert!(result.is_err());
    }

    #[test]
    fn test_display() {
        let did = DID::parse("did:peer:2.Ez6LSms").unwrap();
        assert_eq!(format!("{}", did), "did:peer:2.Ez6LSms");
    }

    #[test]
    fn test_serialization() {
        let did = DID::parse("did:peer:2.Ez6LSms").unwrap();
        let json = serde_json::to_string(&did).unwrap();
        assert_eq!(json, "\"did:peer:2.Ez6LSms\"");

        let deserialized: DID = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, did);
    }

    #[test]
    fn test_try_from_string() {
        let did: DID = "did:peer:2.Ez6LSms".try_into().unwrap();
        assert_eq!(did.method(), "peer");
    }

    #[test]
    fn test_method_with_colon_in_id() {
        // Method-specific ID can contain colons
        let did = DID::parse("did:web:example.com:user:alice").unwrap();
        assert_eq!(did.method(), "web");
        assert_eq!(did.method_specific_id(), "example.com:user:alice");
    }
}
