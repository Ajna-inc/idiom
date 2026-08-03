//! UUID wrapper type for mDoc identifiers

use serde::{Deserialize, Serialize};
use std::fmt;

/// UUID wrapper for mDoc identifiers
///
/// Provides a convenient wrapper around uuid::Uuid with mDoc-specific functionality
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Uuid {
    inner: uuid::Uuid,
}

impl Uuid {
    /// Generate a new random UUID (v4)
    pub fn new() -> Self {
        Self {
            inner: uuid::Uuid::new_v4(),
        }
    }

    /// Create from a uuid::Uuid
    pub fn from_uuid(uuid: uuid::Uuid) -> Self {
        Self { inner: uuid }
    }

    /// Parse from a hyphenated string (e.g., "550e8400-e29b-41d4-a716-446655440000")
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        uuid::Uuid::parse_str(s).map(|inner| Self { inner })
    }

    /// Get as a simple (unhyphenated) string
    pub fn to_simple_string(&self) -> String {
        self.inner.simple().to_string()
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.inner.as_bytes()
    }

    /// Get the underlying uuid::Uuid
    pub fn as_uuid(&self) -> &uuid::Uuid {
        &self.inner
    }

    /// Check if this is a nil UUID (all zeros)
    pub fn is_nil(&self) -> bool {
        self.inner.is_nil()
    }
}

impl Default for Uuid {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl From<uuid::Uuid> for Uuid {
    fn from(uuid: uuid::Uuid) -> Self {
        Self::from_uuid(uuid)
    }
}

impl From<Uuid> for uuid::Uuid {
    fn from(uuid: Uuid) -> Self {
        uuid.inner
    }
}

impl std::str::FromStr for Uuid {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_generation() {
        let uuid1 = Uuid::new();
        let uuid2 = Uuid::new();

        // UUIDs should be unique
        assert_ne!(uuid1, uuid2);
        assert!(!uuid1.is_nil());
    }

    #[test]
    fn test_uuid_parsing() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let uuid = Uuid::parse(uuid_str).unwrap();
        assert_eq!(uuid.to_string(), uuid_str);
    }

    #[test]
    fn test_uuid_simple_string() {
        let uuid = Uuid::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let simple = uuid.to_simple_string();
        assert_eq!(simple, "550e8400e29b41d4a716446655440000");
    }

    #[test]
    fn test_uuid_serialization() {
        let uuid = Uuid::new();
        let json = serde_json::to_string(&uuid).unwrap();

        let deserialized: Uuid = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, uuid);
    }

    #[test]
    fn test_uuid_display() {
        let uuid = Uuid::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let displayed = format!("{}", uuid);
        assert_eq!(displayed, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_uuid_from_str() {
        use std::str::FromStr;
        let uuid = Uuid::from_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(uuid.to_string(), "550e8400-e29b-41d4-a716-446655440000");
    }
}
