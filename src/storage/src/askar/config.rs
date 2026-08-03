//! Configuration for Askar storage

use crate::askar::error::{AskarError, Result};
use aries_askar::storage::{Argon2Level, KdfMethod};
use aries_askar::StoreKeyMethod;

/// Key derivation methods for store encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyDerivationMethod {
    /// Argon2i interactive (moderate security, faster)
    Argon2iInteractive,
    /// Argon2i moderate (high security, slower - recommended)
    #[default]
    Argon2iModerate,
    /// Raw key (no derivation)
    RawKey,
}

impl From<KeyDerivationMethod> for StoreKeyMethod {
    fn from(method: KeyDerivationMethod) -> Self {
        match method {
            KeyDerivationMethod::Argon2iInteractive => {
                StoreKeyMethod::DeriveKey(KdfMethod::Argon2i(Argon2Level::Interactive))
            }
            KeyDerivationMethod::Argon2iModerate => {
                StoreKeyMethod::DeriveKey(KdfMethod::Argon2i(Argon2Level::Moderate))
            }
            KeyDerivationMethod::RawKey => StoreKeyMethod::RawKey,
        }
    }
}

/// Configuration for Askar storage
#[derive(Debug, Clone)]
pub struct AskarConfig {
    /// Database URL (e.g., "sqlite://:memory:", "sqlite://path/to/db", "postgresql://...")
    pub database_url: String,

    /// Passphrase for store encryption
    pub pass_key: String,

    /// Key derivation method
    pub key_method: KeyDerivationMethod,

    /// Create store if it doesn't exist
    pub create_if_missing: bool,

    /// Profile name for multi-tenancy
    pub profile: Option<String>,
}

impl AskarConfig {
    /// Create a new configuration builder
    pub fn builder() -> AskarConfigBuilder {
        AskarConfigBuilder::default()
    }
}

/// Builder for AskarConfig
#[derive(Default)]
pub struct AskarConfigBuilder {
    database_url: Option<String>,
    pass_key: Option<String>,
    key_method: KeyDerivationMethod,
    create_if_missing: bool,
    profile: Option<String>,
}

impl AskarConfigBuilder {
    /// Use an in-memory SQLite database (ephemeral).
    ///
    /// **Pool sizing matters here.** SQLite's bare `:memory:` URL opens a
    /// brand-new database per pool connection — `shared_cache(true)` does
    /// *not* fix this; only the named-memory form (`file::memory:?cache=shared`)
    /// shares across connections. askar's default pool sizes are 1..=4-8
    /// connections, so the first acquire gets the provisioned DB and every
    /// subsequent acquire gets a fresh empty one, which fails the session
    /// ping with "no such table: profiles". We cap min/max to 1 so all
    /// sessions reuse the single provisioned connection.
    pub fn in_memory(mut self) -> Self {
        self.database_url =
            Some("sqlite://:memory:?max_connections=1&min_connections=1".to_string());
        self
    }

    /// Use a SQLite file database
    pub fn sqlite_file(mut self, path: impl Into<String>) -> Self {
        self.database_url = Some(format!("sqlite://{}", path.into()));
        self
    }

    /// Use a PostgreSQL database
    pub fn postgres(mut self, url: impl Into<String>) -> Self {
        self.database_url = Some(url.into());
        self
    }

    /// Set the passphrase for encryption
    pub fn pass_key(mut self, key: impl Into<String>) -> Self {
        self.pass_key = Some(key.into());
        self
    }

    /// Set the key derivation method
    pub fn key_derivation(mut self, method: KeyDerivationMethod) -> Self {
        self.key_method = method;
        self
    }

    /// Create the store if it doesn't exist
    pub fn create_if_missing(mut self, create: bool) -> Self {
        self.create_if_missing = create;
        self
    }

    /// Set the profile name for multi-tenancy
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<AskarConfig> {
        Ok(AskarConfig {
            database_url: self
                .database_url
                .ok_or_else(|| AskarError::config("database_url is required"))?,
            pass_key: self
                .pass_key
                .ok_or_else(|| AskarError::config("pass_key is required"))?,
            key_method: self.key_method,
            create_if_missing: self.create_if_missing,
            profile: self.profile,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder_in_memory() {
        let config = AskarConfig::builder()
            .in_memory()
            .pass_key("test-key")
            .build()
            .unwrap();

        assert_eq!(
            config.database_url,
            "sqlite://:memory:?max_connections=1&min_connections=1"
        );
        assert_eq!(config.pass_key, "test-key");
    }

    #[test]
    fn test_config_builder_sqlite_file() {
        let config = AskarConfig::builder()
            .sqlite_file("/tmp/test.db")
            .pass_key("test-key")
            .build()
            .unwrap();

        assert_eq!(config.database_url, "sqlite:///tmp/test.db");
    }

    #[test]
    fn test_config_builder_postgres() {
        let config = AskarConfig::builder()
            .postgres("postgresql://localhost/test")
            .pass_key("test-key")
            .build()
            .unwrap();

        assert_eq!(config.database_url, "postgresql://localhost/test");
    }

    #[test]
    fn test_config_builder_missing_url() {
        let result = AskarConfig::builder().pass_key("test-key").build();

        assert!(result.is_err());
    }

    #[test]
    fn test_config_builder_missing_pass_key() {
        let result = AskarConfig::builder().in_memory().build();

        assert!(result.is_err());
    }

    #[test]
    fn test_config_with_profile() {
        let config = AskarConfig::builder()
            .in_memory()
            .pass_key("test-key")
            .profile("agent-1")
            .build()
            .unwrap();

        assert_eq!(config.profile, Some("agent-1".to_string()));
    }
}
