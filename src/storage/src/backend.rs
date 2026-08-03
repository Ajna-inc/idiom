//! Modular storage-backend selection.
//!
//! Today every binary hand-wires a concrete `StorageProvider` (the http_server
//! example even mixes in-memory storage with an askar wallet). This module makes
//! the backend a single, config-driven choice so callers pick one of
//! `memory | askar | kanon` (and future backends) uniformly — the same lever the
//! credential benchmark uses to hold storage constant across agents.
//!
//! ```no_run
//! # async fn f() -> Result<(), Box<dyn std::error::Error>> {
//! use storage::backend::StorageBackend;
//! let storage = StorageBackend::from_spec("askar")?.build().await?;
//! # let _ = storage; Ok(()) }
//! ```
//!
//! The wallet side has the same shape; because the askar wallet lives in a
//! separate crate, a parallel `WalletBackend` factory belongs in the `agent`
//! crate (which depends on both `wallet` and `storage`) and mirrors this enum.

use crate::askar::config::AskarConfig;
use crate::askar::AskarStorageProvider;
use crate::memory::MemoryStorage;
use agent_core::traits::StorageProvider;
use agent_core::{AgentError, Result};
use std::sync::Arc;

/// Default at-rest passphrase for dev/bench backends when none is supplied.
const DEFAULT_KEY: &str = "idiom-dev-key";

/// A selectable storage backend. Construct via [`StorageBackend::from_spec`] or
/// the typed constructors, then [`build`](StorageBackend::build).
#[derive(Debug, Clone)]
pub enum StorageBackend {
    /// Pure in-memory (WASM-friendly, ephemeral). No external resources.
    Memory,
    /// Askar (SQLite or Postgres), encrypted at rest.
    Askar {
        database_url: String,
        pass_key: String,
    },
    /// Kanon Postgres, matching the ACA-Py `kanon_storage` schema.
    #[cfg(feature = "kanon")]
    Kanon {
        database_url: String,
        profile: Option<String>,
    },
}

impl StorageBackend {
    /// In-memory backend.
    pub fn memory() -> Self {
        StorageBackend::Memory
    }

    /// Askar over an ephemeral in-memory SQLite database.
    pub fn askar_memory() -> Self {
        StorageBackend::Askar {
            database_url: "sqlite://:memory:?max_connections=1&min_connections=1".to_string(),
            pass_key: DEFAULT_KEY.to_string(),
        }
    }

    /// Parse a spec string, typically from a `STORE` env var:
    ///
    /// | spec | backend |
    /// |------|---------|
    /// | `memory` | in-memory |
    /// | `askar` / `askar-memory` | askar, in-memory SQLite |
    /// | `askar:<db_url>` | askar at `db_url` |
    /// | `kanon` | kanon, url from `KANON_DATABASE_URL` |
    /// | `kanon:<db_url>` | kanon at `db_url` |
    ///
    /// The at-rest key comes from `STORAGE_KEY` (falling back to a dev default).
    pub fn from_spec(spec: &str) -> std::result::Result<Self, String> {
        let key = std::env::var("STORAGE_KEY").unwrap_or_else(|_| DEFAULT_KEY.to_string());
        let (kind, rest) = match spec.split_once(':') {
            Some((k, r)) => (k, Some(r.to_string())),
            None => (spec, None),
        };
        match kind {
            "memory" => Ok(StorageBackend::Memory),
            "askar" | "askar-memory" if rest.is_none() => Ok(StorageBackend::askar_memory()),
            "askar" => Ok(StorageBackend::Askar {
                database_url: rest.unwrap(),
                pass_key: key,
            }),
            #[cfg(feature = "kanon")]
            "kanon" => {
                let url = rest
                    .or_else(|| std::env::var("KANON_DATABASE_URL").ok())
                    .ok_or_else(|| {
                        "kanon backend needs a url (kanon:<url> or KANON_DATABASE_URL)".to_string()
                    })?;
                Ok(StorageBackend::Kanon {
                    database_url: url,
                    profile: None,
                })
            }
            #[cfg(not(feature = "kanon"))]
            "kanon" => Err("kanon backend requires the `kanon` feature".to_string()),
            other => Err(format!("unknown storage backend: {other:?}")),
        }
    }

    /// A short stable name for logs/reports (`memory`, `askar`, `kanon`).
    pub fn name(&self) -> &'static str {
        match self {
            StorageBackend::Memory => "memory",
            StorageBackend::Askar { .. } => "askar",
            #[cfg(feature = "kanon")]
            StorageBackend::Kanon { .. } => "kanon",
        }
    }

    /// Instantiate the selected backend as a trait object.
    pub async fn build(&self) -> Result<Arc<dyn StorageProvider>> {
        match self {
            StorageBackend::Memory => Ok(Arc::new(MemoryStorage::new())),
            StorageBackend::Askar {
                database_url,
                pass_key,
            } => {
                let config = AskarConfig {
                    database_url: database_url.clone(),
                    pass_key: pass_key.clone(),
                    key_method: Default::default(),
                    create_if_missing: true,
                    profile: None,
                };
                let provider = AskarStorageProvider::new(config)
                    .await
                    .map_err(|e| AgentError::Storage(format!("askar backend: {e}")))?;
                Ok(Arc::new(provider))
            }
            #[cfg(feature = "kanon")]
            StorageBackend::Kanon {
                database_url,
                profile,
            } => {
                let provider = crate::kanon::KanonStorageProvider::connect_with_profile(
                    database_url,
                    profile
                        .as_deref()
                        .unwrap_or(crate::kanon::DEFAULT_PROFILE_ID),
                )
                .await?;
                Ok(Arc::new(provider))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_spec_parses_backends() {
        assert!(matches!(
            StorageBackend::from_spec("memory").unwrap(),
            StorageBackend::Memory
        ));
        assert!(matches!(
            StorageBackend::from_spec("askar").unwrap(),
            StorageBackend::Askar { .. }
        ));
        assert!(StorageBackend::from_spec("nope").is_err());
    }

    #[tokio::test]
    async fn builds_memory_and_askar() {
        StorageBackend::memory().build().await.unwrap();
        StorageBackend::askar_memory().build().await.unwrap();
    }
}
