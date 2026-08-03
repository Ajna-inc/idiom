//! Paired storage + wallet backend selection.
//!
//! A credential agent needs *both* a `StorageProvider` (records) and a
//! `WalletProvider` (keys). This factory picks a matched pair from one
//! `STORE=memory|askar|kanon` choice and shares the underlying handle so the two
//! don't open separate connections:
//!
//! | `STORE` | storage | wallet | shared handle |
//! |---------|---------|--------|---------------|
//! | `memory` | in-memory | askar (sqlite `:memory:`) | — |
//! | `askar`  | askar | askar | one `Store` |
//! | `kanon`  | kanon Postgres | kanon Postgres | one `PgPool` |
//!
//! It replaces the per-binary hand-wiring (the http_server example used to
//! hard-code in-memory storage + an askar wallet) with a single lever — the same
//! one the credential benchmark uses to hold storage constant across agents.

use agent_core::traits::{StorageProvider, WalletProvider};
use agent_core::{AgentError, Result};
use std::sync::Arc;
use storage::askar::config::AskarConfig;
use storage::askar::AskarStorageProvider;
use storage::memory::MemoryStorage;
use wallet::askar::AskarWalletProvider;

/// Default at-rest key/passphrase for dev/bench backends.
const DEFAULT_KEY: &str = "idiom-dev-key";

/// A built, matched storage+wallet pair plus the backend's name (for logs).
pub struct Backends {
    pub storage: Arc<dyn StorageProvider>,
    pub wallet: Arc<dyn WalletProvider>,
    pub name: &'static str,
}

/// A selectable backend. Build with [`BackendSpec::build`].
#[derive(Debug, Clone)]
pub enum BackendSpec {
    /// In-memory records + an ephemeral askar wallet.
    Memory,
    /// Askar for both records and keys (SQLite or Postgres), sharing one store.
    Askar { db_url: String, key: String },
    /// Kanon Postgres for both, sharing one pool (ACA-Py `kanon_storage` schema).
    #[cfg(feature = "kanon-storage")]
    Kanon { db_url: String, passphrase: String },
}

impl BackendSpec {
    /// Select from the `STORE` env var (default `memory`); the at-rest key comes
    /// from `STORAGE_KEY`. `askar:<url>` / `kanon:<url>` pin a database; `kanon`
    /// alone reads `KANON_DATABASE_URL`.
    pub fn from_env() -> std::result::Result<Self, String> {
        let spec = std::env::var("STORE").unwrap_or_else(|_| "memory".to_string());
        Self::from_spec(&spec)
    }

    /// Parse a spec string (see [`from_env`](Self::from_env)).
    pub fn from_spec(spec: &str) -> std::result::Result<Self, String> {
        let key = std::env::var("STORAGE_KEY").unwrap_or_else(|_| DEFAULT_KEY.to_string());
        let (kind, rest) = match spec.split_once(':') {
            Some((k, r)) => (k, Some(r.to_string())),
            None => (spec, None),
        };
        match kind {
            "memory" => Ok(BackendSpec::Memory),
            "askar" if rest.is_none() => Ok(BackendSpec::Askar {
                db_url: "sqlite://:memory:?max_connections=1&min_connections=1".to_string(),
                key,
            }),
            "askar" => Ok(BackendSpec::Askar {
                db_url: rest.unwrap(),
                key,
            }),
            #[cfg(feature = "kanon-storage")]
            "kanon" => {
                let url = rest
                    .or_else(|| std::env::var("KANON_DATABASE_URL").ok())
                    .ok_or_else(|| {
                        "kanon needs a url (kanon:<url> or KANON_DATABASE_URL)".to_string()
                    })?;
                Ok(BackendSpec::Kanon {
                    db_url: url,
                    passphrase: key,
                })
            }
            #[cfg(not(feature = "kanon-storage"))]
            "kanon" => Err("kanon backend requires the `kanon-storage` feature".to_string()),
            other => Err(format!("unknown STORE backend: {other:?}")),
        }
    }

    /// Build the matched storage + wallet pair.
    pub async fn build(&self) -> Result<Backends> {
        match self {
            BackendSpec::Memory => {
                let storage = Arc::new(MemoryStorage::new());
                // The wallet still needs real crypto/storage — use an ephemeral
                // in-memory askar store.
                let wallet_store = AskarStorageProvider::new(askar_memory_config())
                    .await
                    .map_err(|e| AgentError::wallet(format!("askar wallet store: {e}")))?;
                let wallet = Arc::new(AskarWalletProvider::new(wallet_store.store().clone()));
                Ok(Backends {
                    storage,
                    wallet,
                    name: "memory",
                })
            }
            BackendSpec::Askar { db_url, key } => {
                let config = AskarConfig {
                    database_url: db_url.clone(),
                    pass_key: key.clone(),
                    key_method: Default::default(),
                    create_if_missing: true,
                    profile: None,
                };
                let storage = AskarStorageProvider::new(config)
                    .await
                    .map_err(|e| AgentError::Storage(format!("askar backend: {e}")))?;
                let wallet = Arc::new(AskarWalletProvider::new(storage.store().clone()));
                Ok(Backends {
                    storage: Arc::new(storage),
                    wallet,
                    name: "askar",
                })
            }
            #[cfg(feature = "kanon-storage")]
            BackendSpec::Kanon { db_url, passphrase } => {
                use storage::kanon::{KanonStorageProvider, KanonWalletProvider};
                let storage = KanonStorageProvider::connect(db_url).await?;
                // Wallet shares the storage's pool — one Postgres connection pool
                // for both, exactly like ACA-Py's plugin.
                let wallet = KanonWalletProvider::from_pool(
                    storage.pool().clone(),
                    storage::kanon::DEFAULT_PROFILE_ID,
                    passphrase,
                )
                .await?;
                Ok(Backends {
                    storage: Arc::new(storage),
                    wallet: Arc::new(wallet),
                    name: "kanon",
                })
            }
        }
    }
}

/// Selectable AnonCreds **registry (VDR/ledger)** backend, mirroring
/// [`BackendSpec`] for storage. The registry is the anchor for schemas /
/// cred-defs / rev-regs, so like storage it should be a config-driven choice,
/// not a hardcode. Chosen via `LEDGER` (default `memory`).
///
/// | `LEDGER` | registry |
/// |----------|----------|
/// | `memory` | `InMemoryRegistry` (ephemeral, local) |
/// | `storage` | `StorageBackedRegistry` over the agent's `StorageProvider` (so schema/cred-def persist to the *same* backend as records — e.g. kanon Postgres) |
///
/// Future variants slot in here feature-gated: the Kanon on-chain registry
/// (`registry_kanon`) and `indy-vdr` against the DigiCred pool (P5).
#[cfg(feature = "anoncreds")]
#[derive(Debug, Clone)]
pub enum LedgerSpec {
    Memory,
    Storage,
    /// Kanon on-chain registry over a Besu chain (the shared VDR both agents
    /// resolve from). Config comes from `KANON_*` env vars. Cred-defs are
    /// anchored on-chain and cached locally, so a holder on a different agent
    /// resolves the issuer's cred-def from the same chain.
    #[cfg(feature = "kanon-registry")]
    Kanon,
}

#[cfg(feature = "anoncreds")]
impl LedgerSpec {
    /// Select from the `LEDGER` env var (default `memory`).
    pub fn from_env() -> std::result::Result<Self, String> {
        Self::from_spec(&std::env::var("LEDGER").unwrap_or_else(|_| "memory".to_string()))
    }

    /// Parse a spec string.
    pub fn from_spec(spec: &str) -> std::result::Result<Self, String> {
        match spec {
            "memory" => Ok(LedgerSpec::Memory),
            "storage" => Ok(LedgerSpec::Storage),
            #[cfg(feature = "kanon-registry")]
            "kanon" => Ok(LedgerSpec::Kanon),
            #[cfg(not(feature = "kanon-registry"))]
            "kanon" => Err("LEDGER=kanon requires the `kanon-registry` feature".to_string()),
            other => Err(format!(
                "unknown LEDGER backend: {other:?} (memory|storage|kanon)"
            )),
        }
    }

    /// A short stable name for logs/reports.
    pub fn name(&self) -> &'static str {
        match self {
            LedgerSpec::Memory => "memory",
            LedgerSpec::Storage => "storage",
            #[cfg(feature = "kanon-registry")]
            LedgerSpec::Kanon => "kanon",
        }
    }

    /// Build the registry. `storage` is used by the `storage`/`kanon` variants
    /// (the kanon registry caches cred-def bodies there).
    pub async fn build(
        &self,
        storage: Arc<dyn StorageProvider>,
    ) -> Result<Arc<dyn anoncreds_core::AnonCredsRegistry>> {
        Ok(match self {
            LedgerSpec::Memory => Arc::new(anoncreds_core::InMemoryRegistry::new()),
            LedgerSpec::Storage => Arc::new(anoncreds_core::StorageBackedRegistry::new(storage)),
            #[cfg(feature = "kanon-registry")]
            LedgerSpec::Kanon => build_kanon_registry(storage).await?,
        })
    }
}

/// Build a `KanonRegistry` over a live Besu chain from `KANON_*` env vars.
/// Mirrors essi-agent-api's wiring, but reads chain-id + address-book from env
/// (rather than the crate's chain-1947 defaults) so it targets whichever chain
/// is configured (e.g. digicred's chain 55056).
#[cfg(feature = "kanon-registry")]
async fn build_kanon_registry(
    storage: Arc<dyn StorageProvider>,
) -> Result<Arc<dyn anoncreds_core::AnonCredsRegistry>> {
    use registry_kanon::{AlloyKanonChain, KanonChain, KanonConfig, KanonRegistry};

    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let rpc = env("KANON_RPC_URL")
        .ok_or_else(|| AgentError::Other("LEDGER=kanon: KANON_RPC_URL required".into()))?;
    let org = env("KANON_ORG_ID")
        .ok_or_else(|| AgentError::Other("LEDGER=kanon: KANON_ORG_ID required".into()))?;

    let mut cfg = KanonConfig::besu_readonly(&rpc).with_issuer(format!("did:kanon:org:{org}"));
    if let Some(cid) = env("KANON_CHAIN_ID").and_then(|s| s.parse::<u64>().ok()) {
        cfg.chain_id = cid;
    }
    if let Some(ab) = env("KANON_ADDRESS_BOOK") {
        cfg.address_book = ab;
    }
    if let Some(key) = env("KANON_OPERATOR_KEY") {
        cfg = cfg.with_operator_key(key);
    }

    let chain: Arc<dyn KanonChain> = Arc::new(
        AlloyKanonChain::connect(&cfg)
            .await
            .map_err(|e| AgentError::Other(format!("kanon chain connect ({rpc}): {e}")))?,
    );
    Ok(Arc::new(KanonRegistry::new(chain, storage, cfg)))
}

fn askar_memory_config() -> AskarConfig {
    AskarConfig {
        database_url: "sqlite://:memory:?max_connections=1&min_connections=1".to_string(),
        pass_key: DEFAULT_KEY.to_string(),
        key_method: Default::default(),
        create_if_missing: true,
        profile: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_specs() {
        assert!(matches!(
            BackendSpec::from_spec("memory").unwrap(),
            BackendSpec::Memory
        ));
        assert!(matches!(
            BackendSpec::from_spec("askar").unwrap(),
            BackendSpec::Askar { .. }
        ));
        assert!(BackendSpec::from_spec("bogus").is_err());
    }

    #[tokio::test]
    async fn builds_memory_and_askar_pairs() {
        for spec in ["memory", "askar"] {
            let b = BackendSpec::from_spec(spec).unwrap().build().await.unwrap();
            // both a storage and a wallet come back
            let _ = b.storage.find("none", "none").await;
            let _ = b.wallet.list_keys().await.unwrap();
        }
    }
}
