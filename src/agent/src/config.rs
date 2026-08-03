//! Agent configuration

use crate::error::{AgentError, Result};
use crate::modules::MediationConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Configuration for an Agent instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Human-readable label for this agent.
    ///
    /// Snapshot taken at agent construction. Use `current_label()` to read
    /// the effective label — that returns the runtime override (set via
    /// `Agent::set_label`) when present and falls back to this static value
    /// otherwise. Direct reads of this field skip the runtime override.
    pub label: String,

    /// Runtime override for `label`, shared across all modules that
    /// clone this `AgentConfig`. Lets the FFI caller swap the label
    /// after `Agent::initialize` — needed because the iOS shell builds
    /// the bridge before FRE finishes, so `label` is initialised to
    /// "Ajna" and the user's actual display-name only arrives later.
    /// Without this, every outgoing connection-request keeps shipping
    /// the pre-FRE placeholder label.
    #[serde(skip, default = "default_runtime_label")]
    pub runtime_label: Arc<RwLock<Option<String>>>,

    /// Endpoints where this agent can receive messages
    pub endpoints: Vec<String>,

    /// Base URL for generating OOB invitation URLs (e.g., "https://example.com")
    pub invitation_url_base: String,

    /// Storage configuration
    pub storage: StorageConfig,

    /// Wallet configuration
    pub wallet: WalletConfig,

    /// DID configuration
    pub did: DidConfig,

    /// Whether to auto-accept connections
    pub auto_accept_connections: bool,

    /// Whether to auto-accept credentials
    pub auto_accept_credentials: bool,

    /// Logger configuration
    pub logger: Option<LoggerConfig>,

    /// Mediation configuration (optional)
    pub mediation: Option<MediationConfig>,
}

fn default_runtime_label() -> Arc<RwLock<Option<String>>> {
    Arc::new(RwLock::new(None))
}

impl AgentConfig {
    /// Effective label — runtime override (set via `Agent::set_label`)
    /// when present, otherwise the static `label` snapshot.
    pub fn current_label(&self) -> String {
        if let Ok(guard) = self.runtime_label.read() {
            if let Some(ref l) = *guard {
                return l.clone();
            }
        }
        self.label.clone()
    }

    /// Write the runtime label override. All modules cloned from this
    /// config share the same Arc, so the new value is visible everywhere
    /// without re-initialising them.
    pub fn set_runtime_label(&self, label: String) {
        if let Ok(mut guard) = self.runtime_label.write() {
            *guard = Some(label);
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage type (currently only "askar" is supported)
    pub storage_type: String,

    /// Storage path or connection string
    pub path: PathBuf,

    /// Storage key for encryption
    pub key: String,
}

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Wallet ID
    pub id: String,

    /// Wallet key for encryption
    pub key: String,

    /// Database URL for Askar wallet
    /// Use "sqlite://:memory:" for in-memory (default)
    /// Use "sqlite://./path/to/db.db" for file-based storage
    pub db_url: Option<String>,
}

/// DID configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidConfig {
    /// Default DID method to use (e.g., "key", "peer", "web")
    pub default_method: String,

    /// Automatic DID creation on initialization
    pub auto_create_did: bool,
}

/// Logger configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,

    /// Log format (json, pretty)
    pub format: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            label: "Agent".to_string(),
            runtime_label: default_runtime_label(),
            endpoints: vec![],
            invitation_url_base: "https://example.org".to_string(),
            storage: StorageConfig::default(),
            wallet: WalletConfig::default(),
            did: DidConfig::default(),
            auto_accept_connections: false,
            auto_accept_credentials: false,
            logger: Some(LoggerConfig::default()),
            mediation: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_type: "askar".to_string(),
            path: PathBuf::from("./storage.db"),
            key: uuid::Uuid::new_v4().to_string(),
        }
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            key: uuid::Uuid::new_v4().to_string(),
            db_url: None, // Defaults to in-memory
        }
    }
}

impl Default for DidConfig {
    fn default() -> Self {
        Self {
            default_method: "key".to_string(),
            auto_create_did: true,
        }
    }
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
        }
    }
}

/// Builder for AgentConfig
pub struct AgentConfigBuilder {
    config: AgentConfig,
}

impl AgentConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: AgentConfig::default(),
        }
    }

    /// Set the agent label
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.config.label = label.into();
        self
    }

    /// Add an endpoint
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.config.endpoints.push(endpoint.into());
        self
    }

    /// Set all endpoints
    pub fn endpoints(mut self, endpoints: Vec<String>) -> Self {
        self.config.endpoints = endpoints;
        self
    }

    /// Set invitation URL base
    pub fn invitation_url_base(mut self, url_base: impl Into<String>) -> Self {
        self.config.invitation_url_base = url_base.into();
        self
    }

    /// Set storage path
    pub fn storage_path(mut self, path: PathBuf) -> Self {
        self.config.storage.path = path;
        self
    }

    /// Set storage key
    pub fn storage_key(mut self, key: impl Into<String>) -> Self {
        self.config.storage.key = key.into();
        self
    }

    /// Set wallet ID
    pub fn wallet_id(mut self, id: impl Into<String>) -> Self {
        self.config.wallet.id = id.into();
        self
    }

    /// Set wallet key
    pub fn wallet_key(mut self, key: impl Into<String>) -> Self {
        self.config.wallet.key = key.into();
        self
    }

    /// Set wallet database URL
    pub fn wallet_db_url(mut self, db_url: impl Into<String>) -> Self {
        self.config.wallet.db_url = Some(db_url.into());
        self
    }

    /// Set default DID method
    pub fn did_method(mut self, method: impl Into<String>) -> Self {
        self.config.did.default_method = method.into();
        self
    }

    /// Set whether to auto-create DID on initialization
    ///
    /// If true (default), creates a DID during agent initialization.
    /// If false, skips DID creation.
    pub fn auto_create_did(mut self, create: bool) -> Self {
        self.config.did.auto_create_did = create;
        self
    }

    /// Set auto-accept connections
    pub fn auto_accept_connections(mut self, accept: bool) -> Self {
        self.config.auto_accept_connections = accept;
        self
    }

    /// Set auto-accept credentials
    pub fn auto_accept_credentials(mut self, accept: bool) -> Self {
        self.config.auto_accept_credentials = accept;
        self
    }

    /// Set log level
    pub fn log_level(mut self, level: impl Into<String>) -> Self {
        if let Some(ref mut logger) = self.config.logger {
            logger.level = level.into();
        }
        self
    }

    /// Disable logging
    pub fn no_logging(mut self) -> Self {
        self.config.logger = None;
        self
    }

    /// Set mediation configuration
    pub fn mediation(mut self, config: MediationConfig) -> Self {
        self.config.mediation = Some(config);
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<AgentConfig> {
        self.validate()?;
        Ok(self.config)
    }

    /// Validate the configuration
    fn validate(&self) -> Result<()> {
        if self.config.label.is_empty() {
            return Err(AgentError::Configuration(
                "Agent label cannot be empty".to_string(),
            ));
        }

        // Validate endpoints are valid URLs
        for endpoint in &self.config.endpoints {
            if !endpoint.starts_with("http://")
                && !endpoint.starts_with("https://")
                && !endpoint.starts_with("ws://")
                && !endpoint.starts_with("wss://")
                && !endpoint.starts_with("channel://")
                && !endpoint.starts_with("mesh://")
            {
                return Err(AgentError::Configuration(format!(
                    "Invalid endpoint URL: {}",
                    endpoint
                )));
            }
        }

        if self.config.storage.key.is_empty() {
            return Err(AgentError::Configuration(
                "Storage key cannot be empty".to_string(),
            ));
        }

        if self.config.wallet.key.is_empty() {
            return Err(AgentError::Configuration(
                "Wallet key cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for AgentConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
