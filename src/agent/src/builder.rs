//! Agent builder for convenient agent construction

use crate::agent::Agent;
use crate::config::AgentConfigBuilder;
use crate::error::Result;
use agent_core::traits::{BlockchainService, StorageProvider, WalletProvider};
use std::sync::Arc;

/// Registration hook stored per pluggable module: registers the concrete
/// module `Arc<M>` into the DI container so `Agent::module::<M>()` resolves it.
/// Type-erased so the builder can hold a heterogeneous list of modules.
type ContainerRegistrar = Box<dyn FnOnce(&mut agent_di::Container) + Send>;

/// Builder for creating Agent instances with a fluent API
pub struct AgentBuilder {
    config_builder: AgentConfigBuilder,
    storage: Option<Arc<dyn StorageProvider>>,
    wallet_provider: Option<Arc<dyn WalletProvider>>,
    /// Pluggable modules handed via [`AgentBuilder::with_module`], each paired
    /// with a closure that registers its concrete type into the DI container.
    agent_modules: Vec<(Arc<dyn agent_module::AgentModule>, ContainerRegistrar)>,
    blockchain_service: Option<Arc<dyn BlockchainService>>,
    oid4vci_issuer: Option<(
        crate::modules::oid4vci::Oid4vciIssuerConfig,
        Arc<dyn crate::modules::oid4vci::Oid4vciCredentialMinter>,
    )>,
    /// Persist the OID4VCI issuer session store to storage on every mutation.
    /// Off by default: pre-authorized sessions are ephemeral (TTL-bounded), and
    /// snapshotting the whole store per offer/token/credential serializes all
    /// issuance on a single row. Wallet keys + issued credentials persist
    /// regardless. Opt in only if sessions must survive a restart.
    oid4vci_persist_sessions: bool,
    wallet_metadata: Option<crate::modules::oid4vp::WalletMetadata>,
    #[cfg(feature = "anoncreds")]
    anoncreds_registry: Option<Arc<dyn anoncreds_core::AnonCredsRegistry>>,
    /// Whether the AnonCreds holder auto-accepts credential offers (drives the
    /// full DIDComm offer→request→issue→store flow). Set by
    /// [`AgentBuilder::auto_accept_credentials`].
    #[cfg(feature = "anoncreds")]
    anoncreds_auto_accept: bool,
}

impl AgentBuilder {
    /// Create a new AgentBuilder
    pub fn new() -> Self {
        Self {
            config_builder: AgentConfigBuilder::new(),
            storage: None,
            wallet_provider: None,
            agent_modules: Vec::new(),
            blockchain_service: None,
            oid4vci_issuer: None,
            oid4vci_persist_sessions: false,
            wallet_metadata: None,
            #[cfg(feature = "anoncreds")]
            anoncreds_registry: None,
            #[cfg(feature = "anoncreds")]
            anoncreds_auto_accept: false,
        }
    }

    /// Anchor AnonCreds schemas / credential definitions on a caller-provided
    /// registry (VDR) instead of the default in-memory one. Pass e.g.
    /// `registry_kanon::KanonRegistry` (did:kanon on Besu) or a `MultiRegistry`.
    /// The module is wired at `build_and_initialize()` (handlers + event bus).
    #[cfg(feature = "anoncreds")]
    pub fn with_anoncreds_registry(
        mut self,
        registry: Arc<dyn anoncreds_core::AnonCredsRegistry>,
    ) -> Self {
        self.anoncreds_registry = Some(registry);
        self
    }

    /// Enable an OID4VCI issuer on the built Agent. The minter is called
    /// once a credential request has been validated; sessions persist to
    /// the same `StorageProvider` already set on the builder so in-flight
    /// flows survive process restarts.
    ///
    /// # Example
    /// ```ignore
    /// let issuer_config = Oid4vciIssuerConfig::default();
    /// let agent = Agent::builder()
    ///     .storage(storage)
    ///     .wallet_provider(wallet)
    ///     .with_oid4vci_issuer(issuer_config, Arc::new(my_minter))
    ///     .build_and_initialize().await?;
    /// ```
    pub fn with_oid4vci_issuer(
        mut self,
        issuer_config: crate::modules::oid4vci::Oid4vciIssuerConfig,
        minter: Arc<dyn crate::modules::oid4vci::Oid4vciCredentialMinter>,
    ) -> Self {
        self.oid4vci_issuer = Some((issuer_config, minter));
        self
    }

    /// Opt in to persisting the OID4VCI issuer session store across restarts.
    /// Default is ephemeral (see [`Self::oid4vci_persist_sessions`] field docs) —
    /// persisting snapshots per operation serializes concurrent issuance.
    pub fn oid4vci_persist_sessions(mut self, persist: bool) -> Self {
        self.oid4vci_persist_sessions = persist;
        self
    }

    /// Replace the default OID4VP wallet metadata document. The default
    /// (`WalletMetadata::default_for_supported_formats()`) advertises
    /// SD-JWT-VC, mDoc, and AnonCreds. Use this to white-label the wallet
    /// or restrict the formats it accepts.
    pub fn with_wallet_metadata(
        mut self,
        metadata: crate::modules::oid4vp::WalletMetadata,
    ) -> Self {
        self.wallet_metadata = Some(metadata);
        self
    }

    /// Hand a pluggable, self-wiring module to the agent.
    ///
    /// The module is stored both as an `Arc<dyn AgentModule>` (so the agent can
    /// loop it in `initialize`/`shutdown` without naming its concrete type) and
    /// registered into the DI container by its concrete type `M`, so typed
    /// access via [`Agent::module::<M>()`](crate::Agent::module) resolves it.
    ///
    /// Modules are sorted by [`AgentModule::priority`](agent_module::AgentModule::priority)
    /// (descending) at build time, so higher-priority modules register first.
    pub fn with_module<M: agent_module::AgentModule + 'static>(mut self, m: M) -> Self {
        let module: Arc<M> = Arc::new(m);
        let dyn_module: Arc<dyn agent_module::AgentModule> = module.clone();
        let registrar: ContainerRegistrar = Box::new(move |container: &mut agent_di::Container| {
            let module = module.clone();
            container.register_singleton_with_factory::<M, M, _>(move || Ok(module.clone()));
        });
        self.agent_modules.push((dyn_module, registrar));
        self
    }

    /// Compose the standard module set on the builder.
    ///
    /// This is the single assembly point for the default modules a consumer
    /// would want. Each is composed via [`AgentBuilder::with_module`] so the
    /// agent core never names concrete module types. Every module here is
    /// config-only and self-wires from the DI container / `ModuleContext` in its
    /// `register(&ctx)`:
    ///
    /// - [`ConnectionsModule`](crate::modules::ConnectionsModule)
    /// - [`OutOfBandModule`](crate::modules::OutOfBandModule)
    /// - [`CredentialsModule`](crate::modules::CredentialsModule)
    /// - [`WorkflowModule`](crate::modules::WorkflowModule)
    /// - [`BasicMessagesModule`](crate::modules::BasicMessagesModule)
    /// - [`UserProfileModule`](crate::modules::UserProfileModule)
    ///
    /// A bare `Agent::builder().build()` (without this call) yields an agent with
    /// no protocol modules composed — the consumer opts in via this helper or
    /// individual [`with_module`](AgentBuilder::with_module) calls.
    ///
    /// `DidModule` / `WalletModule` are always constructed by the agent (used
    /// mid-`initialize`), and `MediationModule` is composed by the agent when
    /// `config.mediation` is set; none need to be added here.
    pub fn with_default_modules(self) -> Self {
        self.with_module(crate::modules::ConnectionsModule::default())
            .with_module(crate::modules::OutOfBandModule::new_config_only())
            .with_module(crate::modules::CredentialsModule::new(
                crate::modules::CredentialsConfig::default(),
            ))
            .with_module(crate::modules::WorkflowModule::new())
            .with_module(crate::modules::BasicMessagesModule::new())
            .with_module(crate::modules::UserProfileModule::new())
    }

    /// Set the storage provider
    pub fn storage(mut self, storage: Arc<dyn StorageProvider>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set the wallet provider
    pub fn wallet_provider(mut self, wallet_provider: Arc<dyn WalletProvider>) -> Self {
        self.wallet_provider = Some(wallet_provider);
        self
    }

    /// Set the blockchain service (optional)
    ///
    /// Enables blockchain operations (queries, transfers, DID registration).
    ///
    /// # Example
    /// ```ignore
    /// let client = AjnaClient::new(config).await?;
    /// let agent = Agent::builder()
    ///     .storage(storage)
    ///     .wallet_provider(wallet)
    ///     .blockchain_service(Arc::new(client))
    ///     .build()?;
    /// ```
    pub fn blockchain_service(mut self, service: Arc<dyn BlockchainService>) -> Self {
        self.blockchain_service = Some(service);
        self
    }

    /// Set the agent label
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.label(label);
        self
    }

    /// Add an endpoint
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.endpoint(endpoint);
        self
    }

    /// Set all endpoints
    pub fn endpoints(mut self, endpoints: Vec<String>) -> Self {
        self.config_builder = self.config_builder.endpoints(endpoints);
        self
    }

    /// Set invitation URL base
    pub fn invitation_url_base(mut self, url_base: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.invitation_url_base(url_base);
        self
    }

    /// Set storage path
    pub fn storage_path(mut self, path: std::path::PathBuf) -> Self {
        self.config_builder = self.config_builder.storage_path(path);
        self
    }

    /// Set storage key
    pub fn storage_key(mut self, key: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.storage_key(key);
        self
    }

    /// Set wallet ID
    pub fn wallet_id(mut self, id: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.wallet_id(id);
        self
    }

    /// Set wallet key
    pub fn wallet_key(mut self, key: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.wallet_key(key);
        self
    }

    /// Set wallet database URL
    pub fn wallet_db_url(mut self, db_url: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.wallet_db_url(db_url);
        self
    }

    /// Set default DID method
    pub fn did_method(mut self, method: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.did_method(method);
        self
    }

    /// Set auto-accept connections
    pub fn auto_accept_connections(mut self, accept: bool) -> Self {
        self.config_builder = self.config_builder.auto_accept_connections(accept);
        self
    }

    /// Set auto-accept credentials. Also drives AnonCreds holder auto-accept
    /// (offer→request) so the full DIDComm issuance flow proceeds automatically.
    pub fn auto_accept_credentials(mut self, accept: bool) -> Self {
        self.config_builder = self.config_builder.auto_accept_credentials(accept);
        #[cfg(feature = "anoncreds")]
        {
            self.anoncreds_auto_accept = accept;
        }
        self
    }

    /// Set whether to auto-create DID on initialization
    ///
    /// If true (default), creates a DID during agent initialization.
    /// If false, skips DID creation.
    pub fn auto_create_did(mut self, create: bool) -> Self {
        self.config_builder = self.config_builder.auto_create_did(create);
        self
    }

    /// Set log level
    pub fn log_level(mut self, level: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.log_level(level);
        self
    }

    /// Disable logging
    pub fn no_logging(mut self) -> Self {
        self.config_builder = self.config_builder.no_logging();
        self
    }

    /// Set mediation configuration
    ///
    /// Enables coordinate mediation protocol (Aries RFC 0211) for message routing.
    ///
    /// # Example
    /// ```ignore
    /// use agent::modules::MediationConfig;
    ///
    /// let agent = Agent::builder()
    ///     .storage(storage)
    ///     .wallet_provider(wallet)
    ///     .mediation(MediationConfig::recipient())  // Act as mediation recipient
    ///     .build()?;
    /// ```
    pub fn mediation(mut self, config: crate::modules::MediationConfig) -> Self {
        self.config_builder = self.config_builder.mediation(config);
        self
    }

    /// Build the Agent
    ///
    /// This creates the agent but does not initialize it.
    /// Call `agent.initialize()` before using.
    ///
    /// # Panics
    /// Panics if storage or wallet provider are not set.
    /// Use `.storage()` and `.wallet_provider()` to set them.
    pub fn build(self) -> Result<Agent> {
        let config = self.config_builder.build()?;

        let storage = self
            .storage
            .expect("Storage provider must be set. Use .storage() method.");
        let wallet_provider = self
            .wallet_provider
            .expect("Wallet provider must be set. Use .wallet_provider() method.");
        let blockchain_service = self.blockchain_service;

        let mut agent = Agent::new_with_modules(config, storage.clone(), wallet_provider)?;

        // Wire pluggable modules: register each concrete module type into the
        // DI container (so `Agent::module::<M>()` resolves it), then store the
        // dyn-module list on the agent sorted by priority() descending so
        // `initialize()` registers higher-priority modules first.
        if !self.agent_modules.is_empty() {
            // Container providers are shared via Arc<RwLock> internally, so
            // registering through a clone mutates the same map the agent holds.
            let mut container = (*agent.container_ref()).clone();
            // Names the agent already assembled (e.g. from
            // `with_default_modules()` re-declaring `connections`). For those we
            // skip BOTH the container registrar (so we don't clobber the agent's
            // real singleton with a throwaway default) and the lifecycle push
            // (handled again defensively by `add_agent_modules`).
            let existing = agent.agent_module_names();
            let mut dyn_modules: Vec<Arc<dyn agent_module::AgentModule>> =
                Vec::with_capacity(self.agent_modules.len());
            for (dyn_module, registrar) in self.agent_modules {
                if existing.iter().any(|n| n == dyn_module.name()) {
                    tracing::debug!(
                        "[AgentBuilder] module '{}' already assembled by the agent; \
                         skipping duplicate container registration",
                        dyn_module.name()
                    );
                    continue;
                }
                registrar(&mut container);
                dyn_modules.push(dyn_module);
            }
            // Append onto the default module set assembled in
            // `new_with_modules` (the agent re-sorts by priority()).
            agent.add_agent_modules(dyn_modules);
        }

        // Inject blockchain service if provided
        if let Some(service) = blockchain_service {
            agent.set_blockchain_service(service);
        }

        // Optional OID4VCI issuer.
        if let Some((issuer_config, minter)) = self.oid4vci_issuer {
            let issuer = if self.oid4vci_persist_sessions {
                crate::modules::oid4vci::Oid4vciIssuerService::new_with_storage(
                    issuer_config,
                    minter,
                    storage,
                )
            } else {
                // Ephemeral sessions (default): no per-op snapshot write, so
                // concurrent issuance isn't serialized on one storage row.
                crate::modules::oid4vci::Oid4vciIssuerService::new(issuer_config, minter)
            };
            agent.oid4vci_issuer = Some(Arc::new(issuer));
        }

        // Custom wallet metadata override.
        if let Some(metadata) = self.wallet_metadata {
            agent.wallet_metadata = Arc::new(metadata);
        }

        Ok(agent)
    }

    /// Build and initialize the Agent in one step
    #[cfg_attr(not(feature = "anoncreds"), allow(unused_mut))]
    pub async fn build_and_initialize(mut self) -> Result<Agent> {
        #[cfg(feature = "anoncreds")]
        let anoncreds_registry = self.anoncreds_registry.take();
        #[cfg(feature = "anoncreds")]
        let anoncreds_auto_accept = self.anoncreds_auto_accept;

        let mut agent = self.build()?;
        agent.initialize().await?;

        // Wire the AnonCreds module against the injected registry (VDR) after
        // init so handler registration reuses the standard async path.
        #[cfg(feature = "anoncreds")]
        if let Some(registry) = anoncreds_registry {
            let config = crate::modules::AnonCredsConfig {
                auto_accept_offers: anoncreds_auto_accept,
                ..Default::default()
            };
            agent
                .setup_anoncreds_with_registry(config, registry)
                .await?;
        }

        Ok(agent)
    }
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent {
    /// Create a new AgentBuilder
    ///
    /// This is a convenience method for starting the builder pattern.
    ///
    /// # Example
    /// ```rust,no_run
    /// use agent::Agent;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let agent = Agent::builder()
    ///     .label("My Agent")
    ///     .endpoint("http://localhost:8080")
    ///     .build_and_initialize()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> AgentBuilder {
        AgentBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{InMemoryStorage, InMemoryWallet};

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builder() {
        let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
        let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;

        let agent = Agent::builder()
            .storage(storage)
            .wallet_provider(wallet)
            .label("Test Agent")
            .endpoint("channel://test")
            .build()
            .unwrap();

        assert_eq!(agent.label(), "Test Agent");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builder_with_multiple_endpoints() {
        let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
        let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;

        let agent = Agent::builder()
            .storage(storage)
            .wallet_provider(wallet)
            .label("Test Agent")
            .endpoint("channel://test1")
            .endpoint("http://localhost:8080")
            .build()
            .unwrap();

        assert_eq!(agent.endpoints().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builder_with_config() {
        let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
        let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;

        let agent = Agent::builder()
            .storage(storage)
            .wallet_provider(wallet)
            .label("Test Agent")
            .endpoint("channel://test")
            .auto_accept_connections(true)
            .did_method("key")
            .build()
            .unwrap();

        assert!(agent.config.auto_accept_connections);
        assert_eq!(agent.config.did.default_method, "key");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builder_with_oid4vci_issuer() {
        use crate::modules::oid4vci::{
            issuer::Oid4vciIssuerConfig, types::CredentialConfiguration, Oid4vciCredentialMinter,
        };

        struct EchoMinter;
        #[async_trait::async_trait]
        impl Oid4vciCredentialMinter for EchoMinter {
            async fn mint(
                &self,
                _configuration_id: &str,
                _subject_id: Option<&str>,
                _request: &crate::modules::oid4vci::types::CredentialRequest,
            ) -> std::result::Result<serde_json::Value, String> {
                Ok(serde_json::json!({"ok": true}))
            }
        }

        let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
        let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;

        let mut issuer_config = Oid4vciIssuerConfig::default();
        issuer_config.credential_configurations_supported.insert(
            "Test".into(),
            CredentialConfiguration {
                format: "vc+sd-jwt".into(),
                scope: None,
                credential_signing_alg_values_supported: vec!["EdDSA".into()],
                anoncreds: None,
                display: None,
            },
        );

        let agent = Agent::builder()
            .storage(storage)
            .wallet_provider(wallet)
            .label("Test Agent")
            .endpoint("channel://test")
            .with_oid4vci_issuer(issuer_config, Arc::new(EchoMinter))
            .build()
            .unwrap();

        assert!(agent.oid4vci_issuer.is_some(), "issuer must be wired");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builder_with_custom_wallet_metadata() {
        let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
        let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;

        let metadata = crate::modules::oid4vp::WalletMetadata::default_for_supported_formats()
            .with_wallet_name("Custom Branded Wallet");

        let agent = Agent::builder()
            .storage(storage)
            .wallet_provider(wallet)
            .label("Test Agent")
            .endpoint("channel://test")
            .with_wallet_metadata(metadata)
            .build()
            .unwrap();

        assert_eq!(
            agent.wallet_metadata.wallet_name.as_deref(),
            Some("Custom Branded Wallet")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_default_modules_present_on_agent() {
        // With `with_default_modules()`, the standard protocol modules are
        // composed. OID4VCI/OID4VP holder services are always agent-built.
        let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
        let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;
        let agent = Agent::builder()
            .storage(storage)
            .wallet_provider(wallet)
            .label("Test Agent")
            .endpoint("channel://test")
            .with_default_modules()
            .build()
            .unwrap();

        let _: Arc<crate::modules::CredentialsModule> = agent
            .credentials()
            .expect("credentials composed by with_default_modules");
        let _: &Arc<crate::modules::oid4vci::Oid4vciHolderService> = &agent.oid4vci_holder;
        let _: &Arc<crate::modules::oid4vp::Oid4vpHolderService> = &agent.oid4vp_holder;
        assert!(agent.oid4vci_issuer.is_none(), "issuer is opt-in");

        // Default protocol modules composed.
        assert!(
            agent.workflow().is_some(),
            "workflow composed by default set"
        );
        assert!(
            agent.basic_messages().is_some(),
            "basic_messages composed by default set"
        );
        let _: Arc<crate::modules::ConnectionsModule> = agent.connections();
        let _: Arc<crate::modules::OutOfBandModule> = agent.oob();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bare_builder_has_no_protocol_modules() {
        // TRUE zero-default: a bare `build()` (no `with_default_modules`)
        // composes no protocol modules, so their Option accessors are `None`.
        // Core dids/wallet are always built.
        let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
        let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;
        let agent = Agent::builder()
            .storage(storage)
            .wallet_provider(wallet)
            .label("Bare Agent")
            .endpoint("channel://test")
            .build()
            .unwrap();

        assert!(agent.credentials().is_none(), "credentials not composed");
        assert!(agent.workflow().is_none(), "workflow not composed");
        assert!(
            agent.basic_messages().is_none(),
            "basic_messages not composed"
        );
        assert!(
            agent.module::<crate::modules::OutOfBandModule>().is_none(),
            "oob not composed"
        );
        assert!(
            agent
                .module::<crate::modules::ConnectionsModule>()
                .is_none(),
            "connections not composed"
        );

        // dids + wallet are always agent-built (used mid-initialize).
        let _: Arc<crate::modules::DidModule> = agent.dids();
        let _: Arc<crate::modules::WalletModule> = agent.wallet_module();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_selective_module_composition() {
        // Consumers can opt into a subset via individual `with_module` calls.
        let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
        let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;
        let agent = Agent::builder()
            .storage(storage)
            .wallet_provider(wallet)
            .label("Selective Agent")
            .endpoint("channel://test")
            .with_module(crate::modules::WorkflowModule::new())
            .build_and_initialize()
            .await
            .unwrap();

        assert!(agent.workflow().is_some(), "workflow explicitly composed");
        assert!(agent.credentials().is_none(), "credentials not composed");
        assert!(agent.is_initialized().await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_with_default_modules_composes_and_initializes() {
        // Composing the default modules via the builder must still yield a fully
        // working agent: the connections accessor resolves the agent's real
        // module (not the throwaway default), and initialize() succeeds without
        // double-registering the DIDExchange handlers.
        let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
        let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;

        let agent = Agent::builder()
            .storage(storage)
            .wallet_provider(wallet)
            .label("Composed Agent")
            .endpoint("channel://test")
            .with_default_modules()
            .build_and_initialize()
            .await
            .unwrap();

        assert!(agent.is_initialized().await);
        // Accessor still resolves the agent's real connections module.
        let _: Arc<crate::modules::ConnectionsModule> = agent.connections();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_build_and_initialize() {
        let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
        let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;

        let agent = Agent::builder()
            .storage(storage)
            .wallet_provider(wallet)
            .label("Test Agent")
            .endpoint("channel://test")
            .build_and_initialize()
            .await
            .unwrap();

        assert!(agent.is_initialized().await);
    }

    #[cfg(feature = "anoncreds")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_with_anoncreds_registry_wires_module() {
        let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
        let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;
        let registry: Arc<dyn anoncreds_core::AnonCredsRegistry> =
            Arc::new(anoncreds_core::InMemoryRegistry::new());

        let agent = Agent::builder()
            .storage(storage)
            .wallet_provider(wallet)
            .label("t")
            .endpoint("channel://test")
            .with_default_modules()
            .with_anoncreds_registry(registry)
            .build_and_initialize()
            .await
            .unwrap();

        assert!(
            agent.anoncreds().is_some(),
            "with_anoncreds_registry must wire the AnonCreds module"
        );
    }
}
