//! Split from the original monolithic `agent.rs`.

use super::*;

impl Agent {
    /// Get the agent's endpoints
    pub fn endpoints(&self) -> &[String] {
        &self.config.endpoints
    }

    /// Get the DID repository (for storing and retrieving DID documents)
    pub fn did_repository(&self) -> Arc<DidRepository> {
        self.did_repository.clone()
    }

    /// Get the wallet provider (for key operations)
    pub fn wallet_provider(&self) -> Arc<dyn WalletProvider> {
        self.wallet_provider.clone()
    }

    /// Get the storage provider
    pub fn storage(&self) -> Arc<dyn StorageProvider> {
        self.storage.clone()
    }

    /// Get the connection repository for managing peer connections
    pub fn connection_repository(
        &self,
    ) -> Arc<dyn protocol_connections::repository::ConnectionRepositoryTrait> {
        self.connection_repository.clone()
    }

    /// Get the agent's DID (returns None if not initialized)
    pub async fn agent_did(&self) -> Option<String> {
        self.agent_did.read().await.clone()
    }

    /// Clone of the shared `Arc<RwLock<Option<String>>>` holding this
    /// agent's DID. Useful for inbound handlers (e.g. welcome-bundle)
    /// that need to look up the invitee's identity at message time.
    pub fn agent_did_arc(&self) -> Arc<RwLock<Option<String>>> {
        self.agent_did.clone()
    }

    /// Record the mediator's DID + endpoint. Tests / startup hooks call
    /// this once a `MediationGrant` has been processed.
    pub async fn set_mediator_transport(&self, mediator_did: &str, mediator_endpoint: &str) {
        *self.mediator_did_cell.write().await = Some(mediator_did.to_string());
        *self.mediator_endpoint_cell.write().await = Some(mediator_endpoint.to_string());
    }

    /// Get the agent's wallet key ID (returns None if not initialized)
    pub async fn agent_key_id(&self) -> Option<String> {
        self.agent_key_id.read().await.clone()
    }

    /// Set the agent's DID
    ///
    /// This allows external code (like validator server) to update the agent's DID
    /// to a different identity (e.g., Sanskrit SID format for validators).
    ///
    /// NOTE: If you're updating to a different identity, you should also call
    /// `set_agent_key_id()` to update the key ID mapping, or use `set_agent_identity()`
    /// which sets both at once.
    pub async fn set_agent_did(&self, did: String) {
        *self.agent_did.write().await = Some(did);
    }

    /// Get the connection ready notify (fires when any connection response is processed)
    pub fn connection_ready_notify(&self) -> Arc<Notify> {
        self.connection_ready_notify.clone()
    }

    /// Get the grant notify (fires when a mediation grant is processed)
    pub fn grant_notify(&self) -> Arc<Notify> {
        self.grant_notify.clone()
    }

    /// Set the agent's key ID (wallet key reference)
    ///
    /// This allows external code (like validator server) to update the agent's key ID
    /// after switching to a different identity. The key ID must correspond to a key
    /// that exists in the wallet provider.
    pub async fn set_agent_key_id(&self, key_id: String) {
        *self.agent_key_id.write().await = Some(key_id);
    }

    /// Set both the agent's DID and key ID atomically
    ///
    /// Use this when switching the agent to a different identity (e.g., validator identity).
    /// This ensures both the DID and key ID are updated together, which is required for
    /// message encryption/decryption to work correctly.
    ///
    /// # Arguments
    /// * `did` - The new DID (e.g., did:ajna:...)
    /// * `key_id` - The wallet key ID that corresponds to this DID's signing key
    pub async fn set_agent_identity(&self, did: String, key_id: String) {
        *self.agent_did.write().await = Some(did);
        *self.agent_key_id.write().await = Some(key_id);
    }

    /// Set up AnonCreds over DIDComm.
    ///
    /// Wires the holder/issuer services to the agent's storage and
    /// registers all six issue-credential v3 + present-proof handlers
    /// (`offer-credential`, `request-credential`, `issue-credential`,
    /// `request-presentation`, `presentation`, `ack`) so inbound
    /// DIDComm messages are routed correctly.
    ///
    /// Idempotent — calling twice returns the existing module.
    #[cfg(feature = "anoncreds")]
    pub async fn setup_anoncreds(
        &mut self,
        config: crate::modules::AnonCredsConfig,
    ) -> Result<Arc<crate::modules::AnonCredsModule>> {
        // Default to an in-memory registry. Callers that anchor schemas /
        // cred-defs on a real VDR (e.g. did:kanon Besu via `registry_kanon`)
        // should use `setup_anoncreds_with_registry`.
        let registry: Arc<dyn anoncreds_core::AnonCredsRegistry> =
            Arc::new(anoncreds_core::InMemoryRegistry::new());
        self.setup_anoncreds_with_registry(config, registry).await
    }

    /// Set up the AnonCreds module against a caller-provided registry (VDR).
    ///
    /// Same as [`setup_anoncreds`] but lets the caller inject the AnonCreds
    /// registry — e.g. `registry_kanon::KanonRegistry` (did:kanon on Besu) or
    /// a `MultiRegistry`. Wires the agent event bus so credential/proof
    /// exchange state changes emit events (webhook source), and registers the
    /// six Issue-Credential / Present-Proof DIDComm handlers.
    #[cfg(feature = "anoncreds")]
    pub async fn setup_anoncreds_with_registry(
        &mut self,
        config: crate::modules::AnonCredsConfig,
        registry: Arc<dyn anoncreds_core::AnonCredsRegistry>,
    ) -> Result<Arc<crate::modules::AnonCredsModule>> {
        if let Some(existing) = &self.anoncreds {
            return Ok(existing.clone());
        }
        let module = crate::modules::AnonCredsModule::with_storage_and_events(
            config,
            registry,
            self.storage.clone(),
            Some((self.events.clone(), self.label())),
        );

        // Register the six DIDComm handlers.
        let handlers = module.create_handlers();
        let mut registry_lock = self.handler_registry.write().await;
        for handler in handlers {
            registry_lock.register(handler);
        }
        drop(registry_lock);

        let module = Arc::new(module);
        self.anoncreds = Some(module.clone());

        // Wire credential workflow actions now that the exchange services +
        // sender exist: a workflow step can issue a credential (offer) or
        // request a proof, sent over the step's connection.
        let workflow = self
            .workflow()
            .expect("workflow module required for AnonCreds workflow actions");
        workflow.register_action(Arc::new(
            crate::modules::workflow_actions::IssueCredentialAction {
                cred_exchange: module.credential_exchange_service(),
                connections: (*self.connections()).clone(),
                sender: self.didcomm_sender.clone(),
                request_handler: module.request_handler(),
            },
        ));
        workflow.register_action(Arc::new(
            crate::modules::workflow_actions::PresentProofAction {
                proof_exchange: module.proof_exchange_service(),
                connections: (*self.connections()).clone(),
                sender: self.didcomm_sender.clone(),
            },
        ));

        tracing::info!("AnonCreds module initialized (handlers + workflow actions registered)");
        Ok(module)
    }

    /// Get the AnonCreds module if initialized
    #[cfg(feature = "anoncreds")]
    pub fn anoncreds(&self) -> Option<&crate::modules::AnonCredsModule> {
        self.anoncreds.as_ref().map(|m| m.as_ref())
    }

    /// Set the blockchain service for chain operations
    ///
    /// This allows injecting an external blockchain client (e.g., AjnaClient)
    /// to enable blockchain operations like transfers, DID registration, etc.
    ///
    /// # Arguments
    /// * `service` - The blockchain service to use
    ///
    /// # Example
    /// ```ignore
    /// let client = AjnaClient::new(config).await?;
    /// agent.set_blockchain_service(Arc::new(client));
    /// ```
    pub fn set_blockchain_service(&mut self, service: Arc<dyn BlockchainService>) {
        self.oob().set_blockchain_service(service.clone());
        self.blockchain_service = Some(service);
    }

    /// Get the blockchain service if available
    ///
    /// Returns the injected blockchain service, or None if not configured.
    pub fn blockchain_service(&self) -> Option<Arc<dyn BlockchainService>> {
        self.blockchain_service.clone()
    }

    /// Check if blockchain service is available
    pub fn has_blockchain_service(&self) -> bool {
        self.blockchain_service.is_some()
    }

    /// Get wallet provider with Askar-specific methods
    pub fn wallet(&self) -> Result<&Arc<dyn WalletProvider>> {
        Ok(&self.wallet_provider)
    }

    /// Get the DID resolver (for advanced configuration)
    pub fn did_resolver(&self) -> Option<Arc<AgentDIDResolver>> {
        self.did_resolver.clone()
    }

    // =========================================================================
    // Module accessors (dependency-injection container)
    //
    // Core modules are always registered, so their accessors resolve
    // infallibly. Optional modules return `Option` — `None` when the module
    // was not composed onto the builder (e.g. no `with_default_modules()` /
    // `with_module(...)`).
    // =========================================================================

    /// Connections module (core, always present).
    pub fn connections(&self) -> Arc<crate::modules::ConnectionsModule> {
        self.container
            .resolve()
            .expect("connections module always registered")
    }

    /// Out-of-Band module (core, always present).
    pub fn oob(&self) -> Arc<crate::modules::OutOfBandModule> {
        self.container
            .resolve()
            .expect("oob module always registered")
    }

    /// DID module (core, always present).
    pub fn dids(&self) -> Arc<crate::modules::DidModule> {
        self.container
            .resolve()
            .expect("dids module always registered")
    }

    /// Wallet module (core, always present).
    ///
    /// Named `wallet_module` (not `wallet`) to avoid colliding with the
    /// pre-existing [`Agent::wallet`] accessor, which returns the wallet
    /// *provider* trait object and has external callers.
    pub fn wallet_module(&self) -> Arc<crate::modules::WalletModule> {
        self.container
            .resolve()
            .expect("wallet module always registered")
    }

    /// Credentials module (optional). `None` if disabled at build time.
    pub fn credentials(&self) -> Option<Arc<crate::modules::CredentialsModule>> {
        self.container.try_resolve()
    }

    /// Workflow module (optional). `None` if disabled at build time.
    pub fn workflow(&self) -> Option<Arc<crate::modules::WorkflowModule>> {
        self.container.try_resolve()
    }

    /// Basic-messages module (optional). `None` if disabled at build time.
    pub fn basic_messages(&self) -> Option<Arc<crate::modules::BasicMessagesModule>> {
        self.container.try_resolve()
    }

    // =========================================================================
    // Pluggable module system (agent_module crate)
    // =========================================================================

    /// Typed access to a pluggable module by concrete type.
    ///
    /// Returns the `Arc<M>` that was registered via
    /// [`AgentBuilder::with_module`](crate::AgentBuilder::with_module), or
    /// `None` if no module of that type was registered. Backed by the DI
    /// container's `try_resolve::<M>()`.
    ///
    /// Ergonomic per-module accessors are provided by extension traits (e.g.
    /// [`crate::ConnectionsExt`]) which delegate here.
    pub fn module<M: agent_module::AgentModule + Send + Sync + 'static>(&self) -> Option<Arc<M>> {
        self.container.try_resolve::<M>()
    }

    /// Internal: clone of the DI container Arc, used by the builder to register
    /// pluggable modules into the same shared provider map.
    pub(crate) fn container_ref(&self) -> Arc<agent_di::Container> {
        self.container.clone()
    }

    /// Internal: names of the pluggable modules currently assembled on the
    /// agent. Used by the builder to avoid clobbering the agent's own module
    /// registrations when a convenience helper re-declares a default module.
    pub(crate) fn agent_module_names(&self) -> Vec<String> {
        self.agent_modules
            .iter()
            .map(|m| m.name().to_string())
            .collect()
    }

    /// Internal: append builder-provided pluggable modules onto the default set
    /// assembled in `new_with_modules`, then re-sort by priority() descending.
    /// Called by the builder after container registration.
    ///
    /// Modules whose `name()` already appears in the current set are skipped, so
    /// convenience helpers like [`AgentBuilder::with_default_modules`] that
    /// re-declare a module the agent already assembled (e.g. `connections`) do
    /// not double-register its DIDComm handlers.
    pub(crate) fn add_agent_modules(&mut self, modules: Vec<Arc<dyn agent_module::AgentModule>>) {
        for module in modules {
            let name = module.name().to_string();
            if self.agent_modules.iter().any(|m| m.name() == name) {
                tracing::debug!(
                    "[Agent] module '{}' already assembled; skipping duplicate from builder",
                    name
                );
                continue;
            }
            self.agent_modules.push(module);
        }
        self.agent_modules
            .sort_by_key(|m| std::cmp::Reverse(m.priority()));
    }
}
