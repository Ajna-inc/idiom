//! Split from the original monolithic `agent.rs`.

use super::*;

impl Agent {
    /// Create a new Agent with the given configuration and dependencies
    ///
    /// # Arguments
    /// * `config` - Agent configuration
    /// * `storage` - Storage provider for persisting records
    /// * `wallet_provider` - Wallet provider for key management
    ///
    /// Note: This does not initialize the agent. Call `initialize()` after creation.
    pub fn new(
        config: AgentConfig,
        storage: Arc<dyn StorageProvider>,
        wallet_provider: Arc<dyn WalletProvider>,
    ) -> Result<Self> {
        // Zero-default: constructs NO protocol modules. Compose them via the
        // builder (`Agent::builder().with_default_modules()`).
        Self::new_with_modules(config, storage, wallet_provider)
    }

    /// Create a new Agent that constructs **zero** protocol modules.
    ///
    /// All protocol modules (connections, oob, credentials, workflow,
    /// basic-messages, user-profile) are composed by the consumer via
    /// the builder ([`AgentBuilder::with_default_modules`] /
    /// [`AgentBuilder::with_module`]). `DidModule` / `WalletModule` are the only
    /// modules built here (used mid-`initialize`), and `MediationModule` is
    /// built when `config.mediation` is set.
    pub fn new_with_modules(
        config: AgentConfig,
        storage: Arc<dyn StorageProvider>,
        wallet_provider: Arc<dyn WalletProvider>,
    ) -> Result<Self> {
        // Convert our AgentConfig to agent_core::AgentConfig
        let core_config = agent_core::context::AgentConfig {
            label: config.label.clone(),
            endpoints: config.endpoints.clone(),
            inbound_host: None,
            inbound_port: None,
            mediator_invitation_url: None,
            auto_accept_connections: config.auto_accept_connections,
            auto_accept_credentials: config.auto_accept_credentials,
            extra: Default::default(),
        };

        // Create context
        let context = Arc::new(AgentContext::new(core_config));

        // Create event bus (with capacity of 1000 events)
        let events = Arc::new(EventBus::new(1000));

        // Create repositories
        // OOB repository uses in-memory storage (invitations are short-lived)
        let oob_repository = Arc::new(OutOfBandRepository::new());

        // Connection repository with storage persistence
        let connection_repository =
            Arc::new(protocol_connections::StorageBackedConnectionRepository::new(storage.clone()));

        // Create DID repository (in-memory cache, backed by storage in DidRegistry)
        let did_repository = Arc::new(DidRepository::new());

        // Create DID registry with BOTH DID repository (cache) AND storage (persistence)
        // This enables DIDs to persist across restarts
        let mut did_registry =
            DidRegistry::with_did_repository_and_storage(did_repository.clone(), storage.clone());

        // Set up DID persistence: create channel and background task
        let (persist_tx, mut persist_rx) =
            tokio::sync::mpsc::unbounded_channel::<did::core::DidRecord>();
        did_repository.set_persist_sender(persist_tx);

        // Clone storage for the background persistence task
        let persistence_storage = storage.clone();
        tokio::spawn(async move {
            use agent_core::traits::Record;
            while let Some(record) = persist_rx.recv().await {
                // Persist the DID record to storage
                let value = match serde_json::to_vec(&record) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("[DID-PERSIST] Failed to serialize DID record: {}", e);
                        continue;
                    }
                };

                let storage_record = Record::new("DidRecord", &record.id, value)
                    .add_tag("did", &record.did)
                    .add_tag("role", format!("{:?}", record.role));

                if let Err(e) = persistence_storage.save(&storage_record).await {
                    tracing::debug!(
                        "[DID-PERSIST] Failed to persist DID record {}: {}",
                        record.did,
                        e
                    );
                } else {
                    tracing::debug!("[DID-PERSIST] ✓ Persisted DID record: {}", record.did);
                }
            }
        });

        // Register DID method resolvers BEFORE sharing the registry
        // This ensures all Arc clones will have the resolvers registered
        did_registry.register_resolver(Arc::new(did::methods::KeyDidResolver::new()));
        did_registry.register_resolver(Arc::new(did::methods::PeerDidResolver::new(
            did_repository.clone(),
        )));

        let did_registry = Arc::new(did_registry);

        // Create DID document service for DID resolution
        let did_document_service = Arc::new(didcomm::messaging::DidCommDocumentService::new(
            did_registry.clone(),
        ));

        // Create Notify instances for event-driven wakeups (replaces polling loops)
        let connection_ready_notify = Arc::new(Notify::new());
        let grant_notify = Arc::new(Notify::new());

        // Create connection service with event bus and connection notify
        let agent_id = config.label.clone();
        let connection_service =
            protocol_connections::ConnectionService::new(connection_repository.clone())
                .with_connection_notify(connection_ready_notify.clone())
                .with_event_bus(events.clone(), agent_id.clone());

        // Create OOB API (registered into the container for the self-wiring OOB
        // module). The ConnectionsModule is composed via the builder and swaps
        // in this `connection_service` (event bus + notify) from the container.
        let oob_api = Arc::new(protocol_oob::OutOfBandApi::new(oob_repository.clone()));
        let connection_service = Arc::new(connection_service);
        let dids = Arc::new(DidModule::new_with_dependencies(
            did_registry.clone(),
            wallet_provider.clone(),
            did_repository.clone(),
        ));
        let wallet = Arc::new(WalletModule::new_with_provider(wallet_provider.clone()));

        // Create transport manager
        let transport = TransportManager::new();

        // Create dispatcher
        let dispatcher = MessageDispatcher::new(Arc::new(transport.clone()));

        // Create handler registry (empty - handlers registered during initialize)
        let handler_registry = Arc::new(RwLock::new(didcomm::messaging::HandlerRegistry::new()));

        // Create agent DID and key ID holders (initialized during initialize())
        let agent_did = Arc::new(RwLock::new(None));
        let agent_key_id = Arc::new(RwLock::new(None));

        // Shared mediation cells, hoisted so they can be both stored on the
        // agent AND registered into the DI container (behind newtype wrappers)
        // for the self-wiring Connections handlers.
        let registered_mediation_key: Arc<std::sync::RwLock<Option<String>>> =
            Arc::new(std::sync::RwLock::new(None));
        let mediation_routing_keys: Arc<std::sync::RwLock<Option<Vec<String>>>> =
            Arc::new(std::sync::RwLock::new(None));
        let pending_key_registrations: Arc<std::sync::RwLock<Vec<String>>> =
            Arc::new(std::sync::RwLock::new(Vec::new()));

        // Create message processor
        let message_processor = Arc::new(MessageProcessor::new(
            handler_registry.clone(),
            connection_repository.clone(),
            did_repository.clone(),
            wallet_provider.clone(),
            did_document_service.clone(),
            agent_did.clone(),
            agent_key_id.clone(),
        ));

        // Create message encryption service
        let message_encryption = Arc::new(MessageEncryption::new(
            wallet_provider.clone(),
            did_document_service.clone(),
            did_repository.clone(),
            agent_did.clone(),
            agent_key_id.clone(),
        ));

        let transport_arc = Arc::new(transport);

        // Canonical DIDComm sender — modules route outbound traffic through
        // this single instance instead of re-implementing
        // resolve/pack/forward/POST per-module.
        let didcomm_sender = Arc::new(crate::messaging::DidCommSender::new(
            transport_arc.clone(),
            message_encryption.clone(),
            did_repository.clone(),
        ));

        // Create message router for routing messages to handlers
        let message_router = Arc::new(MessageRouter::new(
            handler_registry.clone(),
            transport_arc.clone(),
            config.clone(),
        ));

        // OOB module is composed via the builder (`with_default_modules`) and
        // self-wires from the DI container in its `register`. Its low-level
        // `OutOfBandApi` is registered into the container below.

        // User profile service — storage-backed for persistence across restarts.
        // Emits profile.peer_updated / profile.own_updated on the agent event bus.
        // Kept agent-built (a *service*, not a module) and registered into the DI
        // container so the self-wiring UserProfileModule resolves it and the
        // agent's own profile APIs share the same instance.
        let profile_repo: Arc<dyn protocol_user_profile::UserProfileRepositoryTrait> = Arc::new(
            protocol_user_profile::StorageBackedUserProfileRepository::new(storage.clone()),
        );
        let profile_service = Arc::new(protocol_user_profile::UserProfileService::new(
            profile_repo,
            events.clone(),
            agent_id.clone(),
        ));

        let mediator_did_cell = Arc::new(RwLock::new(None::<String>));
        let mediator_endpoint_cell = Arc::new(RwLock::new(None::<String>));

        // OID4VCI holder — stateless transport-level service for wallets
        // receiving credentials from external OID4VC issuers.
        let oid4vci_holder = Arc::new(
            crate::modules::oid4vci::Oid4vciHolderService::new()
                .map_err(|e| AgentError::Module(format!("oid4vci holder init: {}", e)))?,
        );

        // OID4VP holder — stateless transport-level service for presenting
        // credentials to OID4VC verifiers.
        let oid4vp_holder = Arc::new(
            crate::modules::oid4vp::Oid4vpHolderService::new()
                .map_err(|e| AgentError::Module(format!("oid4vp holder init: {}", e)))?,
        );

        // Default wallet metadata advertised to OID4VP verifiers. Callers
        // can replace it via `Agent::set_wallet_metadata` if they want
        // to white-label the wallet name / logo / supported formats.
        let wallet_metadata =
            Arc::new(crate::modules::oid4vp::WalletMetadata::default_for_supported_formats());

        // OID4VP verifier — request creation + vp_token verification, with
        // sessions in the agent's own storage and DID-resolved signatures.
        let oid4vp_verifier = Arc::new(crate::modules::oid4vp::Oid4vpVerifierService::new(
            storage.clone(),
            wallet_provider.clone(),
            did_registry.clone(),
            Some(events.clone()),
            agent_id.clone(),
        ));

        // Create mediation module if configured
        // Use storage-backed repository for persistent mediation records across restarts
        let mediation = if let Some(mediation_config) = &config.mediation {
            tracing::info!("🔧 [Agent::new] Creating mediation module with persistent storage...");
            match MediationModule::with_storage_and_notify(
                mediation_config.clone(),
                storage.clone(),
                grant_notify.clone(),
            ) {
                Ok(module) => {
                    tracing::info!(
                        "✓ [Agent::new] Mediation module created with storage-backed repository"
                    );
                    Some(Arc::new(module))
                }
                Err(e) => {
                    tracing::info!("⚠ [Agent::new] Failed to create mediation module: {}", e);
                    return Err(e);
                }
            }
        } else {
            None
        };

        // Push notifications module is wallet-side and only useful when
        // there's a mediator to send `set-device-info` to. We still build
        // it eagerly so callers can `agent.push_notifications.set_device_token(...)`
        // without an explicit feature toggle — the method itself errors if
        // mediation isn't yet granted.
        let push_notifications = mediation.as_ref().map(|m| {
            Arc::new(crate::modules::PushNotificationsModule::new(
                connection_repository.clone(),
                m.repository(),
                didcomm_sender.clone(),
            ))
        });

        // The workflow module is composed via the builder and self-wires its
        // service (with the event bus) from the DI container in `register`.

        // Build the dependency-injection container and register the agent's
        // modules as pre-built singletons. Registering via a factory that
        // returns the existing Arc means the container hands back the same
        // instance (no re-construction, no extra Clone bound on the module
        // types). Modules are resolved through the accessor methods on
        // `Agent` (see `accessors.rs`).
        let mut container = agent_di::Container::new();

        // ---------------------------------------------------------------------
        // Shared resources for self-wiring modules.
        //
        // Register the agent-internal cells (behind newtype wrappers so distinct
        // resources don't collide by TypeId) and the repositories that
        // self-wiring modules (Connections, Mediation) resolve from
        // `ctx.container` in their `register(&ctx)`. Registered as pre-built
        // singletons via a factory that returns the existing value.
        // ---------------------------------------------------------------------
        {
            use crate::module_runtime::{
                AgentDidCell, ConnectionRepositoryResource, MediationRoutingKeys,
                PendingKeyRegistrations, RegisteredMediationKey,
            };
            let v = AgentDidCell(agent_did.clone());
            container.register_singleton_with_factory::<AgentDidCell, AgentDidCell, _>(move || {
                Ok(Arc::new(v.clone()))
            });
            let v = RegisteredMediationKey(registered_mediation_key.clone());
            container
                .register_singleton_with_factory::<RegisteredMediationKey, RegisteredMediationKey, _>(
                    move || Ok(Arc::new(v.clone())),
                );
            let v = MediationRoutingKeys(mediation_routing_keys.clone());
            container
                .register_singleton_with_factory::<MediationRoutingKeys, MediationRoutingKeys, _>(
                    move || Ok(Arc::new(v.clone())),
                );
            let v = PendingKeyRegistrations(pending_key_registrations.clone());
            container
                .register_singleton_with_factory::<PendingKeyRegistrations, PendingKeyRegistrations, _>(
                    move || Ok(Arc::new(v.clone())),
                );
            let v = ConnectionRepositoryResource(
                connection_repository.clone() as Arc<dyn ConnectionRepositoryTrait>
            );
            container
                .register_singleton_with_factory::<ConnectionRepositoryResource, ConnectionRepositoryResource, _>(
                    move || Ok(Arc::new(v.clone())),
                );
        }
        // The agent's fully-configured ConnectionService (event bus + notify),
        // resolved by ConnectionsModule::register for its DIDExchange handlers.
        {
            let v = connection_service.clone();
            container
                .register_singleton_with_factory::<protocol_connections::ConnectionService, protocol_connections::ConnectionService, _>(
                    move || Ok(v.clone()),
                );
        }
        // Repositories resolved by self-wiring modules.
        {
            let v = oob_repository.clone();
            container
                .register_singleton_with_factory::<OutOfBandRepository, OutOfBandRepository, _>(
                    move || Ok(v.clone()),
                );
            let v = did_repository.clone();
            container.register_singleton_with_factory::<DidRepository, DidRepository, _>(
                move || Ok(v.clone()),
            );
            let v = did_registry.clone();
            container.register_singleton_with_factory::<DidRegistry, DidRegistry, _>(move || {
                Ok(v.clone())
            });
        }

        // ---------------------------------------------------------------------
        // Shared *services* (not modules) resolved by the self-wiring protocol
        // modules in their `register(&ctx)`. These stay agent-built because they
        // are wired from the agent's repositories / event bus / transport, but
        // are registered here so modules (OOB, credentials, workflow, basic
        // messages, user-profile) can construct their protocol
        // services lazily against them — keeping `new_with_modules` free of any
        // concrete *module* construction.
        // ---------------------------------------------------------------------
        {
            // Agent config snapshot (OOB module reads label/endpoints/etc.).
            let v = config.clone();
            container.register_singleton_with_factory::<AgentConfig, AgentConfig, _>(move || {
                Ok(Arc::new(v.clone()))
            });
            // Low-level OOB API over the in-memory OOB repository.
            let oob_api_clone = oob_api.clone();
            container.register_singleton_with_factory::<protocol_oob::OutOfBandApi, protocol_oob::OutOfBandApi, _>(
                move || Ok(oob_api_clone.clone()),
            );
            // Canonical DIDComm sender.
            let v = didcomm_sender.clone();
            container.register_singleton_with_factory::<crate::messaging::DidCommSender, crate::messaging::DidCommSender, _>(
                move || Ok(v.clone()),
            );
            // Message encryption service.
            let v = message_encryption.clone();
            container.register_singleton_with_factory::<MessageEncryption, MessageEncryption, _>(
                move || Ok(v.clone()),
            );
            // Message processor (OOB inbound handling).
            let v = message_processor.clone();
            container.register_singleton_with_factory::<MessageProcessor, MessageProcessor, _>(
                move || Ok(v.clone()),
            );
            // Transport manager (Arc, for mesh fast paths + OOB transport use).
            let v = transport_arc.clone();
            container.register_singleton_with_factory::<TransportManager, TransportManager, _>(
                move || Ok(v.clone()),
            );
            // User-profile service (storage-backed, shared with Agent APIs).
            let v = profile_service.clone();
            container.register_singleton_with_factory::<protocol_user_profile::UserProfileService, protocol_user_profile::UserProfileService, _>(
                move || Ok(v.clone()),
            );
        }

        // DidModule + WalletModule are constructed here and registered into the
        // container. These are documented exceptions to zero-default: DidModule's
        // `manager()` is used mid-`initialize()` (agent DID creation) BEFORE the
        // pluggable module register loop runs, and OOB's `set_envelope_service`
        // is likewise called mid-init, so these must be fully wired at
        // construction time rather than lazily in `register`.
        {
            let dids = dids.clone();
            container.register_singleton_with_factory::<DidModule, DidModule, _>(move || {
                Ok(dids.clone())
            });
        }
        {
            let wallet = wallet.clone();
            container.register_singleton_with_factory::<WalletModule, WalletModule, _>(move || {
                Ok(wallet.clone())
            });
        }

        // ---------------------------------------------------------------------
        // Zero-default module assembly.
        //
        // `new_with_modules` constructs NO protocol modules. Every module
        // (connections, oob, credentials, workflow, basic-messages,
        // user-profile, dids, wallet, mediation) is composed by the
        // consumer via the builder (`AgentBuilder::with_default_modules()` /
        // `with_module`), registered into the DI container by `with_module`, and
        // self-wires from the container / `ModuleContext` in `register(&ctx)`.
        //
        // The only module still built here is `MediationModule`, because it is
        // config-driven (`config.mediation`) and needs the agent's
        // `grant_notify`; when present it is registered into the container and
        // pushed onto the lifecycle list so the module loop drives it.
        // ---------------------------------------------------------------------
        let mut agent_modules: Vec<Arc<dyn agent_module::AgentModule>> = Vec::new();

        // dids + wallet are documented exceptions to zero-default: they are
        // constructed + registered above (used mid-`initialize`) and driven here
        // by the module loop (their `register` is a no-op).
        agent_modules.push(dids.clone() as Arc<dyn agent_module::AgentModule>);
        agent_modules.push(wallet.clone() as Arc<dyn agent_module::AgentModule>);

        // Mediation module — self-wires its recipient/mediator handlers + async
        // init via the module loop. Also registered into the DI container so
        // `Agent::module::<MediationModule>()` resolves it; the agent still keeps
        // the `Option<Arc<MediationModule>>` handle for the direct
        // recipient/mediator/repository APIs used by mediation_setup.
        if let Some(mediation) = mediation.clone() {
            let m = mediation.clone();
            container.register_singleton_with_factory::<MediationModule, MediationModule, _>(
                move || Ok(m.clone()),
            );
            agent_modules.push(mediation as Arc<dyn agent_module::AgentModule>);
        }

        // Order by priority() descending. The builder appends the composed
        // modules onto this list and re-sorts (see `add_agent_modules`).
        agent_modules.sort_by_key(|m| std::cmp::Reverse(m.priority()));

        let container = Arc::new(container);

        Ok(Self {
            config,
            container,
            context,
            storage: storage.clone(),
            wallet_provider: wallet_provider.clone(),
            did_registry,
            did_repository,
            connection_repository,
            envelope_service: None, // Initialized in initialize()
            did_resolver: None,     // Initialized in initialize(), can be configured with DHT later
            did_document_service,
            profile_service,
            oid4vci_holder,
            oid4vci_issuer: None,
            oid4vp_holder,
            oid4vp_verifier,
            wallet_metadata,
            mediator_did_cell,
            mediator_endpoint_cell,
            mediation,
            push_notifications,
            blockchain_service: None, // Set via AgentBuilder.blockchain_service() or set_blockchain_service()
            #[cfg(feature = "anoncreds")]
            anoncreds: None, // Optional AnonCreds module, initialized via setup_anoncreds()
            transport: (*transport_arc).clone(), // Need to dereference and clone the inner value
            dispatcher,
            handler_registry,
            registered_mediation_key,
            mediation_routing_keys,
            pending_key_registrations,
            processed_message_ids: Arc::new(std::sync::RwLock::new(
                std::collections::HashSet::new(),
            )),
            message_processor,
            message_router,
            message_encryption,
            didcomm_sender,
            events,
            http_client: crate::http::shared_didcomm_client(),
            discovered_peers: crate::discovery::DiscoveredPeers::new(),
            #[cfg(feature = "discovery")]
            mdns_discovery: Arc::new(RwLock::new(None)),
            #[cfg(feature = "discovery")]
            ble_discovery: Arc::new(RwLock::new(None)),
            state: Arc::new(RwLock::new(AgentState::NotInitialized)),
            agent_did,
            agent_key_id,
            connection_ready_notify,
            grant_notify,
            // Assembled above (the single assembly point) and sorted by
            // priority(). The builder's `with_module` can append further custom
            // modules on top of these defaults.
            agent_modules,
        })
    }

    /// Initialize the agent
    ///
    /// This must be called before using the agent. It:
    /// - Starts all transport layers
    /// - Initializes storage
    /// - Sets up message handlers
    /// - Creates default DID if configured
    pub async fn initialize(&mut self) -> Result<()> {
        let mut state = self.state.write().await;
        if *state == AgentState::Initialized {
            return Err(AgentError::AlreadyInitialized);
        }
        if *state == AgentState::Shutdown {
            return Err(AgentError::AlreadyShutdown);
        }

        // Load persisted DID records from storage into the in-memory repository
        tracing::info!("🔧 [Agent::initialize] Loading persisted DIDs from storage...");
        if let Err(e) = self.load_persisted_dids().await {
            // Non-fatal error - just log and continue
            tracing::warn!(
                "[Agent::initialize] Warning: Failed to load persisted DIDs: {}",
                e
            );
        }

        // DID method resolvers already registered in constructor (did:key, did:peer)
        // This ensures all services using the registry have access to the resolvers

        // Create EnvelopeService for JWE encryption/decryption
        tracing::info!("🔧 [Agent::initialize] Creating EnvelopeService...");
        let did_resolver_concrete = Arc::new(AgentDIDResolver::new(self.did_registry.clone()));
        self.did_resolver = Some(did_resolver_concrete.clone());
        let did_resolver =
            did_resolver_concrete as Arc<dyn sicpa_didcomm::did::DIDResolver + Send + Sync>;
        let secrets_resolver = Arc::new(AgentSecretsResolver::new(
            self.wallet_provider.clone(),
            self.did_registry.clone(),
        ))
            as Arc<dyn sicpa_didcomm::secrets::SecretsResolver + Send + Sync>;

        let envelope_service = Arc::new(EnvelopeService::new(
            did_resolver,
            secrets_resolver,
            self.wallet_provider.clone(),
        ));
        self.envelope_service = Some(envelope_service.clone());
        tracing::info!("✓ [Agent::initialize] EnvelopeService created");

        // Register the EnvelopeService into the DI container so the self-wiring
        // OOB module resolves it in its `register` (which runs later in the
        // module loop). The container shares its provider map across clones, so
        // registering through a clone mutates the agent's container.
        {
            let mut container = (*self.container).clone();
            let v = envelope_service.clone();
            container.register_singleton_with_factory::<EnvelopeService, EnvelopeService, _>(
                move || Ok(v.clone()),
            );
        }
        // Also set it directly on an already-composed OOB module (harmless
        // idempotent overwrite before its own `register` runs).
        if let Some(oob) = self.module::<OutOfBandModule>() {
            oob.set_envelope_service(envelope_service.clone());
        }
        tracing::info!("✓ [Agent::initialize] EnvelopeService configured for OOB module");

        // Set EnvelopeService on MessageProcessor for version-aware response packing
        self.message_processor
            .set_envelope_service(envelope_service.clone())
            .await;
        tracing::info!("✓ [Agent::initialize] EnvelopeService configured for MessageProcessor");

        // Set EnvelopeService on MessageEncryption so the canonical sender
        // (DidCommSender → MessageEncryption::pack_encrypted_message) gets
        // automatic v1/v2 routing for every protocol package. Until this
        // setter is called, pack_encrypted_message stays on its legacy
        // v1-only path — mirrors the OOB / MessageProcessor wiring above.
        self.message_encryption
            .set_envelope_service(envelope_service)
            .await;
        tracing::info!("✓ [Agent::initialize] EnvelopeService configured for MessageEncryption");

        // Register HTTP outbound transport, sharing our tuned client (see
        // `agent/src/http.rs`) so back-to-back POSTs to the mediator
        // during bootstrap reuse a single TLS connection.
        tracing::info!("🔧 [Agent::initialize] Registering HTTP outbound transport...");
        let http_outbound =
            didcomm::transports::HttpOutboundTransport::with_client(self.http_client.clone());
        self.transport
            .register_outbound(Box::new(http_outbound))
            .await;

        // Verify transport registration
        let (inbound_count, outbound_count) = self.transport.transport_counts().await;
        tracing::info!(
            "✓ [Agent::initialize] Transports registered - inbound: {}, outbound: {}",
            inbound_count,
            outbound_count
        );

        // Start transports
        self.transport
            .start_all()
            .await
            .map_err(|e| AgentError::Transport(e.to_string()))?;

        // TODO: Initialize storage
        // TODO: Initialize wallet

        // Create agent's own DID and store it (if auto_create_did is enabled)
        let agent_did = if self.config.did.auto_create_did {
            tracing::info!("🔧 [Agent::initialize] Creating agent DID...");
            let did_manager = self.dids().manager()?;

            // Choose DID method based on whether we have endpoints configured
            let (agent_did, agent_key_id) = if let Some(endpoint) = self.config.endpoints.first() {
                // If we have an endpoint, create did:peer:2 with service endpoint
                // This enables DID-only messaging (send_to_did) over HTTP
                tracing::debug!("  Creating did:peer:2 with service endpoint: {}", endpoint);
                let (did, key_id, _doc) =
                    did_manager.create_peer_did_2_with_service(endpoint).await?;
                (did, key_id)
            } else {
                // No endpoint configured, use did:key (verification only)
                tracing::debug!("  No endpoint configured, creating did:key");
                did_manager.create_peer_did().await?
            };

            *self.agent_did.write().await = Some(agent_did.clone());
            *self.agent_key_id.write().await = Some(agent_key_id.clone());
            tracing::info!("✓ [Agent::initialize] Agent DID created: {}", agent_did);
            tracing::debug!("  Agent key ID: {}", agent_key_id);

            Some(agent_did)
        } else {
            tracing::info!(
                "⏸️ [Agent::initialize] Skipping auto DID creation (auto_create_did=false)"
            );
            None
        };

        // Initialize mDNS discovery if we have both a DID and an endpoint (requires discovery feature)
        #[cfg(feature = "discovery")]
        if let (Some(agent_did), Some(endpoint)) = (&agent_did, self.config.endpoints.first()) {
            tracing::info!("🔧 [Agent::initialize] Starting mDNS local network discovery...");

            match crate::discovery::mdns::MdnsDiscovery::new(
                agent_did.clone(),
                endpoint.clone(),
                vec!["did_sync".to_string(), "vc_issuance".to_string()],
            )
            .await
            {
                Ok(mdns) => {
                    // Store mDNS service
                    *self.mdns_discovery.write().await = Some(mdns);

                    // Spawn task to handle mDNS discoveries
                    let discovered_peers_for_mdns = self.discovered_peers.clone();
                    let mdns_discovery = self.mdns_discovery.clone();

                    tokio::spawn(async move {
                        loop {
                            if let Some(ref mut mdns_ref) = *mdns_discovery.write().await {
                                if let Some(peer) = mdns_ref.recv_peer().await {
                                    // Add to discovered peers
                                    discovered_peers_for_mdns.add_peer(peer.clone()).await;
                                    tracing::info!(
                                        "🔍 [mDNS] Discovered peer: {} at {}",
                                        peer.did,
                                        peer.endpoint
                                    );
                                } else {
                                    // Channel closed, stop
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    });

                    tracing::info!("✓ [Agent::initialize] mDNS discovery started");
                }
                Err(e) => {
                    tracing::warn!("⚠️  [mDNS] Failed to start mDNS discovery: {}", e);
                    tracing::debug!("  Note: mDNS discovery requires network access and may not work in all environments");
                }
            }
        } else {
            tracing::debug!("  Skipping mDNS discovery (no endpoint configured)");
        }

        // Initialize BLE discovery if we have both a DID and an endpoint (requires discovery feature)
        #[cfg(feature = "discovery")]
        if let (Some(agent_did), Some(endpoint)) = (&agent_did, self.config.endpoints.first()) {
            tracing::info!("🔧 [Agent::initialize] Starting BLE proximity discovery...");

            match crate::discovery::ble::BleDiscovery::new(
                agent_did.clone(),
                endpoint.clone(),
                vec!["did_sync".to_string(), "vc_issuance".to_string()],
            )
            .await
            {
                Ok(ble) => {
                    // Store BLE service
                    *self.ble_discovery.write().await = Some(ble);

                    // Spawn task to handle BLE discoveries
                    let discovered_peers_for_ble = self.discovered_peers.clone();
                    let ble_discovery = self.ble_discovery.clone();

                    tokio::spawn(async move {
                        loop {
                            if let Some(ref mut ble_ref) = *ble_discovery.write().await {
                                if let Some(peer) = ble_ref.recv_peer().await {
                                    // Add to discovered peers
                                    discovered_peers_for_ble.add_peer(peer.clone()).await;
                                    tracing::info!(
                                        "🔍 [BLE] Discovered peer: {} at {}",
                                        peer.did,
                                        peer.endpoint
                                    );
                                } else {
                                    // Channel closed, stop
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    });

                    tracing::info!("✓ [Agent::initialize] BLE discovery started");
                }
                Err(e) => {
                    tracing::warn!("⚠️  [BLE] Failed to start BLE discovery: {}", e);
                    tracing::debug!("  Note: BLE discovery requires Bluetooth hardware and may not work in all environments");
                }
            }
        } else {
            tracing::debug!("  Skipping BLE discovery (no endpoint configured)");
        }

        // Agent DID (created above) is written into the shared cell before the
        // module loop runs, so ConnectionsModule::register reads it there.
        // (The `if let Some(agent_did)` blocks above shadow the binding, so this
        // marks the outer variable as intentionally consumed.)
        let _ = &agent_did;

        // Connection-exchange, basic-message, user-profile, workflow,
        // and mediation handlers are all registered by their respective
        // self-wiring modules via the pluggable module loop at the end of this
        // method (see the `agent_module` assembly point). Nothing DIDComm-handler
        // related is registered agent-side here anymore.

        // Mediation handler registration + async init now happen in the
        // self-wiring `MediationModule::register` (driven by the module loop
        // below), not here.

        // Set up message routing on channel transport
        self.setup_message_routing().await?;

        // The workflow command-queue worker + handlers + send callback are now
        // started/registered by the self-wiring `WorkflowModule::register`
        // (driven by the module loop below), not here.

        // Drive the pluggable module lifecycle: build a shared ModuleContext
        // and let each module wire itself up. Modules are pre-sorted by
        // priority() descending when stored on the agent (see the assembly point
        // in `new_with_modules`), so we iterate in order.
        if !self.agent_modules.is_empty() {
            let ctx = self.build_module_context();
            for module in &self.agent_modules {
                tracing::debug!(
                    "🔧 [Agent::initialize] Registering module '{}'",
                    module.name()
                );
                module.register(&ctx).await.map_err(|e| {
                    AgentError::Module(format!("module '{}' register failed: {e}", module.name()))
                })?;
            }
        }

        // Discover Features (RFC 0031 v1 + RFC 0557 v2): answer "which protocols
        // do you support?" queries. Registered after all modules so it can
        // enumerate every protocol; the handlers hold the shared registry and
        // read it at query time.
        {
            let registry = self.handler_registry.clone();
            let mut w = registry.write().await;
            w.register(Arc::new(
                protocol_discover_features::DiscoverFeaturesV1Handler::new(registry.clone()),
            ));
            w.register(Arc::new(
                protocol_discover_features::DiscoverFeaturesV2Handler::new(registry.clone()),
            ));
            tracing::debug!("✓ Discover Features (v1 + v2) handlers registered");
        }

        *state = AgentState::Initialized;
        Ok(())
    }

    /// Build the shared [`agent_module::ModuleContext`] handed to every
    /// pluggable module's lifecycle hooks. Cheap to construct (all `Arc` /
    /// `String` clones); built fresh per lifecycle pass rather than stored.
    fn build_module_context(&self) -> agent_module::ModuleContext {
        let sender: Arc<dyn agent_module::OutboundSender> =
            Arc::new(crate::module_runtime::AgentOutboundSender::new(
                self.didcomm_sender.clone(),
                self.connection_repository.clone(),
            ));
        agent_module::ModuleContext {
            context: self.context.clone(),
            container: self.container.clone(),
            events: self.events.clone(),
            handler_registry: self.handler_registry.clone(),
            storage: self.storage.clone(),
            wallet: self.wallet_provider.clone(),
            sender,
            label: self.label(),
        }
    }

    /// Bootstrap with did:peer:2 for immediate peer discovery
    ///
    /// This creates a self-resolving did:peer:2 DID that can be used for:
    /// - mDNS discovery (no blockchain needed!)
    /// - Direct DIDComm v2 connections (no OOB invitations!)
    /// - Bootstrap phase before blockchain is available
    ///
    /// # Returns
    /// The did:peer:2 identifier that was created
    pub async fn bootstrap_with_peer_did(&self) -> Result<String> {
        tracing::info!("🔧 [Agent::bootstrap_with_peer_did] Creating bootstrap did:peer:2...");

        // Get endpoint for service
        let endpoint = self
            .config
            .endpoints
            .first()
            .ok_or_else(|| {
                AgentError::Configuration(
                    "No endpoint configured for did:peer:2 service".to_string(),
                )
            })?
            .clone();

        // Create did:peer:2 with service endpoint
        let did_manager = crate::modules::dids::DidManager::new(
            self.wallet_provider.clone(),
            self.did_repository.clone(),
        );

        let (peer_did, _key_id, _did_document) = did_manager
            .create_peer_did_2_with_service(&endpoint)
            .await?;

        // Set as our agent DID
        *self.agent_did.write().await = Some(peer_did.clone());

        tracing::info!(
            "✓ [Agent::bootstrap_with_peer_did] Bootstrap DID created: {}",
            peer_did
        );
        tracing::debug!("  This DID is self-resolving - no blockchain needed!");
        tracing::debug!("  Use this for mDNS discovery and direct DIDComm connections");

        Ok(peer_did)
    }

    /// Shutdown the agent
    ///
    /// This stops all transports and cleans up resources.
    pub async fn shutdown(&mut self) -> Result<()> {
        let mut state = self.state.write().await;
        if *state == AgentState::Shutdown {
            return Err(AgentError::AlreadyShutdown);
        }

        // Tear down pluggable modules in reverse registration order.
        if !self.agent_modules.is_empty() {
            let ctx = self.build_module_context();
            for module in self.agent_modules.iter().rev() {
                if let Err(e) = module.shutdown(&ctx).await {
                    tracing::warn!(
                        "[Agent::shutdown] module '{}' shutdown failed: {e}",
                        module.name()
                    );
                }
            }
        }

        // Mediation module shutdown now runs via the self-wiring module loop
        // above (MediationModule::shutdown), not here.

        // Stop transports
        self.transport
            .stop_all()
            .await
            .map_err(|e| AgentError::Transport(e.to_string()))?;

        // TODO: Close storage connections
        // TODO: Clear sensitive data

        *state = AgentState::Shutdown;
        Ok(())
    }

    /// Check if agent is initialized
    pub async fn is_initialized(&self) -> bool {
        *self.state.read().await == AgentState::Initialized
    }

    /// Check if agent is shutdown
    pub async fn is_shutdown(&self) -> bool {
        *self.state.read().await == AgentState::Shutdown
    }

    /// Get the agent's label — effective value, taking a runtime override
    /// set via `set_label` into account before falling back to the
    /// construction-time snapshot.
    pub fn label(&self) -> String {
        self.config.current_label()
    }

    /// Update the agent's label at runtime. Writes a shared override that
    /// all modules cloning `AgentConfig` (notably `OutOfBandModule`) read
    /// via `current_label()`. Use when the user's display name becomes
    /// available after the agent has already been initialized — e.g. iOS
    /// FRE completing post-bridge-creation.
    ///
    /// Side effects:
    /// 1. Writes through to `profile_service` so the persisted
    ///    `UserProfileRecord.display_name` matches the new label. The
    ///    profile-service emits `profile.own_updated`, which the
    ///    `start_profile_auto_send_watcher` task picks up and turns into
    ///    a broadcast to every Completed connection.
    ///
    /// Returns once the local persist is done. Network sends happen on the
    /// watcher's task so this is sub-millisecond from the caller's view.
    pub async fn set_label(&self, label: String) {
        self.config.set_runtime_label(label.clone());

        let mut record = self
            .profile_service
            .get_own_profile()
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        record.display_name = Some(label);
        if let Err(e) = self.profile_service.set_own_profile(&record).await {
            tracing::warn!("set_label: failed to update profile.display_name: {}", e);
        }
    }

    /// Update our own profile. The FFI's `agent_set_own_profile` calls this,
    /// and the broadcast to existing partners happens asynchronously via the
    /// `profile.own_updated` watcher (see `start_profile_auto_send_watcher`).
    ///
    /// Behaviour:
    /// 1. Persists `record` via `profile_service` (emits `profile.own_updated`).
    /// 2. Syncs `record.display_name` (when present) into the runtime label so
    ///    new OOB invitations and DIDComm `from_prior` strings show the same
    ///    display name peers will see in the profile message.
    ///
    /// Returns as soon as the local persist completes — the caller is not
    /// blocked waiting for partners to acknowledge. iOS callers can therefore
    /// re-render the settings sheet immediately after this returns.
    pub async fn set_own_profile(
        &self,
        record: &protocol_user_profile::UserProfileRecord,
    ) -> Result<()> {
        self.profile_service
            .set_own_profile(record)
            .await
            .map_err(|e| AgentError::Module(format!("Failed to save own profile: {}", e)))?;

        if let Some(ref name) = record.display_name {
            self.config.set_runtime_label(name.clone());
        }

        Ok(())
    }

    /// Send our currently-stored own profile to every Completed connection.
    ///
    /// Internal helper used by `set_own_profile`, `set_label`, and the
    /// connection-completed watcher. Sequential — a wallet has at most a few
    /// dozen partners; parallel send would only matter for thousands. Errors
    /// per peer are logged at `warn!` and do not stop the loop.
    pub async fn broadcast_profile_to_all_partners(&self) {
        let completed = match self.connection_repository.find_all_completed().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("broadcast_profile: list completed failed: {}", e);
                return;
            }
        };

        if completed.is_empty() {
            tracing::debug!("broadcast_profile: no completed connections, nothing to send");
            return;
        }

        tracing::info!(
            "broadcast_profile: pushing own profile to {} connection(s)",
            completed.len()
        );

        for conn in completed {
            if let Err(e) = self.send_profile_to_connection(&conn.id, false, None).await {
                tracing::warn!("broadcast_profile: send to {} failed: {}", conn.id, e);
            }
        }
    }

    /// Subscribe to the agent's event bus and auto-send our profile in
    /// two situations:
    ///
    /// 1. **Connection reaches `Completed`** — push our profile to that
    ///    peer with `send_back_yours=true` so they reply with theirs.
    /// 2. **Our own profile is written** (`profile.own_updated`) — broadcast
    ///    the new profile to every Completed peer so they see the latest
    ///    display name / picture without the UI having to loop partners.
    ///
    /// Both code paths run on this background task so callers of
    /// `set_own_profile` / `set_label` return immediately and never block
    /// on the network. The task self-terminates when the EventBus drops
    /// (i.e. on agent shutdown), so no explicit abort handle is required.
    pub fn start_profile_auto_send_watcher(agent: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mut subscriber = agent.events.subscribe();
        tokio::spawn(async move {
            tracing::info!("[profile-watcher] started");
            loop {
                match subscriber.recv().await {
                    Ok(event) => match event.name.as_str() {
                        "state_changed" => {
                            let state = event
                                .data
                                .get("state")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            if state != "Completed" {
                                continue;
                            }
                            let conn_id = match event
                                .data
                                .get("connection_record")
                                .and_then(|c| c.get("id"))
                                .and_then(|v| v.as_str())
                            {
                                Some(s) => s.to_string(),
                                None => continue,
                            };
                            tracing::info!(
                                "[profile-watcher] connection {} completed, sending own profile",
                                conn_id
                            );
                            if let Err(e) =
                                agent.send_profile_to_connection(&conn_id, true, None).await
                            {
                                tracing::warn!(
                                    "[profile-watcher] send_profile to {} failed: {}",
                                    conn_id,
                                    e
                                );
                            }
                        }
                        "own_updated" | "profile.own_updated" => {
                            tracing::info!(
                                "[profile-watcher] own profile changed, broadcasting to partners"
                            );
                            agent.broadcast_profile_to_all_partners().await;
                        }
                        _ => continue,
                    },
                    Err(e) => {
                        tracing::warn!(
                            "[profile-watcher] subscriber.recv error: {}, exiting watcher",
                            e
                        );
                        break;
                    }
                }
            }
        })
    }

    /// Bridge out-of-band protocol state changes to workflow auto-advance,
    /// mirroring the Python workflow_protocol plugin's `_on_pres_state_changed`
    /// (+ `auto_advance_by_connection`). When a proof exchange this agent is
    /// verifying reaches `PresentationReceived` / `Done`, advance every active
    /// workflow instance on that connection by the mapped event
    /// (`presentation_received` / `verified_ack`) so a proof-request workflow
    /// reaches its `verified` state without an explicit operator advance.
    /// Self-terminates when the EventBus drops (agent shutdown).
    pub fn start_workflow_protocol_bridge(agent: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mut subscriber = agent.events.subscribe();
        tokio::spawn(async move {
            tracing::info!("[workflow-bridge] started");
            loop {
                match subscriber.recv().await {
                    Ok(event) => {
                        // Proof exchange state → workflow event (Python parity).
                        if event.topic != "proof" || event.name != "state_changed" {
                            continue;
                        }
                        let record = match event.data.get("proof_record") {
                            Some(r) => r,
                            None => continue,
                        };
                        let state = record.get("state").and_then(|v| v.as_str()).unwrap_or("");
                        let wf_event = match state {
                            "PresentationReceived" => "presentation_received",
                            "Done" => "verified_ack",
                            _ => continue,
                        };
                        // ProofExchangeRecord serializes connection_id as
                        // `connectionId` (serde rename).
                        let conn_id = match record.get("connectionId").and_then(|v| v.as_str()) {
                            Some(c) => c.to_string(),
                            None => continue,
                        };
                        tracing::info!(
                            "[workflow-bridge] proof state '{}' on {} → event '{}'",
                            state,
                            conn_id,
                            wf_event
                        );
                        if let Some(workflow) = agent.workflow() {
                            workflow.advance_by_connection(&conn_id, wf_event).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("[workflow-bridge] subscriber.recv error: {}, exiting", e);
                        break;
                    }
                }
            }
        })
    }

    /// Load persisted DID records from storage into the in-memory repository
    ///
    /// This is called during initialization to restore DID documents that were
    /// previously stored. This ensures that connections can continue to work
    /// after app restarts.
    async fn load_persisted_dids(&self) -> Result<()> {
        use agent_core::traits::Query;
        use did::core::DidRecord;

        // Query all DidRecord entries from storage
        let query = Query::new();
        let records = self
            .storage
            .find_all("DidRecord", &query)
            .await
            .map_err(|e| AgentError::Storage(e.to_string()))?;

        let mut loaded_count = 0;
        for record in records {
            match serde_json::from_slice::<DidRecord>(&record.value) {
                Ok(did_record) => {
                    tracing::debug!(
                        "  Loading DID: {} (role: {:?})",
                        did_record.did,
                        did_record.role
                    );
                    self.did_repository.insert_loaded_record(did_record);
                    loaded_count += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        "  Warning: Failed to deserialize DID record {}: {}",
                        record.name,
                        e
                    );
                }
            }
        }

        tracing::info!(
            "✓ [Agent::initialize] Loaded {} DID records from storage",
            loaded_count
        );
        Ok(())
    }

    /// Set up message routing (called internally during initialize)
    async fn setup_message_routing(&self) -> Result<()> {
        // For now, this is a no-op
        // In a full implementation, this would set callbacks on all inbound transports
        // For testing, TestAgent will set up the routing directly on the ChannelInboundTransport
        Ok(())
    }
}
