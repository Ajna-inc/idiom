//! MediatorApp — wires together all components for the mediator server.

use crate::config::MediatorConfig;
use crate::crypto::{MediatorDIDResolver, MediatorSecretsResolver};
use crate::metrics::{self, Metrics};
use crate::push_notifier::{
    FcmPushNotifier, FcmServiceAccount, PushNotificationContent, WebhookPushNotifier,
};
use agent_core::traits::StorageProvider;
use did::methods::{KeyDidCreator, KeyDidResolver, PeerDidResolver};
use did::registry::DidRegistry;
use didcomm::core::EnvelopeService;
use didcomm::messaging::{HandlerRegistry, MessageHandler};
use protocol_connections::{
    ConnectionRepositoryTrait, ConnectionService, DidExchangeCompleteHandler,
    DidExchangeRequestHandler, DidExchangeResponseHandler, StorageBackedConnectionRepository,
};
use protocol_coordinate_mediation::{
    ForwardService, KeylistRepositoryTrait, KeylistUpdateHandler, LiveSessionManager,
    MediationRepositoryTrait, MediationRequestHandler, MediatorForwardHandler, MediatorService,
    StorageBackedKeylistRepository, StorageBackedMediationRepository,
};
use protocol_pickup::{
    DeliveryRequestHandler, LiveDeliveryChangeHandler, MessagesReceivedHandler,
    PickupMediatorService, StatusRequestHandler, StorageBackedMessageQueueRepository,
};
use protocol_push_notifications::{
    DeleteDeviceInfoHandler as PnDeleteHandler, DeviceInfoRepository, DeviceInfoRepositoryTrait,
    GetDeviceInfoHandler as PnGetHandler, PushNotificationService, PushNotifier,
    SetDeviceInfoHandler as PnSetHandler,
};
use std::sync::Arc;
use storage::askar::{AskarConfig, AskarStorageProvider};
use wallet::askar::AskarWalletProvider;

/// Shared application state
pub struct MediatorApp {
    /// Handler registry for message routing (immutable after startup — no lock needed)
    pub handler_registry: Arc<HandlerRegistry>,
    /// Live session manager for WebSocket push
    pub live_sessions: Arc<LiveSessionManager>,
    /// Mediator service for mediation operations
    pub mediator_service: Arc<MediatorService>,
    /// Forward service
    pub forward_service: Arc<ForwardService<StorageBackedMessageQueueRepository>>,
    /// Pickup service
    pub pickup_service: Arc<PickupMediatorService<StorageBackedMessageQueueRepository>>,
    /// Envelope service for JWE pack/unpack
    pub envelope_service: Arc<EnvelopeService>,
    /// Storage provider
    pub storage: Arc<dyn StorageProvider>,
    /// OOB invitation (generated on startup)
    pub invitation_json: serde_json::Value,
    /// Public endpoint
    pub endpoint: String,
    /// Agent label
    pub label: String,
    /// Mediator DID
    pub mediator_did: String,
    /// Connection repository for resolving sender verkey → connection ID.
    /// Storage-backed for persistence across restarts + indexed verkey lookups.
    pub connection_repo: Arc<StorageBackedConnectionRepository>,
    /// Keylist repository for direct-routing lookup (JWE kid → mediation)
    pub keylist_repo: Arc<StorageBackedKeylistRepository>,
    /// Prometheus metrics. Wired into hot paths so `/metrics` returns useful
    /// counters without extra instrumentation per call site.
    pub metrics: Arc<Metrics>,
    /// Runtime that owns heavy inbound message processing (the "data plane").
    /// Captured at build time (`Handle::current()`).
    pub data_handle: tokio::runtime::Handle,
}

impl MediatorApp {
    /// Build the mediator app from config
    pub async fn build(config: &MediatorConfig) -> Result<Self, anyhow::Error> {
        // 1. Initialize Askar storage (single connection shared with wallet)
        let askar_config = if config.database_url.starts_with("postgres") {
            AskarConfig::builder()
                .postgres(&config.database_url)
                .pass_key(&config.storage_key)
                .create_if_missing(true)
                .build()
        } else {
            let db_path = config.database_url.trim_start_matches("sqlite://");
            AskarConfig::builder()
                .sqlite_file(db_path)
                .pass_key(&config.storage_key)
                .create_if_missing(true)
                .build()
        }
        .map_err(|e| anyhow::anyhow!("Failed to build Askar config: {}", e))?;

        let askar_provider = AskarStorageProvider::new(askar_config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to initialize Askar storage: {}", e))?;

        // Create wallet from the SAME store (no dual connections)
        let wallet: agent_core::traits::WalletRef =
            Arc::new(AskarWalletProvider::new(askar_provider.store().clone()));

        let storage: Arc<dyn StorageProvider> = Arc::new(askar_provider);

        tracing::info!("Askar storage + wallet initialized");

        // 2. Set up DID registry with KeyDidResolver + PeerDidResolver.
        let did_repository = Arc::new(did::core::DidRepository::new());
        let mut did_registry = DidRegistry::with_storage(storage.clone());
        did_registry.register_resolver(Arc::new(KeyDidResolver::new()));
        did_registry.register_resolver(Arc::new(PeerDidResolver::new(did_repository.clone())));
        let did_registry = Arc::new(did_registry);

        // 3. Create DID resolver + secrets resolver for EnvelopeService
        let did_resolver: Arc<dyn sicpa_didcomm::did::DIDResolver + Send + Sync> =
            Arc::new(MediatorDIDResolver::new(did_registry.clone()));
        let secrets_resolver: Arc<dyn sicpa_didcomm::secrets::SecretsResolver + Send + Sync> =
            Arc::new(MediatorSecretsResolver::new(wallet.clone(), did_registry));

        // 4. Create EnvelopeService for JWE pack/unpack
        let envelope_service = Arc::new(EnvelopeService::new(
            did_resolver,
            secrets_resolver,
            wallet.clone(),
        ));

        // 5. Create repositories (storage-backed)
        let mediation_repo = Arc::new(StorageBackedMediationRepository::new(storage.clone()));
        let keylist_repo = Arc::new(StorageBackedKeylistRepository::new(storage.clone()));
        let message_queue_repo =
            Arc::new(StorageBackedMessageQueueRepository::new(storage.clone()));

        // 6. Generate/load mediator DID (real did:key backed by wallet)
        let mediator_did = load_or_create_mediator_did(&storage, &wallet).await?;
        tracing::info!(did = %mediator_did, "Mediator DID ready");

        // 7. Create services
        let live_sessions = Arc::new(LiveSessionManager::new());

        // Routing keys published in the mediation grant.
        let grant_routing_keys = if config.direct_routing {
            vec![]
        } else {
            vec![mediator_did.clone()]
        };

        let mediator_service = Arc::new(MediatorService::new(
            mediation_repo.clone(),
            keylist_repo.clone(),
            config.endpoint.clone(),
            grant_routing_keys.clone(),
        ));

        let message_queue_repo_ref = message_queue_repo.clone();
        let pickup_service = Arc::new(PickupMediatorService::new(message_queue_repo));

        // Push notifications: build the device-info repository + notifier
        // (FCM or webhook) ONCE per app start.
        let device_info_repo: Arc<dyn DeviceInfoRepositoryTrait> =
            Arc::new(DeviceInfoRepository::new());
        let push_service = Arc::new(PushNotificationService::new(device_info_repo.clone()));
        let push_notifier_opt: Option<Arc<dyn PushNotifier>> =
            build_push_notifier(device_info_repo.clone(), &config.push_notifications);

        let mut fs = ForwardService::new(
            mediation_repo.clone(),
            keylist_repo.clone(),
            pickup_service.clone(),
            live_sessions.clone(),
            config.forwarding_strategy,
        );
        if let Some(ref n) = push_notifier_opt {
            fs = fs.with_push_notifier(n.clone());
            tracing::info!("[push] notifier wired into ForwardService");
        } else {
            tracing::info!("[push] no notifier configured — set FIREBASE_CREDENTIALS_JSON_PATH or PUSH_NOTIFICATION_WEBHOOK_URL");
        }
        let forward_service = Arc::new(fs);

        // Connection service — storage-backed for persistence + indexed verkey lookups.
        let connection_repo = Arc::new(StorageBackedConnectionRepository::new(storage.clone()));
        let connection_service = Arc::new(ConnectionService::new(connection_repo.clone()));

        // OOB repository for connection handlers
        let oob_repository = Arc::new(protocol_oob::OutOfBandRepository::new());

        // Shared mediation state for connection handlers
        // Note: protocol_connections uses std::sync::RwLock, not tokio::sync::RwLock
        let registered_mediation_key: Arc<std::sync::RwLock<Option<String>>> =
            Arc::new(std::sync::RwLock::new(Some(mediator_did.clone())));
        // The mediator itself isn't mediated — its own DID docs should NOT have
        // routing_keys (empty). This is independent of what we grant to clients.
        let mediation_routing_keys: Arc<std::sync::RwLock<Option<Vec<String>>>> =
            Arc::new(std::sync::RwLock::new(Some(grant_routing_keys.clone())));
        let pending_key_registrations: Arc<std::sync::RwLock<Vec<String>>> =
            Arc::new(std::sync::RwLock::new(Vec::new()));

        // 8. Register handlers
        let mut registry = HandlerRegistry::new();

        // Connection handlers (DID Exchange)
        let did_exchange_request_handler = DidExchangeRequestHandler::new(
            connection_service.clone(),
            oob_repository.clone(),
            did_repository.clone(),
            wallet.clone(),
            true, // auto_accept_connections
            mediator_did.clone(),
            registered_mediation_key,
            mediation_routing_keys,
            pending_key_registrations,
        );
        registry.register(Arc::new(did_exchange_request_handler) as Arc<dyn MessageHandler>);

        let did_exchange_response_handler = DidExchangeResponseHandler::new(
            connection_service.clone(),
            did_repository.clone(),
            true, // auto_accept_connections
        );
        registry.register(Arc::new(did_exchange_response_handler) as Arc<dyn MessageHandler>);

        let did_exchange_complete_handler =
            DidExchangeCompleteHandler::new(connection_service.clone());
        registry.register(Arc::new(did_exchange_complete_handler) as Arc<dyn MessageHandler>);

        // Mediation handlers.
        let request_handler = if config.auto_grant {
            MediationRequestHandler::with_auto_grant(mediator_service.clone())
        } else {
            MediationRequestHandler::new(mediator_service.clone())
        };
        registry.register(Arc::new(request_handler) as Arc<dyn MessageHandler>);

        let keylist_handler = KeylistUpdateHandler::new(mediator_service.clone());
        registry.register(Arc::new(keylist_handler) as Arc<dyn MessageHandler>);

        // Forward handler (mediator side)
        let forward_handler = MediatorForwardHandler::new(forward_service.clone());
        registry.register(Arc::new(forward_handler) as Arc<dyn MessageHandler>);

        // Pickup handlers
        let status_handler = StatusRequestHandler::new(pickup_service.clone());
        registry.register(Arc::new(status_handler) as Arc<dyn MessageHandler>);

        let delivery_handler = DeliveryRequestHandler::new(pickup_service.clone());
        registry.register(Arc::new(delivery_handler) as Arc<dyn MessageHandler>);

        let ack_handler = MessagesReceivedHandler::new(pickup_service.clone());
        registry.register(Arc::new(ack_handler) as Arc<dyn MessageHandler>);

        // Live delivery change handler
        let live_delivery_handler = LiveDeliveryChangeHandler::new(pickup_service.clone());
        registry.register(Arc::new(live_delivery_handler) as Arc<dyn MessageHandler>);

        // Push-notifications protocol — wallet → mediator register/get/delete
        // device tokens. Registered even when no backend is configured so
        // wallets can still inspect / clear stored info.
        registry
            .register(Arc::new(PnSetHandler::new(push_service.clone())) as Arc<dyn MessageHandler>);
        registry.register(
            Arc::new(PnDeleteHandler::new(push_service.clone())) as Arc<dyn MessageHandler>
        );
        registry
            .register(Arc::new(PnGetHandler::new(push_service.clone())) as Arc<dyn MessageHandler>);

        tracing::info!(
            handler_count = registry.count(),
            types = ?registry.registered_types(),
            "Handler registry initialized"
        );

        // 9. Build OOB invitation (persisted for restart survival)
        let invitation_json =
            load_or_create_invitation(&storage, &mediator_did, &config.endpoint, &config.label)
                .await?;

        // Register the invitation in the OOB repository so the request handler
        // can look it up by pthid when didexchange requests arrive.
        {
            use protocol_oob::repository::oob_repository::OutOfBandRepositoryTrait;
            let invitation: protocol_oob::OutOfBandInvitation =
                serde_json::from_value(invitation_json.clone()).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to parse mediator invitation for OOB repository: {}",
                        e
                    )
                })?;
            let oob_record = protocol_oob::repository::oob_record::OutOfBandRecord::new(
                invitation,
                protocol_oob::OutOfBandRole::Sender,
            )
            .with_state(protocol_oob::OutOfBandState::AwaitResponse)
            .with_reusable(true);
            // Ignore duplicate error on restart (record already in repo)
            let _ = oob_repository.save(&oob_record).await;
            tracing::info!("OOB invitation registered in repository for request handler lookup");
        }

        // Warm up all caches on startup so the first request doesn't trigger
        // a synchronous DB load.
        tracing::info!("Warming up caches...");
        if let Ok(conns) = connection_repo.get_all().await {
            tracing::info!("  Connections: {} loaded", conns.len());
        }
        if let Ok(keys) = keylist_repo.get_all().await {
            tracing::info!("  Keylist entries: {} loaded", keys.len());
        }
        if let Ok(meds) = mediation_repo.get_all().await {
            tracing::info!("  Mediation records: {} loaded", meds.len());
        }
        // Warm up message queue + reset orphaned "Sending" messages from prior crash
        if let Ok(count) = message_queue_repo_ref.warm_up().await {
            tracing::info!("  Message queue: {} messages loaded (orphans reset)", count);
        }

        // Build metrics early so the TTL task can reference it.
        let metrics = metrics::build();

        // Spawn the pickup-queue TTL cleanup task. Periodically deletes
        // messages older than `pickup_message_max_age_secs`.
        {
            let pickup_for_ttl = pickup_service.clone();
            let metrics_for_ttl = metrics.clone();
            let max_age = std::time::Duration::from_secs(config.pickup_message_max_age_secs);
            let interval_secs = config.pickup_cleanup_interval_secs;
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                // Skip immediate tick — first sweep at +interval, not at boot.
                tick.tick().await;
                loop {
                    tick.tick().await;
                    match pickup_for_ttl.delete_expired(max_age).await {
                        Ok(0) => {
                            tracing::debug!("[Pickup TTL] sweep complete: 0 stale messages");
                        }
                        Ok(n) => {
                            metrics_for_ttl.stale_cleanup_deleted_total.inc_by(n);
                            tracing::info!(
                                deleted = n,
                                max_age_secs = max_age.as_secs(),
                                "[Pickup TTL] swept stale messages"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "[Pickup TTL] sweep failed");
                        }
                    }
                }
            });
            tracing::info!(
                interval_secs = config.pickup_cleanup_interval_secs,
                max_age_secs = config.pickup_message_max_age_secs,
                "[Pickup TTL] cleanup task started"
            );
        }

        // Periodic gauge updater. Polls live_session_count every 5s and updates
        // the Prometheus gauge, so a `/metrics` scrape never blocks.
        {
            let live_sessions_for_metrics = live_sessions.clone();
            let metrics_for_gauge = metrics.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    tick.tick().await;
                    let count = live_sessions_for_metrics.session_count().await;
                    metrics_for_gauge.live_session_count.set(count as i64);
                }
            });
        }

        Ok(Self {
            handler_registry: Arc::new(registry),
            live_sessions,
            mediator_service,
            forward_service,
            pickup_service,
            envelope_service,
            storage,
            invitation_json,
            endpoint: config.endpoint.clone(),
            label: config.label.clone(),
            mediator_did,
            connection_repo,
            keylist_repo,
            metrics,
            // The runtime this build() runs on becomes the message-processing
            // ("data plane") runtime.
            data_handle: tokio::runtime::Handle::current(),
        })
    }
}

/// Load or create the mediator's DID (persisted in Askar).
///
/// Uses `KeyDidCreator` to generate a real did:key backed by an Ed25519 key in the wallet.
/// The DID is persisted in storage so it survives restarts.
async fn load_or_create_mediator_did(
    storage: &Arc<dyn StorageProvider>,
    wallet: &agent_core::traits::WalletRef,
) -> Result<String, anyhow::Error> {
    use agent_core::traits::Record;
    use did::core::{CreateDidOptions, DidCreator};

    const DID_CATEGORY: &str = "mediator_did";
    const DID_NAME: &str = "primary";

    // Try to load existing DID
    if let Ok(Some(record)) = storage.find(DID_CATEGORY, DID_NAME).await {
        let did = String::from_utf8(record.value)
            .map_err(|e| anyhow::anyhow!("Invalid DID encoding: {}", e))?;
        tracing::info!("Loaded existing mediator DID");
        return Ok(did);
    }

    // Create a real did:key with Ed25519 key in wallet
    let creator = KeyDidCreator::new(wallet.clone());
    let result = creator
        .create(CreateDidOptions::default())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create did:key: {:?}", e))?;
    let did = result.did.as_str().to_string();

    // Persist the DID string
    let record = Record::new(DID_CATEGORY, DID_NAME, did.as_bytes().to_vec());
    storage
        .save(&record)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to persist mediator DID: {}", e))?;

    // Also persist the DidRecord so the DID resolver can find it
    let record_json = serde_json::to_vec(&result.did_record)
        .map_err(|e| anyhow::anyhow!("Failed to serialize DidRecord: {}", e))?;
    let did_record =
        Record::new("DidRecord", &result.did_record.id, record_json).add_tag("did", &did);
    storage
        .save(&did_record)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to persist DidRecord: {}", e))?;

    tracing::info!("Generated new mediator DID (real did:key)");
    Ok(did)
}

/// Load or create the OOB invitation (persisted for restart survival).
///
/// Always advertises BOTH the HTTP and WS endpoints so mobile wallets can pick
/// a WebSocket service for live-mode message pickup. If a previously-persisted
/// invitation only has the HTTP service, it is rewritten in place to include WS.
async fn load_or_create_invitation(
    storage: &Arc<dyn StorageProvider>,
    mediator_did: &str,
    endpoint: &str,
    label: &str,
) -> Result<serde_json::Value, anyhow::Error> {
    use agent_core::traits::Record;

    const INVITE_CATEGORY: &str = "mediator_invitation";
    const INVITE_NAME: &str = "primary";

    // Derive the WS endpoint from the HTTP endpoint.
    fn derive_ws_endpoint(http: &str) -> String {
        if let Some(rest) = http.strip_prefix("https://") {
            format!("wss://{}/ws", rest.trim_end_matches('/'))
        } else if let Some(rest) = http.strip_prefix("http://") {
            format!("ws://{}/ws", rest.trim_end_matches('/'))
        } else {
            // Unknown scheme — best effort
            format!("{}/ws", http.trim_end_matches('/'))
        }
    }
    let ws_endpoint = derive_ws_endpoint(endpoint);

    let build_services = || {
        serde_json::json!([
            {
                "id": format!("{}#inline-http", mediator_did),
                "type": "did-communication",
                "recipientKeys": [mediator_did],
                "serviceEndpoint": endpoint
            },
            {
                "id": format!("{}#inline-ws", mediator_did),
                "type": "did-communication",
                "recipientKeys": [mediator_did],
                "serviceEndpoint": ws_endpoint
            }
        ])
    };

    // Try to load existing invitation
    if let Ok(Some(record)) = storage.find(INVITE_CATEGORY, INVITE_NAME).await {
        let mut invitation: serde_json::Value = serde_json::from_slice(&record.value)
            .map_err(|e| anyhow::anyhow!("Invalid invitation encoding: {}", e))?;
        // Migrate older single-service OOBs to include the WS service.
        let needs_migration = invitation
            .get("services")
            .and_then(|s| s.as_array())
            .map(|arr| arr.len() < 2)
            .unwrap_or(true);
        if needs_migration {
            tracing::info!("Migrating OOB invitation to include WS service");
            invitation["services"] = build_services();
            let value = serde_json::to_vec(&invitation)
                .map_err(|e| anyhow::anyhow!("Failed to serialize invitation: {}", e))?;
            let record = Record::new(INVITE_CATEGORY, INVITE_NAME, value);
            // Use update() to overwrite the existing entry (save() is INSERT-only).
            storage
                .update(&record)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to persist migrated invitation: {}", e))?;
        }
        tracing::info!("Loaded existing OOB invitation");
        return Ok(invitation);
    }

    // Create new invitation
    let invitation = serde_json::json!({
        "@type": "https://didcomm.org/out-of-band/1.1/invitation",
        "@id": uuid::Uuid::new_v4().to_string(),
        "label": label,
        "accept": ["didcomm/aip2;env=rfc19"],
        "handshake_protocols": [
            "https://didcomm.org/didexchange/1.0",
            "https://didcomm.org/connections/1.0"
        ],
        "services": build_services()
    });

    // Persist it
    let value = serde_json::to_vec(&invitation)
        .map_err(|e| anyhow::anyhow!("Failed to serialize invitation: {}", e))?;
    let record = Record::new(INVITE_CATEGORY, INVITE_NAME, value);
    storage
        .save(&record)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to persist invitation: {}", e))?;

    tracing::info!("Created new OOB invitation");
    Ok(invitation)
}

/// Build the push notifier based on env config. FCM wins if both backends
/// are set. Returns `None` when neither is configured — that's the silent
/// "push disabled" path.
fn build_push_notifier(
    repo: Arc<dyn DeviceInfoRepositoryTrait>,
    cfg: &crate::config::PushNotificationConfig,
) -> Option<Arc<dyn PushNotifier>> {
    let content = PushNotificationContent {
        title: cfg.title.clone(),
        body: cfg.body.clone(),
    };

    // Preferred: inline service-account JSON straight from a secret env var
    // (FIREBASE_CREDENTIALS_JSON) — no on-disk credentials.
    if let Some(json) = &cfg.firebase_credentials_json {
        match FcmServiceAccount::from_json(json) {
            Ok(acct) => {
                let project_id = acct.project_id.clone();
                let notifier = Arc::new(FcmPushNotifier::new(repo, acct, content));
                tracing::info!(
                    project_id = project_id,
                    "[push] FCM notifier loaded from FIREBASE_CREDENTIALS_JSON secret"
                );
                return Some(notifier);
            }
            Err(e) => {
                tracing::error!(
                    "[push] failed to parse FIREBASE_CREDENTIALS_JSON: {} — trying file/webhook",
                    e
                );
            }
        }
    }

    if let Some(path) = &cfg.firebase_credentials_path {
        match FcmServiceAccount::from_file(path) {
            Ok(acct) => {
                let project_id = acct.project_id.clone();
                let notifier = Arc::new(FcmPushNotifier::new(repo, acct, content));
                tracing::info!(
                    project_id = project_id,
                    "[push] FCM notifier loaded from {}",
                    path
                );
                return Some(notifier);
            }
            Err(e) => {
                tracing::error!(
                    "[push] failed to load FCM service-account from {}: {} — falling back to webhook (if set)",
                    path,
                    e
                );
            }
        }
    }

    if let Some(url) = &cfg.webhook_url {
        let notifier = Arc::new(WebhookPushNotifier::new(repo, url.clone()));
        tracing::info!("[push] webhook notifier configured → {}", url);
        return Some(notifier);
    }

    None
}
