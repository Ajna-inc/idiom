//! Mediation Module
//!
//! Provides coordinate mediation protocol support (Aries RFC 0211).
//! This module can be configured as either a recipient (client) or mediator (server),
//! or both.

use crate::error::{AgentError, Result};
use agent_core::traits::StorageProvider;
use protocol_coordinate_mediation::{
    handlers::{
        KeylistUpdateHandler, KeylistUpdateResponseHandler, MediationDenyHandler,
        MediationGrantHandler, MediationRequestHandler,
    },
    services::{MediationRecipientService, MediatorService},
    KeylistRecord, KeylistRepository, KeylistRepositoryTrait, KeylistUpdate, MediationRecord,
    MediationRepository, MediationRepositoryTrait, StorageBackedMediationRepository,
};
use std::sync::Arc;
use tokio::sync::Notify;

/// Mediation module configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct MediationConfig {
    /// Enable mediation recipient (client) functionality
    pub enable_recipient: bool,

    /// Enable mediator (server) functionality
    pub enable_mediator: bool,

    /// Mediator endpoint (required if enable_mediator = true)
    pub mediator_endpoint: Option<String>,

    /// Mediator routing keys (required if enable_mediator = true)
    pub mediator_routing_keys: Vec<String>,

    /// Auto-grant mediation requests (mediator only)
    pub auto_grant: bool,

    /// Mediator invitation URL for auto-connect (recipient only)
    pub mediator_invitation_url: Option<String>,
}

impl MediationConfig {
    /// Create a new mediation configuration as a recipient
    pub fn recipient() -> Self {
        Self {
            enable_recipient: true,
            enable_mediator: false,
            ..Default::default()
        }
    }

    /// Create a new mediation configuration as a mediator
    pub fn mediator(endpoint: String, routing_keys: Vec<String>) -> Self {
        Self {
            enable_recipient: false,
            enable_mediator: true,
            mediator_endpoint: Some(endpoint),
            mediator_routing_keys: routing_keys,
            ..Default::default()
        }
    }

    /// Create a new mediation configuration supporting both roles
    pub fn both(endpoint: String, routing_keys: Vec<String>) -> Self {
        Self {
            enable_recipient: true,
            enable_mediator: true,
            mediator_endpoint: Some(endpoint),
            mediator_routing_keys: routing_keys,
            ..Default::default()
        }
    }

    /// Set mediator invitation URL for auto-connect (recipient only)
    pub fn with_mediator_invitation_url(mut self, url: String) -> Self {
        self.mediator_invitation_url = Some(url);
        self
    }

    /// Enable auto-grant for mediation requests (mediator only)
    pub fn with_auto_grant(mut self, auto_grant: bool) -> Self {
        self.auto_grant = auto_grant;
        self
    }
}

/// Mediation Recipient API
///
/// Provides methods for recipient (client) operations
pub struct MediationRecipientApi {
    service: Arc<MediationRecipientService>,
}

impl MediationRecipientApi {
    fn new(service: Arc<MediationRecipientService>) -> Self {
        Self { service }
    }

    /// Create a mediation request for a connection
    pub async fn request_mediation(
        &self,
        connection_id: String,
    ) -> Result<(
        MediationRecord,
        protocol_coordinate_mediation::MediationRequestMessage,
    )> {
        self.service
            .create_request(connection_id)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }

    /// Get routing information for a mediation
    pub async fn get_routing_info(&self, mediation_id: &str) -> Result<(String, Vec<String>)> {
        self.service
            .get_routing_info(mediation_id)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }

    /// Create a keylist update request
    pub fn create_keylist_update(
        &self,
        updates: Vec<KeylistUpdate>,
    ) -> protocol_coordinate_mediation::KeylistUpdateMessage {
        self.service.create_keylist_update(updates)
    }

    /// Get all keylist entries for a mediation
    pub async fn get_keylist(&self, mediation_id: &str) -> Result<Vec<KeylistRecord>> {
        self.service
            .get_keylist(mediation_id)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }

    /// Find mediation by connection ID
    pub async fn find_by_connection_id(
        &self,
        connection_id: &str,
    ) -> Result<Option<MediationRecord>> {
        self.service
            .find_by_connection_id(connection_id)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }

    /// Get all granted mediations
    pub async fn get_all_granted(&self) -> Result<Vec<MediationRecord>> {
        self.service
            .get_all_granted()
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }

    /// Process a mediation grant response
    ///
    /// Updates the mediation record state from Requested to Granted
    /// and stores the endpoint and routing keys from the grant message.
    pub async fn process_grant(
        &self,
        connection_id: &str,
        grant_message: &protocol_coordinate_mediation::MediationGrantMessage,
    ) -> Result<MediationRecord> {
        self.service
            .process_grant(connection_id, grant_message)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }

    /// Process a keylist-update-response from the mediator
    ///
    /// Persists per-key `KeylistRecord` rows scoped to `mediation_id` so
    /// the forward handler's `is_key_in_keylist` lookups hit, and (when
    /// the events feature is on) emits `KeylistUpdatedPayload` so UIs can
    /// flip "Registered with mediator" indicators.
    pub async fn process_keylist_update_response(
        &self,
        mediation_id: &str,
        updated: &[protocol_coordinate_mediation::KeylistUpdated],
    ) -> Result<()> {
        self.service
            .process_keylist_update_response(mediation_id, updated)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }

    /// Update a mediation record
    ///
    /// Used to persist changes like the registered_recipient_key
    pub async fn update(&self, record: &MediationRecord) -> Result<()> {
        self.service
            .update(record)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }

    /// Delete a mediation record by ID
    ///
    /// Used to clear stale grants during re-mediation
    pub async fn delete(&self, id: &str) -> Result<()> {
        self.service
            .delete(id)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }
}

/// Mediation Mediator API
///
/// Provides methods for mediator (server) operations
pub struct MediationMediatorApi {
    service: Arc<MediatorService>,
}

impl MediationMediatorApi {
    fn new(service: Arc<MediatorService>) -> Self {
        Self { service }
    }

    /// Grant mediation for a request
    pub async fn grant_mediation(
        &self,
        mediation_id: &str,
        thread_id: String,
    ) -> Result<(
        MediationRecord,
        protocol_coordinate_mediation::MediationGrantMessage,
    )> {
        self.service
            .grant_mediation(mediation_id, thread_id)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }

    /// Deny mediation for a request
    pub async fn deny_mediation(
        &self,
        mediation_id: &str,
        thread_id: String,
    ) -> Result<(
        MediationRecord,
        protocol_coordinate_mediation::MediationDenyMessage,
    )> {
        self.service
            .deny_mediation(mediation_id, thread_id)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }

    /// Get all keylist entries for a mediation
    pub async fn get_keylist(&self, mediation_id: &str) -> Result<Vec<KeylistRecord>> {
        self.service
            .get_keylist(mediation_id)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }

    /// Check if a recipient key is in the keylist
    pub async fn is_key_in_keylist(&self, mediation_id: &str, recipient_key: &str) -> Result<bool> {
        self.service
            .is_key_in_keylist(mediation_id, recipient_key)
            .await
            .map_err(|e| AgentError::Mediation(e.to_string()))
    }
}

/// Mediation Module
///
/// Provides coordinate mediation protocol support. Can be configured as:
/// - Recipient only (client requesting mediation)
/// - Mediator only (server providing mediation)
/// - Both (full mediation node)
pub struct MediationModule {
    config: MediationConfig,
    recipient_service: Option<Arc<MediationRecipientService>>,
    mediator_service: Option<Arc<MediatorService>>,
    recipient_api: Option<MediationRecipientApi>,
    mediator_api: Option<MediationMediatorApi>,
    mediation_repository: Arc<dyn MediationRepositoryTrait>,
}

impl MediationModule {
    /// Create a new mediation module with the given configuration (in-memory storage)
    pub fn new(config: MediationConfig) -> Result<Self> {
        Self::new_internal(config, None, None)
    }

    /// Create a new mediation module with persistent storage
    ///
    /// This uses StorageBackedMediationRepository to persist mediation records
    /// across app restarts. Use this for production deployments.
    pub fn with_storage(
        config: MediationConfig,
        storage: Arc<dyn StorageProvider>,
    ) -> Result<Self> {
        Self::new_internal(config, Some(storage), None)
    }

    /// Create a new mediation module with persistent storage and grant notify
    pub fn with_storage_and_notify(
        config: MediationConfig,
        storage: Arc<dyn StorageProvider>,
        grant_notify: Arc<Notify>,
    ) -> Result<Self> {
        Self::new_internal(config, Some(storage), Some(grant_notify))
    }

    /// Internal constructor that handles both in-memory and storage-backed repositories
    fn new_internal(
        config: MediationConfig,
        storage: Option<Arc<dyn StorageProvider>>,
        grant_notify: Option<Arc<Notify>>,
    ) -> Result<Self> {
        // Validate configuration
        if config.enable_mediator
            && (config.mediator_endpoint.is_none() || config.mediator_routing_keys.is_empty())
        {
            return Err(AgentError::Configuration(
                "Mediator endpoint and routing keys are required when enable_mediator=true"
                    .to_string(),
            ));
        }

        // Create shared repositories - use storage-backed if storage is provided
        let mediation_repository: Arc<dyn MediationRepositoryTrait> = match storage {
            Some(storage) => {
                tracing::info!(
                    "🔧 [MediationModule] Using storage-backed mediation repository (persistent)"
                );
                Arc::new(StorageBackedMediationRepository::new(storage))
            }
            None => {
                tracing::info!(
                    "⚠️ [MediationModule] Using in-memory mediation repository (non-persistent)"
                );
                Arc::new(MediationRepository::new())
            }
        };
        let keylist_repository =
            Arc::new(KeylistRepository::new()) as Arc<dyn KeylistRepositoryTrait>;

        // Create recipient service and API if enabled
        let (recipient_service, recipient_api) = if config.enable_recipient {
            let mut service = MediationRecipientService::new(
                mediation_repository.clone(),
                keylist_repository.clone(),
            );
            if let Some(notify) = grant_notify {
                service = service.with_grant_notify(notify);
            }
            let service = Arc::new(service);
            let api = MediationRecipientApi::new(service.clone());
            (Some(service), Some(api))
        } else {
            (None, None)
        };

        // Create mediator service and API if enabled
        let (mediator_service, mediator_api) = if config.enable_mediator {
            let endpoint = config
                .mediator_endpoint
                .clone()
                .expect("Mediator endpoint validated above");
            let routing_keys = config.mediator_routing_keys.clone();

            let service = Arc::new(MediatorService::new(
                mediation_repository.clone(),
                keylist_repository.clone(),
                endpoint,
                routing_keys,
            ));
            let api = MediationMediatorApi::new(service.clone());
            (Some(service), Some(api))
        } else {
            (None, None)
        };

        Ok(Self {
            config,
            recipient_service,
            mediator_service,
            recipient_api,
            mediator_api,
            mediation_repository,
        })
    }

    /// Get the module configuration
    pub fn config(&self) -> &MediationConfig {
        &self.config
    }

    /// Mediation repository (shared with the recipient + mediator services).
    /// Exposed so adjacent modules (e.g. PushNotificationsModule) can locate
    /// the currently-granted mediator connection without going through the
    /// recipient API + an extra storage round-trip.
    pub fn repository(&self) -> Arc<dyn MediationRepositoryTrait> {
        self.mediation_repository.clone()
    }

    /// Get the recipient API (if enabled)
    pub fn recipient(&self) -> Option<&MediationRecipientApi> {
        self.recipient_api.as_ref()
    }

    /// Get the mediator API (if enabled)
    pub fn mediator(&self) -> Option<&MediationMediatorApi> {
        self.mediator_api.as_ref()
    }

    /// Register message handlers with the handler registry
    ///
    /// This should be called during agent initialization to register
    /// the appropriate handlers based on the module configuration.
    pub fn register_handlers(
        &self,
        registry: &mut didcomm::messaging::HandlerRegistry,
    ) -> Result<()> {
        // Register recipient handlers if enabled
        if let Some(service) = &self.recipient_service {
            tracing::info!("🔧 [MediationModule] Registering recipient handlers...");
            registry.register(Arc::new(MediationGrantHandler::new(service.clone())));
            registry.register(Arc::new(MediationDenyHandler::new(service.clone())));
            registry.register(Arc::new(KeylistUpdateResponseHandler::new(service.clone())));
            // NB: no ForwardHandler here. The recipient receives *unwrapped*
            // inner messages from the mediator's pickup queue (decrypted +
            // authcrypt-verified in `process_inbound`), never re-wrapped
            // `routing/2.0/forward` envelopes — so registering the stub
            // ForwardHandler only risked silently dropping (Ok(None)) any
            // forward that did reach the dispatcher. Delivery is handled by
            // the pickup loop, not this registry.
            tracing::info!("✓ [MediationModule] Recipient handlers registered");
        }

        // Register mediator handlers if enabled
        if let Some(service) = &self.mediator_service {
            tracing::info!("🔧 [MediationModule] Registering mediator handlers...");

            let request_handler = if self.config.auto_grant {
                MediationRequestHandler::with_auto_grant(service.clone())
            } else {
                MediationRequestHandler::new(service.clone())
            };

            registry.register(Arc::new(request_handler));
            registry.register(Arc::new(KeylistUpdateHandler::new(service.clone())));
            tracing::info!(
                "✓ [MediationModule] Mediator handlers registered (auto_grant={})",
                self.config.auto_grant
            );
        }

        Ok(())
    }

    /// Initialize the module (called after agent initialization)
    ///
    /// This can be used for lifecycle tasks like:
    /// - Auto-connecting to a mediator (recipient)
    /// - Setting up periodic tasks
    /// - Initializing storage
    pub async fn initialize(&self) -> Result<()> {
        // Recipient initialization
        if self.config.enable_recipient {
            tracing::info!("🔧 [MediationModule] Initializing recipient...");

            // If mediator invitation URL provided, we could auto-connect here
            if let Some(url) = &self.config.mediator_invitation_url {
                tracing::info!("  Note: Mediator invitation URL provided: {}", url);
                tracing::debug!("  (Auto-connect will be implemented in future version)");
            }

            tracing::info!("✓ [MediationModule] Recipient initialized");
        }

        // Mediator initialization
        if self.config.enable_mediator {
            tracing::info!("🔧 [MediationModule] Initializing mediator...");
            tracing::info!(
                "  Endpoint: {}",
                self.config.mediator_endpoint.as_ref().unwrap()
            );
            tracing::info!(
                "  Routing keys: {} keys configured",
                self.config.mediator_routing_keys.len()
            );
            tracing::debug!("  Auto-grant: {}", self.config.auto_grant);
            tracing::info!("✓ [MediationModule] Mediator initialized");
        }

        Ok(())
    }

    /// Shutdown the module (called during agent shutdown)
    pub async fn shutdown(&self) -> Result<()> {
        // Cleanup tasks (stop polling, close connections, etc.)
        Ok(())
    }
}

#[async_trait::async_trait]
impl agent_module::AgentModule for MediationModule {
    fn name(&self) -> &str {
        "mediation"
    }

    /// Register ahead of ordinary protocol modules (but below connections) so
    /// mediation recipient/mediator handlers are in place early.
    fn priority(&self) -> i32 {
        90
    }

    /// Self-wire: register the recipient/mediator DIDComm handlers into the
    /// shared registry, then run the module's own async initialization. This
    /// reuses the existing [`MediationModule::register_handlers`] and
    /// [`MediationModule::initialize`] so behavior is identical to the old
    /// agent-level wiring — only the call site moved into the module loop.
    async fn register(&self, ctx: &agent_module::ModuleContext) -> agent_module::ModuleResult {
        {
            let mut registry = ctx.handler_registry.write().await;
            self.register_handlers(&mut registry)
                .map_err(|e| format!("mediation: register handlers: {e}"))?;
        }
        self.initialize()
            .await
            .map_err(|e| format!("mediation: initialize: {e}"))?;
        Ok(())
    }

    async fn shutdown(&self, _ctx: &agent_module::ModuleContext) -> agent_module::ModuleResult {
        // Delegate to the inherent async shutdown (cleanup tasks).
        MediationModule::shutdown(self)
            .await
            .map_err(|e| format!("mediation: shutdown: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recipient_config() {
        let config = MediationConfig::recipient();
        assert!(config.enable_recipient);
        assert!(!config.enable_mediator);
    }

    #[test]
    fn test_mediator_config() {
        let config = MediationConfig::mediator(
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        );
        assert!(!config.enable_recipient);
        assert!(config.enable_mediator);
        assert_eq!(
            config.mediator_endpoint.unwrap(),
            "https://mediator.example.com"
        );
    }

    #[test]
    fn test_both_config() {
        let config = MediationConfig::both(
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        );
        assert!(config.enable_recipient);
        assert!(config.enable_mediator);
    }

    #[test]
    fn test_module_creation_recipient() {
        let config = MediationConfig::recipient();
        let module = MediationModule::new(config).unwrap();
        assert!(module.recipient().is_some());
        assert!(module.mediator().is_none());
    }

    #[test]
    fn test_module_creation_mediator() {
        let config = MediationConfig::mediator(
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        );
        let module = MediationModule::new(config).unwrap();
        assert!(module.recipient().is_none());
        assert!(module.mediator().is_some());
    }

    #[test]
    fn test_module_creation_invalid() {
        let config = MediationConfig {
            enable_mediator: true, // Missing endpoint and routing keys
            ..Default::default()
        };
        let result = MediationModule::new(config);
        assert!(result.is_err());
    }
}
