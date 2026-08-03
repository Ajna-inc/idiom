//! AnonCreds Module
//!
//! High-level API for AnonCreds credential issuance, holding, and verification.
//! Feature-gated behind the `anoncreds` feature flag.

use std::sync::Arc;

use agent_core::traits::StorageProvider;
use anoncreds_core::{
    AnonCredsHolderService, AnonCredsIssuerService, AnonCredsRegistry, AnonCredsVerifierService,
    InMemoryRegistry, StorageBackedAnonCredsStore,
};
use protocol_credentials::{
    CredentialAckHandler, CredentialExchangeRepository, CredentialExchangeRepositoryTrait,
    CredentialExchangeService, IssueCredentialHandler, OfferCredentialHandler,
    RequestCredentialHandler, StorageBackedCredentialExchangeRepository,
};
use protocol_proofs::{
    AckHandler as ProofAckHandler, PresentationHandler, ProofExchangeRepository,
    ProofExchangeRepositoryTrait, ProofExchangeService, RequestPresentationHandler,
    StorageBackedProofExchangeRepository,
};

/// AnonCreds module configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnonCredsConfig {
    /// Whether to auto-accept credential offers
    #[serde(default)]
    pub auto_accept_offers: bool,
    /// Whether to auto-verify presentations
    #[serde(default = "default_auto_verify")]
    pub auto_verify_presentations: bool,
}

fn default_auto_verify() -> bool {
    true
}

impl Default for AnonCredsConfig {
    fn default() -> Self {
        Self {
            auto_accept_offers: false,
            auto_verify_presentations: true,
        }
    }
}

/// AnonCreds module providing schema/cred-def management, credential issuance,
/// and presentation verification.
pub struct AnonCredsModule {
    config: AnonCredsConfig,
    registry: Arc<dyn AnonCredsRegistry>,
    issuer: Arc<AnonCredsIssuerService>,
    holder: Arc<AnonCredsHolderService>,
    verifier: Arc<AnonCredsVerifierService>,
    credential_exchange: Arc<CredentialExchangeService>,
    proof_exchange: Arc<ProofExchangeService>,
    /// Shared issuer-side request handler. Holds the auto-issue attribute map,
    /// so workflow actions can pre-register attributes for auto-issuance.
    request_handler: Arc<RequestCredentialHandler>,
}

impl AnonCredsModule {
    /// Create a new AnonCreds module with in-memory registry
    pub fn new(config: AnonCredsConfig) -> Self {
        Self::with_registry(config, Arc::new(InMemoryRegistry::new()))
    }

    /// Create with a custom registry
    pub fn with_registry(config: AnonCredsConfig, registry: Arc<dyn AnonCredsRegistry>) -> Self {
        let issuer = Arc::new(AnonCredsIssuerService::new(registry.clone()));
        let holder = Arc::new(AnonCredsHolderService::new(registry.clone()));
        let verifier = Arc::new(AnonCredsVerifierService::new(registry.clone()));

        let cred_repo: Arc<dyn CredentialExchangeRepositoryTrait> =
            Arc::new(CredentialExchangeRepository::new());
        let credential_exchange = Arc::new(CredentialExchangeService::new(
            issuer.clone(),
            holder.clone(),
            cred_repo.clone(),
        ));

        let proof_repo = Arc::new(ProofExchangeRepository::new());
        let proof_exchange = Arc::new(ProofExchangeService::new(
            holder.clone(),
            verifier.clone(),
            proof_repo,
        ));

        let request_handler = Arc::new(RequestCredentialHandler::new(credential_exchange.clone()));
        Self {
            config,
            registry,
            issuer,
            holder,
            verifier,
            credential_exchange,
            proof_exchange,
            request_handler,
        }
    }

    /// Create with a custom registry and persistent storage
    ///
    /// Uses storage-backed repositories for all AnonCreds data:
    /// link secrets, credentials, issuer private keys, and exchange records.
    pub fn with_storage(
        config: AnonCredsConfig,
        registry: Arc<dyn AnonCredsRegistry>,
        storage: Arc<dyn StorageProvider>,
    ) -> Self {
        Self::with_storage_and_events(config, registry, storage, None)
    }

    /// Like [`with_storage`], but wires the agent `EventBus` into the
    /// credential- and proof-exchange services so they emit
    /// `credential_exchange.state_changed` / `proof.state_changed` events on
    /// every protocol transition (the source for outbound webhooks).
    pub fn with_storage_and_events(
        config: AnonCredsConfig,
        registry: Arc<dyn AnonCredsRegistry>,
        storage: Arc<dyn StorageProvider>,
        events: Option<(Arc<agent_events::EventBus>, String)>,
    ) -> Self {
        let store = Arc::new(StorageBackedAnonCredsStore::new(storage.clone()));

        let issuer = Arc::new(AnonCredsIssuerService::new_with_store(
            registry.clone(),
            store.clone(),
        ));
        let holder = Arc::new(AnonCredsHolderService::new_with_store(
            registry.clone(),
            store.clone(),
        ));
        let verifier = Arc::new(AnonCredsVerifierService::new(registry.clone()));

        let cred_repo: Arc<dyn CredentialExchangeRepositoryTrait> = Arc::new(
            StorageBackedCredentialExchangeRepository::new(storage.clone()),
        );
        let mut cred_svc =
            CredentialExchangeService::new(issuer.clone(), holder.clone(), cred_repo.clone());

        let proof_repo: Arc<dyn ProofExchangeRepositoryTrait> =
            Arc::new(StorageBackedProofExchangeRepository::new(storage));
        let mut proof_svc = ProofExchangeService::new(holder.clone(), verifier.clone(), proof_repo);

        if let Some((bus, agent_id)) = events {
            cred_svc = cred_svc.with_event_bus(bus.clone(), agent_id.clone());
            proof_svc = proof_svc.with_event_bus(bus, agent_id);
        }

        let credential_exchange = Arc::new(cred_svc);
        let proof_exchange = Arc::new(proof_svc);

        let request_handler = Arc::new(RequestCredentialHandler::new(credential_exchange.clone()));
        Self {
            config,
            registry,
            issuer,
            holder,
            verifier,
            credential_exchange,
            proof_exchange,
            request_handler,
        }
    }

    /// Create protocol handlers for registration with the handler registry
    pub fn create_handlers(&self) -> Vec<Arc<dyn didcomm::messaging::MessageHandler>> {
        let handlers: Vec<Arc<dyn didcomm::messaging::MessageHandler>> = vec![
            // Issue Credential handlers. The offer handler auto-accepts (sends a
            // credential request) when configured, driving the full DIDComm flow.
            Arc::new(OfferCredentialHandler::new(
                self.credential_exchange.clone(),
                self.config.auto_accept_offers,
            )),
            // Share the same instance the module holds so workflow-registered
            // auto-issue attributes are visible to the dispatcher's handler.
            self.request_handler.clone(),
            Arc::new(IssueCredentialHandler::new(
                self.credential_exchange.clone(),
            )),
            // Issuer-side ack: holder confirms receipt → exchange Done.
            Arc::new(CredentialAckHandler::new(self.credential_exchange.clone())),
            // Present Proof handlers
            Arc::new(RequestPresentationHandler::new(self.proof_exchange.clone())),
            Arc::new(PresentationHandler::new(
                self.proof_exchange.clone(),
                self.config.auto_verify_presentations,
            )),
            Arc::new(ProofAckHandler::new(self.proof_exchange.clone())),
        ];

        handlers
    }

    /// Get the issuer service
    pub fn issuer(&self) -> &AnonCredsIssuerService {
        &self.issuer
    }

    /// Get the holder service
    pub fn holder(&self) -> &AnonCredsHolderService {
        &self.holder
    }

    /// Get the verifier service
    pub fn verifier(&self) -> &AnonCredsVerifierService {
        &self.verifier
    }

    /// Get the credential exchange service
    pub fn credential_exchange(&self) -> &CredentialExchangeService {
        &self.credential_exchange
    }

    /// Get the proof exchange service
    pub fn proof_exchange(&self) -> &ProofExchangeService {
        &self.proof_exchange
    }

    /// Shared (owned) handle to the issuer service — lets async callers avoid
    /// holding a borrow of the module across an await point.
    pub fn issuer_service(&self) -> Arc<AnonCredsIssuerService> {
        self.issuer.clone()
    }

    /// Shared (owned) handle to the holder service.
    pub fn holder_service(&self) -> Arc<AnonCredsHolderService> {
        self.holder.clone()
    }

    /// Shared (owned) handle to the verifier service.
    pub fn verifier_service(&self) -> Arc<AnonCredsVerifierService> {
        self.verifier.clone()
    }

    /// Shared handle to the credential exchange service (for wiring workflow
    /// action handlers).
    pub fn credential_exchange_service(&self) -> Arc<CredentialExchangeService> {
        self.credential_exchange.clone()
    }

    /// Shared handle to the proof exchange service.
    pub fn proof_exchange_service(&self) -> Arc<ProofExchangeService> {
        self.proof_exchange.clone()
    }

    /// Shared issuer-side request handler (for pre-registering auto-issue
    /// attributes from workflow actions).
    pub fn request_handler(&self) -> Arc<RequestCredentialHandler> {
        self.request_handler.clone()
    }

    /// Get the registry
    pub fn registry(&self) -> &dyn AnonCredsRegistry {
        self.registry.as_ref()
    }
}
