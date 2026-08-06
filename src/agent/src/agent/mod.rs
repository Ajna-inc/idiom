//! Core Agent implementation

use crate::config::AgentConfig;
use crate::crypto::{AgentDIDResolver, AgentSecretsResolver};
use crate::dispatcher::MessageDispatcher;
use crate::error::{AgentError, Result};
use crate::messaging::{MessageEncryption, MessageProcessor, MessageRouter};
use crate::modules::{DidModule, MediationModule, OutOfBandModule, WalletModule};
use crate::transport::TransportManager;
use agent_core::context::AgentContext;
use agent_core::traits::{BlockchainService, StorageProvider, WalletProvider};
use agent_events::event_bus::EventBus;
use base64::Engine;
use did::core::DidRepository;
use did::registry::DidRegistry;
use didcomm::core::EnvelopeService;
use protocol_connections::ConnectionRepositoryTrait;
use protocol_oob::OutOfBandRepository;
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
use tracing::{debug, trace, warn};

/// Agent State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// Agent has been created but not initialized
    NotInitialized,
    /// Agent is initialized and ready
    Initialized,
    /// Agent has been shutdown
    Shutdown,
}

/// Main Agent struct that integrates all SSI functionality
///
/// This is the primary entry point for using the SSI agent. It provides
/// module-based access to different protocols and functionality.
pub struct Agent {
    /// Agent configuration
    pub config: AgentConfig,

    /// Dependency-injection container holding the agent's modules.
    ///
    /// Core modules (`oob`, `connections`, `dids`, `wallet`) are always
    /// registered; optional modules (`credentials`, `workflow`,
    /// `basic_messages`) are registered only when enabled via the builder.
    /// Access modules through the accessor methods (`connections()`,
    /// `credentials()`, …) rather than resolving directly.
    container: Arc<agent_di::Container>,

    /// Agent context for dependency injection
    pub context: Arc<AgentContext>,

    /// Storage provider (injected dependency)
    storage: Arc<dyn StorageProvider>,

    /// Wallet provider (injected dependency)
    wallet_provider: Arc<dyn WalletProvider>,

    /// DID Registry (kept for resolvers)
    did_registry: Arc<DidRegistry>,

    /// DID Repository (for storing DID documents)
    did_repository: Arc<DidRepository>,

    /// Repositories (kept for handler registration)
    connection_repository: Arc<dyn ConnectionRepositoryTrait>,

    /// Envelope service for JWE encryption/decryption
    envelope_service: Option<Arc<EnvelopeService>>,

    /// DID resolver for DIDComm (kept for DHT configuration)
    did_resolver: Option<Arc<AgentDIDResolver>>,

    /// DID document service for DID resolution and key/endpoint extraction
    did_document_service: Arc<didcomm::messaging::DidCommDocumentService>,

    /// User profile service (storage-backed, persists across restarts)
    pub profile_service: Arc<protocol_user_profile::UserProfileService>,

    /// OID4VCI holder service — stateless, exposes resolve_credential_offer +
    /// request_credential for wallets receiving credentials from external
    /// OID4VC issuers (e.g. EU EUDI Wallet ecosystem).
    pub oid4vci_holder: Arc<crate::modules::oid4vci::Oid4vciHolderService>,

    /// OID4VCI issuer service — server-side credential issuance over OID4VC,
    /// optional because most wallets don't act as issuers. Constructed via
    /// `AgentBuilder::with_oid4vci_issuer(...)`.
    pub oid4vci_issuer: Option<Arc<crate::modules::oid4vci::Oid4vciIssuerService>>,

    /// OID4VP holder service — stateless, for presenting credentials to
    /// OID4VC verifiers.
    pub oid4vp_holder: Arc<crate::modules::oid4vp::Oid4vpHolderService>,

    /// OID4VP verifier service — server-side: create authorization requests
    /// and verify posted vp_tokens (SD-JWT / JWT-VC). Sessions persist in the
    /// agent's storage; state changes fire `(oid4vp, state_changed)` events.
    pub oid4vp_verifier: Arc<crate::modules::oid4vp::Oid4vpVerifierService>,

    /// Wallet metadata document advertised to OID4VP verifiers (formats,
    /// algorithms, client_id schemes supported). Defaults from
    /// `WalletMetadata::default_for_supported_formats()`; override via
    /// `AgentBuilder::with_wallet_metadata(...)`.
    pub wallet_metadata: Arc<crate::modules::oid4vp::WalletMetadata>,

    /// Mediation module (optional). Held as an `Arc` so it can be both used
    /// directly (recipient/mediator APIs, repository) AND driven as a
    /// self-wiring [`agent_module::AgentModule`] via the module loop.
    pub mediation: Option<Arc<MediationModule>>,

    /// Push-notifications module — wallet-side `set/delete/get-device-info`
    /// (RFC 0734). Always constructed when the agent has
    /// a mediation module and a sender, since the API itself does not
    /// require a granted mediation until first use.
    pub push_notifications: Option<Arc<crate::modules::PushNotificationsModule>>,

    /// Mediator's DID + endpoint, populated after a mediation grant is
    /// received.
    pub mediator_did_cell: Arc<RwLock<Option<String>>>,
    pub mediator_endpoint_cell: Arc<RwLock<Option<String>>>,

    /// Injectable blockchain service (for external clients like AjnaClient)
    /// This allows using the Agent with blockchain functionality via dependency injection
    blockchain_service: Option<Arc<dyn BlockchainService>>,

    /// AnonCreds module — DIDComm issue-credential v3 holder/issuer
    /// services + present-proof. Opt-in via `setup_anoncreds`; loaded
    /// only when the `anoncreds` feature is on.
    #[cfg(feature = "anoncreds")]
    pub anoncreds: Option<Arc<crate::modules::AnonCredsModule>>,

    /// Transport manager
    pub transport: TransportManager,

    /// Message dispatcher
    pub dispatcher: MessageDispatcher,

    /// Handler registry for DIDComm messages
    handler_registry: Arc<RwLock<didcomm::messaging::HandlerRegistry>>,

    /// Declarative feature registry for Discover Features (roles/goal-codes/send-only)
    feature_registry: Arc<RwLock<didcomm::messaging::FeatureRegistry>>,

    /// Registered mediation key (did:key format) shared with handlers
    /// CRITICAL: This is the key registered with the mediator. All connection DIDs
    /// must use this key as their recipient key, otherwise the mediator cannot
    /// route Forward messages to us.
    registered_mediation_key: Arc<std::sync::RwLock<Option<String>>>,

    /// Mediation routing keys from the mediator grant message, shared with handlers
    /// These are the ONLY keys that should go into
    /// DID document routingKeys field. The agent's registered key should NOT be here.
    mediation_routing_keys: Arc<std::sync::RwLock<Option<Vec<String>>>>,

    /// Pending key registrations - keys created by connection handlers that need
    /// to be registered with the mediator via keylist-update BEFORE the response is sent.
    /// Each connection gets a unique key
    /// that is registered with the mediator for message routing.
    pending_key_registrations: Arc<std::sync::RwLock<Vec<String>>>,

    /// Processed message IDs for deduplication.
    /// Prevents duplicate processing when both Rust background polling and iOS FFI polling
    /// pick up the same message from the mediator.
    processed_message_ids: Arc<std::sync::RwLock<std::collections::HashSet<String>>>,

    /// Message processor for handling inbound messages
    message_processor: Arc<MessageProcessor>,

    /// Message router for routing messages to handlers
    message_router: Arc<MessageRouter>,

    /// Message encryption service (public for direct access)
    pub message_encryption: Arc<MessageEncryption>,

    /// Canonical DIDComm sender. Every site that packs+sends a DIDComm
    /// message should go through this instead of re-implementing the
    /// resolve/pack/forward/POST dance.
    pub didcomm_sender: Arc<crate::messaging::DidCommSender>,

    /// Event bus
    pub events: Arc<EventBus>,

    /// Shared HTTP client, tuned for DIDComm: HTTP/2 prior knowledge,
    /// keepalive on, idle pool kept warm so back-to-back POSTs to the same
    /// mediator (connection-request → mediate-request → keylist-update)
    /// share a single TLS connection. Construct via
    /// `crate::http::shared_didcomm_client()`.
    ///
    /// All HTTP transport on `Agent` MUST go through this client — the
    /// `HttpOutboundTransport` clones it for outbound DIDComm sends, and
    /// `Agent::setup_mediation` + `register_recipient_key_with_mediator`
    /// clone it for the mediation-bootstrap POSTs. Building ad-hoc
    /// `reqwest::Client::new()` instances is forbidden: each fresh client
    /// pays a TLS handshake.
    pub http_client: reqwest::Client,

    /// Discovered peers storage
    pub discovered_peers: crate::discovery::DiscoveredPeers,

    /// mDNS discovery service (optional - enabled via config, requires `discovery` feature)
    #[cfg(feature = "discovery")]
    mdns_discovery: Arc<RwLock<Option<crate::discovery::mdns::MdnsDiscovery>>>,

    /// BLE discovery service (optional - enabled via config, requires `discovery` feature)
    #[cfg(feature = "discovery")]
    ble_discovery: Arc<RwLock<Option<crate::discovery::ble::BleDiscovery>>>,

    /// Agent state
    state: Arc<RwLock<AgentState>>,

    /// Agent's own DID and key ID (set during initialization)
    agent_did: Arc<RwLock<Option<String>>>,
    agent_key_id: Arc<RwLock<Option<String>>>,

    /// Notify waiters when a connection response is processed (event-driven, replaces polling)
    connection_ready_notify: Arc<Notify>,

    /// Notify waiters when a mediation grant is processed (event-driven, replaces polling)
    grant_notify: Arc<Notify>,

    /// Pluggable, self-wiring agent modules (see [`agent_module::AgentModule`]).
    ///
    /// The agent does not name concrete module types here: the builder is
    /// handed modules via `with_module` (default set assembled in
    /// `builder::default_modules`) and stores them in this list, ordered by
    /// `priority()` descending. `initialize()` loops the list calling
    /// `register(&ctx)`; `shutdown()` loops in reverse calling `shutdown(&ctx)`.
    /// Typed access is via [`Agent::module`], backed by the DI container.
    agent_modules: Vec<Arc<dyn agent_module::AgentModule>>,
}

mod accessors;
mod lifecycle;
mod mediation;
mod messaging;
