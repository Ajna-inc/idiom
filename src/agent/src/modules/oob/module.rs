//! Out-of-Band Module
//!
//! High-level API for the Out-of-Band protocol, providing ergonomic methods
//! to manage OOB invitations and related operations.
//!
//! that coordinates multiple agent subsystems (DID creation, encryption, transport, connections).

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use crate::messaging::{MessageEncryption, MessageProcessor};
use crate::modules::{dids::DidManager, ConnectionsModule};
use crate::transport::{EncryptedMessage, TransportManager};
use agent_core::traits::{BlockchainService, WalletProvider};
use did::core::DidRepository;
use didcomm::core::{EnvelopeService, MessageBuilder as DidcommMessageBuilder, PackOptions};
use protocol_coordinate_mediation::ForwardMessage;
use protocol_oob::{
    repository::oob_repository::OutOfBandRepositoryTrait, OutOfBandApi, OutOfBandInvitation,
    OutOfBandRecord, OutOfBandRepository, OutOfBandRole, OutOfBandService as ServiceType,
};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

/// DID Exchange protocol-version URIs advertised as OOB `handshake_protocols`.
/// These are the bare protocol identifiers (no message suffix), sent verbatim
/// in out-of-band invitations, so the exact strings are wire-format.
const DIDEXCHANGE_1_1: &str = "https://didcomm.org/didexchange/1.1";
const DIDEXCHANGE_2_0: &str = "https://didcomm.org/didexchange/2.0";

/// Async callback that mints a fresh Ed25519 recipient key, registers it
/// with the active mediator via RFC 0211 keylist-update, and returns the
/// did:key. Used per-invitation accept to give every outbound connection a
/// distinct mediator-routed recipient — obtains routing and registers it
/// with the mediator.
///
/// Reusing one shared key (the previous behaviour) made every
/// `create_peer_did_1_with_registered_key` produce an identical
/// `did:peer:1z…`, so two invitations from any peer collided on `our_did`
/// in the connection repository.
/// Returns `(recipient_did_key, wallet_key_id)` — the fresh did:key plus the
/// wallet key id backing it, so the caller can build a self-resolving
/// did:peer:2 that maps to a decryptable key.
pub type MintRecipientKeyFn =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(String, String)>> + Send>> + Send + Sync>;

/// Ensure a key is in base58 verkey format for Forward message 'to' field
///
/// The Forward `to` field carries the base58 form of the recipient key.
/// The mediator converts did:key → base58 during keylist-update storage
/// and does EXACT STRING MATCH on base58 verkey during Forward lookup.
fn ensure_base58_verkey(key: &str) -> Result<String> {
    if key.starts_with("did:key:z") {
        return did::methods::key::did_key_to_base58_verkey(key)
            .ok_or_else(|| AgentError::OutOfBand(format!("Failed to decode did:key: {}", key)));
    }
    // Already base58 or unknown format, return as-is
    Ok(key.to_string())
}

/// Configuration for creating an invitation
#[derive(Debug, Clone, Default)]
pub struct InvitationConfig {
    /// Human-readable label for the inviter
    pub label: Option<String>,

    /// Goal code (machine-readable)
    pub goal_code: Option<String>,

    /// Goal description (human-readable)
    pub goal: Option<String>,

    /// Whether this invitation can be used multiple times
    pub multi_use: bool,

    /// Auto-accept connections from this invitation
    pub auto_accept: Option<bool>,

    /// Service endpoints (DIDs or inline services)
    pub services: Option<Vec<ServiceType>>,

    /// Handshake protocols to use
    pub handshake_protocols: Option<Vec<String>>,

    /// If true, add a mesh:// service endpoint to the invitation
    /// so the DIDComm connection can be established over BLE mesh
    pub include_mesh_endpoint: bool,

    /// Mesh routing ID hex (set by the agent when mesh is active)
    pub mesh_routing_id: Option<String>,

    /// If true, prefer DIDComm v2 for this invitation.
    /// Sets handshake_protocols to both didexchange/2.0 and 1.1 (fallback).
    /// Uses did:peer:2 (self-resolving) as the invitation service.
    pub prefer_v2: bool,
}

impl InvitationConfig {
    /// Create a new invitation configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the label
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set the goal
    pub fn with_goal(mut self, goal_code: impl Into<String>, goal: impl Into<String>) -> Self {
        self.goal_code = Some(goal_code.into());
        self.goal = Some(goal.into());
        self
    }

    /// Set multi-use
    pub fn with_multi_use(mut self, multi_use: bool) -> Self {
        self.multi_use = multi_use;
        self
    }

    /// Set auto-accept
    pub fn with_auto_accept(mut self, auto_accept: bool) -> Self {
        self.auto_accept = Some(auto_accept);
        self
    }

    /// Set services
    pub fn with_services(mut self, services: Vec<ServiceType>) -> Self {
        self.services = Some(services);
        self
    }

    /// Set handshake protocols
    pub fn with_handshake_protocols(mut self, protocols: Vec<String>) -> Self {
        self.handshake_protocols = Some(protocols);
        self
    }

    /// Include a mesh:// endpoint in the invitation
    pub fn with_mesh_endpoint(mut self, routing_id_hex: String) -> Self {
        self.include_mesh_endpoint = true;
        self.mesh_routing_id = Some(routing_id_hex);
        self
    }

    /// Prefer DIDComm v2 for this invitation.
    /// Sets dual handshake protocols (v2 + v1 fallback) and uses did:peer:2 service.
    pub fn with_prefer_v2(mut self) -> Self {
        self.prefer_v2 = true;
        self
    }
}

/// Result type for receiving an invitation
#[derive(Debug)]
pub struct ReceiveInvitationResult {
    /// The created OOB record
    pub oob_record: OutOfBandRecord,

    /// The connection record ID (if a connection was created)
    pub connection_record_id: Option<String>,
}

/// Information about a single service endpoint in an OOB invitation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Index of this service in the invitation's services array
    pub index: usize,
    /// The service endpoint URL (e.g., "https://mediator.ajna.dev" or "mesh://a1b2c3...")
    pub endpoint: String,
    /// Transport type: "http", "mesh", or "did"
    pub transport_type: String,
    /// For mesh services, the routing ID (hex). None for http/did services.
    pub routing_id: Option<String>,
}

/// Parsed invitation info with label and available services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedInvitationInfo {
    /// Invitation label (e.g., "BWN Wallet")
    pub label: String,
    /// Available service endpoints
    pub services: Vec<ServiceInfo>,
}

/// Out-of-Band Module providing high-level protocol APIs
///
/// This module contains all the orchestration logic needed for OOB protocol operations.
pub struct OutOfBandModule {
    /// Low-level OOB API (for basic record operations). Built lazily in
    /// `register` (or supplied via `new`).
    api: once_cell::sync::OnceCell<Arc<OutOfBandApi>>,

    /// Orchestration dependencies, resolved from the DI container in
    /// [`AgentModule::register`] (or supplied via `new_with_dependencies`).
    /// `OnceCell::get()` yields `Option<&T>`, matching the previous
    /// `Option::as_ref()` guard pattern.
    config: once_cell::sync::OnceCell<AgentConfig>,
    wallet_provider: once_cell::sync::OnceCell<Arc<dyn WalletProvider>>,
    did_repository: once_cell::sync::OnceCell<Arc<DidRepository>>,
    oob_repository: once_cell::sync::OnceCell<Arc<OutOfBandRepository>>,
    transport: once_cell::sync::OnceCell<Arc<TransportManager>>,
    connections: once_cell::sync::OnceCell<Arc<ConnectionsModule>>,
    message_encryption: once_cell::sync::OnceCell<Arc<MessageEncryption>>,
    message_processor: once_cell::sync::OnceCell<Arc<MessageProcessor>>,

    /// Mediation routing info (set when agent has active mediation)
    /// This is used to include routing info in DID documents for mediated connections
    /// Wrapped in RwLock for interior mutability (safe mutation from Arc<Agent>)
    mediation_endpoint: RwLock<Option<String>>,
    mediation_routing_keys: RwLock<Option<Vec<String>>>,
    /// Registered recipient key (did:key) for mediation - registered with mediator.
    /// Used as the recipient key on the mediator connection itself + as a
    /// fallback when `mint_recipient_key` is not wired.
    registered_recipient_key: RwLock<Option<String>>,
    /// Optional per-invitation recipient-key minter. When set, every OOB
    /// accept calls this to obtain a fresh did:key already registered with
    /// the mediator.
    mint_recipient_key: RwLock<Option<MintRecipientKeyFn>>,

    /// EnvelopeService for version-aware DIDComm encryption (v1/v2)
    /// This is set after Agent initialization via set_envelope_service().
    /// Wrapped in RwLock for interior mutability so it can be set on a
    /// shared reference (the module is stored behind `Arc` in the agent's
    /// DI container).
    envelope_service: RwLock<Option<Arc<EnvelopeService>>>,

    /// Blockchain service for handle resolution (optional).
    /// Wrapped in RwLock for interior mutability (see `envelope_service`).
    blockchain_service: RwLock<Option<Arc<dyn BlockchainService>>>,
}

impl OutOfBandModule {
    /// Config-only constructor (no agent deps). All orchestration dependencies
    /// (including the low-level API) are resolved from the DI container when the
    /// module is registered with an agent (see [`AgentModule::register`]).
    pub fn new_config_only() -> Self {
        Self {
            api: once_cell::sync::OnceCell::new(),
            config: once_cell::sync::OnceCell::new(),
            wallet_provider: once_cell::sync::OnceCell::new(),
            did_repository: once_cell::sync::OnceCell::new(),
            oob_repository: once_cell::sync::OnceCell::new(),
            transport: once_cell::sync::OnceCell::new(),
            connections: once_cell::sync::OnceCell::new(),
            message_encryption: once_cell::sync::OnceCell::new(),
            message_processor: once_cell::sync::OnceCell::new(),
            mediation_endpoint: RwLock::new(None),
            mediation_routing_keys: RwLock::new(None),
            registered_recipient_key: RwLock::new(None),
            mint_recipient_key: RwLock::new(None),
            envelope_service: RwLock::new(None),
            blockchain_service: RwLock::new(None),
        }
    }

    /// Create a new OutOfBandModule with just the API (for basic operations)
    pub fn new(api: Arc<OutOfBandApi>) -> Self {
        let m = Self::new_config_only();
        let _ = m.api.set(api);
        m
    }

    /// Create a new OutOfBandModule with all dependencies (for full orchestration)
    ///
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_dependencies(
        api: Arc<OutOfBandApi>,
        config: AgentConfig,
        wallet_provider: Arc<dyn WalletProvider>,
        did_repository: Arc<DidRepository>,
        oob_repository: Arc<OutOfBandRepository>,
        transport: Arc<TransportManager>,
        connections: Arc<ConnectionsModule>,
        message_encryption: Arc<MessageEncryption>,
        message_processor: Arc<MessageProcessor>,
    ) -> Self {
        let m = Self::new_config_only();
        let _ = m.api.set(api);
        let _ = m.config.set(config);
        let _ = m.wallet_provider.set(wallet_provider);
        let _ = m.did_repository.set(did_repository);
        let _ = m.oob_repository.set(oob_repository);
        let _ = m.transport.set(transport);
        let _ = m.connections.set(connections);
        let _ = m.message_encryption.set(message_encryption);
        let _ = m.message_processor.set(message_processor);
        m
    }

    /// Accessor for the low-level OOB API. Panics if used before the API is set
    /// (i.e. before registration for a config-only module).
    fn api(&self) -> &Arc<OutOfBandApi> {
        self.api
            .get()
            .expect("OutOfBandModule API used before register")
    }

    /// Set the EnvelopeService for version-aware DIDComm encryption
    ///
    /// This should be called after Agent::initialize() to enable v2 packing with v1 fallback.
    /// If not set, the module will fall back to using MessageEncryption (v1 only).
    pub fn set_envelope_service(&self, envelope_service: Arc<EnvelopeService>) {
        *self.envelope_service.write().unwrap() = Some(envelope_service);
    }

    /// Set the blockchain service for handle resolution
    pub fn set_blockchain_service(&self, service: Arc<dyn BlockchainService>) {
        *self.blockchain_service.write().unwrap() = Some(service);
    }

    /// Set mediation routing info for creating mediated DID documents
    ///
    /// When set, the module will include this routing info in DID documents created
    /// for connection requests. This is required for agents that use mediation
    /// (e.g., browser-based agents that cannot receive direct inbound connections).
    ///
    /// # Arguments
    /// * `endpoint` - The mediator's endpoint URL
    /// * `routing_keys` - The mediator's routing keys (usually in did:key format)
    /// * `registered_recipient_key` - The recipient key (did:key) that was registered with the mediator via keylist update
    /// Set mediation routing info (thread-safe with interior mutability)
    ///
    /// This method uses interior mutability via RwLock, so it can be called
    /// on a shared reference (from Arc<Agent>). This is the proper way to
    /// set mediation routing after agent initialization.
    pub fn set_mediation_routing(
        &self,
        endpoint: String,
        routing_keys: Vec<String>,
        registered_recipient_key: Option<String>,
    ) {
        tracing::debug!(
            "[OOB] set_mediation_routing: endpoint={}, routing_keys={:?}",
            endpoint,
            routing_keys
        );
        tracing::debug!("📍 [OOB] Setting mediation routing (interior mutability):");
        tracing::debug!("   Endpoint: {}", endpoint);
        tracing::debug!("   Routing keys: {:?}", routing_keys);
        if let Some(ref key) = &registered_recipient_key {
            tracing::debug!("   Registered recipient key: {}", key);
        }

        // Empty routing_keys is valid for direct-routing mediators.
        // The mediator routes by JWE recipient key inspection instead of Forward unwrapping.
        // We just need endpoint + registered_recipient_key.
        if routing_keys.is_empty() {
            tracing::debug!("[OOB] set_mediation_routing with empty routing_keys — using direct routing (Aries TS-compatible)");
            tracing::debug!(
                "[OOB] set_mediation_routing: empty routing_keys (direct routing mode)"
            );
        }

        // Use write locks to update the values
        if let Ok(mut ep) = self.mediation_endpoint.write() {
            *ep = Some(endpoint);
            tracing::debug!("   ✓ Endpoint set successfully");
        } else {
            tracing::debug!("   ❌ Failed to acquire write lock for endpoint!");
        }

        if let Ok(mut rk) = self.mediation_routing_keys.write() {
            *rk = Some(routing_keys);
            tracing::debug!("   ✓ Routing keys set successfully");
        } else {
            tracing::debug!("   ❌ Failed to acquire write lock for routing_keys!");
        }

        if let Ok(mut rrk) = self.registered_recipient_key.write() {
            *rrk = registered_recipient_key;
            tracing::debug!("   ✓ Registered recipient key set successfully");
        } else {
            tracing::debug!("   ❌ Failed to acquire write lock for registered_recipient_key!");
        }
    }

    /// Install the per-invitation recipient-key minter.
    ///
    /// When wired, every call to `accept_invitation_with_service_index`
    /// invokes the minter to obtain a fresh did:key already registered with
    /// the mediator. Without it the module falls back to the singleton
    /// `registered_recipient_key`, which causes deterministic did:peer:1
    /// collisions across multiple invitations (one shared recipient key →
    /// identical genesis_doc hash → same DID).
    pub fn set_mint_recipient_key(&self, minter: MintRecipientKeyFn) {
        if let Ok(mut g) = self.mint_recipient_key.write() {
            *g = Some(minter);
            tracing::debug!("[OOB] mint_recipient_key callback installed");
        }
    }

    /// Check if mediation routing is configured
    ///
    /// Returns true if both mediation_endpoint and mediation_routing_keys are set.
    /// NOTE: This does NOT check if registered_recipient_key is set - use is_ready_for_mediated_invitations for that.
    pub fn has_mediation_routing(&self) -> bool {
        let has_endpoint = self
            .mediation_endpoint
            .read()
            .map(|ep| ep.is_some())
            .unwrap_or(false);
        // routing_keys configured (even if empty — empty means direct routing)
        let has_routing_config = self
            .mediation_routing_keys
            .read()
            .map(|rk| rk.is_some())
            .unwrap_or(false);
        let has_recipient_key = self
            .registered_recipient_key
            .read()
            .map(|rrk| rrk.is_some())
            .unwrap_or(false);

        tracing::debug!("📍 [OOB] has_mediation_routing check:");
        tracing::debug!("   has_endpoint: {}", has_endpoint);
        tracing::debug!("   has_routing_config: {}", has_routing_config);
        tracing::debug!("   has_recipient_key: {}", has_recipient_key);

        has_endpoint && has_routing_config && has_recipient_key
    }

    /// Check if the module is ready to create mediated invitations
    ///
    /// Returns true only if ALL of the following are set:
    /// - mediation_endpoint
    /// - mediation_routing_keys (non-empty)
    /// - registered_recipient_key
    ///
    /// This is stricter than has_mediation_routing() because it ensures the
    /// registered key is available, which is required for the mediator to
    /// route messages to us.
    pub fn is_ready_for_mediated_invitations(&self) -> bool {
        let has_endpoint = self
            .mediation_endpoint
            .read()
            .map(|ep| ep.is_some())
            .unwrap_or(false);
        let has_routing_keys = self
            .mediation_routing_keys
            .read()
            .map(|rk| rk.as_ref().map(|k| !k.is_empty()).unwrap_or(false))
            .unwrap_or(false);
        let has_recipient_key = self
            .registered_recipient_key
            .read()
            .map(|rrk| rrk.is_some())
            .unwrap_or(false);

        tracing::info!("[OOB] is_ready_for_mediated_invitations check: endpoint={}, routing_keys={}, recipient_key={}",
            has_endpoint, has_routing_keys, has_recipient_key);

        has_endpoint && has_routing_keys && has_recipient_key
    }

    /// Get diagnostic info about the current mediation routing state
    pub fn get_mediation_routing_state(&self) -> (bool, bool, bool) {
        let has_endpoint = self
            .mediation_endpoint
            .read()
            .map(|ep| ep.is_some())
            .unwrap_or(false);
        let has_routing_keys = self
            .mediation_routing_keys
            .read()
            .map(|rk| rk.as_ref().map(|k| !k.is_empty()).unwrap_or(false))
            .unwrap_or(false);
        let has_recipient_key = self
            .registered_recipient_key
            .read()
            .map(|rrk| rrk.is_some())
            .unwrap_or(false);

        (has_endpoint, has_routing_keys, has_recipient_key)
    }

    /// Create an Out-of-Band invitation (basic version)
    ///
    /// # Arguments
    /// * `config` - Configuration for the invitation
    ///
    /// # Returns
    /// The created OutOfBandRecord containing the invitation
    ///
    /// # Example
    /// ```rust,no_run
    /// use agent::Agent;
    /// use agent::modules::oob::InvitationConfig;
    ///
    /// # async fn example(agent: Agent) -> Result<(), Box<dyn std::error::Error>> {
    /// let config = InvitationConfig::new()
    ///     .with_label("Faber College")
    ///     .with_handshake_protocols(vec![
    ///         "https://didcomm.org/didexchange/1.1".to_string()
    ///     ]);
    ///
    /// let record = agent.oob().create_invitation(config).await?;
    /// let url = record.invitation.to_url("https://faber.edu")?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_invitation(&self, config: InvitationConfig) -> Result<OutOfBandRecord> {
        // Determine services to use
        let services = if let Some(services) = config.services {
            services
        } else {
            // Return error - services are required
            // The Agent should provide these when creating invitations
            return Err(AgentError::OutOfBand(
                "Services are required for invitation. Use Agent-level method or provide services."
                    .to_string(),
            ));
        };

        // Determine handshake protocols
        let handshake_protocols = config.handshake_protocols.or_else(|| {
            if config.prefer_v2 {
                // Dual-protocol: v2 preferred, v1 fallback
                Some(vec![
                    DIDEXCHANGE_2_0.to_string(),
                    DIDEXCHANGE_1_1.to_string(),
                ])
            } else {
                // Default: DID Exchange 1.1 only
                Some(vec![DIDEXCHANGE_1_1.to_string()])
            }
        });

        // Create invitation based on configuration
        let record = if config.multi_use {
            if let (Some(_goal_code), Some(_goal)) = (config.goal_code, config.goal) {
                return Err(AgentError::OutOfBand(
                    "Multi-use invitations cannot have goals".to_string(),
                ));
            }

            self.api()
                .create_multi_use_invitation(services, config.label, handshake_protocols)
                .await?
        } else if let (Some(goal_code), Some(goal)) = (config.goal_code, config.goal) {
            self.api()
                .create_invitation_with_goal(
                    services,
                    config.label,
                    goal_code,
                    goal,
                    handshake_protocols,
                )
                .await?
        } else {
            self.api()
                .create_invitation(services, config.label, handshake_protocols)
                .await?
        };

        Ok(record)
    }

    /// Create an Out-of-Band invitation with automatic endpoint configuration
    ///
    /// This orchestration method automatically creates an inline service with the agent's
    /// endpoint and a generated key.
    /// handles the routing and service creation.
    ///
    /// # Arguments
    /// * `config` - Invitation configuration (services will be auto-generated if not provided)
    ///
    /// # Returns
    /// The created OutOfBandRecord
    pub async fn create_invitation_with_auto_services(
        &self,
        config: InvitationConfig,
    ) -> Result<OutOfBandRecord> {
        let agent_config = self.config.get().ok_or_else(|| {
            AgentError::OutOfBand("Module not initialized with dependencies".to_string())
        })?;
        let wallet_provider = self.wallet_provider.get().ok_or_else(|| {
            AgentError::OutOfBand("Module not initialized with wallet provider".to_string())
        })?;
        let oob_repository = self.oob_repository.get().ok_or_else(|| {
            AgentError::OutOfBand("Module not initialized with OOB repository".to_string())
        })?;

        // Add the agent's endpoint as an inline service if no services provided
        let (config_with_services, maybe_key_mapping) = if config.services.is_none() {
            // Read mediation routing from RwLock (thread-safe)
            let med_endpoint = self
                .mediation_endpoint
                .read()
                .map(|r| r.clone())
                .unwrap_or(None);
            let med_routing_keys = self
                .mediation_routing_keys
                .read()
                .map(|r| r.clone())
                .unwrap_or(None);
            let med_recipient_key = self
                .registered_recipient_key
                .read()
                .map(|r| r.clone())
                .unwrap_or(None);

            // Use mediation routing if endpoint + recipient_key are set.
            // routing_keys MAY be empty (direct routing mode) — the mediator
            // will route by JWE recipient key lookup instead of Forward unwrapping.
            let has_mediation =
                med_endpoint.is_some() && med_recipient_key.is_some() && med_routing_keys.is_some();

            tracing::debug!("📍 [OOB] Checking mediation routing for invitation:");
            tracing::debug!("   has_mediation: {}", has_mediation);
            tracing::debug!("   med_endpoint: {:?}", med_endpoint);
            tracing::debug!("   med_routing_keys: {:?}", med_routing_keys);
            tracing::debug!("   med_recipient_key: {:?}", med_recipient_key);

            // Mediation routing: use mediator endpoint + routing_keys from grant.
            // Empty routing_keys is valid (direct routing mode) — mediator
            // routes by recipient key lookup in JWE headers.
            let (endpoint, routing_keys) = if has_mediation {
                let ep = med_endpoint.as_ref().unwrap();
                let rk = med_routing_keys.as_ref().cloned().unwrap_or_default();
                if rk.is_empty() {
                    tracing::debug!("📍 [OOB] Creating invitation with direct-routing mediation (empty routing_keys):");
                    tracing::debug!("   Mediator endpoint: {}", ep);
                } else {
                    tracing::debug!("📍 [OOB] Creating invitation with Forward-routing mediation:");
                    tracing::debug!("   Mediator endpoint: {}", ep);
                    tracing::debug!("   Routing keys: {:?}", rk);
                }
                (ep.clone(), rk)
            } else {
                let direct_endpoint = agent_config.endpoints.first().ok_or_else(|| {
                    AgentError::OutOfBand("Agent has no endpoints configured".to_string())
                })?;
                tracing::debug!(
                    "📍 [OOB] Creating invitation with direct endpoint (no mediation): {}",
                    direct_endpoint
                );
                (direct_endpoint.clone(), vec![])
            };

            // --- DIDComm v2 path: create did:peer:2 as the invitation service ---
            if config.prefer_v2 {
                let did_repo = self.did_repository.get().ok_or_else(|| {
                    AgentError::OutOfBand(
                        "Module not initialized with DID repository (needed for v2)".to_string(),
                    )
                })?;
                let did_manager = DidManager::new(wallet_provider.clone(), did_repo.clone());

                let (peer_did_2, _key_id, _doc) = did_manager
                    .create_peer_did_2_with_service(&endpoint)
                    .await
                    .map_err(|e| {
                        AgentError::OutOfBand(format!("Failed to create did:peer:2: {}", e))
                    })?;

                tracing::debug!(
                    "📍 [OOB] Created did:peer:2 for v2 invitation: {}",
                    peer_did_2
                );

                // Use DID reference instead of inline service (v2 is self-resolving)
                let services = vec![ServiceType::Did(peer_did_2)];
                // No key mapping needed — keys are embedded in the did:peer:2 DID
                (config.with_services(services), None)
            } else {
                // --- DIDComm v1 path (unchanged) ---

                // For mediated invitations, use the registered recipient key if available
                // This is CRITICAL - the mediator only knows about keys registered via keylist update
                // Creating a new key here would mean the mediator can't route messages to us
                let (did_key, maybe_key_id) = if has_mediation {
                    if let Some(ref registered_key) = med_recipient_key {
                        tracing::debug!(
                            "📍 [OOB] Using registered recipient key for mediated invitation: {}",
                            registered_key
                        );
                        tracing::debug!(
                            "📍 [OOB] Mediator has this key registered for pickup (did:key format)"
                        );
                        // Use the registered key - no new key mapping needed since key already exists
                        (registered_key.clone(), None)
                    } else {
                        // No registered key - this is a FATAL error for mediated invitations!
                        // Creating a new key here would mean the mediator can't route messages to us
                        // because it only knows about keys registered via keylist update.
                        tracing::error!(
                            "[OOB] CRITICAL ERROR: No registered recipient key for mediation!"
                        );
                        tracing::error!(
                            "[OOB] Mediation is configured but registered_recipient_key is None."
                        );
                        tracing::error!("[OOB] This means set_mediation_routing was not called with the key, or the key was not persisted.");
                        tracing::error!(
                            "[OOB] Refusing to create invitation with unregistered key!"
                        );
                        tracing::debug!(
                            "❌ [OOB] CRITICAL ERROR: No registered recipient key for mediation!"
                        );
                        tracing::debug!(
                            "   Mediation is configured (endpoint and routing_keys are set)."
                        );
                        tracing::debug!("   But registered_recipient_key is None.");
                        tracing::debug!("   This means invitations would use an unregistered key that the mediator doesn't know about.");
                        tracing::debug!("   Messages to this invitation would NOT be delivered!");
                        tracing::debug!("   FIX: Ensure set_mediation_routing is called with the registered key before creating invitations.");

                        return Err(AgentError::OutOfBand(
                        "Cannot create mediated invitation: registered_recipient_key is not set. \
                         Call set_mediation_routing with the registered key first, or wait for mediation setup to complete.".to_string()
                    ));
                    }
                } else {
                    // Direct connection (no mediation) - create a new key
                    let key = wallet_provider
                        .create_key(
                            agent_core::traits::KeyType::Ed25519,
                            agent_core::traits::KeyPurpose::AgentMessaging,
                        )
                        .await
                        .map_err(|e| {
                            AgentError::OutOfBand(format!("Failed to create key: {}", e))
                        })?;

                    let multicodec = vec![0xed, 0x01];
                    let mut multicodec_key = multicodec;
                    multicodec_key.extend_from_slice(&key.public_key);
                    let new_did_key = format!(
                        "did:key:{}",
                        multibase::encode(multibase::Base::Base58Btc, &multicodec_key)
                    );
                    tracing::debug!(
                        "📍 [OOB] Created new recipient key for direct invitation: {}",
                        new_did_key
                    );

                    (new_did_key, Some(key.id.clone()))
                };

                // Create an inline service with the agent's endpoint (and routing keys if mediated)
                let inline_service = protocol_oob::messages::InlineService {
                    id: "#service-1".to_string(),
                    service_type: "did-communication".to_string(),
                    service_endpoint: endpoint,
                    recipient_keys: vec![did_key.clone()],
                    routing_keys,
                };

                // Store the key mapping for later signing operations (only if we created a new key)
                let key_mapping = maybe_key_id.map(|key_id| (key_id, did_key.clone()));

                // Build services list — always include the HTTP/mediator service
                let mut services = vec![ServiceType::Inline(inline_service)];

                // Optionally add a mesh:// service endpoint for BLE mesh connections
                if config.include_mesh_endpoint {
                    if let Some(ref mesh_rid) = config.mesh_routing_id {
                        let mesh_service = protocol_oob::messages::InlineService {
                            id: "#service-mesh".to_string(),
                            service_type: "did-communication".to_string(),
                            service_endpoint: format!("mesh://{}", mesh_rid),
                            recipient_keys: vec![did_key],
                            routing_keys: vec![], // No routing keys for mesh — direct delivery
                        };
                        services.push(ServiceType::Inline(mesh_service));
                        tracing::debug!("📍 [OOB] Added mesh endpoint: mesh://{}", mesh_rid);
                    }
                }

                (config.with_services(services), key_mapping)
            } // close else (v1 path)
        } else {
            (config, None)
        };

        let mut record = self.create_invitation(config_with_services).await?;

        // Add the inline service key mapping if we created a key
        if let Some((kms_key_id, recipient_key_fingerprint)) = maybe_key_mapping {
            record.add_inline_service_key(protocol_oob::repository::InlineServiceKey::new(
                kms_key_id,
                recipient_key_fingerprint,
            ));

            // Update the record with the key mapping
            oob_repository.update(&record).await.map_err(|e| {
                AgentError::OutOfBand(format!("Failed to update OOB record: {}", e))
            })?;
        }

        Ok(record)
    }

    /// Accept an out-of-band invitation and create a connection
    ///
    /// This orchestration method ties together multiple subsystems:
    /// 1. Creating a did:peer:1 DID with service endpoint
    /// 2. Creating a connection request message
    /// 3. Adding signed did_doc~attach to the request
    /// 4. Packing and sending the request message
    ///
    ///
    /// # Arguments
    /// * `oob_record` - The out-of-band invitation record
    ///
    /// # Returns
    /// The connection record ID
    pub async fn accept_invitation(&self, oob_record: &OutOfBandRecord) -> Result<String> {
        self.accept_invitation_with_service_index(oob_record, 0)
            .await
    }

    /// Accept an out-of-band invitation using a specific service endpoint by index.
    ///
    /// This allows choosing between multiple service endpoints (e.g., mesh vs mediator).
    /// Index 0 is typically the HTTP mediator, index 1 is the mesh endpoint (if present).
    ///
    /// # Arguments
    /// * `oob_record` - The out-of-band invitation record
    /// * `service_index` - Index of the service endpoint to use from the invitation
    ///
    /// # Returns
    /// The connection record ID
    pub async fn accept_invitation_with_service_index(
        &self,
        oob_record: &OutOfBandRecord,
        service_index: usize,
    ) -> Result<String> {
        let agent_config = self.config.get().ok_or_else(|| {
            AgentError::OutOfBand("Module not initialized with dependencies".to_string())
        })?;
        let wallet_provider = self.wallet_provider.get().ok_or_else(|| {
            AgentError::OutOfBand("Module not initialized with wallet provider".to_string())
        })?;
        let did_repository = self.did_repository.get().ok_or_else(|| {
            AgentError::OutOfBand("Module not initialized with DID repository".to_string())
        })?;
        let transport = self.transport.get().ok_or_else(|| {
            AgentError::OutOfBand("Module not initialized with transport".to_string())
        })?;
        let connections = self.connections.get().ok_or_else(|| {
            AgentError::OutOfBand("Module not initialized with connections module".to_string())
        })?;
        let message_encryption = self.message_encryption.get().ok_or_else(|| {
            AgentError::OutOfBand("Module not initialized with message encryption".to_string())
        })?;

        // 1. Create our DID with service endpoint for this connection
        // Detect v2: if the invitation service is a did:peer:2 reference, create did:peer:2
        // Otherwise create did:peer:1 (existing behavior)
        let did_manager = DidManager::new(wallet_provider.clone(), did_repository.clone());

        // Check if invitation uses did:peer:2 service (v2 indicator)
        let invitation_is_v2 = oob_record
            .invitation
            .services
            .get(service_index)
            .map(|svc| matches!(svc, ServiceType::Did(did) if did.starts_with("did:peer:2")))
            .unwrap_or(false);

        // Read mediation routing from RwLock (thread-safe)
        let mediator_endpoint_opt = self
            .mediation_endpoint
            .read()
            .map(|r| r.clone())
            .unwrap_or(None);
        let routing_keys_opt = self
            .mediation_routing_keys
            .read()
            .map(|r| r.clone())
            .unwrap_or(None);
        let registered_key_opt = self
            .registered_recipient_key
            .read()
            .map(|r| r.clone())
            .unwrap_or(None);

        // Tracks whether OUR request DID ended up self-resolving (did:peer:2).
        // When true we skip the did_doc~attach below (nothing to attach).
        let mut our_did_is_v2 = invitation_is_v2;

        let (our_did, key_id, did_document) = if invitation_is_v2 {
            // V2 path: create did:peer:2 for the requester (self-resolving, no did_doc~attach needed)
            let our_service_endpoint = if let Some(ref ep) = mediator_endpoint_opt {
                ep.clone()
            } else {
                agent_config
                    .endpoints
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "http://localhost:3002".to_string())
            };
            tracing::debug!(
                "📍 Creating did:peer:2 for v2 requester DID: {}",
                our_service_endpoint
            );

            let (peer_did_2, kid, doc) = did_manager
                .create_peer_did_2_with_service(&our_service_endpoint)
                .await?;

            tracing::debug!("✓ Created did:peer:2 for requester: {}", peer_did_2);
            // Convert the JSON doc to a DidDocument-like value for downstream use
            (peer_did_2, kid, doc)
        } else if let (
            Some(ref mediator_endpoint),
            Some(ref routing_keys),
            Some(ref registered_key),
        ) = (
            &mediator_endpoint_opt,
            &routing_keys_opt,
            &registered_key_opt,
        ) {
            // Mint a fresh recipient key for THIS invitation (obtain routing +
            // register it with the mediator) and build a self-resolving
            // **did:peer:2** request DID so resolver-only counterparties
            // (some resolver-only agents, whose store_did_document always
            // resolves the request DID) accept it — did:peer:1 is rejected with
            // DIDMethodNotSupported. Falls back to the shared registered key +
            // did:peer:1 when the minter isn't wired (legacy; idiom↔idiom).
            let minter = self.mint_recipient_key.read().ok().and_then(|g| g.clone());
            let minted = if let Some(minter) = minter {
                match minter().await {
                    Ok((k, kid)) => {
                        tracing::debug!("[OOB] minted fresh recipient key: {}", k);
                        Some((k, kid))
                    }
                    Err(e) => {
                        tracing::warn!(
                            "[OOB] mint_recipient_key failed: {}; falling back to shared registered key + did:peer:1",
                            e
                        );
                        None
                    }
                }
            } else {
                None
            };

            if let Some((key_for_did, key_id_for_did)) = minted {
                tracing::debug!("📍 did:peer:2 (mediated) requester DID:");
                tracing::debug!("   Mediator endpoint: {}", mediator_endpoint);
                tracing::debug!("   Routing keys: {:?}", routing_keys);
                tracing::debug!("   Recipient key (this connection): {}", key_for_did);
                our_did_is_v2 = true;
                did_manager
                    .create_peer_did_2_with_service_and_routing(
                        mediator_endpoint,
                        routing_keys.clone(),
                        &key_for_did,
                        &key_id_for_did,
                    )
                    .await?
            } else {
                tracing::debug!("📍 did:peer:1 (mediated, shared registered key) requester DID");
                tracing::debug!(
                    "[OOB] Creating did:peer:1 with recipient key: {}",
                    registered_key
                );
                did_manager
                    .create_peer_did_1_with_registered_key(
                        mediator_endpoint,
                        routing_keys.clone(),
                        registered_key,
                    )
                    .await?
            }
        } else if let (Some(ref mediator_endpoint), Some(ref routing_keys)) =
            (&mediator_endpoint_opt, &routing_keys_opt)
        {
            // Use mediation routing but no registered key (fallback - less reliable)
            tracing::debug!(
                "📍 Using mediation routing for requester DID (no registered key - WARNING):"
            );
            tracing::debug!("   Mediator endpoint: {}", mediator_endpoint);
            tracing::debug!("   Routing keys: {:?}", routing_keys);
            tracing::debug!("[OOB] WARNING: Creating did:peer:1 WITHOUT registered key - Forward messages may not be delivered!");

            did_manager
                .create_peer_did_1_with_service_and_routing(mediator_endpoint, routing_keys.clone())
                .await?
        } else {
            // Use direct endpoint (or fall back to default)
            let our_service_endpoint = agent_config
                .endpoints
                .first()
                .cloned()
                .unwrap_or_else(|| "http://localhost:3002".to_string());

            tracing::debug!(
                "📍 Using direct endpoint for requester DID: {}",
                our_service_endpoint
            );

            did_manager
                .create_peer_did_1_with_service(&our_service_endpoint)
                .await?
        };

        if !invitation_is_v2 {
            tracing::debug!("✓ Created did:peer:1 for requester: {}", our_did);
        }

        // 2. Use ConnectionsModule to create the connection and request message.
        //    Use `current_label()` so a runtime label set via
        //    `Agent::set_label` overrides the cached config snapshot —
        //    the iOS shell builds the agent before FRE finishes, so without
        //    this we'd always ship the pre-FRE placeholder label
        //    ("Ajna") in the outbound connection-request.
        let (connection_record, mut request_message) = connections
            .accept_out_of_band_invitation(
                oob_record,
                our_did.clone(),
                Some(agent_config.current_label()),
            )
            .await?;

        // 3. Create signed did_doc~attach and add it to the request message.
        //    Skip when OUR did is did:peer:2 (self-resolving) — whether the
        //    invitation was v2 or we upgraded to did:peer:2 for mediation.
        if !our_did_is_v2 {
            tracing::debug!("📝 Creating signed did_doc~attach for request...");
            let did_doc_attach = did_manager
                .create_did_doc_attach_signed(did_document, &key_id)
                .await?;
            request_message = request_message.with_did_doc_attach(did_doc_attach);
            tracing::debug!("✓ Added did_doc~attach to request message");
        } else {
            tracing::debug!("📍 Skipping did_doc~attach (did:peer:2 is self-resolving)");
        }

        // 4. Get the recipient endpoint and recipient DID from the OOB invitation
        tracing::debug!(
            "🔍 [accept_invitation] Extracting endpoint from invitation (service_index={})...",
            service_index
        );
        let recipient_endpoint = oob_record
            .invitation
            .services
            .get(service_index)
            .ok_or_else(|| {
                AgentError::OutOfBand(format!(
                    "No service at index {} (invitation has {} services)",
                    service_index,
                    oob_record.invitation.services.len()
                ))
            })?;

        let (endpoint, recipient_did, routing_keys) = match recipient_endpoint {
            ServiceType::Did(did) => {
                tracing::debug!("  Service type: DID reference");
                tracing::debug!("  DID: {}", did);
                // For did:peer:2, extract endpoint from the S element in the DID string
                if did.starts_with("did:peer:2") {
                    use base64::Engine;
                    let s_prefix = ".S";
                    if let Some(s_start) = did.find(s_prefix) {
                        let s_data = &did[s_start + s_prefix.len()..];
                        // S element ends at next '.' or end of string
                        let s_encoded = s_data.split('.').next().unwrap_or(s_data);
                        if let Ok(decoded) =
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s_encoded)
                        {
                            if let Ok(service_json) =
                                serde_json::from_slice::<serde_json::Value>(&decoded)
                            {
                                let ep = service_json["s"].as_str().unwrap_or("").to_string();
                                let rk: Vec<String> = service_json["r"]
                                    .as_array()
                                    .map(|a| {
                                        a.iter()
                                            .filter_map(|v| v.as_str().map(String::from))
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                tracing::debug!("  Resolved endpoint from did:peer:2: {}", ep);
                                (ep, did.clone(), rk)
                            } else {
                                return Err(AgentError::OutOfBand(
                                    "Failed to parse did:peer:2 service JSON".to_string(),
                                ));
                            }
                        } else {
                            return Err(AgentError::OutOfBand(
                                "Failed to decode did:peer:2 service base64url".to_string(),
                            ));
                        }
                    } else {
                        return Err(AgentError::OutOfBand(
                            "did:peer:2 missing S (service) element".to_string(),
                        ));
                    }
                } else {
                    // For other DID methods, would need DID resolution
                    return Err(AgentError::OutOfBand(format!(
                        "DID service resolution not implemented for: {}",
                        did
                    )));
                }
            }
            ServiceType::Inline(service) => {
                tracing::debug!("  Service type: Inline");
                tracing::debug!("  Service ID: {}", service.id);
                tracing::debug!("  Service endpoint: {}", service.service_endpoint);
                tracing::debug!("  Recipient keys: {}", service.recipient_keys.len());
                tracing::debug!("  Routing keys: {}", service.routing_keys.len());

                // CRITICAL LOGGING: Trace routing keys extraction for mediation debugging
                tracing::debug!("[FORWARD-TRACE] ========================================");
                tracing::debug!("[FORWARD-TRACE] Extracting service from invitation:");
                tracing::debug!(
                    "[FORWARD-TRACE]   service_endpoint: {}",
                    service.service_endpoint
                );
                tracing::debug!(
                    "[FORWARD-TRACE]   recipient_keys: {:?}",
                    service.recipient_keys
                );
                tracing::debug!("[FORWARD-TRACE]   routing_keys: {:?}", service.routing_keys);
                tracing::debug!(
                    "[FORWARD-TRACE]   routing_keys.len(): {}",
                    service.routing_keys.len()
                );
                tracing::debug!(
                    "[FORWARD-TRACE]   routing_keys.is_empty(): {}",
                    service.routing_keys.is_empty()
                );
                tracing::debug!("[FORWARD-TRACE] ========================================");

                // Extract first recipient key as the recipient DID
                let recipient_did = service
                    .recipient_keys
                    .first()
                    .ok_or_else(|| {
                        AgentError::OutOfBand("No recipient keys in service".to_string())
                    })?
                    .clone();
                tracing::debug!("  Recipient DID: {}", recipient_did);

                (
                    service.service_endpoint.clone(),
                    recipient_did,
                    service.routing_keys.clone(),
                )
            }
        };

        tracing::debug!("✓ Extracted endpoint: {}", endpoint);
        tracing::debug!("✓ Recipient DID: {}", recipient_did);
        if !routing_keys.is_empty() {
            tracing::debug!("✓ Routing keys: {:?}", routing_keys);
        }

        // 5. Pack the request message with proper JWE encryption
        tracing::debug!("📦 Packing request message with JWE encryption...");

        // Debug: Print the message before packing
        let request_json = serde_json::to_string_pretty(&request_message)?;
        tracing::debug!("🔍 Request message BEFORE packing:");
        tracing::debug!("{}", request_json);

        // Use EnvelopeService for version-aware packing (v2 with v1 fallback) if available.
        // Clone the Arc out of the RwLock guard so we don't hold the lock across `.await`.
        let envelope_service_opt = self.envelope_service.read().unwrap().clone();
        let packed_jwe = if let Some(envelope_service) = envelope_service_opt {
            tracing::debug!("📦 Using EnvelopeService for version-aware packing");

            // Convert protocol message to DIDComm core message
            let msg_type = &request_message.msg_type;
            let msg_id = &request_message.id;

            // Add ~transport decorator for return routing (RFC 0092)
            // This is CRITICAL for agents behind NAT - tells the mediator to return
            // the connection response on the same HTTP connection
            let didcomm_msg = DidcommMessageBuilder::new(msg_type.clone())
                .id(msg_id.clone())
                .body(serde_json::to_value(&request_message)?)
                .from(our_did.clone())
                .to(vec![recipient_did.clone()])
                .add_extra(
                    "~transport".to_string(),
                    serde_json::json!({"return_route": "all"}),
                )
                .build();

            // Pack version follows the INVITATION (the peer's advertised
            // capability), not our own DID format. A v1 (inline-service)
            // invitation — an interoperable agent, the Ajna mediator, or an
            // idiom v1 peer — must be packed v1 even when OUR request DID is
            // did:peer:2 (which we use purely so resolver-only peers can
            // resolve it).
            // Without this, a did:peer:2 sender flips EnvelopeService to a v2
            // pack that fails against a v1 recipient.
            let pack_options = if invitation_is_v2 {
                PackOptions::with_fallback()
            } else {
                PackOptions::v1_only()
            };
            envelope_service
                .pack_encrypted_with_version(
                    &didcomm_msg,
                    &recipient_did,
                    Some(&our_did),
                    &pack_options,
                )
                .await
                .map_err(|e| AgentError::OutOfBand(format!("EnvelopeService pack failed: {}", e)))?
        } else {
            tracing::debug!("📦 Using MessageEncryption (v1 only) for packing");
            message_encryption
                .pack_encrypted_message(&request_message, &recipient_did, &our_did)
                .await?
        };
        tracing::debug!("✓ Message encrypted as JWE");
        tracing::debug!(
            "  JWE preview: {}...",
            &packed_jwe[..packed_jwe.len().min(100)]
        );

        // 5b. If there are routing keys, wrap in Forward envelope(s)
        // Each routing key gets its own Forward wrapper, encrypted with anoncrypt
        tracing::debug!("[FORWARD-TRACE] Checking routing_keys for Forward wrapping:");
        tracing::debug!("[FORWARD-TRACE]   routing_keys: {:?}", routing_keys);
        tracing::debug!("[FORWARD-TRACE]   is_empty: {}", routing_keys.is_empty());

        let final_packed_jwe = if !routing_keys.is_empty() {
            tracing::debug!("[FORWARD-TRACE] *** ENTERING FORWARD WRAPPING CODE PATH ***");
            tracing::debug!(
                "[FORWARD-TRACE] Wrapping message in Forward envelope(s) for {} routing key(s)",
                routing_keys.len()
            );

            let mut current_packed = packed_jwe;

            // Convert recipient key to base58 verkey for the Forward 'to' field
            // Mediators store base58 verkeys and do exact string match
            let mut current_to = ensure_base58_verkey(&recipient_did)?;
            tracing::debug!(
                "  → Forward 'to' field (base58): {} (from {})",
                current_to,
                recipient_did
            );

            // Process routing keys - the message is wrapped for each routing key
            // For DIDComm v1, Forward messages are anon-packed (no sender authentication)
            for routing_key in routing_keys.iter() {
                tracing::debug!("  → Creating Forward for routing key: {}", routing_key);

                // Parse the current packed message as JSON for the Forward wrapper
                let current_packed_json: serde_json::Value = serde_json::from_str(&current_packed)
                    .map_err(|e| {
                        AgentError::OutOfBand(format!("Failed to parse JWE as JSON: {}", e))
                    })?;

                // Forward 'to' field is in verkey (base58) format to match mediator's stored keys
                tracing::debug!("  → Forward 'to' field (verkey): {}", current_to);

                // Create Forward message with verkey format (matching mediator's stored keylist format)
                let forward_msg = ForwardMessage::new(current_to.clone(), current_packed_json);
                tracing::debug!("  → Forward message 'to': {}", forward_msg.to);

                // Debug: Print the Forward message structure
                if let Ok(forward_json) = serde_json::to_string_pretty(&forward_msg) {
                    tracing::debug!("  → Forward message structure:");
                    // Only print first 500 chars to avoid spam
                    let preview = if forward_json.len() > 500 {
                        format!("{}...", &forward_json[..500])
                    } else {
                        forward_json
                    };
                    tracing::debug!("{}", preview);
                }

                // Anon-pack the Forward message for the routing key
                // CRITICAL: Forward messages MUST use DIDComm v1 Anoncrypt for mediator compatibility
                // Do NOT use EnvelopeService here - it tries v2 first which mediators don't understand
                let forward_packed = message_encryption
                    .pack_anon_message(&forward_msg, routing_key)
                    .await
                    .map_err(|e| {
                        AgentError::OutOfBand(format!("Failed to anon-pack Forward: {}", e))
                    })?;

                // Debug: Decode and print the protected header to verify kid and algorithm
                if let Ok(jwe_json) = serde_json::from_str::<serde_json::Value>(&forward_packed) {
                    if let Some(protected_b64) = jwe_json.get("protected").and_then(|v| v.as_str())
                    {
                        use base64::Engine;
                        if let Ok(protected_bytes) =
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(protected_b64)
                        {
                            if let Ok(protected_str) = String::from_utf8(protected_bytes) {
                                tracing::debug!(
                                    "  → Forward JWE protected header: {}",
                                    protected_str
                                );
                            }
                        }
                    }
                }

                tracing::debug!("  ✓ Forward envelope created and encrypted");
                current_packed = forward_packed;
                // Convert routing_key to base58 verkey for next Forward layer (if any)
                current_to = ensure_base58_verkey(routing_key)?;
            }

            tracing::debug!("[FORWARD-TRACE] Forward wrapping COMPLETE");
            current_packed
        } else {
            tracing::debug!("[FORWARD-TRACE] Direct routing mode — sending authcrypt JWE directly (no Forward wrapping)");
            tracing::debug!("[FORWARD-TRACE] Mediator (if any) will route by recipient key lookup in JWE headers.");
            packed_jwe
        };

        // 6. Log final message before sending
        tracing::debug!("[FORWARD-TRACE] Sending message to endpoint: {}", endpoint);
        tracing::debug!(
            "[FORWARD-TRACE]   final_packed_jwe length: {} bytes",
            final_packed_jwe.len()
        );

        // 7. Create EncryptedMessage from JWE string
        let encrypted_msg = EncryptedMessage::new(
            "jwe".to_string(),
            "jwe".to_string(),
            final_packed_jwe,
            "jwe".to_string(),
        )
        .with_sender_endpoint(agent_config.endpoints.first().cloned().unwrap_or_default());

        // DIAG: surface exactly what the wallet is POSTing for the
        // DidExchange Request — endpoint, recipient_did, routing_keys.
        // Cross-reference with mediator `to=…` kubectl logs.
        tracing::debug!(
            target: "didcomm.diag",
            %recipient_did,
            %endpoint,
            ?routing_keys,
            "oob.send"
        );

        // 8. Send the request message via transport
        tracing::debug!("[FORWARD-TRACE] Sending encrypted request to: {}", endpoint);
        let response = transport
            .send_message(encrypted_msg, &endpoint)
            .await
            .map_err(|e| {
                tracing::debug!("[FORWARD-TRACE] FAILED to send message: {}", e);
                AgentError::Transport(e.to_string())
            })?;

        tracing::debug!("[FORWARD-TRACE] Encrypted request sent successfully!");

        // 8. Process HTTP response if present (contains Alice's connection response)
        if let Some(response_body) = response {
            tracing::debug!("📥 Processing HTTP response from Alice...");
            tracing::debug!("  Response size: {} bytes", response_body.len());

            // Debug: Check what we're actually receiving
            let preview = if response_body.len() > 200 {
                format!("{}...", &response_body[..200])
            } else {
                response_body.clone()
            };
            tracing::debug!("  Response preview: {}", preview);

            // Check if it's HTML (error page) instead of JSON
            if response_body.starts_with("<!DOCTYPE") || response_body.starts_with("<html") {
                tracing::debug!("❌ Received HTML response instead of DIDComm message!");
                tracing::debug!(
                    "  This usually indicates the HTTP endpoint returned an error page"
                );
                return Err(AgentError::Transport(
                    "Received HTML error page instead of DIDComm message".to_string(),
                ));
            }

            // The response is Alice's connection response message - decrypt it first
            let message_encryption = self.message_encryption.get().ok_or_else(|| {
                AgentError::OutOfBand("Message encryption not initialized".to_string())
            })?;

            // First decrypt the response (it's a JWE)
            let decrypted_response = message_encryption
                .decrypt_message(&response_body)
                .await
                .map_err(|e| AgentError::Transport(format!("Failed to decrypt response: {}", e)))?;

            // Then process the decrypted message
            let message_processor = self.message_processor.get().ok_or_else(|| {
                AgentError::OutOfBand("Message processor not initialized".to_string())
            })?;

            // Note: sender_did is None here because this is processing our own outbound response,
            // not an inbound message. The response handler doesn't need to reply back.
            tracing::debug!("[DEBUG-OOB] About to call process_message on decrypted response");
            tracing::debug!(
                "[DEBUG-OOB] decrypted_response preview: {}",
                &decrypted_response[..decrypted_response.len().min(200)]
            );
            let processed_response = message_processor
                .process_message(&decrypted_response, Some(endpoint.to_string()), None)
                .await
                .map_err(|e| {
                    tracing::debug!("[DEBUG-OOB] process_message FAILED: {}", e);
                    AgentError::Transport(format!("Failed to process response: {}", e))
                })?;
            tracing::debug!("[DEBUG-OOB] process_message completed successfully");

            if processed_response.is_some() {
                tracing::debug!("✓ Response processed - Alice sent a return message");
            } else {
                tracing::debug!("✓ Response processed - no return message needed");
            }
        } else {
            tracing::debug!("  No HTTP response body (202 Accepted pattern)");
        }

        // 9. Store transport metadata on the connection record
        // This records the selected transport, endpoint, and all available services
        // so we can switch transports later (e.g., mesh → mediator fallback)
        {
            let transport_type = if endpoint.starts_with("mesh://") {
                "mesh"
            } else {
                "http"
            };
            let available_services: Vec<serde_json::Value> = oob_record
                .invitation
                .services
                .iter()
                .enumerate()
                .map(|(idx, svc)| match svc {
                    ServiceType::Inline(inline) => {
                        let svc_type = if inline.service_endpoint.starts_with("mesh://") {
                            "mesh"
                        } else {
                            "http"
                        };
                        serde_json::json!({
                            "index": idx,
                            "endpoint": inline.service_endpoint,
                            "type": svc_type,
                            "recipient_keys": inline.recipient_keys,
                            "routing_keys": inline.routing_keys,
                        })
                    }
                    ServiceType::Did(did) => serde_json::json!({
                        "index": idx,
                        "endpoint": did,
                        "type": "did",
                    }),
                })
                .collect();

            let transport_metadata = serde_json::json!({
                "transport": {
                    "preferred": transport_type,
                    "selected_service_index": service_index,
                    "selected_endpoint": endpoint,
                    "available_services": available_services,
                }
            });

            tracing::debug!(
                "[OOB] Storing transport metadata: preferred={}, endpoint={}",
                transport_type,
                endpoint
            );
            if let Err(e) = connections
                .update_connection_metadata(&connection_record.id, transport_metadata)
                .await
            {
                tracing::debug!("[OOB] WARNING: Failed to store transport metadata: {}", e);
                // Non-fatal — connection still works, just without transport preference
            }
        }

        // 10. Return the connection record ID
        Ok(connection_record.id)
    }

    /// Receive an out-of-band invitation and optionally auto-create a connection
    ///
    /// - Stores the invitation
    /// - If auto_accept is true and invitation has handshake protocols, automatically creates connection
    ///
    /// # Arguments
    /// * `invitation` - The out-of-band invitation
    /// * `auto_accept` - Whether to automatically create a connection (default: true)
    ///
    /// # Returns
    /// ReceiveInvitationResult containing the OOB record and optional connection ID
    pub async fn receive_invitation_with_auto_accept(
        &self,
        invitation: OutOfBandInvitation,
        auto_accept: Option<bool>,
    ) -> Result<ReceiveInvitationResult> {
        self.receive_invitation_with_auto_accept_and_transport(invitation, auto_accept, None)
            .await
    }

    /// Receive an out-of-band invitation with optional service index for transport selection.
    ///
    /// # Arguments
    /// * `invitation` - The out-of-band invitation
    /// * `auto_accept` - Whether to automatically create a connection (default: true)
    /// * `service_index` - Which service endpoint to use (None = 0 = first/default)
    pub async fn receive_invitation_with_auto_accept_and_transport(
        &self,
        invitation: OutOfBandInvitation,
        auto_accept: Option<bool>,
        service_index: Option<usize>,
    ) -> Result<ReceiveInvitationResult> {
        // Default auto_accept to true
        let auto_accept = auto_accept.unwrap_or(true);
        let service_index = service_index.unwrap_or(0);
        tracing::debug!(
            "[AUTO-ACCEPT] auto_accept = {}, service_index = {}",
            auto_accept,
            service_index
        );

        // Store the OOB record
        let result = self
            .receive_invitation(invitation, Some(auto_accept))
            .await?;

        // If auto_accept and invitation has handshake protocols, create connection
        let has_handshake_protocols = result
            .oob_record
            .invitation
            .handshake_protocols
            .as_ref()
            .map(|p| !p.is_empty())
            .unwrap_or(false);

        tracing::debug!(
            "[AUTO-ACCEPT] has_handshake_protocols = {}",
            has_handshake_protocols
        );
        tracing::debug!(
            "[AUTO-ACCEPT] Will call accept_invitation: {}",
            auto_accept && has_handshake_protocols
        );

        if auto_accept && has_handshake_protocols {
            tracing::debug!(
                "[AUTO-ACCEPT] *** CALLING accept_invitation_with_service_index(index={}) NOW ***",
                service_index
            );
            let connection_id = self
                .accept_invitation_with_service_index(&result.oob_record, service_index)
                .await?;
            tracing::debug!(
                "[AUTO-ACCEPT] accept_invitation returned connection_id: {}",
                connection_id
            );

            return Ok(ReceiveInvitationResult {
                oob_record: result.oob_record,
                connection_record_id: Some(connection_id),
            });
        }

        Ok(result)
    }

    /// Receive an Out-of-Band invitation from a URL
    ///
    /// # Arguments
    /// * `url` - The invitation URL (containing ?oob=... parameter)
    /// * `auto_accept` - Whether to auto-accept connections from this invitation
    ///
    /// # Returns
    /// ReceiveInvitationResult containing the OOB record and optional connection record
    ///
    /// # Example
    /// ```rust,no_run
    /// use agent::Agent;
    ///
    /// # async fn example(agent: Agent, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    /// let result = agent.oob().receive_invitation_from_url(url, None).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn receive_invitation_from_url(
        &self,
        url: &str,
        auto_accept: Option<bool>,
    ) -> Result<ReceiveInvitationResult> {
        // Parse invitation from URL
        let invitation = OutOfBandInvitation::from_url(url)
            .map_err(|e| AgentError::OutOfBand(format!("Invalid invitation URL: {}", e)))?;

        // Receive invitation with auto-accept logic
        self.receive_invitation_with_auto_accept(invitation, auto_accept)
            .await
    }

    /// Receive an Out-of-Band invitation from a URL with transport selection.
    ///
    /// # Arguments
    /// * `url` - The invitation URL (containing ?oob=... parameter)
    /// * `auto_accept` - Whether to auto-accept connections from this invitation
    /// * `service_index` - Which service endpoint to use (None = 0 = first/default)
    pub async fn receive_invitation_from_url_with_transport(
        &self,
        url: &str,
        auto_accept: Option<bool>,
        service_index: Option<usize>,
    ) -> Result<ReceiveInvitationResult> {
        let invitation = OutOfBandInvitation::from_url(url)
            .map_err(|e| AgentError::OutOfBand(format!("Invalid invitation URL: {}", e)))?;

        self.receive_invitation_with_auto_accept_and_transport(
            invitation,
            auto_accept,
            service_index,
        )
        .await
    }

    /// Parse an invitation URL and return information about all available services.
    ///
    /// This is used by the UI to show transport options (mesh vs internet) before accepting.
    /// Does NOT create a connection — read-only parse.
    ///
    /// # Arguments
    /// * `url` - The invitation URL (containing ?oob=... parameter)
    ///
    /// # Returns
    /// ParsedInvitationInfo containing the label and list of ServiceInfo entries
    pub fn parse_invitation_services(url: &str) -> Result<ParsedInvitationInfo> {
        let invitation = OutOfBandInvitation::from_url(url)
            .map_err(|e| AgentError::OutOfBand(format!("Invalid invitation URL: {}", e)))?;

        let services: Vec<ServiceInfo> = invitation
            .services
            .iter()
            .enumerate()
            .map(|(idx, svc)| match svc {
                ServiceType::Inline(inline) => {
                    let transport_type = if inline.service_endpoint.starts_with("mesh://") {
                        "mesh".to_string()
                    } else {
                        "http".to_string()
                    };
                    let routing_id = if inline.service_endpoint.starts_with("mesh://") {
                        Some(
                            inline
                                .service_endpoint
                                .trim_start_matches("mesh://")
                                .to_string(),
                        )
                    } else {
                        None
                    };
                    ServiceInfo {
                        index: idx,
                        endpoint: inline.service_endpoint.clone(),
                        transport_type,
                        routing_id,
                    }
                }
                ServiceType::Did(did) => ServiceInfo {
                    index: idx,
                    endpoint: did.clone(),
                    transport_type: "did".to_string(),
                    routing_id: None,
                },
            })
            .collect();

        Ok(ParsedInvitationInfo {
            label: invitation.label.clone().unwrap_or_default(),
            services,
        })
    }

    /// Receive an Out-of-Band invitation message directly (without auto-accept)
    ///
    /// # Arguments
    /// * `invitation` - The invitation message
    /// * `auto_accept` - Whether to auto-accept connections from this invitation
    ///
    /// # Returns
    /// ReceiveInvitationResult containing the OOB record
    pub async fn receive_invitation(
        &self,
        invitation: OutOfBandInvitation,
        auto_accept: Option<bool>,
    ) -> Result<ReceiveInvitationResult> {
        let oob_record = if let Some(auto_accept) = auto_accept {
            self.api()
                .receive_invitation_with_auto_accept(invitation, auto_accept)
                .await?
        } else {
            self.api().receive_invitation(invitation).await?
        };

        Ok(ReceiveInvitationResult {
            oob_record,
            connection_record_id: None,
        })
    }

    /// Find an Out-of-Band record by ID
    pub async fn find_by_id(&self, id: &str) -> Result<Option<OutOfBandRecord>> {
        Ok(self.api().find_by_id(id).await?)
    }

    /// Find an Out-of-Band record by invitation ID and role
    pub async fn find_by_invitation_id(
        &self,
        invitation_id: &str,
        role: OutOfBandRole,
    ) -> Result<Option<OutOfBandRecord>> {
        Ok(self
            .api()
            .find_by_invitation_id(invitation_id, role)
            .await?)
    }

    /// Get all Out-of-Band records
    pub async fn get_all(&self) -> Result<Vec<OutOfBandRecord>> {
        Ok(self.api().get_all().await?)
    }

    /// Delete an Out-of-Band record
    pub async fn delete(&self, id: &str) -> Result<()> {
        Ok(self.api().delete(id).await?)
    }

    /// Get the invitation URL for sharing
    ///
    /// # Arguments
    /// * `record` - The OutOfBandRecord containing the invitation
    /// * `domain` - The base domain for the URL
    ///
    /// # Returns
    /// A URL string that can be shared (e.g., via QR code)
    pub fn get_invitation_url(&self, record: &OutOfBandRecord, domain: &str) -> Result<String> {
        self.api()
            .get_invitation_url(record, domain)
            .map_err(|e| e.into())
    }

    /// Connect to a peer by their human-readable handle (e.g., "alice-karamada").
    ///
    /// 1. Resolves the handle via the blockchain service (explorer lookup + decrypt)
    /// 2. Extracts service endpoint and DID from the decrypted DID document
    /// 3. Synthesizes an OOB invitation and auto-accepts it (DIDExchange)
    /// 4. Returns the connection ID (pairwise did:peer:2)
    pub async fn connect_by_handle(&self, handle: &str) -> Result<String> {
        // Clone the Arc out of the RwLock guard so we don't hold the lock across `.await`.
        let blockchain = self
            .blockchain_service
            .read()
            .unwrap()
            .clone()
            .ok_or_else(|| {
                AgentError::OutOfBand(
                    "Blockchain service not available for handle resolution".to_string(),
                )
            })?;

        // 1. Resolve handle → decrypted DID document
        let did_doc = blockchain
            .resolve_handle(handle)
            .await
            .map_err(|e| AgentError::OutOfBand(format!("Handle resolution failed: {}", e)))?
            .ok_or_else(|| AgentError::OutOfBand(format!("Handle '{}' not found", handle)))?;

        // 2. Extract DID from document
        let their_did = did_doc
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AgentError::OutOfBand("Resolved DID document has no 'id' field".to_string())
            })?
            .to_string();

        // 3. Extract service endpoint from decrypted document
        let service_endpoint = did_doc
            .get("service")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|svc| {
                svc.get("serviceEndpoint").and_then(|ep| {
                    // serviceEndpoint can be a string or object with "uri"
                    ep.as_str().map(|s| s.to_string()).or_else(|| {
                        ep.get("uri")
                            .and_then(|u| u.as_str())
                            .map(|s| s.to_string())
                    })
                })
            })
            .ok_or_else(|| {
                AgentError::OutOfBand("No service endpoint in resolved DID document".to_string())
            })?;

        tracing::info!(
            handle = %handle,
            did = %their_did,
            endpoint = %service_endpoint,
            "Resolved handle, synthesizing OOB invitation"
        );

        // 4. Synthesize an OOB invitation using the resolved DID as the service
        let invitation = OutOfBandInvitation::new(vec![ServiceType::Did(their_did.clone())])
            .with_label(format!("handle:{}", handle))
            .with_handshake_protocols(vec![
                DIDEXCHANGE_2_0.to_string(),
                DIDEXCHANGE_1_1.to_string(),
            ]);

        // 5. Receive + auto-accept the synthesized invitation
        let result = self
            .receive_invitation_with_auto_accept(invitation, Some(true))
            .await?;

        result
            .connection_record_id
            .ok_or_else(|| AgentError::OutOfBand("Connection was not auto-accepted".to_string()))
    }
}

#[async_trait::async_trait]
impl agent_module::AgentModule for OutOfBandModule {
    fn name(&self) -> &str {
        "oob"
    }

    /// OOB orchestration is driven directly through the module's rich API
    /// (invitation create/receive) rather than inbound DIDComm handlers. This
    /// `register` wires the module's orchestration dependencies from the DI
    /// container (idempotent: `new_with_dependencies` may have set them). Higher
    /// priority so it orders near connections.
    fn priority(&self) -> i32 {
        90
    }

    async fn register(&self, ctx: &agent_module::ModuleContext) -> agent_module::ModuleResult {
        // Low-level OOB API + orchestration deps (all agent-built services
        // registered into the container in `Agent::new_with_modules`).
        let _ = self.api.set(
            ctx.container
                .resolve::<OutOfBandApi>()
                .map_err(|e| format!("oob: resolve OutOfBandApi: {e}"))?,
        );
        let config = ctx
            .container
            .resolve::<AgentConfig>()
            .map_err(|e| format!("oob: resolve AgentConfig: {e}"))?;
        let _ = self.config.set((*config).clone());
        let _ = self.wallet_provider.set(ctx.wallet.clone());
        let _ = self.did_repository.set(
            ctx.container
                .resolve::<DidRepository>()
                .map_err(|e| format!("oob: resolve DidRepository: {e}"))?,
        );
        let _ = self.oob_repository.set(
            ctx.container
                .resolve::<OutOfBandRepository>()
                .map_err(|e| format!("oob: resolve OutOfBandRepository: {e}"))?,
        );
        let _ = self.transport.set(
            ctx.container
                .resolve::<TransportManager>()
                .map_err(|e| format!("oob: resolve TransportManager: {e}"))?,
        );
        let _ = self.connections.set(
            ctx.container
                .resolve::<ConnectionsModule>()
                .map_err(|e| format!("oob: resolve ConnectionsModule: {e}"))?,
        );
        let _ = self.message_encryption.set(
            ctx.container
                .resolve::<MessageEncryption>()
                .map_err(|e| format!("oob: resolve MessageEncryption: {e}"))?,
        );
        let _ = self.message_processor.set(
            ctx.container
                .resolve::<MessageProcessor>()
                .map_err(|e| format!("oob: resolve MessageProcessor: {e}"))?,
        );

        // EnvelopeService for version-aware packing is created during
        // `Agent::initialize` and registered into the container before the
        // module loop runs; resolve it here (best-effort).
        if let Some(env) = ctx.container.try_resolve::<EnvelopeService>() {
            self.set_envelope_service(env);
        }

        tracing::debug!("✓ [OutOfBandModule] orchestration dependencies wired");
        Ok(())
    }
}

/// Typed, decoupled access to the [`OutOfBandModule`] from an [`crate::Agent`].
pub trait OobExt {
    fn oob_module(&self) -> Option<std::sync::Arc<OutOfBandModule>>;
}

impl OobExt for crate::Agent {
    fn oob_module(&self) -> Option<std::sync::Arc<OutOfBandModule>> {
        self.module::<OutOfBandModule>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_oob::OutOfBandRepository;

    fn create_test_module() -> OutOfBandModule {
        let repo = Arc::new(OutOfBandRepository::new());
        let api = Arc::new(OutOfBandApi::new(repo));
        OutOfBandModule::new(api)
    }

    #[tokio::test]
    async fn test_create_simple_invitation() {
        let module = create_test_module();

        let services = vec![ServiceType::Did("did:example:123".to_string())];

        let config = InvitationConfig::new()
            .with_label("Test Agent")
            .with_services(services)
            .with_handshake_protocols(vec![DIDEXCHANGE_1_1.to_string()]);

        let record = module.create_invitation(config).await.unwrap();

        assert_eq!(record.invitation.label, Some("Test Agent".to_string()));
        assert!(!record.reusable);
    }

    #[tokio::test]
    async fn test_create_multi_use_invitation() {
        let module = create_test_module();

        let services = vec![ServiceType::Did("did:example:123".to_string())];

        let config = InvitationConfig::new()
            .with_label("Test Agent")
            .with_services(services)
            .with_multi_use(true)
            .with_handshake_protocols(vec![DIDEXCHANGE_1_1.to_string()]);

        let record = module.create_invitation(config).await.unwrap();

        assert!(record.reusable);
    }

    // TODO: Fix this test - needs module to be initialized with dependencies for receive_invitation
    // #[tokio::test]
    // async fn test_receive_invitation_from_url() {
    //     let module = create_test_module();

    //     // Create an invitation first
    //     let invitation = OutOfBandInvitation::new(vec![ServiceType::Did(
    //         "did:example:123".to_string(),
    //     )])
    //     .with_label("Test Agent".to_string())
    //     .with_handshake_protocols(vec![
    //         "https://didcomm.org/didexchange/1.1".to_string(),
    //     ]);

    //     let url = invitation.to_url("https://example.com").unwrap();

    //     // Receive from URL
    //     let result = module
    //         .receive_invitation_from_url(&url, Some(true))
    //         .await
    //         .unwrap();

    //     assert_eq!(
    //         result.oob_record.invitation.label,
    //         Some("Test Agent".to_string())
    //     );
    //     assert_eq!(result.oob_record.auto_accept_connection, Some(true));
    // }

    #[tokio::test]
    async fn test_find_operations() {
        let module = create_test_module();

        let services = vec![ServiceType::Did("did:example:123".to_string())];

        let config = InvitationConfig::new()
            .with_label("Test Agent")
            .with_services(services)
            .with_handshake_protocols(vec![DIDEXCHANGE_1_1.to_string()]);

        let record = module.create_invitation(config).await.unwrap();

        // Find by ID
        let found = module.find_by_id(&record.id).await.unwrap();
        assert!(found.is_some());

        // Get all
        let all = module.get_all().await.unwrap();
        assert_eq!(all.len(), 1);
    }
}
