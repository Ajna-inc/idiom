//! Standalone Rust agent with HTTP API and Server-Sent Events
//!
//! Usage:
//!   cargo run --example http_server --features http-server [OPTIONS]
//!
//! Options:
//!   --port <PORT>          HTTP server port (default: 3002)
//!   --host <HOST>          HTTP server host (default: 0.0.0.0)
//!   --label <LABEL>        Agent label (default: "Rust Interop Agent")
//!
//! Environment Variables:
//!   AGENT_PORT            Override port
//!   AGENT_HOST            Override host
//!   AGENT_LABEL           Override label
//!   AGENT_DB_URL          Database URL (e.g., "sqlite://./wallets/agent.db")
//!   MEDIATOR_INVITATION_URL  Mediator OOB invitation URL (enables mediation)
//!
//! Examples:
//!   cargo run --example http_server --features http-server
//!   cargo run --example http_server --features http-server -- --port 4000
//!   AGENT_PORT=4000 cargo run --example http_server --features http-server
//!   AGENT_DB_URL="sqlite://./wallets/agent.db" cargo run --example http_server --features http-server
//!
//! With Mediation (DigiCred):
//!   MEDIATOR_INVITATION_URL="https://mediator.digicred.services?oob=..." cargo run --example http_server --features http-server

// A multi-threaded, allocation-heavy HTTP issuer contends badly on the system
// allocator under load; mimalloc removes that as a bottleneck (frees more cores).
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use agent::backends::BackendSpec;
use agent::modules::oob::InvitationConfig;
use agent::modules::MediationConfig;
use agent::{Agent, AgentBuilder};
use agent_core::traits::{StorageProvider, WalletProvider};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::sse::{Event as SseEvent, KeepAlive, Sse},
    routing::{get, post},
    Json, Router,
};
use didcomm::transports::InboundTransport;
use futures_util::stream::Stream;
use serde::Deserialize;
use serde_json::json;
use std::convert::Infallible;
use std::env;
use std::sync::Arc;

type SharedAgent = Arc<Agent>;

/// Wrapper to implement MessageReceiver for Arc<Agent>
struct AgentReceiver {
    agent: SharedAgent,
}

impl AgentReceiver {
    fn new(agent: SharedAgent) -> Self {
        Self { agent }
    }
}

#[async_trait::async_trait]
impl didcomm::transports::MessageReceiver for AgentReceiver {
    async fn receive_message(
        &self,
        packed_message: String,
        metadata: didcomm::transports::TransportMetadata,
    ) -> didcomm::transports::Result<()> {
        self.agent.receive_message(packed_message, metadata).await
    }

    async fn receive_message_http(
        &self,
        packed_message: String,
        metadata: didcomm::transports::TransportMetadata,
    ) -> didcomm::transports::Result<Option<String>> {
        self.agent
            .receive_message_http(packed_message, metadata)
            .await
    }
}

#[tokio::main]
async fn main() {
    println!("🚀 Starting Rust Agent...\n");

    // Initialize tracing so RUST_LOG actually surfaces protocol-level events
    // (didexchange, mediation, pickup). Silent fallback if subscriber already set.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    // Parse configuration from environment/CLI
    let port = get_config_value("port", "AGENT_PORT", "3002");
    let host = get_config_value("host", "AGENT_HOST", "0.0.0.0");
    let label = get_config_value("label", "AGENT_LABEL", "Rust Interop Agent");
    let db_url = env::var("AGENT_DB_URL").ok();
    let mediator_url = env::var("MEDIATOR_INVITATION_URL").ok();
    // Advertised DIDComm endpoint. Override with AGENT_ENDPOINT to route inbound
    // through a capture proxy (the credential-message corpus recorder) while the
    // agent still listens on AGENT_PORT.
    let endpoint =
        env::var("AGENT_ENDPOINT").unwrap_or_else(|_| format!("http://localhost:{}", port));

    // Initialize dependencies
    println!("📦 Initializing dependencies...\n");

    // Storage + wallet are a matched pair chosen by the `STORE` env var
    // (memory | askar | kanon), via the Backends factory — no more hand-wiring.
    // Default `memory` preserves the previous behavior (in-memory records + an
    // ephemeral askar wallet).
    let backends = BackendSpec::from_env()
        .unwrap_or_else(|e| panic!("invalid STORE: {e}"))
        .build()
        .await
        .expect("Failed to build storage/wallet backend");
    println!("  → Storage + wallet backend: {}", backends.name);
    let storage: Arc<dyn StorageProvider> = backends.storage;
    let wallet: Arc<dyn WalletProvider> = backends.wallet;

    // OID4VCI issuer: create a wallet-held Ed25519 signing key and register a
    // real minter (signs vc+sd-jwt and jwt_vc_json credentials). Endpoints are
    // advertised relative to the agent's endpoint so the holder drives the full
    // HTTP flow (metadata → token → nonce → credential).
    let oid4vci_setup = oid4vci::build_oid4vci_issuer_setup(wallet.clone(), &endpoint).await;

    // Build agent using the library's builder pattern
    println!("\n🔧 Creating agent...\n");
    println!("  → Config:");
    println!("    - Label: {}", label);
    println!("    - Endpoints: [{}]", endpoint);
    println!("\n  → Modules:");
    println!("    - Connections: auto_accept=true");
    println!("    - Out-of-Band: enabled");
    println!("    - DIDs: enabled");
    println!("    - Wallet: enabled");
    if mediator_url.is_some() {
        println!("    - Mediation: enabled (recipient mode)");
    }

    let mut agent_builder = AgentBuilder::new()
        .storage(storage.clone())
        .wallet_provider(wallet)
        .label(&label)
        .endpoint(&endpoint)
        .auto_accept_connections(true)
        .with_oid4vci_issuer(oid4vci_setup.0, oid4vci_setup.1);
    println!("    - OID4VCI: issuer enabled (vc+sd-jwt, jwt_vc_json)");

    // AnonCreds: the registry (VDR/ledger) is a swappable backend chosen by the
    // `LEDGER` env var (default `memory`; `storage` persists to the same backend
    // as records) — just like storage, not a hardcode. Auto-accept credentials
    // so the holder side of a benchmark flow progresses without manual steps.
    #[cfg(feature = "anoncreds")]
    {
        let ledger = agent::backends::LedgerSpec::from_env()
            .unwrap_or_else(|e| panic!("invalid LEDGER: {e}"));
        let registry = ledger
            .build(storage.clone())
            .await
            .expect("Failed to build ledger registry");
        println!(
            "    - AnonCreds: enabled (ledger backend: {})",
            ledger.name()
        );
        agent_builder = agent_builder
            .with_anoncreds_registry(registry)
            .auto_accept_credentials(true);
    }

    // Add db_url to config if provided
    if let Some(ref url) = db_url {
        agent_builder = agent_builder.wallet_db_url(url);
    }

    // Add mediation config if mediator URL is provided
    if let Some(ref url) = mediator_url {
        println!("\n  📡 Mediation:");
        println!("    - Mediator URL: {}...", &url[..80.min(url.len())]);
        let mediation_config =
            MediationConfig::recipient().with_mediator_invitation_url(url.clone());
        agent_builder = agent_builder.mediation(mediation_config);
    }

    // Compose the standard protocol modules (Connections/OOB/Credentials/
    // Workflow/BasicMessages/UserProfile). The agent is zero-default: without
    // this call it has no DIDComm handlers and interop fails.
    // build_and_initialize builds, initializes, AND wires the AnonCreds module
    // against the injected registry (plain `build()` skips the anoncreds wiring).
    let agent_initialized = agent_builder
        .with_default_modules()
        .build_and_initialize()
        .await
        .expect("Failed to build and initialize agent");

    println!("\n✓ Agent initialized successfully\n");

    // Wrap agent in Arc so we can call setup_mediation (needs &Arc<Self>) and
    // share the same instance with the HTTP server / handlers.
    let agent_arc: Arc<Agent> = Arc::new(agent_initialized);

    // Connect to mediator if configured — full handshake (didexchange + mediation
    // request with return_route:"all" + keylist-update + routing wiring).
    if let Some(ref url) = mediator_url {
        println!("🔗 Connecting to mediator...\n");
        let invitation = parse_oob_from_url(url).expect("Failed to parse mediator OOB invitation");
        println!(
            "  → Mediator: {}",
            invitation.label.as_deref().unwrap_or("Unknown")
        );

        match agent_arc.setup_mediation(url).await {
            Ok(record) => {
                println!("  ✅ Mediation fully granted");
                println!("    - Record ID: {}", record.id);
                println!("    - State: {:?}", record.state);

                // Spawn HTTP pickup loop so we actually retrieve messages from the
                // mediator (HTTP transport is poll-based; no persistent inbound).
                //
                // Re-fetch the record from the mediation repo — setup_mediation
                // persists `registered_recipient_key` AFTER returning, so the
                // copy returned here is stale.
                let latest = agent_arc
                    .mediation
                    .as_ref()
                    .and_then(|m| m.recipient())
                    .map(|r| async {
                        r.find_by_connection_id(&record.connection_id)
                            .await
                            .ok()
                            .flatten()
                    });
                let latest = match latest {
                    Some(fut) => fut.await,
                    None => None,
                };
                let mediator_did = agent_arc
                    .connections()
                    .find_by_id(&record.connection_id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|c| c.their_did.clone())
                    .unwrap_or_default();
                let endpoint = latest
                    .as_ref()
                    .and_then(|r| r.endpoint.clone())
                    .unwrap_or_else(|| record.endpoint.clone().unwrap_or_default());
                // The mediator indexes its forward queue by base58 verkey (not
                // the did:key wrapper). Convert before handing off to pickup,
                // otherwise the per-key filter never matches and polls return 0.
                let recipient_key_did = latest
                    .as_ref()
                    .and_then(|r| r.registered_recipient_key.clone())
                    .unwrap_or_default();
                let recipient_key =
                    if let Some(encoded) = recipient_key_did.strip_prefix("did:key:z") {
                        match bs58::decode(encoded).into_vec() {
                            Ok(decoded) if decoded.len() > 2 => {
                                bs58::encode(&decoded[2..]).into_string()
                            }
                            _ => recipient_key_did.clone(),
                        }
                    } else {
                        recipient_key_did.clone()
                    };

                if !mediator_did.is_empty() && !endpoint.is_empty() && !recipient_key.is_empty() {
                    // Bug A fix: prefer WebSocket live-mode pickup (RFC 0685),
                    // exactly like credo. Opens a persistent WS, enables
                    // live-delivery, and receives forwarded messages with ~0s
                    // latency (no polling gap). The HTTP delivery-request loop
                    // still runs as a fallback but pauses whenever the WS is
                    // connected (via the shared `ws_connected` watch), so we
                    // never double-pull. Derive the WS endpoint from the
                    // mediator's HTTP endpoint (https→wss, http→ws, `/ws` path).
                    let ws_endpoint = {
                        let base = endpoint.trim_end_matches('/');
                        let scheme_swapped = if let Some(rest) = base.strip_prefix("https://") {
                            format!("wss://{}", rest)
                        } else if let Some(rest) = base.strip_prefix("http://") {
                            format!("ws://{}", rest)
                        } else {
                            base.to_string()
                        };
                        format!("{}/ws", scheme_swapped)
                    };

                    let ws_handle =
                        agent_arc
                            .clone()
                            .spawn_ws_pickup_loop(agent::ws_pickup::WsPickupConfig {
                                ws_endpoint,
                                http_endpoint: endpoint.clone(),
                                mediator_did: mediator_did.clone(),
                                connection_id: record.connection_id.clone(),
                            });
                    let ws_connected = ws_handle.connected.clone();
                    // Detach: the spawned WS task and its `connected` watch
                    // sender outlive the handle; dropping only detaches.
                    std::mem::forget(ws_handle);
                    println!("  ✅ WS live-mode pickup loop spawned");

                    let _handle = agent_arc.spawn_pickup_loop(
                        record.connection_id.clone(),
                        mediator_did,
                        endpoint,
                        recipient_key,
                        Some(ws_connected), // HTTP loop pauses while WS is up
                    );
                    println!("  ✅ HTTP pickup fallback loop spawned");
                } else {
                    eprintln!("  ⚠️ Skipping pickup loop — missing routing info");
                }
            }
            Err(e) => {
                eprintln!("  ⚠️ Mediation setup failed: {}", e);
            }
        }
        println!();
    }

    // Start HTTP server
    start_http_server(&host, &port, &endpoint, agent_arc).await;

    // Keep the process running
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl-c");

    println!("\n🛑 Shutting down...");
}

/// Start HTTP server with API routes
async fn start_http_server(host: &str, port: &str, endpoint: &str, agent: Arc<Agent>) {
    println!("🌐 Starting HTTP server...\n");

    // Management API routes
    let mut router = Router::new()
        .route("/health", get(api::health))
        .route("/oob/create-invitation", post(api::create_oob_invitation))
        .route("/oob/receive-invitation", post(api::receive_oob_invitation))
        .route("/connections", get(api::get_connections))
        .route("/connections/:id", get(api::get_connection))
        .route("/oob/records", get(api::get_oob_records))
        .route("/basic-messages", get(api::get_basic_messages))
        .route("/basic-messages/send", post(api::send_basic_message))
        .route("/events", get(api::event_stream));

    // Workflow routes
    {
        println!("  → Adding Workflow routes...");
        router = router
            .route(
                "/workflow/templates",
                get(wf_list_templates).post(wf_publish_template),
            )
            .route("/workflow/templates/:template_id", get(wf_get_template))
            .route("/workflow/templates/fetch", post(wf_fetch_template_remote))
            .route("/workflow/start", post(wf_start))
            .route("/workflow/advance", post(wf_advance))
            .route("/workflow/instances/:instance_id", get(wf_get_instance))
            .route("/workflow/instances/:instance_id/status", get(wf_status))
            .route("/workflow/instances/:instance_id/pause", post(wf_pause))
            .route("/workflow/instances/:instance_id/resume", post(wf_resume))
            .route("/workflow/instances/:instance_id/cancel", post(wf_cancel))
            .route(
                "/workflow/instances/:instance_id/complete",
                post(wf_complete),
            );
        println!("  ✓ Workflow routes added");
    }

    // AnonCreds credential control API (feature-gated). Setup endpoints are
    // single-agent; issue/proof endpoints are added alongside the benchmark
    // driver (they need the two-agent flow to verify).
    #[cfg(feature = "anoncreds")]
    {
        println!("  → Adding AnonCreds routes...");
        router = router
            .route("/setup/schema", post(anoncreds::setup_schema))
            .route("/setup/cred-def", post(anoncreds::setup_cred_def))
            // Real DIDComm issuance over a connection (the full path).
            .route("/issue/offer", post(anoncreds::issue_offer))
            .route("/credentials/count", get(anoncreds::credentials_count));
        println!("  ✓ AnonCreds routes added");
    }

    // OID4VCI routes: issuer endpoints (metadata/token/nonce/credential) + a
    // control endpoint to mint offers, plus a holder driver that runs the full
    // HTTP exchange against a peer issuer.
    {
        println!("  → Adding OID4VCI routes...");
        router = router
            .route(
                "/.well-known/openid-credential-issuer",
                get(oid4vci::oid4vci_metadata),
            )
            .route("/oid4vci/offer", post(oid4vci::oid4vci_create_offer))
            .route("/oid4vci/token", post(oid4vci::oid4vci_token))
            .route("/oid4vci/nonce", post(oid4vci::oid4vci_nonce))
            .route("/oid4vci/credential", post(oid4vci::oid4vci_credential))
            .route(
                "/oid4vci/receive-offer",
                post(oid4vci::oid4vci_receive_offer),
            );
        println!("  ✓ OID4VCI routes added");
    }

    let management_api = router.with_state(agent.clone());

    // Create HTTP inbound transport with management API
    let agent_receiver = Arc::new(AgentReceiver::new(agent.clone()));
    let mut http_inbound = didcomm::transports::HttpInboundTransport::new(
        host,
        port.parse::<u16>().expect("Invalid port"),
        agent_receiver as Arc<dyn didcomm::transports::MessageReceiver>,
    )
    .with_app(management_api);

    // Start server
    http_inbound
        .start()
        .await
        .expect("Failed to start HTTP inbound transport");

    let addr = format!("{}:{}", host, port);
    println!("✅ Agent ready at http://{}", addr);
    println!("\n  📡 Management API:");
    println!("     GET  /health");
    println!("     POST /oob/create-invitation");
    println!("     POST /oob/receive-invitation");
    println!("     GET  /connections");
    println!("     GET  /connections/:id");
    println!("     GET  /oob/records");
    println!("     GET  /basic-messages?connectionId=xxx");
    println!("     POST /basic-messages/send");
    println!("     GET  /events (Server-Sent Events)");
    println!("\n  🔄 Workflow Protocol:");
    println!("     GET  /workflow/templates");
    println!("     POST /workflow/templates");
    println!("     GET  /workflow/templates/:template_id");
    println!("     POST /workflow/templates/fetch");
    println!("     POST /workflow/start");
    println!("     POST /workflow/advance");
    println!("     GET  /workflow/instances/:instance_id");
    println!("     GET  /workflow/instances/:instance_id/status");
    println!("     POST /workflow/instances/:instance_id/pause");
    println!("     POST /workflow/instances/:instance_id/resume");
    println!("     POST /workflow/instances/:instance_id/cancel");
    println!("     POST /workflow/instances/:instance_id/complete");
    println!("\n  💬 DIDComm:");
    println!("     POST /");
    println!("\n  🔗 Endpoint: {}", endpoint);
    println!();
}

mod oid4vci;
/// Get configuration value from CLI args or environment variable
fn get_config_value(arg_name: &str, env_name: &str, default: &str) -> String {
    if let Ok(val) = env::var(env_name) {
        return val;
    }

    let args: Vec<String> = env::args().collect();
    let flag = format!("--{}", arg_name);

    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return args[i + 1].clone();
        }
    }

    default.to_string()
}

mod api;

#[cfg(feature = "anoncreds")]
mod anoncreds;
// ===== Workflow Protocol Handlers =====

mod workflow_handlers;

use workflow_handlers::{
    advance as wf_advance, cancel as wf_cancel, complete as wf_complete,
    fetch_template_remote as wf_fetch_template_remote, get_instance as wf_get_instance,
    get_template as wf_get_template, list_templates as wf_list_templates, pause as wf_pause,
    publish_template as wf_publish_template, resume as wf_resume, start as wf_start,
    status as wf_status,
};

// ===== Mediation Helpers =====

/// Parse OOB invitation from URL query parameter
fn parse_oob_from_url(url: &str) -> Result<protocol_oob::OutOfBandInvitation, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    // Parse URL and extract 'oob' query parameter
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    let oob_param = parsed
        .query_pairs()
        .find(|(key, _)| key == "oob")
        .map(|(_, value)| value.to_string())
        .ok_or_else(|| "No 'oob' query parameter found".to_string())?;

    // Base64 decode the invitation
    let decoded = URL_SAFE_NO_PAD
        .decode(&oob_param)
        .map_err(|e| format!("Failed to base64 decode: {}", e))?;

    // Parse as JSON
    let invitation: protocol_oob::OutOfBandInvitation = serde_json::from_slice(&decoded)
        .map_err(|e| format!("Failed to parse invitation JSON: {}", e))?;

    Ok(invitation)
}
