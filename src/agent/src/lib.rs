//! # Agent - High-level Orchestration Layer
//!
//! This crate provides the central `Agent` struct that integrates all SSI functionality
//! into a cohesive, easy-to-use API.
//! module-based access to different protocol implementations.
//!
//! ## Architecture
//!
//! ```text
//! Agent
//! ├── config: AgentConfig
//! ├── context: Arc<AgentContext>
//! ├── modules
//! │   ├── oob: OutOfBandModule
//! │   ├── connections: ConnectionsModule
//! │   ├── dids: DidModule
//! │   └── wallet: WalletModule
//! ├── transport: TransportManager
//! ├── dispatcher: MessageDispatcher
//! └── events: EventBus
//! ```
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use agent::{Agent, test_utils::{InMemoryStorage, InMemoryWallet}};
//! use agent_core::traits::{StorageProvider, WalletProvider};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create dependencies
//!     let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn StorageProvider>;
//!     let wallet = Arc::new(InMemoryWallet::new()) as Arc<dyn WalletProvider>;
//!
//!     // Build and configure agent using the builder
//!     let mut agent = Agent::builder()
//!         .storage(storage)
//!         .wallet_provider(wallet)
//!         .label("My Agent")
//!         .endpoint("http://localhost:8080")
//!         .build_and_initialize()
//!         .await?;
//!
//!     // Use modules (resolved from the DI container via accessor methods)
//!     let record = agent.oob().create_invitation(Default::default()).await?;
//!     println!("Invitation URL: {}", record.invitation.to_url("https://example.com")?);
//!
//!     // Shutdown when done
//!     agent.shutdown().await?;
//!     Ok(())
//! }
//! ```

pub mod agent;
pub mod backends;
pub mod builder;
pub mod config;
pub mod crypto;
pub mod events;
// Discovery types (DiscoveredPeers, PeerInfo) are always available
// mDNS/BLE submodules require the `discovery` feature
pub mod discovery;
pub mod dispatcher;
pub mod error;
pub mod http;
pub mod mediation_setup;
pub mod mediator_identity;
pub mod messaging;
pub mod module_runtime;
pub mod modules;
#[cfg(feature = "http-server")]
pub mod monitoring;
pub mod pickup;
pub mod transport;
pub mod ws_pickup;

// Make test_utils public for integration tests
pub mod test_utils;

pub use agent::Agent;
pub use builder::AgentBuilder;

// Extension traits for typed, decoupled access to pluggable modules
// (`agent.connections_module()`, `agent.workflow_module()`, …). These delegate
// to `Agent::module::<T>()` and are the recommended accessors for the pluggable
// module system. The pre-existing inherent accessors (`connections()`,
// `workflow()`, …) remain for compatibility.
pub use modules::basic_messages::BasicMessagesExt;
pub use modules::connections::ConnectionsExt;
pub use modules::credentials::CredentialsExt;
pub use modules::dids::DidsExt;
pub use modules::oob::OobExt;
pub use modules::user_profile::UserProfileExt;
pub use modules::wallet::WalletModuleExt;
pub use modules::workflow::WorkflowExt;

// Re-export the pluggable module contract for consumers writing custom modules.
pub use agent_module::{AgentModule, ModuleContext, ModuleResult, OutboundSender};
pub use config::{
    AgentConfig, AgentConfigBuilder, DidConfig, LoggerConfig, StorageConfig, WalletConfig,
};
pub use error::{AgentError, Result};
pub use mediator_identity::MediatorIdentityService;
