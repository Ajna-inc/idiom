//! Pluggable agent module system.
//!
//! The agent core does **not** know which concrete modules exist. Consumers
//! compose an agent by handing it a set of [`AgentModule`]s (via the builder),
//! and each module wires itself up in [`AgentModule::register`] using the shared
//! [`ModuleContext`]. This keeps protocol modules decoupled from the agent and
//! from each other.
//!
//! ```ignore
//! Agent::builder()
//!     .with_module(ConnectionsModule::default())
//!     .with_module(CredentialsModule::default())
//!     .build()?; // the agent never names these modules itself
//! ```

use std::sync::Arc;

use async_trait::async_trait;

/// Error returned by module lifecycle hooks. Boxed so modules can surface any
/// error type without the framework imposing a shared error enum.
pub type ModuleError = Box<dyn std::error::Error + Send + Sync>;
pub type ModuleResult = Result<(), ModuleError>;

/// Abstraction over the agent's outbound DIDComm sender.
///
/// Defined here (rather than referencing the agent crate) so `ModuleContext`
/// stays decoupled from the agent binary. The agent provides an implementation.
#[async_trait]
pub trait OutboundSender: Send + Sync {
    /// Send a JSON DIDComm message over an existing connection (by id).
    async fn send_via_connection(
        &self,
        connection_id: &str,
        message: &serde_json::Value,
    ) -> Result<(), String>;
}

/// Shared infrastructure handed to every module's lifecycle hooks.
///
/// Holds only generic, protocol-agnostic services. Module-specific
/// dependencies (repositories, protocol services, `DidRegistry`, other
/// modules) are either built from [`ModuleContext::storage`] or resolved from
/// [`ModuleContext::container`] — keeping this crate free of protocol deps.
pub struct ModuleContext {
    /// Core agent context (config surface, correlation id, …).
    pub context: Arc<agent_core::AgentContext>,
    /// DI container for resolving concrete shared services / peer modules.
    pub container: Arc<agent_di::Container>,
    /// Typed event bus.
    pub events: Arc<agent_events::EventBus>,
    /// DIDComm handler registry — modules add their handlers here.
    pub handler_registry: Arc<tokio::sync::RwLock<didcomm::messaging::HandlerRegistry>>,
    /// Record storage backend.
    pub storage: Arc<dyn agent_core::traits::StorageProvider>,
    /// Key-management wallet backend.
    pub wallet: Arc<dyn agent_core::traits::WalletProvider>,
    /// Outbound message sender (for modules that push protocol messages).
    pub sender: Arc<dyn OutboundSender>,
    /// Agent display label at init time.
    pub label: String,
}

/// A self-contained, pluggable agent module.
///
/// Modules construct their own services (from [`ModuleContext::storage`] /
/// [`ModuleContext::container`]) and register their DIDComm handlers in
/// [`register`](AgentModule::register). The agent simply loops over the modules
/// it was given — it never names them.
#[async_trait]
pub trait AgentModule: Send + Sync {
    /// Stable module name (for ordering, dependency resolution, and logging).
    fn name(&self) -> &str;

    /// Wire the module up: build services, register handlers, subscribe to
    /// events. Called once during agent initialization.
    async fn register(&self, ctx: &ModuleContext) -> ModuleResult;

    /// Tear down. Called during agent shutdown in reverse init order.
    async fn shutdown(&self, _ctx: &ModuleContext) -> ModuleResult {
        Ok(())
    }

    /// Names of modules that must be registered before this one.
    fn dependencies(&self) -> Vec<&str> {
        Vec::new()
    }

    /// Higher priority registers first (default 0).
    fn priority(&self) -> i32 {
        0
    }
}
