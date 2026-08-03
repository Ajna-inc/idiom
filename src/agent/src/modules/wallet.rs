//! Wallet Module
//!
//! High-level API for wallet operations

use agent_core::traits::WalletProvider;
use std::sync::Arc;

/// Wallet Module providing high-level wallet APIs
pub struct WalletModule {
    /// Wallet provider (injected dependency)
    provider: Arc<dyn WalletProvider>,
}

impl WalletModule {
    /// Create a new WalletModule with a wallet provider
    pub fn new_with_provider(provider: Arc<dyn WalletProvider>) -> Self {
        Self { provider }
    }

    /// Get a reference to the wallet provider
    pub fn provider(&self) -> &Arc<dyn WalletProvider> {
        &self.provider
    }
}

#[async_trait::async_trait]
impl agent_module::AgentModule for WalletModule {
    fn name(&self) -> &str {
        "wallet"
    }

    /// Core module with no DIDComm handlers of its own; implements the trait so
    /// the agent can drive all modules uniformly and
    /// `Agent::module::<WalletModule>()` resolves.
    async fn register(&self, _ctx: &agent_module::ModuleContext) -> agent_module::ModuleResult {
        Ok(())
    }
}

/// Typed, decoupled access to the [`WalletModule`] from an [`crate::Agent`].
pub trait WalletModuleExt {
    fn wallet_module_ext(&self) -> Option<std::sync::Arc<WalletModule>>;
}

impl WalletModuleExt for crate::Agent {
    fn wallet_module_ext(&self) -> Option<std::sync::Arc<WalletModule>> {
        self.module::<WalletModule>()
    }
}
