//! DID Module
//!
//! High-level API for DID operations

mod manager;

pub use manager::DidManager;
pub use manager::{
    decode_mldsa65_multibase, encode_ed25519_multibase, encode_mldsa65_multibase,
    encode_x25519_multibase, multicodec,
};

use crate::error::Result;
use agent_core::traits::WalletProvider;
use did::core::DidRepository;
use did::registry::DidRegistry;
use std::sync::Arc;

/// DID Module providing high-level DID APIs
pub struct DidModule {
    registry: Arc<DidRegistry>,
    wallet_provider: Option<Arc<dyn WalletProvider>>,
    did_repository: Option<Arc<DidRepository>>,
}

impl DidModule {
    /// Create a new DidModule (basic - registry only)
    pub fn new(registry: Arc<DidRegistry>) -> Self {
        Self {
            registry,
            wallet_provider: None,
            did_repository: None,
        }
    }

    /// Create a new DidModule with dependencies for manager operations
    pub fn new_with_dependencies(
        registry: Arc<DidRegistry>,
        wallet_provider: Arc<dyn WalletProvider>,
        did_repository: Arc<DidRepository>,
    ) -> Self {
        Self {
            registry,
            wallet_provider: Some(wallet_provider),
            did_repository: Some(did_repository),
        }
    }

    /// Get the DID registry
    pub fn registry(&self) -> Arc<DidRegistry> {
        Arc::clone(&self.registry)
    }

    /// Create a DidManager instance for DID operations
    ///
    /// This allows direct access to DidManager methods without delegation.
    /// Requires the module to be created with dependencies.
    pub fn manager(&self) -> Result<DidManager> {
        let wallet_provider = self.wallet_provider.as_ref().ok_or_else(|| {
            crate::error::AgentError::Did(
                "DID module not initialized with wallet provider".to_string(),
            )
        })?;
        let did_repository = self.did_repository.as_ref().ok_or_else(|| {
            crate::error::AgentError::Did(
                "DID module not initialized with DID repository".to_string(),
            )
        })?;

        Ok(DidManager::new(
            wallet_provider.clone(),
            did_repository.clone(),
        ))
    }
}

#[async_trait::async_trait]
impl agent_module::AgentModule for DidModule {
    fn name(&self) -> &str {
        "dids"
    }

    /// Core module with no DIDComm handlers of its own; implements the trait so
    /// the agent can drive all modules uniformly and
    /// `Agent::module::<DidModule>()` resolves.
    async fn register(&self, _ctx: &agent_module::ModuleContext) -> agent_module::ModuleResult {
        Ok(())
    }
}

/// Typed, decoupled access to the [`DidModule`] from an [`crate::Agent`].
pub trait DidsExt {
    fn dids_module(&self) -> Option<std::sync::Arc<DidModule>>;
}

impl DidsExt for crate::Agent {
    fn dids_module(&self) -> Option<std::sync::Arc<DidModule>> {
        self.module::<DidModule>()
    }
}
