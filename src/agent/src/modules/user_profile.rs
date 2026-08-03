//! User Profile Module (RFC 0711 user-profile/1.0)
//!
//! Self-wiring [`agent_module::AgentModule`] that registers the two user-profile
//! DIDComm handlers:
//!   - `ProfileHandler` — stores an inbound peer profile and emits
//!     `profile.received` on the event bus.
//!   - `RequestProfileHandler` — replies with our own profile when a peer asks.
//!
//! The `UserProfileService` is storage-backed (persists across restarts) and is
//! built from the module's dependencies at construction time; the handlers are
//! registered in [`AgentModule::register`].

use std::sync::Arc;

use once_cell::sync::OnceCell;
use protocol_user_profile::UserProfileService;

/// User-profile protocol module.
///
/// Config-only: holds no agent dependencies at construction. In
/// [`AgentModule::register`] it resolves the agent-shared [`UserProfileService`]
/// and connection repository from the DI container and registers the two
/// user-profile handlers.
#[derive(Default)]
pub struct UserProfileModule {
    /// Resolved from the container in `register`.
    profile_service: OnceCell<Arc<UserProfileService>>,
}

impl UserProfileModule {
    /// Config-only constructor (no agent deps).
    pub fn new() -> Self {
        Self {
            profile_service: OnceCell::new(),
        }
    }

    /// The shared user-profile service, available after registration.
    /// Panics if called before [`AgentModule::register`] has run.
    pub fn service(&self) -> Arc<UserProfileService> {
        self.profile_service
            .get()
            .expect("UserProfileModule::service called before register")
            .clone()
    }
}

#[async_trait::async_trait]
impl agent_module::AgentModule for UserProfileModule {
    fn name(&self) -> &str {
        "user_profile"
    }

    async fn register(&self, ctx: &agent_module::ModuleContext) -> agent_module::ModuleResult {
        let profile_service = ctx
            .container
            .resolve::<UserProfileService>()
            .map_err(|e| format!("user_profile: resolve UserProfileService: {e}"))?;
        let _ = self.profile_service.set(profile_service.clone());

        let connection_repository = ctx
            .container
            .resolve::<crate::module_runtime::ConnectionRepositoryResource>()
            .map_err(|e| format!("user_profile: resolve connection_repository: {e}"))?
            .0
            .clone();

        let mut registry = ctx.handler_registry.write().await;
        registry.register(Arc::new(protocol_user_profile::ProfileHandler::new(
            profile_service.clone(),
            Some(connection_repository),
            ctx.events.clone(),
            ctx.label.clone(),
        )));
        registry.register(Arc::new(protocol_user_profile::RequestProfileHandler::new(
            profile_service,
        )));
        tracing::debug!("✓ [UserProfileModule] User profile handlers registered");
        Ok(())
    }
}

/// Typed, decoupled access to the [`UserProfileModule`] from an [`crate::Agent`].
pub trait UserProfileExt {
    fn user_profile_module(&self) -> Option<std::sync::Arc<UserProfileModule>>;
}

impl UserProfileExt for crate::Agent {
    fn user_profile_module(&self) -> Option<std::sync::Arc<UserProfileModule>> {
        self.module::<UserProfileModule>()
    }
}
