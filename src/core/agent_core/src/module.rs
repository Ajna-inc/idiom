//! Module trait for pluggable agent components

use crate::{AgentContext, Result};
use async_trait::async_trait;

/// Module trait for pluggable agent components.
///
/// Modules represent major functional areas of the agent (e.g., storage, DIDComm,
/// connections, credentials). Each module can register services, initialize
/// resources, and clean up on shutdown.
///
/// # Lifecycle
///
/// 1. **Construction**: Module is created with configuration
/// 2. **Initialize**: Async initialization (open connections, start servers, etc.)
/// 3. **Run**: Module operates during agent lifetime
/// 4. **Shutdown**: Clean up resources
///
/// # Example
///
/// ```rust
/// use agent_core::{Module, AgentContext, Result};
/// use async_trait::async_trait;
///
/// pub struct MyModule {
///     config: MyConfig,
/// }
///
/// #[async_trait]
/// impl Module for MyModule {
///     fn name(&self) -> &str {
///         "my_module"
///     }
///
///     async fn initialize(&self, ctx: &AgentContext) -> Result<()> {
///         // Initialize resources
///         println!("Initializing {}", self.name());
///         Ok(())
///     }
///
///     async fn shutdown(&self, ctx: &AgentContext) -> Result<()> {
///         // Clean up
///         println!("Shutting down {}", self.name());
///         Ok(())
///     }
/// }
/// # struct MyConfig;
/// ```
#[async_trait]
pub trait Module: Send + Sync {
    /// Returns the module name (for identification and logging)
    fn name(&self) -> &str;

    /// Initialize the module.
    ///
    /// This is called during agent startup after all modules have been registered.
    /// Use this to:
    /// - Open database connections
    /// - Start HTTP servers
    /// - Register message handlers
    /// - Perform one-time setup
    ///
    /// # Errors
    ///
    /// Return an error if initialization fails. This will prevent the agent
    /// from starting.
    async fn initialize(&self, ctx: &AgentContext) -> Result<()>;

    /// Shutdown the module.
    ///
    /// This is called during agent shutdown in reverse order of initialization.
    /// Use this to:
    /// - Close database connections
    /// - Stop HTTP servers
    /// - Flush buffers
    /// - Clean up resources
    ///
    /// # Errors
    ///
    /// Errors during shutdown are logged but don't prevent other modules
    /// from shutting down.
    async fn shutdown(&self, ctx: &AgentContext) -> Result<()>;

    /// Optional: Module dependencies.
    ///
    /// Return the names of modules that must be initialized before this one.
    /// The agent will ensure proper initialization order.
    fn dependencies(&self) -> Vec<&str> {
        vec![]
    }

    /// Optional: Module priority.
    ///
    /// Modules with higher priority are initialized first.
    /// Default is 0. Use negative numbers for late initialization.
    fn priority(&self) -> i32 {
        0
    }
}

/// Helper trait for module builders
pub trait ModuleBuilder: Sized {
    type Module: Module;

    fn build(self) -> Self::Module;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestModule;

    #[async_trait]
    impl Module for TestModule {
        fn name(&self) -> &str {
            "test"
        }

        async fn initialize(&self, _ctx: &AgentContext) -> Result<()> {
            Ok(())
        }

        async fn shutdown(&self, _ctx: &AgentContext) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_module_lifecycle() {
        let module = TestModule;
        assert_eq!(module.name(), "test");
        assert_eq!(module.priority(), 0);
        assert!(module.dependencies().is_empty());
    }
}
