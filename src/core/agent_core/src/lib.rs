//! # Agent Core
//!
//! Core abstractions and traits for the SSI agent framework.
//!
//! This crate provides the fundamental building blocks for creating modular
//! SSI agents, including:
//!
//! - Module trait for pluggable components
//! - Context for agent runtime state
//! - Core service traits (storage, wallet, transport)
//! - Error types
//!
//! ## Example
//!
//! ```rust
//! use agent_core::{Module, AgentContext};
//! use async_trait::async_trait;
//!
//! struct MyModule;
//!
//! #[async_trait]
//! impl Module for MyModule {
//!     fn name(&self) -> &str {
//!         "my_module"
//!     }
//!
//!     async fn initialize(&self, _ctx: &AgentContext) -> agent_core::Result<()> {
//!         println!("Module initialized!");
//!         Ok(())
//!     }
//!
//!     async fn shutdown(&self, _ctx: &AgentContext) -> agent_core::Result<()> {
//!         Ok(())
//!     }
//! }
//! ```

pub mod context;
pub mod error;
pub mod module;
pub mod traits;

// Re-exports
pub use context::AgentContext;
pub use error::{AgentError, Result};
pub use module::Module;
