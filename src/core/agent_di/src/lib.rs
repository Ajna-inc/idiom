//! # Agent Dependency Injection
//!
//! Dependency injection container for the agent framework.
//!
//! This crate provides a simplified DI system that wraps Shaku for
//! compile-time dependency injection with ergonomic APIs.
//!
//! ## Features
//!
//! - Type-safe service registration and resolution
//! - Singleton, scoped, and transient lifecycles
//! - Module-based organization
//! - Compile-time dependency validation
//!
//! ## Example
//!
//! ```rust
//! use agent_di::Container;
//! use std::sync::Arc;
//!
//! #[derive(Default)]
//! struct MyService {
//!     message: String,
//! }
//!
//! impl MyService {
//!     fn do_something(&self) -> &str {
//!         "Hello from service!"
//!     }
//! }
//!
//! let mut container = Container::new();
//! container.register_singleton::<MyService, MyService>();
//!
//! let service = container.resolve::<MyService>().unwrap();
//! assert_eq!(service.do_something(), "Hello from service!");
//! ```

pub mod container;
pub mod error;
pub mod lifecycle;
pub mod provider;

// Re-exports
pub use container::Container;
pub use error::{DependencyError, Result};
pub use lifecycle::Lifecycle;
pub use provider::Provider;
