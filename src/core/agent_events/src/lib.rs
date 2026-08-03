//! # Agent Events
//!
//! Event bus for the agent framework using Tokio broadcast channels.
//!
//! This crate provides a simple, efficient event system for inter-module
//! communication without tight coupling.
//!
//! ## Features
//!
//! - Type-safe event publishing and subscription
//! - Topic-based filtering
//! - Multiple concurrent subscribers
//! - Built on Tokio broadcast (zero-copy cloning)
//!
//! ## Example
//!
//! ```rust
//! use agent_events::{EventBus, Event};
//!
//! #[tokio::main]
//! async fn main() {
//!     let bus = EventBus::new(100);
//!
//!     // Subscribe to events
//!     let mut subscriber = bus.subscribe();
//!
//!     // Publish an event
//!     bus.publish(Event::new("agent1", "connection", "state_changed",
//!         serde_json::json!({"state": "active"})))
//!         .await.ok();
//!
//!     // Receive the event
//!     if let Ok(event) = subscriber.recv().await {
//!         println!("Received: {} - {}", event.topic, event.name);
//!     }
//! }
//! ```

pub mod event;
pub mod event_bus;
pub mod filter;
pub mod typed;

// Re-exports
pub use event::Event;
pub use event_bus::{EmitError, EventBus, Subscriber, TypedRecvError};
pub use filter::EventFilter;
pub use typed::{EventMetadata, TypedEvent, TypedEventError};
