//! Typed events.
//!
//! `TypedEvent` binds a payload struct to a compile-time `(topic, name)` pair so
//! producers can't typo the strings and consumers can decode without guessing
//! the JSON shape. The wire envelope (`crate::Event`) is unchanged — this is
//! purely a discipline layer over the existing string-typed bus.
//!
//! ## Example
//!
//! ```ignore
//! use agent_events::{EventBus, EventMetadata, TypedEvent};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Clone, Serialize, Deserialize)]
//! struct ConnectionStateChangedPayload {
//!     connection_id: String,
//!     state: String,
//! }
//!
//! impl TypedEvent for ConnectionStateChangedPayload {
//!     const TOPIC: &'static str = "connection";
//!     const NAME:  &'static str = "state_changed";
//! }
//!
//! let bus = EventBus::new(100);
//! let meta = EventMetadata::for_tenant("alice");
//! bus.emit(&meta, ConnectionStateChangedPayload {
//!     connection_id: "c1".into(),
//!     state: "Completed".into(),
//! }).await.ok();
//! ```

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

/// Marker trait that binds a payload type to a compile-time `(topic, name)`.
///
/// Implementors live next to their protocol's existing `topics` / `types`
/// constants — typically by `impl TypedEvent for FooPayload { const TOPIC =
/// topics::FOO; const NAME = types::STATE_CHANGED; }`.
///
/// The trait deliberately requires `Clone + Send + Sync + 'static` so events
/// can fan out through `tokio::sync::broadcast` without further bounds at the
/// call site.
pub trait TypedEvent: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {
    const TOPIC: &'static str;
    const NAME: &'static str;
}

/// Per-emit metadata. `tenant_id` is the multi-tenant correlation id and lands
/// on `Event::agent_id` so existing
/// `EventFilter::agent_id(...)` consumers continue to filter correctly.
#[derive(Debug, Clone)]
pub struct EventMetadata {
    pub tenant_id: String,
    pub trace_id: Option<String>,
}

impl EventMetadata {
    /// Convenience constructor for the common case (no trace id).
    pub fn for_tenant(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            trace_id: None,
        }
    }

    /// Constructor that pins a trace id alongside the tenant id.
    pub fn with_trace(tenant_id: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            trace_id: Some(trace_id.into()),
        }
    }
}

/// Errors raised by `Event::payload::<E>()` / `Subscriber::recv_typed::<E>()`.
#[derive(Debug, Error)]
pub enum TypedEventError {
    /// The wire envelope's `topic` doesn't match `E::TOPIC`. Caller is decoding
    /// the wrong payload type for this event.
    #[error("typed-event topic mismatch: expected `{expected}`, got `{actual}`")]
    TopicMismatch {
        expected: &'static str,
        actual: String,
    },

    /// The wire envelope's `name` doesn't match `E::NAME`. Same protocol but a
    /// different event variant.
    #[error("typed-event name mismatch: expected `{expected}`, got `{actual}`")]
    NameMismatch {
        expected: &'static str,
        actual: String,
    },

    /// The payload JSON couldn't be deserialized into `E`. Producer/consumer
    /// schemas have drifted.
    #[error("typed-event payload decode failed: {0}")]
    Json(#[from] serde_json::Error),
}
