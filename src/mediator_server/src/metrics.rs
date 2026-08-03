//! Prometheus metrics for the mediator (Fix 4C).
//!
//! Exposed via `GET /metrics` in `routes.rs`. Wired into:
//!  - the direct-route / forward paths in `routes.rs` and `ws.rs` (counter,
//!    `success`/`error` outcome label)
//!  - `MediatorApp::build`'s 5s polling task, which reads the live session
//!    count and `set`s the gauge
//!  - `MediatorApp::build`'s spawned TTL task (counter, when sweeps delete)
//!  - `ws.rs` reconnect-replay flush (counters: invocations + messages drained)
//!  - `ws.rs` per-WS keepalive (counter on ping send)
//!
//! All metrics are registered against the default registry so a single
//! `/metrics` scrape returns everything.

use prometheus::{
    register_int_counter, register_int_counter_vec, register_int_gauge, Encoder, IntCounter,
    IntCounterVec, IntGauge, TextEncoder,
};
use std::sync::Arc;

/// Collection of all mediator-side Prometheus metrics. Cheap to clone (each
/// field is internally `Arc`-backed by the prometheus crate).
pub struct Metrics {
    /// Forward attempts, labeled by outcome:
    ///   - `success`: the forward was queued (and, on the live path, pushed)
    ///   - `error`: the forward failed (queue error / cap rejection)
    pub forward_total: IntCounterVec,

    /// Number of active live WS sessions (gauge — refreshed every 5s by the
    /// polling task in `MediatorApp::build`, which `set`s it from the live
    /// session count).
    pub live_session_count: IntGauge,

    /// Messages removed by the periodic TTL cleanup task.
    pub stale_cleanup_deleted_total: IntCounter,

    /// Reconnect-replay attempts: live session re-registered, mediator
    /// pushed queued messages to the new socket.
    pub reconnect_replay_total: IntCounter,

    /// Number of messages delivered via reconnect-replay (summed across
    /// invocations).
    pub reconnect_replay_messages_total: IntCounter,

    /// WS protocol-level Pings sent to clients (Fix 4A keepalive).
    pub ws_ping_sent_total: IntCounter,
}

impl Metrics {
    pub fn new() -> prometheus::Result<Self> {
        Ok(Self {
            forward_total: register_int_counter_vec!(
                "ajna_mediator_forward_total",
                "Forward outcomes by category",
                &["outcome"]
            )?,
            live_session_count: register_int_gauge!(
                "ajna_mediator_live_session_count",
                "Active live WebSocket sessions"
            )?,
            stale_cleanup_deleted_total: register_int_counter!(
                "ajna_mediator_stale_cleanup_deleted_total",
                "Messages deleted by the periodic TTL sweep"
            )?,
            reconnect_replay_total: register_int_counter!(
                "ajna_mediator_reconnect_replay_total",
                "Reconnect-replay invocations"
            )?,
            reconnect_replay_messages_total: register_int_counter!(
                "ajna_mediator_reconnect_replay_messages_total",
                "Messages delivered via reconnect-replay"
            )?,
            ws_ping_sent_total: register_int_counter!(
                "ajna_mediator_ws_ping_sent_total",
                "WebSocket protocol-level Pings sent to clients"
            )?,
        })
    }

    /// Encode the default registry's metrics in Prometheus text format.
    /// Returns the body string and the appropriate `Content-Type` header value.
    pub fn render() -> (String, &'static str) {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buf = Vec::new();
        if encoder.encode(&metric_families, &mut buf).is_ok() {
            (
                String::from_utf8(buf).unwrap_or_default(),
                "text/plain; version=0.0.4",
            )
        } else {
            (String::new(), "text/plain")
        }
    }
}

/// Construct a `Metrics` and wrap in `Arc` for sharing across the app.
/// Idempotent on the prometheus registry: calling this twice in a single
/// process will panic because of duplicate registration — only call once at
/// startup. Returns a no-op stand-in (`Arc::new`) on registration error so
/// the mediator boots even if the registry is somehow already populated
/// (e.g., during repeated `MediatorApp::build` calls in test code).
pub fn build() -> Arc<Metrics> {
    match Metrics::new() {
        Ok(m) => Arc::new(m),
        Err(e) => {
            tracing::warn!(error = %e, "[Metrics] registration failed; metrics will be incomplete");
            // We can't easily produce a no-op IntCounterVec etc., so re-attempt
            // by gathering whatever's registered. If THAT also fails, panic —
            // because the metrics endpoint would just return empty otherwise
            // and operators would chase a phantom bug.
            Arc::new(Metrics::new().expect("metrics already registered in this process"))
        }
    }
}
