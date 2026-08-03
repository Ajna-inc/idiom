//! Canonical WebSocket pickup loop for single-agent mediators.
//!
//! Aries RFC 0685 live delivery — opens one persistent WebSocket to the
//! mediator, sends `messagepickup/2.0/live-delivery-change { live_delivery:
//! true }`, drains the existing queue with `delivery-request`, then sits in
//! a read loop processing pushed Forward envelopes.
//!
//! Until this module existed there were **three** WS pickup loops in the
//! tree, all reinventing the same connect / drain / live-delivery /
//! read-loop / reconnect sequence:
//!
//! | Consumer                       | What it added on top of the core  |
//! |--------------------------------|------------------------------------|
//! | `agent_tenants::pickup_loop`   | route incoming frames to tenants  |
//! | `agent_ffi::ws_session`        | FFI event emission, state machine |
//! | (single-tenant Rust wallets)   | nothing — was missing entirely    |
//!
//! This module owns the canonical core. `agent_tenants` and `agent_ffi`
//! now wrap it by intercepting the dispatch callback and subscribing to
//! the lifecycle events on `Agent::events`. Single-tenant wallets call
//! [`Agent::spawn_ws_pickup_loop`] directly and get the same ~0 s
//! live delivery via `PickUpV2LiveMode`.
//!
//! ## Defensive timing
//!
//! - **30 s read-idle timeout** — iOS App Nap / macOS suspend silently
//!   pauses TCP reads without surfacing an error. A 30 s ceiling forces
//!   a clean reconnect via the outer backoff.
//! - **25 s keepalive Ping** — keeps the OS from reclaiming an otherwise
//!   quiet socket. Mediator pongs count as activity and slide the idle
//!   window forward.
//! - **Exponential reconnect backoff** — 1 s → 2 → 4 → 8 → 16 → 32 → 64,
//!   capped at 120 s, reset on a successful connect.
//!
//! ## Event surface
//!
//! Lifecycle is emitted on `Agent::events` under topic `pickup`:
//!
//! | Event                       | Payload fields                              |
//! |-----------------------------|---------------------------------------------|
//! | `ws_connecting`             | `attempt`, `endpoint`                       |
//! | `ws_connect_failed`         | `attempt`, `endpoint`, `error`              |
//! | `ws_connected`              | `endpoint`                                  |
//! | `ws_disconnected`           | `reason`                                    |
//! | `ws_reconnecting`           | `attempt`, `backoff_secs`                   |
//! | `ws_read_timeout`           | `connection_id`, `idle_secs`                |
//! | `live_session_saved`        | `session_id`, `connection_id`, `transport`  |
//! | `live_session_removed`     | `session_id`, `connection_id`, `reason`     |

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use didcomm::transports::ws::{WsConnection, WsMessage, WsReadStream};
use futures_util::StreamExt;
use tokio::sync::{mpsc, watch, Notify, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use crate::agent::Agent;
use crate::error::{AgentError, Result};

/// 30 s ceiling on a WebSocket read before we force a reconnect.
///
/// iOS App Nap / macOS suspend silently pauses the read half without
/// surfacing an error — the future hangs forever. The timeout drops
/// us back into the outer backoff, where exponential reconnect picks
/// up cleanly and the mediator's reconnect-replay re-delivers anything
/// in flight.
const WS_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// 25 s keepalive Ping. Sits under the typical 30 s OS-suspend
/// threshold so the socket stays "warm" for the read-idle window.
const WS_PING_INTERVAL: Duration = Duration::from_secs(25);

/// Cap on the exponential reconnect backoff.
const WS_RECONNECT_MAX_BACKOFF: u64 = 120;

/// Inputs for [`Agent::spawn_ws_pickup_loop`].
///
/// All three fields are normally derived from the mediator handshake
/// in [`Agent::setup_mediation`] — pass them straight through to this
/// loop after the handshake completes.
#[derive(Clone, Debug)]
pub struct WsPickupConfig {
    /// WebSocket endpoint advertised by the mediator's OOB
    /// (`wss://mediator.example/ws` or `ws://...`).
    pub ws_endpoint: String,
    /// HTTP endpoint advertised by the mediator's OOB. Used for the
    /// reconnect-fallback path and for re-running pickup over HTTP if
    /// the WS gets demoted; pass the same string `setup_mediation`
    /// stored on the mediation record.
    pub http_endpoint: String,
    /// Mediator's pairwise DID after DidExchange completed.
    pub mediator_did: String,
    /// Our pairwise connection record id with the mediator.
    pub connection_id: String,
}

/// State of the WS pickup task.
///
/// `state` on [`WsPickupHandle`] is updated on every transition. FFI /
/// UI consumers can `.read().await` this for status indicators without
/// subscribing to the event bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsPickupState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting { attempt: u32 },
}

/// Handle returned by [`Agent::spawn_ws_pickup_loop`].
///
/// Clone freely — shutdown / state inspection / connected-watcher all
/// share the inner Arcs. The `JoinHandle` field is consumed by
/// [`WsPickupHandle::await_done`] when you want to wait for the loop
/// to exit (typically after `shutdown()`).
pub struct WsPickupHandle {
    pub state: Arc<RwLock<WsPickupState>>,
    /// `watch::Receiver<bool>` — `true` while the WS is connected.
    /// HTTP pickup-poll loops watch this to pause polling during live
    /// delivery and resume on disconnect.
    pub connected: watch::Receiver<bool>,
    /// Unix-ms timestamp of the most recent successful frame read.
    /// `-1` until the first frame. Useful for FFI health checks that
    /// need to detect a stalled but still-connected session.
    pub last_message_ts_ms: Arc<AtomicI64>,
    /// Best-effort shutdown signal. Set the flag, notify the waiter,
    /// the next read or backoff sleep exits and the task returns.
    shutdown_flag: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    /// Outbound channel — `try_send_packed` writes pre-packed DIDComm
    /// envelopes here, the inner read loop picks them up via `select!`
    /// and writes them to the open WS. Cloneable so multiple
    /// outbound-transport instances can share one pickup session.
    outbound_tx: mpsc::UnboundedSender<String>,
    /// Binary-outbound channel for DCX frames. Same shape as
    /// `outbound_tx` but the read loop writes these as WS binary frames
    /// (opcode `0x2`) instead of text frames. Used by
    /// `didcomm::dcx::transports::outbound::DcxOutboundTransport`.
    outbound_binary_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// The spawned task. Public so wrappers (agent_tenants, agent_ffi)
    /// that want to return a plain `JoinHandle` for backward compat
    /// can consume the handle and re-expose this. Use
    /// [`Self::await_done`] for the typical pattern.
    pub join_handle: JoinHandle<()>,
}

impl WsPickupHandle {
    /// Request the loop to exit. Returns immediately — the task may
    /// take up to one read-timeout window (30 s) to actually finish if
    /// it's mid-read. Idempotent.
    pub fn shutdown(&self) {
        if !self.shutdown_flag.swap(true, Ordering::Relaxed) {
            self.shutdown_notify.notify_waiters();
        }
    }

    /// Whether shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown_flag.load(Ordering::Relaxed)
    }

    /// Wait for the loop task to finish.
    pub async fn await_done(self) {
        let _ = self.join_handle.await;
    }

    /// Consume the handle and return the underlying tokio task. The
    /// shutdown flag / notify / connected watcher all get dropped on
    /// the way out, so prefer this only when you specifically need a
    /// plain `JoinHandle<()>` for backward-compat APIs.
    pub fn into_join_handle(self) -> JoinHandle<()> {
        self.join_handle
    }

    /// True iff the WS is currently connected. Cheap — reads a
    /// `watch::Receiver`, no lock.
    pub fn is_connected(&self) -> bool {
        *self.connected.borrow()
    }

    /// Send a pre-packed DIDComm envelope over the open pickup WS.
    ///
    /// Returns `Err(Transport)` if the WS isn't currently connected or
    /// the loop has exited. The caller should fall back to HTTP in that
    /// case. The send itself is fire-and-forget — the inner loop
    /// dequeues the message and writes it on the next `select!` tick;
    /// there is no per-message ack here.
    ///
    /// This is the primary entry point for outbound transport:
    /// `WsMediatorOutboundTransport` calls this when its
    /// `supports_endpoint` check matched the pickup mediator URL.
    pub fn try_send_packed(&self, packed: String) -> std::result::Result<(), &'static str> {
        if !self.is_connected() {
            return Err("ws pickup not connected");
        }
        self.outbound_tx
            .send(packed)
            .map_err(|_| "ws pickup loop closed")
    }

    /// Clone the outbound sender for use by an outbound transport. The
    /// transport keeps the sender; sending fails fast if the loop
    /// shuts down.
    pub fn outbound_sender(&self) -> mpsc::UnboundedSender<String> {
        self.outbound_tx.clone()
    }

    /// Send a pre-packed DCX binary frame over the open pickup WS.
    ///
    /// Same semantics as [`Self::try_send_packed`] but writes as a
    /// WebSocket binary frame (opcode `0x2`). The mediator's WS
    /// handler demuxes by opcode: text frames take the legacy DIDComm
    /// v2 path, binary frames are routed by the DCX `routing_prefix`.
    pub fn try_send_binary(&self, frame: Vec<u8>) -> std::result::Result<(), &'static str> {
        if !self.is_connected() {
            return Err("ws pickup not connected");
        }
        self.outbound_binary_tx
            .send(frame)
            .map_err(|_| "ws pickup loop closed")
    }

    /// Clone the binary outbound sender for use by
    /// [`didcomm::dcx::transports::outbound::DcxOutboundTransport`].
    pub fn binary_outbound_sender(&self) -> mpsc::UnboundedSender<Vec<u8>> {
        self.outbound_binary_tx.clone()
    }
}

/// Build a packed `messagepickup/2.0/delivery-request` for an agent's
/// connection to the mediator. Used by both the WS pickup loop here and
/// the HTTP poll path in `pickup.rs`; until now both built it inline.
///
/// Body shape per RFC 0685:
/// - always `{ "limit": N }`
/// - optional `{ "recipient_key": "did:key:…" }` for per-key polling
/// - `~transport.return_route = "all"` so the mediator may inline the
///   response on the same transport (matters for HTTP, harmless on WS)
pub(crate) async fn build_delivery_request(
    agent: &Arc<Agent>,
    connection_id: &str,
    mediator_did: &str,
    limit: u32,
    recipient_key: Option<&str>,
) -> Result<String> {
    let conn = agent
        .connections()
        .find_by_id(connection_id)
        .await
        .map_err(|e| AgentError::Mediation(format!("find mediator connection: {}", e)))?
        .ok_or_else(|| {
            AgentError::Mediation(format!("mediator connection not found: {}", connection_id))
        })?;
    let our_did = conn.did.clone();

    let body = if let Some(key) = recipient_key {
        serde_json::json!({ "limit": limit, "recipient_key": key })
    } else {
        serde_json::json!({ "limit": limit })
    };

    let mut extra = std::collections::HashMap::new();
    extra.insert(
        "~transport".to_string(),
        serde_json::json!({ "return_route": "all" }),
    );

    let request = didcomm::core::Message {
        id: uuid::Uuid::new_v4().to_string(),
        msg_type: protocol_pickup::messages::types::DELIVERY_REQUEST.to_string(),
        body,
        from: Some(our_did.clone()),
        to: Some(vec![mediator_did.to_string()]),
        thread: None,
        pthid: None,
        created_time: None,
        expires_time: None,
        attachments: None,
        extra,
    };

    agent
        .pack_message_with_sender(&request, mediator_did, &our_did, true)
        .await
        .map_err(|e| AgentError::Mediation(format!("pack delivery-request: {}", e)))
}

/// Build a packed `messagepickup/2.0/live-delivery-change { live_delivery: true }`.
pub(crate) async fn build_live_delivery_change(
    agent: &Arc<Agent>,
    connection_id: &str,
    mediator_did: &str,
    live: bool,
) -> Result<String> {
    let conn = agent
        .connections()
        .find_by_id(connection_id)
        .await
        .map_err(|e| AgentError::Mediation(format!("find mediator connection: {}", e)))?
        .ok_or_else(|| {
            AgentError::Mediation(format!("mediator connection not found: {}", connection_id))
        })?;
    let our_did = conn.did.clone();

    let mut extra = std::collections::HashMap::new();
    extra.insert(
        "~transport".to_string(),
        serde_json::json!({ "return_route": "all" }),
    );

    let msg = didcomm::core::Message {
        id: uuid::Uuid::new_v4().to_string(),
        msg_type: protocol_pickup::messages::types::LIVE_DELIVERY_CHANGE.to_string(),
        body: serde_json::json!({ "live_delivery": live }),
        from: Some(our_did.clone()),
        to: Some(vec![mediator_did.to_string()]),
        thread: None,
        pthid: None,
        created_time: None,
        expires_time: None,
        attachments: None,
        extra,
    };

    agent
        .pack_message_with_sender(&msg, mediator_did, &our_did, true)
        .await
        .map_err(|e| AgentError::Mediation(format!("pack live-delivery-change: {}", e)))
}

impl Agent {
    /// Spawn the canonical WS pickup loop.
    ///
    /// Returns a [`WsPickupHandle`] — clone-cheap, drop-safe, exposes
    /// shutdown + state. Lifecycle events fire on `Agent::events` under
    /// topic `pickup` (see module docs for the full event list).
    ///
    /// Pass the dispatch callback as `None` for the standard
    /// single-agent behaviour: every received frame is funneled through
    /// [`Agent::process_inbound_http`] (which handles JWE detection,
    /// unpacking, and handler-registry dispatch). The multi-tenant
    /// `agent_tenants` wrapper supplies a custom callback that routes
    /// by JWE kid to the addressed tenant; the FFI wrapper uses the
    /// default and additionally subscribes to the event bus for its
    /// JS/Swift-side event emissions.
    pub fn spawn_ws_pickup_loop(self: Arc<Self>, config: WsPickupConfig) -> WsPickupHandle {
        self.spawn_ws_pickup_loop_with_dispatch(config, None)
    }

    /// Variant that lets the caller intercept frame dispatch.
    ///
    /// `dispatch` receives the raw text/binary payload of every
    /// inbound WS frame (after Ping/Pong/Close are filtered out). When
    /// `None`, the default dispatch hands the frame to
    /// [`Agent::process_inbound_http`].
    pub fn spawn_ws_pickup_loop_with_dispatch(
        self: Arc<Self>,
        config: WsPickupConfig,
        dispatch: Option<DispatchFn>,
    ) -> WsPickupHandle {
        self.spawn_ws_pickup_loop_with_full_dispatch(config, dispatch, None)
    }

    /// Variant that additionally accepts a binary-frame hook. When set
    /// and it returns `true`, the loop skips the UTF-8 fallback for
    /// that frame. `agent_tenants` installs a hook that routes DCX
    /// frames to the recipient tenant's inbound extension.
    pub fn spawn_ws_pickup_loop_with_full_dispatch(
        self: Arc<Self>,
        config: WsPickupConfig,
        dispatch: Option<DispatchFn>,
        binary_dispatch: Option<BinaryDispatchFn>,
    ) -> WsPickupHandle {
        let (connected_tx, connected_rx) = watch::channel(false);
        let state = Arc::new(RwLock::new(WsPickupState::Disconnected));
        let last_message_ts_ms = Arc::new(AtomicI64::new(-1));
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let shutdown_notify = Arc::new(Notify::new());
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<String>();
        let (outbound_binary_tx, outbound_binary_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        let inner = WsLoopInner {
            agent: self.clone(),
            config: config.clone(),
            state: state.clone(),
            connected_tx,
            last_message_ts_ms: last_message_ts_ms.clone(),
            shutdown_flag: shutdown_flag.clone(),
            shutdown_notify: shutdown_notify.clone(),
            dispatch,
            binary_dispatch,
            outbound_rx,
            outbound_binary_rx,
        };

        let join_handle = tokio::spawn(async move {
            inner.run().await;
        });

        WsPickupHandle {
            state,
            connected: connected_rx,
            last_message_ts_ms,
            shutdown_flag,
            shutdown_notify,
            outbound_tx,
            outbound_binary_tx,
            join_handle,
        }
    }

    /// Convenience: spawn the pickup loop AND register a
    /// [`WsMediatorOutboundTransport`] bound to the same mediator,
    /// so subsequent outbound DIDComm to the mediator's HTTP endpoint
    /// rides the open WS instead of opening a fresh HTTP POST.
    ///
    /// This is the Phase 0 "blazing fast" entrypoint — replaces every
    /// `spawn_ws_pickup_loop` callsite that wants bidirectional WS.
    /// Returns the handle; the outbound transport is owned by the
    /// agent's `TransportManager`. There is no protocol change — the
    /// mediator's existing WS handler accepts JWE frames bidirectionally
    /// via its direct-routing fast path.
    pub async fn spawn_ws_pickup_with_outbound(
        self: Arc<Self>,
        config: WsPickupConfig,
    ) -> WsPickupHandle {
        let agent = self.clone();
        let mediator_endpoint = config.http_endpoint.clone();
        let handle = self.spawn_ws_pickup_loop(config);
        let transport =
            crate::transport::WsMediatorOutboundTransport::new(mediator_endpoint, &handle);
        // Register at index 0 so the selector picks WS over HTTP
        // whenever the endpoint matches and the WS is connected.
        // `supports_endpoint` returns false on disconnect, so the
        // selector transparently falls through to HTTP.
        agent
            .transport
            .register_outbound_first(Box::new(transport))
            .await;
        handle
    }
}

/// Dispatch callback type used by
/// [`Agent::spawn_ws_pickup_loop_with_dispatch`]. Receives the raw
/// payload of each inbound WS frame as a `String` (Binary frames are
/// already converted to UTF-8 before this is called). The return type
/// is intentionally `()` — the loop logs and continues regardless of
/// whether the handler accepted the message.
pub type DispatchFn = Arc<
    dyn Fn(Arc<Agent>, String) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Callback invoked on every WS Binary frame BEFORE the UTF-8 fallback.
/// Return `true` to signal the handler consumed the frame — the loop
/// then skips the UTF-8 branch. Return `false` to let it fall through
/// (the default when no handler is installed).
///
/// Used by the DCX opaque-relay path: `agent_tenants` installs a
/// handler that decodes the frame header, routes to the owning tenant,
/// and calls `tenant.dcx.inbound.try_handle`.
pub type BinaryDispatchFn = Arc<
    dyn Fn(Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        + Send
        + Sync,
>;

struct WsLoopInner {
    agent: Arc<Agent>,
    config: WsPickupConfig,
    state: Arc<RwLock<WsPickupState>>,
    connected_tx: watch::Sender<bool>,
    last_message_ts_ms: Arc<AtomicI64>,
    shutdown_flag: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    dispatch: Option<DispatchFn>,
    /// Optional pre-UTF-8 hook for binary WS frames. When set and it
    /// returns `true`, the frame is considered handled and the loop
    /// skips the legacy `String::from_utf8` fallback.
    binary_dispatch: Option<BinaryDispatchFn>,
    /// Outbound queue from `WsPickupHandle::try_send_packed`. Polled by
    /// the read loop's `select!`; writes go straight to the open WS.
    outbound_rx: mpsc::UnboundedReceiver<String>,
    /// Binary-outbound queue from `WsPickupHandle::try_send_binary`.
    /// Read loop writes these as WS binary frames.
    outbound_binary_rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl WsLoopInner {
    async fn run(mut self) {
        let mut attempt: u32 = 0;
        let session_id = uuid::Uuid::new_v4().to_string();

        loop {
            if self.shutdown_flag.load(Ordering::Relaxed) {
                debug!(target: "agent.ws_pickup", "shutdown requested, exiting");
                let _ = self.connected_tx.send(false);
                self.emit_disconnected("shutdown").await;
                self.emit_live_session_removed(&session_id, Some("shutdown"))
                    .await;
                *self.state.write().await = WsPickupState::Disconnected;
                return;
            }

            // Exponential backoff before reconnect attempts (skip first try)
            if attempt > 0 {
                let backoff_secs = (1u64 << std::cmp::min(attempt.saturating_sub(1), 6))
                    .min(WS_RECONNECT_MAX_BACKOFF);
                *self.state.write().await = WsPickupState::Reconnecting { attempt };
                self.emit_reconnecting(attempt, backoff_secs).await;
                info!(
                    target: "agent.ws_pickup",
                    attempt,
                    backoff_secs,
                    "reconnecting"
                );
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(backoff_secs)) => {}
                    _ = self.shutdown_notify.notified() => {
                        let _ = self.connected_tx.send(false);
                        self.emit_disconnected("shutdown during backoff").await;
                        *self.state.write().await = WsPickupState::Disconnected;
                        return;
                    }
                }
            }

            // Connect
            *self.state.write().await = WsPickupState::Connecting;
            self.emit_connecting(attempt).await;
            info!(target: "agent.ws_pickup", endpoint = %self.config.ws_endpoint, attempt, "connecting");

            let (ws, reader) = match WsConnection::connect(&self.config.ws_endpoint).await {
                Ok(pair) => pair,
                Err(e) => {
                    let err = e.to_string();
                    warn!(target: "agent.ws_pickup", error = %err, attempt, "connect failed");
                    self.emit_connect_failed(attempt, &err).await;
                    attempt += 1;
                    continue;
                }
            };

            // Connected
            attempt = 0;
            *self.state.write().await = WsPickupState::Connected;
            let _ = self.connected_tx.send(true);
            self.emit_connected().await;
            self.emit_live_session_saved(&session_id).await;
            info!(target: "agent.ws_pickup", endpoint = %self.config.ws_endpoint, "connected");

            // Session: drain → enable live delivery → read loop
            let reason = self.run_session(ws, reader).await;

            // Disconnected
            *self.state.write().await = WsPickupState::Disconnected;
            let _ = self.connected_tx.send(false);
            self.emit_disconnected(&reason).await;
            self.emit_live_session_removed(&session_id, Some(reason.as_str()))
                .await;
            info!(target: "agent.ws_pickup", reason = %reason, "disconnected");

            if self.shutdown_flag.load(Ordering::Relaxed) {
                return;
            }

            attempt += 1;
        }
    }

    /// Drain the existing queue, enable live delivery, then enter the
    /// read loop. Returns a short reason string on disconnect.
    async fn run_session(&mut self, ws: WsConnection, mut reader: WsReadStream) -> String {
        // 1. Drain whatever's already queued
        if let Err(e) = self.drain_queue(&ws, &mut reader).await {
            return format!("drain failed: {}", e);
        }
        // 2. Subscribe to live delivery
        if let Err(e) = self.enable_live_delivery(&ws).await {
            return format!("enable live delivery: {}", e);
        }
        // 3. Read pushed messages until close / error / timeout
        let reason = self.read_loop(&ws, &mut reader).await;
        let _ = ws.close().await;
        reason
    }

    async fn drain_queue(&self, ws: &WsConnection, reader: &mut WsReadStream) -> Result<()> {
        debug!(target: "agent.ws_pickup", "draining queue");
        let mut total = 0u32;
        loop {
            let packed = build_delivery_request(
                &self.agent,
                &self.config.connection_id,
                &self.config.mediator_did,
                10,
                None,
            )
            .await?;
            ws.send(&packed)
                .await
                .map_err(|e| AgentError::Transport(format!("WS send delivery-request: {}", e)))?;

            let raw = self.read_next_text(reader).await?;
            let decrypted = self
                .agent
                .decrypt_only(&raw)
                .await
                .map_err(|e| AgentError::Mediation(format!("decrypt drain response: {}", e)))?;
            let response: serde_json::Value = serde_json::from_str(&decrypted)
                .map_err(|e| AgentError::Mediation(format!("parse drain response: {}", e)))?;

            // status with count=0 → done
            if let Some(t) = response
                .get("@type")
                .or_else(|| response.get("type"))
                .and_then(|v| v.as_str())
            {
                if t.contains("status") {
                    let count = response
                        .get("message_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    if count == 0 {
                        info!(target: "agent.ws_pickup", drained = total, "drain complete");
                        return Ok(());
                    }
                }
            }

            let (processed, ack_ids) = self
                .agent
                .process_pickup_delivery(
                    &response,
                    &self.config.connection_id,
                    &self.config.mediator_did,
                    &self.config.http_endpoint,
                )
                .await?;

            if !ack_ids.is_empty() {
                let ack = self
                    .agent
                    .build_pickup_ack(
                        &self.config.connection_id,
                        &self.config.mediator_did,
                        &ack_ids,
                    )
                    .await?;
                ws.send(&ack)
                    .await
                    .map_err(|e| AgentError::Transport(format!("WS send ACK: {}", e)))?;
                total += processed;
            }

            if processed == 0 {
                info!(target: "agent.ws_pickup", drained = total, "drain complete");
                return Ok(());
            }
        }
    }

    async fn enable_live_delivery(&self, ws: &WsConnection) -> Result<()> {
        let packed = build_live_delivery_change(
            &self.agent,
            &self.config.connection_id,
            &self.config.mediator_did,
            true,
        )
        .await?;
        ws.send(&packed)
            .await
            .map_err(|e| AgentError::Transport(format!("WS send live-delivery-change: {}", e)))?;
        info!(target: "agent.ws_pickup", "live delivery enabled");
        Ok(())
    }

    async fn read_loop(&mut self, ws: &WsConnection, reader: &mut WsReadStream) -> String {
        let mut ping_tick = tokio::time::interval(WS_PING_INTERVAL);
        // skip the immediate first tick — we want first ping at +25s
        ping_tick.tick().await;

        loop {
            tokio::select! {
                framed = tokio::time::timeout(WS_READ_IDLE_TIMEOUT, reader.next()) => {
                    match framed {
                        Ok(Some(Ok(msg))) => {
                            match msg {
                                WsMessage::Text(text) => {
                                    self.bump_last_message_ts();
                                    self.dispatch_payload(text.to_string()).await;
                                }
                                WsMessage::Binary(bin) => {
                                    self.bump_last_message_ts();
                                    let bytes = bin.to_vec();
                                    // DCX opaque-relay hook. When
                                    // `binary_dispatch` returns true,
                                    // the frame is a decoded DCX one and
                                    // no further processing is needed.
                                    let mut consumed = false;
                                    if let Some(ref handler) = self.binary_dispatch {
                                        consumed = handler(bytes.clone()).await;
                                    }
                                    if !consumed {
                                        if let Ok(text) = String::from_utf8(bytes) {
                                            self.dispatch_payload(text).await;
                                        } else {
                                            warn!(target: "agent.ws_pickup",
                                                "binary frame not UTF-8 and no DCX handler, dropping");
                                        }
                                    }
                                }
                                WsMessage::Ping(_) | WsMessage::Pong(_) => {
                                    self.bump_last_message_ts();
                                    trace!(target: "agent.ws_pickup", "ping/pong (keepalive)");
                                }
                                WsMessage::Close(frame) => {
                                    let reason = frame
                                        .map(|f| format!("code={} reason={}", f.code, f.reason))
                                        .unwrap_or_else(|| "no close frame".into());
                                    return format!("server closed: {}", reason);
                                }
                                _ => {}
                            }
                        }
                        Ok(Some(Err(e))) => return format!("read error: {}", e),
                        Ok(None) => return "stream ended".into(),
                        Err(_elapsed) => {
                            warn!(target: "agent.ws_pickup",
                                connection_id = %self.config.connection_id,
                                idle_secs = WS_READ_IDLE_TIMEOUT.as_secs(),
                                "read idle timeout — forcing reconnect");
                            self.emit_read_timeout().await;
                            return "read idle timeout".into();
                        }
                    }
                }
                _ = ping_tick.tick() => {
                    if let Err(e) = ws.send_ping(Vec::new()).await {
                        warn!(target: "agent.ws_pickup", error = %e, "keepalive ping send failed");
                    }
                }
                outbound = self.outbound_rx.recv() => {
                    match outbound {
                        Some(packed) => {
                            // Drain whatever else is queued in one batch
                            // to avoid yielding back to `select!` per
                            // message under bursty load.
                            trace!(target: "agent.ws_pickup", bytes = packed.len(), "outbound send");
                            if let Err(e) = ws.send(&packed).await {
                                warn!(target: "agent.ws_pickup", error = %e, "outbound WS send failed");
                                // Drop the connection — caller will reconnect
                                // and fall back to HTTP for in-flight sends.
                                return format!("outbound send error: {}", e);
                            }
                            while let Ok(more) = self.outbound_rx.try_recv() {
                                if let Err(e) = ws.send(&more).await {
                                    warn!(target: "agent.ws_pickup", error = %e, "outbound WS send failed (batch)");
                                    return format!("outbound send error: {}", e);
                                }
                            }
                        }
                        None => {
                            // sender side dropped — shouldn't happen
                            // while the handle is alive; treat as a
                            // normal disconnect.
                            return "outbound channel closed".into();
                        }
                    }
                }
                outbound_bin = self.outbound_binary_rx.recv() => {
                    match outbound_bin {
                        Some(frame) => {
                            trace!(target: "agent.ws_pickup", bytes = frame.len(), "outbound binary send (DCX)");
                            if let Err(e) = ws.send_binary(frame).await {
                                warn!(target: "agent.ws_pickup", error = %e, "outbound binary WS send failed");
                                return format!("outbound binary send error: {}", e);
                            }
                            while let Ok(more) = self.outbound_binary_rx.try_recv() {
                                if let Err(e) = ws.send_binary(more).await {
                                    warn!(target: "agent.ws_pickup", error = %e, "outbound binary WS send failed (batch)");
                                    return format!("outbound binary send error: {}", e);
                                }
                            }
                        }
                        None => return "binary outbound channel closed".into(),
                    }
                }
                _ = self.shutdown_notify.notified() => {
                    return "shutdown requested".into();
                }
            }
        }
    }

    async fn dispatch_payload(&self, raw: String) {
        if raw.is_empty() {
            return;
        }
        if let Some(ref dispatch) = self.dispatch {
            // Custom dispatch path (agent_tenants uses this to route by
            // recipient kid to the addressed tenant before unwrapping).
            let agent = self.agent.clone();
            dispatch(agent, raw).await;
            return;
        }

        // Default single-agent dispatch. The mediator's live-pushed
        // payload is most commonly the original JWE the sender posted
        // (after the mediator strips the outer Forward), but it can
        // also be a `messagepickup/2.0/delivery` envelope wrapping
        // one or more attachments. Peek the inner type so we can
        // route either case correctly.
        let decrypted = match self.agent.decrypt_only(&raw).await {
            Ok(d) => d,
            Err(e) => {
                debug!(target: "agent.ws_pickup", error = %e, "decrypt_only failed; treating as direct push");
                self.process_direct(&raw).await;
                return;
            }
        };
        let json: serde_json::Value = match serde_json::from_str(&decrypted) {
            Ok(j) => j,
            Err(_) => {
                self.process_direct(&raw).await;
                return;
            }
        };
        let msg_type = json
            .get("@type")
            .or_else(|| json.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if msg_type.contains("delivery") {
            // messagepickup/2.0/delivery wrapper → process attachments.
            // `process_pickup_delivery` already handles the flush of
            // pending keylist registrations + `route_packed_response`
            // per attachment, so we don't need to repeat that here.
            match self
                .agent
                .process_pickup_delivery(
                    &json,
                    &self.config.connection_id,
                    &self.config.mediator_did,
                    &self.config.http_endpoint,
                )
                .await
            {
                Ok((_processed, ack_ids)) if !ack_ids.is_empty() => {
                    // ACK over HTTP — easier than threading the WS
                    // sender down into the dispatch callback. The
                    // mediator doesn't care which transport carries
                    // the ACK as long as the ids come back.
                    self.http_ack(&ack_ids).await;
                }
                Ok(_) => {}
                Err(e) => {
                    debug!(target: "agent.ws_pickup", error = %e, "process_pickup_delivery failed")
                }
            }
        } else if msg_type.contains("status") {
            // messagepickup/2.0/status — informational, just log
            trace!(target: "agent.ws_pickup", msg_type, "pickup status frame");
        } else {
            // Direct push from live delivery (not wrapped) — fall
            // through to the same path used for HTTP delivery
            // attachments.
            self.process_direct(&raw).await;
        }
    }

    /// Process a raw inbound payload (JWE or plaintext) via the
    /// agent's canonical inbound pipeline, then flush pending
    /// keylist-update queue items and route any synchronous response
    /// back to the peer. Matches the previous FFI behaviour exactly —
    /// without the keylist flush, DidExchange Response messages addressed
    /// to a freshly-minted pairwise key get 500'd by the mediator.
    async fn process_direct(&self, raw: &str) {
        match self.agent.process_inbound_http(raw.to_string(), None).await {
            Ok(Some(response)) => {
                for key in self.agent.take_pending_key_registrations() {
                    if let Err(e) = self
                        .agent
                        .update_keylist_with_mediator(
                            &self.config.connection_id,
                            &key,
                            &self.config.http_endpoint,
                        )
                        .await
                    {
                        debug!(target: "agent.ws_pickup", error = %e, key = %key, "keylist-update failed");
                    }
                }
                if let Err(e) = self.agent.route_packed_response(&response).await {
                    debug!(target: "agent.ws_pickup", error = %e, "route_packed_response failed");
                }
            }
            Ok(None) => {}
            Err(e) => debug!(target: "agent.ws_pickup", error = %e, "process_inbound_http failed"),
        }
    }

    /// Send a `messages-received` ACK over HTTP.
    async fn http_ack(&self, ack_ids: &[String]) {
        let ack = match self
            .agent
            .build_pickup_ack(
                &self.config.connection_id,
                &self.config.mediator_did,
                ack_ids,
            )
            .await
        {
            Ok(p) => p,
            Err(e) => {
                debug!(target: "agent.ws_pickup", error = %e, "build_pickup_ack failed");
                return;
            }
        };
        let resp = self
            .agent
            .http_client
            .post(&self.config.http_endpoint)
            .header("Content-Type", "application/didcomm-envelope-enc")
            .body(ack)
            .send()
            .await;
        if let Err(e) = resp {
            debug!(target: "agent.ws_pickup", error = %e, "HTTP ACK send failed");
        }
    }

    async fn read_next_text(&self, reader: &mut WsReadStream) -> Result<String> {
        loop {
            match reader.next().await {
                Some(Ok(WsMessage::Text(text))) => return Ok(text.to_string()),
                Some(Ok(WsMessage::Binary(bin))) => {
                    return String::from_utf8(bin.to_vec()).map_err(|e| {
                        AgentError::Transport(format!("binary frame not UTF-8: {}", e))
                    })
                }
                Some(Ok(WsMessage::Ping(_))) | Some(Ok(WsMessage::Pong(_))) => continue,
                Some(Ok(WsMessage::Close(_))) => {
                    return Err(AgentError::Transport("WS closed during read".into()))
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(AgentError::Transport(format!("WS read: {}", e))),
                None => return Err(AgentError::Transport("WS stream ended".into())),
            }
        }
    }

    fn bump_last_message_ts(&self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        self.last_message_ts_ms.store(now_ms, Ordering::Relaxed);
    }

    // ── Event emission helpers (topic = "pickup") ───────────────────

    /// Centralised raw-event publish so each emit helper is a 2-liner
    /// and we don't repeat the `EventBus::publish` boilerplate.
    async fn emit(&self, name: &str, data: serde_json::Value) {
        let event = agent_events::Event::new(&self.config.connection_id, "pickup", name, data);
        let _ = self.agent.events.publish(event).await;
    }

    async fn emit_connecting(&self, attempt: u32) {
        self.emit(
            "ws_connecting",
            serde_json::json!({
                "attempt": attempt,
                "endpoint": self.config.ws_endpoint,
            }),
        )
        .await;
    }

    async fn emit_connect_failed(&self, attempt: u32, err: &str) {
        self.emit(
            "ws_connect_failed",
            serde_json::json!({
                "attempt": attempt,
                "endpoint": self.config.ws_endpoint,
                "error": err,
            }),
        )
        .await;
    }

    async fn emit_connected(&self) {
        self.emit(
            "ws_connected",
            serde_json::json!({ "endpoint": self.config.ws_endpoint }),
        )
        .await;
    }

    async fn emit_disconnected(&self, reason: &str) {
        self.emit("ws_disconnected", serde_json::json!({ "reason": reason }))
            .await;
    }

    async fn emit_reconnecting(&self, attempt: u32, backoff_secs: u64) {
        self.emit(
            "ws_reconnecting",
            serde_json::json!({
                "attempt": attempt,
                "backoff_secs": backoff_secs,
            }),
        )
        .await;
    }

    async fn emit_read_timeout(&self) {
        self.emit(
            "ws_read_timeout",
            serde_json::json!({
                "connection_id": self.config.connection_id,
                "idle_secs": WS_READ_IDLE_TIMEOUT.as_secs(),
            }),
        )
        .await;
    }

    async fn emit_live_session_saved(&self, session_id: &str) {
        let payload = protocol_pickup::events::PickupLiveSessionSavedPayload {
            session_id: session_id.to_string(),
            connection_id: self.config.connection_id.clone(),
            transport: "ws".to_string(),
        };
        let meta = agent_events::EventMetadata::for_tenant(&self.config.connection_id);
        let _ = self.agent.events.emit(&meta, payload).await;
    }

    async fn emit_live_session_removed(&self, session_id: &str, reason: Option<&str>) {
        let payload = protocol_pickup::events::PickupLiveSessionRemovedPayload {
            session_id: session_id.to_string(),
            connection_id: self.config.connection_id.clone(),
            reason: reason.map(str::to_string),
        };
        let meta = agent_events::EventMetadata::for_tenant(&self.config.connection_id);
        let _ = self.agent.events.emit(&meta, payload).await;
    }
}
