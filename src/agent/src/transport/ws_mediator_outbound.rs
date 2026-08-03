//! WebSocket outbound transport that piggybacks on the open pickup WS.
//!
//! Phase 0 of the speed work: when a wallet has an open
//! [`WsPickupHandle`] to its mediator, every outbound DIDComm message
//! that would otherwise go via HTTP POST to that mediator can ride the
//! same WebSocket instead. That eliminates the per-message TCP+TLS
//! handshake (~30–90 ms saved cold, ~30 ms warm) and the HTTP
//! request/response framing.
//!
//! Mechanism:
//! - The transport holds the mediator's HTTP endpoint URL it was wired
//!   to (the same string the mediator advertised in its OOB invitation
//!   and that [`Agent::set_mediation_routing`] persisted as the
//!   `routing_endpoint`). [`Self::supports_endpoint`] returns `true`
//!   iff a peer's `serviceEndpoint` exactly matches this URL **and**
//!   the WS is currently connected.
//! - On a match, [`Self::send`] writes the packed JWE (a Forward
//!   addressed to the mediator's recipient key) directly into the WS
//!   via the mpsc sender exposed by
//!   [`WsPickupHandle::outbound_sender`].
//! - When the WS is disconnected, `supports_endpoint` returns `false`
//!   so the [`TransportManager`] falls through to the next registered
//!   transport — typically the HTTP outbound. There is no protocol
//!   change: the mediator's WS handler already accepts JWEs on the
//!   pickup socket (it direct-routes by recipient kid in its fast
//!   path).
//!
//! This is **not** a DIDComm protocol change. The wire payload is the
//! same Forward envelope the HTTP path would have sent. We're only
//! choosing a different transport for the wallet→mediator hop.
//!
//! The longer-term protocol change
//! drops the Forward envelope entirely and uses symmetric session keys
//! after first contact — DCX Phase 1 builds on this transport.

use std::sync::Arc;

use async_trait::async_trait;
use didcomm::transports::{OutboundTransport, Result as TransportResult, TransportError};
use tokio::sync::mpsc;
use tracing::{debug, trace};

use crate::ws_pickup::WsPickupHandle;

/// Outbound transport that sends through the open mediator pickup WS.
///
/// Registered before the HTTP outbound transport in
/// [`Agent::initialize`] (after `setup_mediation` succeeds), so the
/// transport-selector picks WS first whenever the endpoint matches
/// and the connection is up.
pub struct WsMediatorOutboundTransport {
    /// The mediator HTTP endpoint we shadow. Compared exactly against
    /// `endpoint` in `supports_endpoint`. Must match what the wallet
    /// would have used with `HttpOutboundTransport`.
    mediator_endpoint: String,

    /// Cloned from [`WsPickupHandle::outbound_sender`]. Each `send`
    /// pushes a packed envelope here; the pickup loop's read-select
    /// dequeues and writes to the live WS.
    outbound_tx: mpsc::UnboundedSender<String>,

    /// Mirrored from [`WsPickupHandle::connected`] so
    /// `supports_endpoint` can fail fast without an `.await`. The
    /// pickup loop updates this on every connect/disconnect.
    connected: tokio::sync::watch::Receiver<bool>,
}

impl WsMediatorOutboundTransport {
    /// Build a new transport bound to a given mediator endpoint and
    /// pickup-handle. The transport keeps clones of the handle's
    /// outbound sender + connected watcher; the handle itself can be
    /// dropped or moved elsewhere without affecting this transport.
    pub fn new(mediator_endpoint: String, handle: &WsPickupHandle) -> Self {
        Self {
            mediator_endpoint,
            outbound_tx: handle.outbound_sender(),
            connected: handle.connected.clone(),
        }
    }

    /// Mediator endpoint this transport is bound to. Useful for tests
    /// and diagnostics.
    pub fn mediator_endpoint(&self) -> &str {
        &self.mediator_endpoint
    }

    /// True iff the pickup WS is currently connected.
    pub fn is_connected(&self) -> bool {
        *self.connected.borrow()
    }
}

#[async_trait]
impl OutboundTransport for WsMediatorOutboundTransport {
    async fn send(&self, endpoint: &str, message: &str) -> TransportResult<Option<String>> {
        if !self.supports_endpoint(endpoint) {
            return Err(TransportError::InvalidEndpoint(format!(
                "WsMediatorOutboundTransport bound to {}, cannot send to {}",
                self.mediator_endpoint, endpoint
            )));
        }
        if !self.is_connected() {
            // Race: TransportManager called us because supports_endpoint
            // returned true, but the WS dropped in the meantime. Surface
            // a transport-not-available so the manager can fall through
            // to HTTP (caller will retry).
            return Err(TransportError::NotAvailable(self.mediator_endpoint.clone()));
        }

        trace!(
            target: "agent.ws_outbound",
            endpoint = %endpoint,
            bytes = message.len(),
            "send via pickup WS"
        );

        self.outbound_tx.send(message.to_string()).map_err(|_| {
            TransportError::SendFailed("ws pickup loop closed (handle dropped)".into())
        })?;

        // Fire-and-forget — DIDComm Forward to the mediator never
        // expects an inline response on this transport. The peer's
        // reply (if any) arrives back as a delivery push on the same
        // WS, dispatched through the normal inbound pipeline.
        Ok(None)
    }

    fn supports_endpoint(&self, endpoint: &str) -> bool {
        if endpoint != self.mediator_endpoint {
            return false;
        }
        if !self.is_connected() {
            debug!(
                target: "agent.ws_outbound",
                endpoint,
                "endpoint matches but WS disconnected — yielding to next transport"
            );
            return false;
        }
        true
    }
}

/// Convenience wrapper so callers can register the transport with one
/// call. Used by [`Agent::register_ws_mediator_outbound`].
pub fn into_boxed(transport: WsMediatorOutboundTransport) -> Box<dyn OutboundTransport> {
    Box::new(transport) as Box<dyn OutboundTransport>
}

/// Build and register the transport on an [`Agent`]'s
/// [`TransportManager`]. Returns an `Arc` so the caller can keep
/// inspection access (`is_connected`, `mediator_endpoint`) while the
/// transport-manager owns the trait-object.
///
/// Idempotency: the transport-manager does not dedupe, so callers must
/// ensure this is called once per mediator. The agent's
/// `setup_mediation` is already process-locked per mediator key, so
/// calling this from within that lock is the right pattern.
pub async fn register(agent: &Arc<crate::agent::Agent>, transport: WsMediatorOutboundTransport) {
    agent
        .transport
        .register_outbound(into_boxed(transport))
        .await;
}
