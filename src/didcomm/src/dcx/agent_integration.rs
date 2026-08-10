//! Agent integration helpers.
//!
//! Wires DCX components together for a typical wallet:
//! - Builds a [`DcxRuntime`] bundling the channel manager, classical
//!   provider, outbound transport, and inbound extension.
//! - Provides a one-call helper that, given an agent's WS pickup
//!   handle + a peer's X25519 key material, registers the channel and
//!   returns a working outbound transport.
//!
//! Wallet code calls [`DcxRuntime::new`] once at agent startup and
//! [`DcxRuntime::register_classical_peer`] once per connection.

use crate::dcx::channel::{ChannelCounterStore, ChannelManager};
use crate::dcx::providers::classical::{ClassicalKeyMaterial, ClassicalX25519Provider};
use crate::dcx::session::SessionKeyProvider;
use crate::dcx::transports::{DcxInboundExtension, DcxOutboundTransport};
use std::sync::{Arc, OnceLock};
use tokio::sync::mpsc;

/// Bundled DCX runtime for a wallet.
///
/// Hand it the binary outbound sender from your `WsPickupHandle`
/// (via `binary_outbound_sender()`) and a dispatcher callback that
/// handles inbound DATA frames.
pub struct DcxRuntime {
    /// Lookup tables for all open DCX channels.
    pub channels: Arc<ChannelManager>,
    /// The classical SessionKeyProvider; PqBridge can be added later.
    pub classical: Arc<ClassicalX25519Provider>,
    /// Outbound transport — call [`DcxOutboundTransport::send_to_peer`]
    /// from your application code.
    pub outbound: Arc<DcxOutboundTransport>,
    /// Inbound extension — hand binary WS frames to
    /// [`DcxInboundExtension::try_handle`] before treating them as text.
    pub inbound: Arc<DcxInboundExtension>,
    /// Durable counter store (nonce/replay safety across restarts). Also
    /// consulted by [`Self::ensure_channel`] so the proactive rebuild path
    /// resumes counters instead of resetting them.
    counter_store: OnceLock<Arc<dyn ChannelCounterStore>>,
}

impl DcxRuntime {
    /// Build a new DCX runtime.
    ///
    /// `binary_tx` comes from [`WsPickupHandle::binary_outbound_sender`].
    /// `dispatcher` is invoked for every successfully-decoded inbound
    /// frame; typically it forwards the plaintext to the agent's
    /// normal message handler.
    /// `is_initiator` controls directional key derivation — `true`
    /// for the wallet that initiated the OOB invitation.
    pub fn new(
        binary_tx: mpsc::UnboundedSender<Vec<u8>>,
        dispatcher: crate::dcx::transports::inbound::DcxDispatcher,
        is_initiator: bool,
    ) -> Self {
        let channels = Arc::new(ChannelManager::new());
        let classical = ClassicalX25519Provider::new(64);
        let outbound = Arc::new(DcxOutboundTransport::new(
            channels.clone(),
            classical.clone() as Arc<dyn SessionKeyProvider>,
            binary_tx,
            is_initiator,
        ));
        let inbound = DcxInboundExtension::new(channels.clone(), dispatcher);
        Self {
            channels,
            classical,
            outbound,
            inbound,
            counter_store: OnceLock::new(),
        }
    }

    /// Attach a durable [`ChannelCounterStore`] to both transports and
    /// the runtime, enabling cross-restart nonce/replay safety. A process
    /// that persists DCX channels MUST call this before any DCX traffic.
    /// Idempotent; wired through the `Arc`s so the constructor stays
    /// backward-compatible.
    pub fn set_counter_store(&self, store: Arc<dyn ChannelCounterStore>) {
        let _ = self.counter_store.set(store.clone());
        self.outbound.set_counter_store(store.clone());
        self.inbound.set_counter_store(store);
    }

    /// Register a peer for classical-provider DCX.
    ///
    /// Call once per established DIDComm v2 connection, after the
    /// wallet has extracted the relevant X25519 keys + DIDs.
    pub async fn register_classical_peer(&self, material: ClassicalKeyMaterial) {
        self.classical.register_peer_material(material).await;
    }

    /// Proactively establish a peer channel from already-registered
    /// material and insert it into the channel manager, so inbound
    /// frames find it even before this side sends anything.
    ///
    /// Without this, a channel is only created lazily on first *send*
    /// (see [`DcxOutboundTransport::send_to_peer`]). The peer that
    /// receives first would have no channel and would drop the frame as
    /// "unknown channel". Call once, right after
    /// [`register_classical_peer`], on both ends of a connection.
    ///
    /// Idempotent: a no-op if the channel already exists. The initiator
    /// role is taken from the provider's per-pair decision.
    pub async fn ensure_channel(&self, peer_did: &str) {
        if self.channels.get_by_peer_did(peer_did).await.is_some() {
            return;
        }
        match self.classical.establish(peer_did).await {
            Ok(keys) => {
                let provider_id = self.classical.provider_id().to_string();
                // Resume persisted counters on this proactive rebuild path
                // (after a restart) — a bare reset here under the classical
                // provider's deterministic k_send would reuse nonces.
                let channel = {
                    let base = || {
                        crate::dcx::channel::Channel::from_session_keys(
                            &keys,
                            peer_did.to_string(),
                            provider_id.clone(),
                            keys.is_initiator,
                        )
                    };
                    if let Some(store) = self.counter_store.get() {
                        let channel_id = crate::dcx::routing::derive_channel_id(
                            &provider_id,
                            &keys.connection_id,
                            keys.generation,
                        );
                        match store.load(&channel_id).await {
                            Some(persisted) => crate::dcx::channel::Channel::resume(
                                &keys,
                                peer_did.to_string(),
                                provider_id.clone(),
                                keys.is_initiator,
                                persisted,
                            ),
                            None => base(),
                        }
                    } else {
                        base()
                    }
                };
                self.channels.insert(channel).await;
                tracing::debug!(
                    target: "dcx",
                    peer_did,
                    is_initiator = keys.is_initiator,
                    "ensured peer DCX channel"
                );
            }
            Err(e) => {
                tracing::debug!(
                    target: "dcx",
                    peer_did,
                    error = %e,
                    "ensure_channel: establish failed (material missing?)"
                );
            }
        }
    }

    /// Build a dormant DCX runtime — no real WS wire, no real dispatcher.
    ///
    /// Used at agent/tenant startup before any DIDComm channels are
    /// established. The outbound `binary_tx` writes into a channel
    /// whose receiver is a spawned drain-and-drop task, keeping sends
    /// from erroring; the dispatcher is a no-op. As long as no peers
    /// are registered on `classical`, no traffic ever flows — the
    /// runtime is inert.
    ///
    /// Session B replaces the placeholder consumer with a real WS
    /// binary sender, and Session C swaps in a dispatcher that feeds
    /// decoded plaintext into the agent's MessageProcessor. Same
    /// construction shape as here.
    pub fn new_dormant(is_initiator: bool) -> Self {
        let (binary_tx, mut binary_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move { while binary_rx.recv().await.is_some() {} });
        let dispatcher: crate::dcx::transports::inbound::DcxDispatcher =
            std::sync::Arc::new(move |_channel_id, _msg_id, _body| Box::pin(async move {}));
        Self::new(binary_tx, dispatcher, is_initiator)
    }
}
