//! Inbound DCX handler — invoked by the WS pickup loop for every WS
//! binary frame received.
//!
//! Three outcomes per frame:
//! - [`InboundOutcome::Handled`] — frame was a valid DCX frame for a
//!   known channel and was dispatched to the channel handler
//! - [`InboundOutcome::NotDcx`] — bytes didn't parse as DCX; caller
//!   should fall through to the legacy text-frame path
//! - [`InboundOutcome::DcxError`] — bytes parsed as DCX but
//!   verification failed; caller MUST drop the frame and SHOULD log

use crate::dcx::channel::{ChannelCounterStore, ChannelManager};
use crate::dcx::errors::FrameError;
use crate::dcx::frame::{decode_and_verify, decode_header, FrameBody};
use std::sync::{Arc, OnceLock};
use tracing::{debug, trace, warn};

/// Outcome of inspecting a binary WS frame.
#[derive(Debug)]
pub enum InboundOutcome {
    /// Frame was recognized and dispatched.
    Handled,
    /// Frame did not parse as DCX; caller should try the legacy path
    /// (e.g., treat as UTF-8 text DIDComm v2).
    NotDcx,
    /// Frame parsed as DCX but verification failed (unknown channel,
    /// AEAD failure, replay, etc.).
    DcxError(FrameError),
}

/// Callback invoked on each decoded plaintext body.
///
/// The dispatcher receives the channel id (so it can look up which
/// peer this frame came from), the inbound msg_id (for replay
/// tracking by the application if it cares), and the decoded body.
pub type DcxDispatcher = Arc<
    dyn Fn(
            [u8; 16],
            u64,
            FrameBody,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Inbound extension for the WS pickup loop.
pub struct DcxInboundExtension {
    channels: Arc<ChannelManager>,
    dispatcher: DcxDispatcher,
    /// Durable store for the inbound replay high-water mark, so replay
    /// protection survives a restart. Unset ⇒ in-memory only.
    counter_store: OnceLock<Arc<dyn ChannelCounterStore>>,
}

impl DcxInboundExtension {
    /// Build a new inbound extension.
    pub fn new(channels: Arc<ChannelManager>, dispatcher: DcxDispatcher) -> Arc<Self> {
        Arc::new(Self {
            channels,
            dispatcher,
            counter_store: OnceLock::new(),
        })
    }

    /// Attach a durable [`ChannelCounterStore`] so the inbound replay
    /// high-water mark is persisted. Idempotent; callable through `Arc`.
    pub fn set_counter_store(&self, store: Arc<dyn ChannelCounterStore>) {
        let _ = self.counter_store.set(store);
    }

    /// Try to handle `bytes` as a DCX binary frame. See [`InboundOutcome`].
    pub async fn try_handle(&self, bytes: &[u8]) -> InboundOutcome {
        // Step 1: parse header. Cheap; if it fails the frame is not DCX.
        let (header, tail) = match decode_header(bytes) {
            Ok(parts) => parts,
            Err(_) => {
                trace!(target: "dcx.inbound", bytes = bytes.len(), "not a DCX frame");
                return InboundOutcome::NotDcx;
            }
        };

        // Step 2: look up channel by channel_id.
        let Some(channel_arc) = self.channels.get_by_channel_id(&header.channel_id).await else {
            trace!(
                target: "dcx.inbound",
                channel_id = hex_short(&header.channel_id),
                "unknown channel"
            );
            return InboundOutcome::DcxError(FrameError::MalformedPayload(
                "unknown channel".into(),
            ));
        };

        // Step 3: AEAD-verify FIRST, then observe msg_id for replay.
        //
        // Ordering is security-critical. `channel_id` is cleartext in
        // every frame header, so anyone on-path (including the
        // mediator) learns it from one captured frame. If we advanced
        // the replay counter on the unauthenticated header BEFORE the
        // AEAD check, an attacker could send a single forged frame with
        // `msg_id = u64::MAX`; the counter would pin there, the AEAD
        // verify would then fail and drop the frame — but every
        // subsequent LEGITIMATE frame would now be rejected as a
        // replay, permanently wedging the channel. Verifying the tag
        // first means we only ever mutate replay state on authentic
        // frames.
        let mut channel = channel_arc.lock().await;
        let body = match decode_and_verify(&header, tail, &channel.k_recv) {
            Ok(b) => b,
            Err(e) => {
                debug!(
                    target: "dcx.inbound",
                    channel_id = hex_short(&header.channel_id),
                    error = %e,
                    "frame decode/verify failed"
                );
                return InboundOutcome::DcxError(e);
            }
        };

        // Frame is authenticated — now safe to enforce replay ordering.
        if let Err(e) = channel.observe_recv(header.msg_id) {
            warn!(
                target: "dcx.inbound",
                channel_id = hex_short(&header.channel_id),
                msg_id = header.msg_id,
                error = %e,
                "replay rejected"
            );
            return InboundOutcome::DcxError(FrameError::MalformedPayload(
                "replay rejected".into(),
            ));
        }

        let channel_id = header.channel_id;
        let msg_id = header.msg_id;
        drop(channel);

        // Persist the inbound replay high-water mark so a restart resumes
        // replay protection instead of resetting to 0. Recorded as a
        // high-water max by the store, so occasional lag only widens the
        // post-restart replay window — it can never cause nonce reuse.
        if let Some(store) = self.counter_store.get() {
            store.save_recv(&channel_id, msg_id).await;
        }

        // Step 4: dispatch.
        let dispatcher = self.dispatcher.clone();
        let body_clone = body.clone();
        tokio::spawn(async move {
            dispatcher(channel_id, msg_id, body_clone).await;
        });

        debug!(
            target: "dcx.inbound",
            channel_id = hex_short(&channel_id),
            msg_id,
            "DCX frame dispatched"
        );
        InboundOutcome::Handled
    }
}

fn hex_short(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b.iter().take(4) {
        s.push_str(&format!("{:02x}", byte));
    }
    s.push('…');
    s
}
