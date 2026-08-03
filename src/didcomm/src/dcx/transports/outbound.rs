//! Outbound DCX transport — packs application messages into DATA frames
//! and writes them as WS binary frames.
//!
//! Wires into the agent's existing transport selector so that, for a
//! peer with an active DCX channel, the message is sent as a binary
//! frame instead of being JWE-packed and routed via HTTP / text-frame WS.

use crate::dcx::channel::ChannelManager;
use crate::dcx::errors::ProviderError;
use crate::dcx::frame::{Frame, FrameBody, FrameHeader, FRAME_TYPE_DATA, FRAME_VERSION};
use crate::dcx::padding::{padding_length, DEFAULT_PADDING_BOUNDARY};
use crate::dcx::session::SessionKeyProvider;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, trace};

/// Outbound transport for DCX.
///
/// Holds:
/// - a `ChannelManager` for peer→channel lookup
/// - a `SessionKeyProvider` to establish channels lazily on first send
/// - a `mpsc::UnboundedSender<Vec<u8>>` (the binary outbound queue
///   from [`WsPickupHandle::binary_outbound_sender`])
pub struct DcxOutboundTransport {
    channels: Arc<ChannelManager>,
    provider: Arc<dyn SessionKeyProvider>,
    binary_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Legacy runtime-wide initiator flag. Superseded by the provider's
    /// per-pair `SessionKeys::is_initiator`; retained for construction
    /// compatibility only.
    #[allow(dead_code)]
    is_initiator: bool,
}

/// Errors produced by [`DcxOutboundTransport::send_to_peer`].
#[derive(Debug, thiserror::Error)]
pub enum DcxOutboundError {
    /// No active channel and provider couldn't establish one.
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),
    /// Frame codec rejected the packed body (e.g., > 1 MiB).
    #[error("frame codec: {0}")]
    Frame(#[from] crate::dcx::errors::FrameError),
    /// WS pickup loop has shut down or isn't connected.
    #[error("ws unavailable: {0}")]
    WsUnavailable(&'static str),
}

impl DcxOutboundTransport {
    /// Build a new outbound transport.
    pub fn new(
        channels: Arc<ChannelManager>,
        provider: Arc<dyn SessionKeyProvider>,
        binary_tx: mpsc::UnboundedSender<Vec<u8>>,
        is_initiator: bool,
    ) -> Self {
        Self {
            channels,
            provider,
            binary_tx,
            is_initiator,
        }
    }

    /// Send `application_payload` to `peer_did` as a DCX `DATA` frame.
    ///
    /// Establishes a channel on first send via the SessionKeyProvider.
    /// Pads to the next 64-byte boundary by default.
    pub async fn send_to_peer(
        &self,
        peer_did: &str,
        application_payload: Vec<u8>,
    ) -> Result<(), DcxOutboundError> {
        // 1. Ensure we have a channel.
        let channel_arc = match self.channels.get_by_peer_did(peer_did).await {
            Some(c) => c,
            None => {
                // No existing channel — drive the provider to establish.
                trace!(target: "dcx.outbound", peer_did, "establishing new DCX channel");
                let keys = self.provider.establish(peer_did).await?;
                // Honour the provider's per-pair initiator decision, not
                // the runtime-wide flag — peer channels need each end to
                // pick the opposite role for directional keys to align.
                let channel = crate::dcx::channel::Channel::from_session_keys(
                    &keys,
                    peer_did.to_string(),
                    self.provider.provider_id().to_string(),
                    keys.is_initiator,
                );
                self.channels.insert(channel).await;
                self.channels
                    .get_by_peer_did(peer_did)
                    .await
                    .ok_or(DcxOutboundError::WsUnavailable("channel registration race"))?
            }
        };

        // 2. Allocate msg_id + build frame.
        let mut channel = channel_arc.lock().await;
        let msg_id = channel.next_send_msg_id();
        let pad_len = padding_length(application_payload.len(), DEFAULT_PADDING_BOUNDARY);
        let body = FrameBody::Data {
            application_payload,
            padding: vec![0u8; pad_len],
        };
        let header = FrameHeader {
            frame_type: FRAME_TYPE_DATA,
            version: FRAME_VERSION,
            channel_id: channel.channel_id,
            routing_prefix: channel.peer_routing_prefix,
            msg_id,
        };
        let frame = Frame { header, body };
        let bytes = frame.encode(&channel.k_send)?;
        let bytes_len = bytes.len();
        drop(channel);

        // 3. Push to the WS binary outbound channel.
        self.binary_tx
            .send(bytes)
            .map_err(|_| DcxOutboundError::WsUnavailable("ws pickup loop closed"))?;

        debug!(
            target: "dcx.outbound",
            peer_did,
            msg_id,
            bytes = bytes_len,
            "sent DCX DATA frame"
        );
        Ok(())
    }
}
