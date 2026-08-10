//! Durable channel counter state — replay + nonce-reuse safety across restarts.
//!
//! DCX derives its AEAD nonce as `0x00000000 || msg_id_be(8)`. Under a
//! given `k_send` the pair `(k_send, msg_id)` MUST never repeat, or
//! ChaCha20-Poly1305 confidentiality and integrity both collapse. The
//! `classical-x25519/1.0` provider derives `k_send` deterministically from
//! the long-lived connection keys, so a process restart that rebuilds the
//! channel produces the **same** `k_send`. If the in-memory `msg_id_send`
//! also resets to 0, every post-restart frame reuses a nonce that was
//! already used pre-restart — catastrophic.
//!
//! The fix (per the DCX spec, "msg_id_send MUST be persisted across
//! restarts" and "msg_id_recv MUST be persisted"): reserve outbound ids in
//! batches and durably record the ceiling, and record the inbound
//! high-water mark. On rebuild the channel **resumes** from the persisted
//! state instead of resetting to 0.

use async_trait::async_trait;

/// Persisted per-channel counters, loaded on channel (re)build.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PersistedCounters {
    /// Highest reserved outbound `msg_id` ceiling. On resume the send
    /// counter jumps to this value, so no id in the previously-reserved
    /// window can be reused. Monotonic; the skipped gap is harmless
    /// (only strict increase matters, not contiguity).
    pub send_reserved: u64,
    /// Last accepted inbound `msg_id` (replay high-water mark).
    pub msg_id_recv: u64,
    /// Whether any inbound frame was ever accepted (disambiguates
    /// "nothing received" from "received msg_id 0").
    pub received_any: bool,
}

/// Durable store for per-channel counters, keyed by `channel_id`.
///
/// Implemented by the hosting agent over its wallet/DB (e.g. Askar). The
/// DCX runtime reserves send ids in batches — one `save_send_reserved`
/// write per [`SEND_RESERVATION_BATCH`] frames, not one per frame — and
/// records the recv high-water mark, so a crash/restart resumes without
/// nonce reuse or a replay-window reset.
///
/// If `load` returns `None` for a channel whose provider derives keys
/// deterministically (classical-x25519), the runtime MUST NOT resume it
/// with reset counters; it MUST re-establish the channel under a fresh
/// generation (or tear it down), because reset counters under an
/// unchanged key are exactly the nonce-reuse condition.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait ChannelCounterStore: Send + Sync {
    /// Load persisted counters for `channel_id`, or `None` if unknown.
    async fn load(&self, channel_id: &[u8; 16]) -> Option<PersistedCounters>;

    /// Durably record a new outbound reservation ceiling. MUST complete
    /// (be flushed to durable storage) before any frame with
    /// `msg_id >= previous_ceiling` is sent.
    async fn save_send_reserved(&self, channel_id: &[u8; 16], send_reserved: u64);

    /// Record the inbound replay high-water mark. SHOULD be called as the
    /// counter advances; a lagging write only widens the post-restart
    /// replay window, it cannot cause nonce reuse.
    async fn save_recv(&self, channel_id: &[u8; 16], msg_id_recv: u64);
}

/// Number of outbound `msg_id`s reserved (and persisted) per store write.
/// Larger ⇒ fewer durable writes, more ids skipped per restart. 1024
/// balances write amplification against id-space waste (the id space is
/// `u64`, so waste is irrelevant; `2^32` per generation triggers rotation
/// long before exhaustion).
pub const SEND_RESERVATION_BATCH: u64 = 1024;
