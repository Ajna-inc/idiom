//! Per-peer channel state.

use crate::dcx::crypto::derive_directional_keys;
use crate::dcx::errors::ChannelError;
use crate::dcx::session::SessionKeys;
use zeroize::ZeroizeOnDrop;

/// Channel state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Provider has no session; DCX cannot operate.
    Inactive,
    /// Provider session in progress; keys not yet derived.
    Establishing,
    /// Keys derived; first DATA not yet sent.
    ActiveUnconfirmed,
    /// First DATA flowed; channel-confirm exchange in progress.
    AwaitingConfirm,
    /// CHANNEL_CONFIRM matched; channel in steady state.
    Confirmed,
    /// Provider is rotating to a new generation.
    Rotating,
    /// In-place upgrade to a stronger provider in progress.
    Upgrading,
}

/// One peer's channel state plus its derived directional keys.
///
/// Receivers track `msg_id_recv` for replay protection. Senders track
/// `msg_id_send` to derive nonces deterministically.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Channel {
    /// 16-byte channel identifier (rotates with provider generation).
    #[zeroize(skip)]
    pub channel_id: [u8; 16],
    /// Stable provider-supplied connection identifier.
    #[zeroize(skip)]
    pub connection_id: String,
    /// Peer's long-lived DID (NOT the ephemeral DID).
    #[zeroize(skip)]
    pub peer_did: String,
    /// DID-relative kid of the peer's recipient key.
    #[zeroize(skip)]
    pub peer_kid: String,
    /// `SHA-256(peer_kid)[0..16]` for mediator routing.
    #[zeroize(skip)]
    pub peer_routing_prefix: [u8; 16],
    /// Active SessionKeyProvider id.
    #[zeroize(skip)]
    pub provider_id: String,
    /// Provider's current generation.
    #[zeroize(skip)]
    pub generation: u32,
    /// AEAD key for outbound frames.
    pub k_send: [u8; 32],
    /// AEAD key for inbound frames.
    pub k_recv: [u8; 32],
    /// HMAC key for CHANNEL_CONFIRM.
    pub auth_key: [u8; 32],
    /// Strictly-monotonic send counter (incremented per frame sent).
    #[zeroize(skip)]
    pub msg_id_send: u64,
    /// Highest durably-reserved outbound `msg_id` ceiling. A frame with
    /// `msg_id >= send_reserved` MUST NOT be sent until a higher ceiling
    /// has been persisted (see [`Channel::needs_send_reservation`] /
    /// [`Channel::reserve_send`]). On resume the send counter is set to
    /// this value so no previously-reserved id can be reused after a
    /// restart — the nonce-reuse defense for deterministic providers.
    #[zeroize(skip)]
    pub send_reserved: u64,
    /// Last received `msg_id` (frames with `msg_id <= msg_id_recv` are rejected).
    #[zeroize(skip)]
    pub msg_id_recv: u64,
    /// Whether ANY inbound frame has been accepted yet. Disambiguates
    /// "nothing received" from "received msg_id 0" — without it, a
    /// replay of the very first frame (msg_id 0) slips past the
    /// `msg_id <= msg_id_recv` check because both are 0.
    #[zeroize(skip)]
    pub received_any: bool,
    /// Current channel state.
    #[zeroize(skip)]
    pub state: ChannelState,
}

impl Channel {
    /// Build a freshly-derived channel from provider-supplied session keys.
    ///
    /// `is_initiator` controls directional key assignment (see
    /// [`derive_directional_keys`]).
    pub fn from_session_keys(
        session: &SessionKeys,
        peer_did: String,
        provider_id: String,
        is_initiator: bool,
    ) -> Self {
        let dir = derive_directional_keys(&session.kek, is_initiator);
        let channel_id = crate::dcx::routing::derive_channel_id(
            &provider_id,
            &session.connection_id,
            session.generation,
        );
        let routing_prefix = crate::dcx::routing::derive_routing_prefix(&session.peer_kid);
        Self {
            channel_id,
            connection_id: session.connection_id.clone(),
            peer_did,
            peer_kid: session.peer_kid.clone(),
            peer_routing_prefix: routing_prefix,
            provider_id,
            generation: session.generation,
            k_send: dir.k_send,
            k_recv: dir.k_recv,
            auth_key: session.auth_key,
            msg_id_send: 0,
            send_reserved: 0,
            msg_id_recv: 0,
            received_any: false,
            state: ChannelState::ActiveUnconfirmed,
        }
    }

    /// Rebuild a channel from provider keys **plus** persisted counters,
    /// for use after a process restart. Unlike [`Self::from_session_keys`]
    /// (which resets counters to 0), this resumes the send counter at the
    /// durable reservation ceiling — so no `msg_id` that may already have
    /// been used under the (deterministically-identical) `k_send` can be
    /// reused — and restores the inbound replay high-water mark.
    ///
    /// The caller MUST have loaded `persisted` from a
    /// [`super::persistence::ChannelCounterStore`]; if no persisted state
    /// exists for a deterministic provider, the caller MUST re-establish
    /// under a fresh generation instead of calling this (see the store's
    /// trait docs) — resuming with reset counters is the nonce-reuse bug.
    pub fn resume(
        session: &SessionKeys,
        peer_did: String,
        provider_id: String,
        is_initiator: bool,
        persisted: super::persistence::PersistedCounters,
    ) -> Self {
        let mut ch = Self::from_session_keys(session, peer_did, provider_id, is_initiator);
        // Jump past the entire previously-reserved window: any id in
        // `[0, send_reserved)` might already be on the wire, so the next
        // send MUST start at `send_reserved` (strictly monotonic; the gap
        // is harmless).
        ch.send_reserved = persisted.send_reserved;
        ch.msg_id_send = persisted.send_reserved;
        ch.msg_id_recv = persisted.msg_id_recv;
        ch.received_any = persisted.received_any;
        ch
    }

    /// Whether the next send would exceed the durable reservation and so
    /// requires a fresh [`Self::reserve_send`] (persisted) before it is
    /// safe to transmit.
    pub fn needs_send_reservation(&self) -> bool {
        self.msg_id_send >= self.send_reserved
    }

    /// Reserve the next `batch` outbound ids, raising the ceiling. The
    /// returned value MUST be durably persisted (via
    /// [`super::persistence::ChannelCounterStore::save_send_reserved`])
    /// **before** any frame at or above the previous ceiling is sent.
    pub fn reserve_send(&mut self, batch: u64) -> u64 {
        self.send_reserved = self.msg_id_send.saturating_add(batch.max(1));
        self.send_reserved
    }

    /// Allocate the next outbound `msg_id`, returning the value to use
    /// in the frame header.
    pub fn next_send_msg_id(&mut self) -> u64 {
        let id = self.msg_id_send;
        self.msg_id_send = self.msg_id_send.saturating_add(1);
        id
    }

    /// Record an inbound `msg_id`, enforcing strict monotonicity for
    /// replay protection.
    ///
    /// MUST be called only AFTER the frame's AEAD tag has been verified
    /// — advancing this counter on unauthenticated header data lets an
    /// attacker who has observed the (cleartext) `channel_id` wedge the
    /// channel with a single forged high-`msg_id` frame. See
    /// `transports::inbound::try_handle` for the enforced ordering.
    pub fn observe_recv(&mut self, msg_id: u64) -> Result<(), ChannelError> {
        // `received_any` distinguishes the fresh-channel state from
        // "received msg_id 0", so the first frame (any msg_id,
        // including 0) is accepted exactly once and its replay is
        // rejected.
        if self.received_any && msg_id <= self.msg_id_recv {
            return Err(ChannelError::Replay {
                got: msg_id,
                last: self.msg_id_recv,
            });
        }
        self.msg_id_recv = msg_id;
        self.received_any = true;
        Ok(())
    }

    /// Transition the channel state, with basic validation.
    pub fn set_state(&mut self, new_state: ChannelState) -> Result<(), ChannelError> {
        // No exhaustive transition matrix; the state machine is
        // enforced at a higher layer. Here
        // we just record the transition.
        self.state = new_state;
        Ok(())
    }
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("channel_id", &hex_short(&self.channel_id))
            .field("peer_did", &self.peer_did)
            .field("peer_kid", &self.peer_kid)
            .field("provider_id", &self.provider_id)
            .field("generation", &self.generation)
            .field("msg_id_send", &self.msg_id_send)
            .field("send_reserved", &self.send_reserved)
            .field("msg_id_recv", &self.msg_id_recv)
            .field("state", &self.state)
            .finish()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_session() -> SessionKeys {
        SessionKeys {
            kek: [3u8; 32],
            auth_key: [4u8; 32],
            generation: 0,
            peer_kid: "did:peer:bob#key-1".into(),
            connection_id: "conn-1".into(),
            is_initiator: true,
        }
    }

    #[test]
    fn from_session_keys_assigns_directional_keys_symmetrically() {
        let s = sample_session();
        let alice =
            Channel::from_session_keys(&s, "did:bob".into(), "classical-x25519/1.0".into(), true);
        let bob = Channel::from_session_keys(
            &s,
            "did:alice".into(),
            "classical-x25519/1.0".into(),
            false,
        );
        assert_eq!(alice.k_send, bob.k_recv);
        assert_eq!(alice.k_recv, bob.k_send);
        // Channel IDs match because connection_id + generation + provider_id all match.
        assert_eq!(alice.channel_id, bob.channel_id);
    }

    #[test]
    fn next_send_msg_id_is_monotonic() {
        let s = sample_session();
        let mut c =
            Channel::from_session_keys(&s, "did:bob".into(), "classical-x25519/1.0".into(), true);
        assert_eq!(c.next_send_msg_id(), 0);
        assert_eq!(c.next_send_msg_id(), 1);
        assert_eq!(c.next_send_msg_id(), 2);
    }

    #[test]
    fn observe_recv_rejects_replay() {
        let s = sample_session();
        let mut c =
            Channel::from_session_keys(&s, "did:bob".into(), "classical-x25519/1.0".into(), false);
        c.observe_recv(0).unwrap();
        c.observe_recv(1).unwrap();
        c.observe_recv(2).unwrap();
        // Replay of msg_id=1
        let err = c.observe_recv(1);
        assert!(matches!(err, Err(ChannelError::Replay { .. })));
    }

    #[test]
    fn observe_recv_rejects_first_frame_replay() {
        // Regression: the first frame legitimately uses msg_id 0, but a
        // REPLAY of that same frame (also msg_id 0) must be rejected.
        // The old `0/0` sentinel accepted it a second time.
        let s = sample_session();
        let mut c =
            Channel::from_session_keys(&s, "did:bob".into(), "classical-x25519/1.0".into(), false);
        assert!(!c.received_any);
        c.observe_recv(0).unwrap(); // first frame: accepted
        assert!(c.received_any);
        let err = c.observe_recv(0); // replay of frame 0: must reject
        assert!(matches!(err, Err(ChannelError::Replay { .. })));
    }

    #[test]
    fn resume_prevents_nonce_reuse_across_restart() {
        // Pre-restart: send a handful of frames under a deterministic key.
        let s = sample_session();
        let mut before =
            Channel::from_session_keys(&s, "did:bob".into(), "classical-x25519/1.0".into(), true);
        before.reserve_send(1024); // ceiling = 1024, persisted
        let used: Vec<u64> = (0..5).map(|_| before.next_send_msg_id()).collect();
        assert_eq!(used, vec![0, 1, 2, 3, 4]);

        // Simulate a crash + rebuild: the SAME provider keys yield the SAME
        // k_send, so resetting the counter would reuse nonces 0..4. Resume
        // from the persisted reservation ceiling instead.
        let persisted = super::super::persistence::PersistedCounters {
            send_reserved: before.send_reserved, // 1024
            msg_id_recv: 0,
            received_any: false,
        };
        let mut after = Channel::resume(
            &s,
            "did:bob".into(),
            "classical-x25519/1.0".into(),
            true,
            persisted,
        );
        // Same key material — the whole point of the defense.
        assert_eq!(after.k_send, before.k_send);
        // The next id issued after restart is strictly greater than EVERY
        // id used before restart → no (k_send, nonce) pair can repeat.
        let next = after.next_send_msg_id();
        assert!(next >= persisted.send_reserved);
        assert!(used.iter().all(|&u| next > u));
    }

    #[test]
    fn reserve_send_raises_ceiling_and_needs_reservation_tracks_it() {
        let s = sample_session();
        let mut c =
            Channel::from_session_keys(&s, "did:bob".into(), "classical-x25519/1.0".into(), true);
        assert!(c.needs_send_reservation()); // fresh: 0 >= 0
        assert_eq!(c.reserve_send(4), 4);
        assert!(!c.needs_send_reservation());
        for _ in 0..4 {
            c.next_send_msg_id();
        }
        // Consumed the whole window → needs a new reservation before sending.
        assert!(c.needs_send_reservation());
    }

    #[test]
    fn resume_restores_recv_high_water() {
        let s = sample_session();
        let persisted = super::super::persistence::PersistedCounters {
            send_reserved: 2048,
            msg_id_recv: 99,
            received_any: true,
        };
        let mut c = Channel::resume(
            &s,
            "did:bob".into(),
            "classical-x25519/1.0".into(),
            false,
            persisted,
        );
        // A replay of an already-seen id is rejected after resume.
        assert!(matches!(
            c.observe_recv(99),
            Err(ChannelError::Replay { .. })
        ));
        assert!(matches!(
            c.observe_recv(50),
            Err(ChannelError::Replay { .. })
        ));
        c.observe_recv(100).unwrap(); // strictly greater → accepted
    }

    #[test]
    fn observe_recv_accepts_first_nonzero_frame() {
        // A fresh channel whose first observed frame is msg_id > 0 is
        // still accepted (no artificial "must start at 0" requirement).
        let s = sample_session();
        let mut c =
            Channel::from_session_keys(&s, "did:bob".into(), "classical-x25519/1.0".into(), false);
        c.observe_recv(7).unwrap();
        assert_eq!(c.msg_id_recv, 7);
        assert!(matches!(
            c.observe_recv(7),
            Err(ChannelError::Replay { .. })
        ));
        c.observe_recv(8).unwrap();
    }
}
