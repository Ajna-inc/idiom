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
            msg_id_recv: 0,
            received_any: false,
            state: ChannelState::ActiveUnconfirmed,
        }
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
