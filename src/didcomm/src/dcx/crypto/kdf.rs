//! HKDF-based directional key derivation.
//!
//! From a provider's 32-byte `kek`, derive separate `K_send` / `K_recv`:
//!
//! ```text
//! K_send = HKDF-Expand-SHA256(kek, info = "dcx/1.0/send", L = 32)
//! K_recv = HKDF-Expand-SHA256(kek, info = "dcx/1.0/recv", L = 32)
//! ```
//!
//! The peer derives the symmetric mapping (their K_send == our K_recv).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

/// Directional keys derived from a provider's `kek`. One side encrypts
/// outbound frames with [`Self::k_send`]; receives with [`Self::k_recv`].
/// The peer's derivation is symmetric.
#[derive(Clone, ZeroizeOnDrop)]
pub struct DirectionalKeys {
    /// Outbound AEAD key.
    pub k_send: [u8; 32],
    /// Inbound AEAD key.
    pub k_recv: [u8; 32],
}

impl std::fmt::Debug for DirectionalKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectionalKeys")
            .field("k_send", &"<redacted 32B>")
            .field("k_recv", &"<redacted 32B>")
            .finish()
    }
}

/// Derive `K_send` and `K_recv` from the provider's `kek`.
///
/// The `is_initiator` flag controls which info string maps to which
/// direction so both peers end up with the symmetric mapping. The
/// initiator's `K_send` becomes the responder's `K_recv` and vice
/// versa — both compute the same HKDF outputs but assign them
/// oppositely.
pub fn derive_directional_keys(kek: &[u8; 32], is_initiator: bool) -> DirectionalKeys {
    let hkdf = Hkdf::<Sha256>::new(None, kek);
    let mut send = [0u8; 32];
    let mut recv = [0u8; 32];
    // Initiator: SEND with "dcx/1.0/initiator-out", RECV with "dcx/1.0/initiator-in"
    // Responder: SEND with "dcx/1.0/initiator-in",  RECV with "dcx/1.0/initiator-out"
    // So their K_send == our K_recv (and vice versa).
    if is_initiator {
        hkdf.expand(b"dcx/1.0/initiator-out", &mut send)
            .expect("HKDF expand 32B never fails");
        hkdf.expand(b"dcx/1.0/initiator-in", &mut recv)
            .expect("HKDF expand 32B never fails");
    } else {
        hkdf.expand(b"dcx/1.0/initiator-in", &mut send)
            .expect("HKDF expand 32B never fails");
        hkdf.expand(b"dcx/1.0/initiator-out", &mut recv)
            .expect("HKDF expand 32B never fails");
    }
    DirectionalKeys {
        k_send: send,
        k_recv: recv,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiator_and_responder_derive_symmetric_pair() {
        let kek = [7u8; 32];
        let alice = derive_directional_keys(&kek, true);
        let bob = derive_directional_keys(&kek, false);
        // Alice sends, Bob receives — same key for that direction.
        assert_eq!(alice.k_send, bob.k_recv);
        // Bob sends, Alice receives — same key for that direction.
        assert_eq!(bob.k_send, alice.k_recv);
    }

    #[test]
    fn directional_keys_differ() {
        let kek = [42u8; 32];
        let keys = derive_directional_keys(&kek, true);
        assert_ne!(keys.k_send, keys.k_recv);
    }

    #[test]
    fn different_kek_produces_different_keys() {
        let a = derive_directional_keys(&[1u8; 32], true);
        let b = derive_directional_keys(&[2u8; 32], true);
        assert_ne!(a.k_send, b.k_send);
        assert_ne!(a.k_recv, b.k_recv);
    }
}
