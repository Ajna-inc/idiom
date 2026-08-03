//! Classical X25519 SessionKeyProvider.
//!
//! Derives a 32-byte `kek` and 32-byte `auth_key` from an existing
//! X25519 ECDH between the two peers' DIDComm keys — no separate
//! handshake. Forward secrecy is limited (pre-first-rotation traffic
//! becomes decryptable if the long-term keys leak). Acceptable for
//! non-PQ deployments or bootstrap before pq-bridge handshake completes.

use crate::dcx::errors::ProviderError;
use crate::dcx::session::{SessionEvent, SessionKeyProvider, SessionKeys};
use async_trait::async_trait;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};

/// Discover-Features id for this provider.
pub const PROVIDER_ID: &str = "classical-x25519/1.0";

/// Strength rank used by [`SessionKeyProvider::strength`]. Lower than
/// the PQ-secure provider so DCX prefers PQ when both are available.
pub const PROVIDER_STRENGTH: u32 = 10;

/// Input bundle a wallet provides to the classical provider for one peer.
///
/// In production this is sourced from the wallet's existing DIDComm
/// connection record. Tests inject directly.
#[derive(Clone)]
pub struct ClassicalKeyMaterial {
    /// Our X25519 secret half for the connection to this peer.
    pub our_x25519_secret: StaticSecret,
    /// Peer's X25519 public key from the DIDComm connection.
    pub peer_x25519_public: PublicKey,
    /// Our long-lived DID for this connection.
    pub our_did: String,
    /// Peer's long-lived DID.
    pub peer_did: String,
    /// DID-relative kid of the peer's recipient key (used for routing).
    pub peer_kid: String,
    /// Stable connection identifier.
    pub connection_id: String,
}

/// Built-in classical-x25519/1.0 provider.
///
/// Wallets register one instance with [`crate::dcx::session::SessionKeyProvider`]
/// adapters at startup; DCX picks it up via the provider list.
pub struct ClassicalX25519Provider {
    sessions: RwLock<HashMap<String, SessionKeys>>,
    pending: RwLock<HashMap<String, ClassicalKeyMaterial>>,
    events_tx: broadcast::Sender<SessionEvent>,
}

impl ClassicalX25519Provider {
    /// Create a new classical provider.
    ///
    /// `event_capacity` controls the size of the broadcast channel used
    /// to deliver [`SessionEvent`]s; 64 is fine for typical workloads.
    pub fn new(event_capacity: usize) -> Arc<Self> {
        let (tx, _rx) = broadcast::channel(event_capacity);
        Arc::new(Self {
            sessions: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            events_tx: tx,
        })
    }

    /// Register key material for a peer so a subsequent
    /// [`Self::establish`] call can derive keys without further input.
    pub async fn register_peer_material(&self, material: ClassicalKeyMaterial) {
        self.pending
            .write()
            .await
            .insert(material.peer_did.clone(), material);
    }

    /// Derive `(kek, auth_key, nonce_mask)` from raw X25519 inputs.
    pub fn derive_keys(
        shared_secret: &[u8; 32],
        our_did: &str,
        peer_did: &str,
    ) -> Result<([u8; 32], [u8; 32]), ProviderError> {
        // Defense against low-order X25519 points.
        if shared_secret.iter().all(|b| *b == 0) {
            return Err(ProviderError::LowOrderX25519);
        }

        let mut salt_hasher = Sha256::new();
        salt_hasher.update(b"dcx/1.0/classical-x25519");
        let (a, b) = if our_did <= peer_did {
            (our_did, peer_did)
        } else {
            (peer_did, our_did)
        };
        salt_hasher.update(a.as_bytes());
        salt_hasher.update(b.as_bytes());
        let salt = salt_hasher.finalize();

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
        let mut km = [0u8; 96];
        hkdf.expand(b"dcx/1.0/classical-x25519/v1", &mut km)
            .map_err(|e| ProviderError::Internal(format!("HKDF expand: {e}")))?;

        let mut kek = [0u8; 32];
        let mut auth = [0u8; 32];
        kek.copy_from_slice(&km[0..32]);
        auth.copy_from_slice(&km[32..64]);
        // km[64..96] is the nonce_mask, reserved for future
        // extensions. We don't currently use it.
        Ok((kek, auth))
    }
}

#[async_trait]
impl SessionKeyProvider for ClassicalX25519Provider {
    fn provider_id(&self) -> &'static str {
        PROVIDER_ID
    }

    fn strength(&self) -> u32 {
        PROVIDER_STRENGTH
    }

    async fn get_keys(&self, peer_did: &str) -> Option<SessionKeys> {
        self.sessions.read().await.get(peer_did).cloned()
    }

    async fn establish(&self, peer_did: &str) -> Result<SessionKeys, ProviderError> {
        // Already established? Return existing keys idempotently.
        if let Some(existing) = self.sessions.read().await.get(peer_did) {
            return Ok(existing.clone());
        }

        let material = self
            .pending
            .read()
            .await
            .get(peer_did)
            .cloned()
            .ok_or_else(|| ProviderError::NoSession(peer_did.into()))?;

        let shared = material
            .our_x25519_secret
            .diffie_hellman(&material.peer_x25519_public)
            .to_bytes();

        let (kek, auth_key) = Self::derive_keys(&shared, &material.our_did, &material.peer_did)?;

        // Deterministic per-pair role: both ends compare the same two
        // DIDs and pick opposite sides, so our K_send == peer's K_recv.
        let is_initiator = material.our_did < material.peer_did;
        let session = SessionKeys {
            kek,
            auth_key,
            generation: 0,
            peer_kid: material.peer_kid,
            connection_id: material.connection_id,
            is_initiator,
        };

        self.sessions
            .write()
            .await
            .insert(peer_did.to_string(), session.clone());

        let _ = self.events_tx.send(SessionEvent::Established {
            peer_did: peer_did.to_string(),
            generation: 0,
            provider_id: PROVIDER_ID,
        });
        Ok(session)
    }

    async fn rotate(&self, peer_did: &str) -> Result<SessionKeys, ProviderError> {
        // v0.1 only supports establish; classical-rotate-init/ack is a
        // future workstream. Surface clearly so callers can decide.
        Err(ProviderError::NotImplemented(format!(
            "classical-x25519 rotation for {peer_did}"
        )))
    }

    async fn close(&self, peer_did: &str) -> Result<(), ProviderError> {
        let removed = self.sessions.write().await.remove(peer_did).is_some();
        if removed {
            let _ = self.events_tx.send(SessionEvent::Closed {
                peer_did: peer_did.to_string(),
                reason: "user-requested".to_string(),
            });
        }
        Ok(())
    }

    fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.events_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_x25519() -> StaticSecret {
        StaticSecret::random_from_rng(OsRng)
    }

    fn material_for(alice_sk: &StaticSecret, bob_pk: PublicKey) -> ClassicalKeyMaterial {
        ClassicalKeyMaterial {
            our_x25519_secret: alice_sk.clone(),
            peer_x25519_public: bob_pk,
            our_did: "did:peer:alice".into(),
            peer_did: "did:peer:bob".into(),
            peer_kid: "did:peer:bob#key-1".into(),
            connection_id: "conn-1".into(),
        }
    }

    #[tokio::test]
    async fn establish_derives_symmetric_kek_for_both_peers() {
        let alice_sk = random_x25519();
        let bob_sk = random_x25519();
        let alice_pk = PublicKey::from(&alice_sk);
        let bob_pk = PublicKey::from(&bob_sk);

        let p_alice = ClassicalX25519Provider::new(8);
        let p_bob = ClassicalX25519Provider::new(8);
        p_alice
            .register_peer_material(material_for(&alice_sk, bob_pk))
            .await;

        // Bob's "view" of the connection has roles swapped.
        let mut bob_view = material_for(&bob_sk, alice_pk);
        bob_view.our_did = "did:peer:bob".into();
        bob_view.peer_did = "did:peer:alice".into();
        bob_view.peer_kid = "did:peer:alice#key-1".into();
        p_bob.register_peer_material(bob_view).await;

        let alice_session = p_alice.establish("did:peer:bob").await.unwrap();
        let bob_session = p_bob.establish("did:peer:alice").await.unwrap();

        // Same kek + auth_key because X25519 ECDH is symmetric and the
        // sorted-DID salt is the same regardless of role.
        assert_eq!(alice_session.kek, bob_session.kek);
        assert_eq!(alice_session.auth_key, bob_session.auth_key);
    }

    #[tokio::test]
    async fn establish_is_idempotent() {
        let alice_sk = random_x25519();
        let bob_pk = PublicKey::from(&random_x25519());
        let p = ClassicalX25519Provider::new(8);
        p.register_peer_material(material_for(&alice_sk, bob_pk))
            .await;

        let first = p.establish("did:peer:bob").await.unwrap();
        let second = p.establish("did:peer:bob").await.unwrap();
        assert_eq!(first.kek, second.kek);
        assert_eq!(first.auth_key, second.auth_key);
        assert_eq!(first.generation, second.generation);
    }

    #[tokio::test]
    async fn establish_without_material_returns_no_session() {
        let p = ClassicalX25519Provider::new(8);
        let err = p.establish("did:peer:unknown").await;
        assert!(matches!(err, Err(ProviderError::NoSession(_))));
    }

    #[tokio::test]
    async fn close_removes_session() {
        let alice_sk = random_x25519();
        let bob_pk = PublicKey::from(&random_x25519());
        let p = ClassicalX25519Provider::new(8);
        p.register_peer_material(material_for(&alice_sk, bob_pk))
            .await;
        p.establish("did:peer:bob").await.unwrap();
        assert!(p.get_keys("did:peer:bob").await.is_some());
        p.close("did:peer:bob").await.unwrap();
        assert!(p.get_keys("did:peer:bob").await.is_none());
    }

    #[test]
    fn derive_keys_rejects_low_order_point() {
        let err = ClassicalX25519Provider::derive_keys(&[0u8; 32], "did:a", "did:b");
        assert!(matches!(err, Err(ProviderError::LowOrderX25519)));
    }

    #[test]
    fn derive_keys_is_did_order_independent() {
        let secret = [42u8; 32];
        let (kek1, auth1) =
            ClassicalX25519Provider::derive_keys(&secret, "did:a", "did:b").unwrap();
        let (kek2, auth2) =
            ClassicalX25519Provider::derive_keys(&secret, "did:b", "did:a").unwrap();
        assert_eq!(kek1, kek2);
        assert_eq!(auth1, auth2);
    }

    #[tokio::test]
    async fn rotate_returns_not_implemented_for_now() {
        let p = ClassicalX25519Provider::new(8);
        let err = p.rotate("did:peer:bob").await;
        assert!(matches!(err, Err(ProviderError::NotImplemented(_))));
    }
}
