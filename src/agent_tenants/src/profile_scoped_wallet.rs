//! Profile-scoped wallet provider.
//!
//! Wraps `Arc<Store>` and scopes ALL key operations to a specific Askar profile.
//! Each tenant's cryptographic keys (Ed25519, X25519) are isolated in their profile.
//!
//! This is a simplified version focusing on classical keys needed for DIDComm.
//! Quantum keys (SLHDSA, MLDSA65) are handled by the full AskarWalletProvider.

use agent_core::traits::{Key, KeyPurpose, KeyType, Signature, WalletProvider};
use arc_swap::ArcSwap;
use aries_askar::kms::{KeyAlg, LocalKey};
use aries_askar::Store;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// Wallet provider scoped to a single Askar profile.
#[derive(Clone)]
pub struct ProfileScopedWalletProvider {
    store: Arc<Store>,
    profile: String,
    /// Cache of loaded signing keys (key_id → LocalKey). `sign` otherwise opens
    /// a profile-scoped session and `fetch_key`s on **every** signature — each
    /// session validates the profile (`SELECT COUNT(*) FROM profiles`) and the
    /// pool has a fixed size, so per-credential signing serializes on the pool.
    /// Signing keys are long-lived; caching the loaded key makes repeat signs
    /// pure-CPU (no session). `ArcSwap` gives lock-free reads so cache hits on
    /// the hot signing path don't contend across cores.
    signing_cache: Arc<ArcSwap<HashMap<String, Arc<LocalKey>>>>,
}

impl ProfileScopedWalletProvider {
    pub fn new(store: Arc<Store>, profile: impl Into<String>) -> Self {
        Self {
            store,
            profile: profile.into(),
            signing_cache: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    async fn session(&self) -> agent_core::Result<aries_askar::Session> {
        self.store
            .session(Some(self.profile.clone()))
            .await
            .map_err(|e| {
                agent_core::AgentError::wallet(format!("Session [{}]: {}", self.profile, e))
            })
    }
}

#[async_trait]
impl WalletProvider for ProfileScopedWalletProvider {
    async fn create_key(&self, key_type: KeyType, purpose: KeyPurpose) -> agent_core::Result<Key> {
        if !purpose.validate_key_type(key_type) {
            return Err(agent_core::AgentError::wallet(format!(
                "Key type {:?} invalid for purpose {:?}",
                key_type, purpose
            )));
        }

        let key_id = uuid::Uuid::new_v4().to_string();
        let key_alg = match key_type {
            KeyType::Ed25519 => KeyAlg::Ed25519,
            KeyType::X25519 => KeyAlg::X25519,
            _ => {
                return Err(agent_core::AgentError::wallet(format!(
                    "ProfileScopedWallet only supports Ed25519/X25519, got {:?}",
                    key_type
                )))
            }
        };

        let local_key = LocalKey::generate_with_rng(key_alg, false)
            .map_err(|e| agent_core::AgentError::wallet(format!("Key gen: {}", e)))?;

        let public_key_bytes = local_key
            .to_public_bytes()
            .map_err(|e| agent_core::AgentError::wallet(format!("Public key: {}", e)))?
            .to_vec();

        let key = Key::new(key_id.clone(), key_type, public_key_bytes).with_purpose(purpose);

        let mut session = self.session().await?;
        let metadata = serde_json::to_string(&key)
            .map_err(|e| agent_core::AgentError::wallet(format!("Serialize: {}", e)))?;
        let tags = vec![aries_askar::entry::EntryTag::Plaintext(
            "metadata".to_string(),
            metadata,
        )];

        session
            .insert_key(&key_id, &local_key, None, None, Some(&tags), None)
            .await
            .map_err(|e| agent_core::AgentError::wallet(format!("Store key: {}", e)))?;

        session
            .commit()
            .await
            .map_err(|e| agent_core::AgentError::wallet(format!("Commit: {}", e)))?;

        Ok(key)
    }

    async fn get_key(&self, key_id: &str) -> agent_core::Result<Option<Key>> {
        let mut session = self.session().await?;

        match session.fetch_key(key_id, false).await {
            Ok(Some(entry)) => {
                for tag in entry.tags_as_slice() {
                    if let aries_askar::entry::EntryTag::Plaintext(name, value) = tag {
                        if name == "metadata" {
                            let key: Key = serde_json::from_str(value).map_err(|e| {
                                agent_core::AgentError::wallet(format!("Parse: {}", e))
                            })?;
                            return Ok(Some(key));
                        }
                    }
                }
                Err(agent_core::AgentError::wallet(
                    "Key metadata missing".to_string(),
                ))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(agent_core::AgentError::wallet(format!("Fetch key: {}", e))),
        }
    }

    async fn list_keys(&self) -> agent_core::Result<Vec<Key>> {
        let mut session = self.session().await?;
        let mut keys = Vec::new();

        let key_entries = session
            .fetch_all_keys(None, None, None, None, false)
            .await
            .map_err(|e| agent_core::AgentError::wallet(format!("List keys: {}", e)))?;

        for entry in key_entries {
            if let Ok(Some(key_entry)) = session.fetch_key(entry.name(), false).await {
                for tag in key_entry.tags_as_slice() {
                    if let aries_askar::entry::EntryTag::Plaintext(name, value) = tag {
                        if name == "metadata" {
                            if let Ok(key) = serde_json::from_str::<Key>(value) {
                                keys.push(key);
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok(keys)
    }

    async fn delete_key(&self, key_id: &str) -> agent_core::Result<()> {
        let mut session = self.session().await?;
        let _ = session.remove_key(key_id).await;
        session
            .commit()
            .await
            .map_err(|e| agent_core::AgentError::wallet(format!("Commit: {}", e)))?;
        Ok(())
    }

    async fn sign(&self, key_id: &str, data: &[u8]) -> agent_core::Result<Signature> {
        // Fast path: cached key, pure CPU, no profile session (lock-free read).
        if let Some(local_key) = self.signing_cache.load().get(key_id).cloned() {
            let signature_bytes = local_key
                .sign_message(data, None)
                .map_err(|e| agent_core::AgentError::wallet(format!("Sign: {}", e)))?;
            return Ok(Signature {
                bytes: signature_bytes.to_vec(),
                key_id: key_id.to_string(),
            });
        }

        let mut session = self.session().await?;

        let key_entry = session
            .fetch_key(key_id, false)
            .await
            .map_err(|e| agent_core::AgentError::wallet(format!("Fetch key: {}", e)))?
            .ok_or_else(|| agent_core::AgentError::wallet(format!("Key not found: {}", key_id)))?;

        let local_key = Arc::new(
            key_entry
                .load_local_key()
                .map_err(|e| agent_core::AgentError::wallet(format!("Load key: {}", e)))?,
        );

        let signature_bytes = local_key
            .sign_message(data, None)
            .map_err(|e| agent_core::AgentError::wallet(format!("Sign: {}", e)))?;
        {
            let mut m = (**self.signing_cache.load()).clone();
            m.insert(key_id.to_string(), local_key);
            self.signing_cache.store(Arc::new(m));
        }

        Ok(Signature {
            bytes: signature_bytes.to_vec(),
            key_id: key_id.to_string(),
        })
    }

    async fn verify(
        &self,
        key_id: &str,
        data: &[u8],
        signature: &[u8],
    ) -> agent_core::Result<bool> {
        let mut session = self.session().await?;

        let key_entry = session
            .fetch_key(key_id, false)
            .await
            .map_err(|e| agent_core::AgentError::wallet(format!("Fetch key: {}", e)))?
            .ok_or_else(|| agent_core::AgentError::wallet(format!("Key not found: {}", key_id)))?;

        let local_key = key_entry
            .load_local_key()
            .map_err(|e| agent_core::AgentError::wallet(format!("Load key: {}", e)))?;

        local_key
            .verify_signature(data, signature, None)
            .map_err(|e| agent_core::AgentError::wallet(format!("Verify: {}", e)))
    }

    async fn get_secret_bytes(&self, key_id: &str) -> agent_core::Result<Vec<u8>> {
        let mut session = self.session().await?;

        let key_entry = session
            .fetch_key(key_id, false)
            .await
            .map_err(|e| agent_core::AgentError::wallet(format!("Fetch key: {}", e)))?
            .ok_or_else(|| agent_core::AgentError::wallet(format!("Key not found: {}", key_id)))?;

        let local_key = key_entry
            .load_local_key()
            .map_err(|e| agent_core::AgentError::wallet(format!("Load key: {}", e)))?;

        let secret_bytes = local_key
            .to_secret_bytes()
            .map_err(|e| agent_core::AgentError::wallet(format!("Secret bytes: {}", e)))?;

        Ok(secret_bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aries_askar::storage::generate_raw_store_key;
    use aries_askar::StoreKeyMethod;

    async fn test_store() -> Arc<Store> {
        let pass_key = generate_raw_store_key(None).unwrap();
        let store = Store::provision(
            "sqlite://:memory:",
            StoreKeyMethod::RawKey,
            pass_key.as_ref(),
            None,
            false,
        )
        .await
        .unwrap();
        Arc::new(store)
    }

    #[tokio::test]
    async fn test_create_and_get_key() {
        let store = test_store().await;
        store
            .create_profile(Some("test-wallet".to_string()))
            .await
            .unwrap();

        let wallet = ProfileScopedWalletProvider::new(store, "test-wallet");

        let key = wallet
            .create_key(KeyType::Ed25519, KeyPurpose::AgentDID)
            .await
            .unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
        assert!(!key.public_key.is_empty());

        let found = wallet.get_key(&key.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, key.id);
    }

    #[tokio::test]
    async fn test_sign_and_verify() {
        let store = test_store().await;
        store
            .create_profile(Some("test-sign".to_string()))
            .await
            .unwrap();

        let wallet = ProfileScopedWalletProvider::new(store, "test-sign");
        let key = wallet
            .create_key(KeyType::Ed25519, KeyPurpose::AgentDID)
            .await
            .unwrap();

        let data = b"hello world";
        let sig = wallet.sign(&key.id, data).await.unwrap();
        assert!(!sig.bytes.is_empty());

        let valid = wallet.verify(&key.id, data, &sig.bytes).await.unwrap();
        assert!(valid);

        let invalid = wallet
            .verify(&key.id, b"wrong data", &sig.bytes)
            .await
            .unwrap();
        assert!(!invalid);
    }

    #[tokio::test]
    async fn test_profile_key_isolation() {
        let store = test_store().await;
        store
            .create_profile(Some("alice-wallet".to_string()))
            .await
            .unwrap();
        store
            .create_profile(Some("bob-wallet".to_string()))
            .await
            .unwrap();

        let alice = ProfileScopedWalletProvider::new(store.clone(), "alice-wallet");
        let bob = ProfileScopedWalletProvider::new(store, "bob-wallet");

        // Alice creates a key
        let key = alice
            .create_key(KeyType::Ed25519, KeyPurpose::AgentDID)
            .await
            .unwrap();

        // Alice can see it
        assert!(alice.get_key(&key.id).await.unwrap().is_some());

        // Bob cannot see it
        assert!(bob.get_key(&key.id).await.unwrap().is_none());
    }
}
