//! Test utilities for agent testing
//!
//! Provides in-memory implementations of StorageProvider and WalletProvider
//! for testing purposes.

use agent_core::traits::{
    Key, KeyPurpose, KeyType, Query, Record, Signature, StorageProvider, WalletProvider,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// In-memory storage provider for testing
pub struct InMemoryStorage {
    records: Arc<RwLock<HashMap<String, Record>>>,
}

impl InMemoryStorage {
    /// Create a new in-memory storage provider
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageProvider for InMemoryStorage {
    async fn save(&self, record: &Record) -> agent_core::error::Result<()> {
        let mut records = self.records.write().await;
        records.insert(record.name.clone(), record.clone());
        Ok(())
    }

    async fn find(&self, category: &str, name: &str) -> agent_core::error::Result<Option<Record>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .find(|r| r.category == category && r.name == name)
            .cloned())
    }

    async fn find_all(
        &self,
        category: &str,
        query: &Query,
    ) -> agent_core::error::Result<Vec<Record>> {
        let records = self.records.read().await;

        // Simple query implementation - just filter by tags
        let filtered: Vec<Record> = records
            .values()
            .filter(|r| r.category == category)
            .filter(|r| {
                // Check if all query tags match
                query
                    .tags
                    .iter()
                    .all(|(key, value)| r.tags.get(key).map(|v| v == value).unwrap_or(false))
            })
            .cloned()
            .collect();

        Ok(filtered)
    }

    async fn update(&self, record: &Record) -> agent_core::error::Result<()> {
        let mut records = self.records.write().await;
        records.insert(record.name.clone(), record.clone());
        Ok(())
    }

    async fn delete(&self, category: &str, name: &str) -> agent_core::error::Result<()> {
        let mut records = self.records.write().await;
        records.retain(|_, r| !(r.category == category && r.name == name));
        Ok(())
    }

    async fn delete_all(&self, category: &str) -> agent_core::error::Result<()> {
        let mut records = self.records.write().await;
        records.retain(|_, r| r.category != category);
        Ok(())
    }
}

/// In-memory wallet provider for testing
pub struct InMemoryWallet {
    keys: Arc<RwLock<HashMap<String, (Key, Vec<u8>)>>>, // id -> (key, private_key_bytes)
}

impl InMemoryWallet {
    /// Create a new in-memory wallet provider
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryWallet {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WalletProvider for InMemoryWallet {
    async fn create_key(
        &self,
        key_type: KeyType,
        purpose: KeyPurpose,
    ) -> agent_core::error::Result<Key> {
        let id = Uuid::new_v4().to_string();

        // Generate REAL cryptographic keys using aries-askar for DIDComm compatibility
        let (public_key, private_key) = match key_type {
            KeyType::Ed25519 => {
                // Generate real Ed25519 keypair using aries-askar
                use aries_askar::kms::{KeyAlg, LocalKey};
                let local_key =
                    LocalKey::generate_with_rng(KeyAlg::Ed25519, false).map_err(|e| {
                        agent_core::error::AgentError::Other(format!(
                            "Failed to generate Ed25519 key: {}",
                            e
                        ))
                    })?;

                let public = local_key.to_public_bytes().map_err(|e| {
                    agent_core::error::AgentError::Other(format!(
                        "Failed to get public bytes: {}",
                        e
                    ))
                })?;
                let private = local_key.to_secret_bytes().map_err(|e| {
                    agent_core::error::AgentError::Other(format!(
                        "Failed to get secret bytes: {}",
                        e
                    ))
                })?;

                (public.to_vec(), private.to_vec())
            }
            KeyType::X25519 => {
                use aries_askar::kms::{KeyAlg, LocalKey};
                let local_key =
                    LocalKey::generate_with_rng(KeyAlg::X25519, false).map_err(|e| {
                        agent_core::error::AgentError::Other(format!(
                            "Failed to generate X25519 key: {}",
                            e
                        ))
                    })?;

                let public = local_key.to_public_bytes().map_err(|e| {
                    agent_core::error::AgentError::Other(format!(
                        "Failed to get public bytes: {}",
                        e
                    ))
                })?;
                let private = local_key.to_secret_bytes().map_err(|e| {
                    agent_core::error::AgentError::Other(format!(
                        "Failed to get secret bytes: {}",
                        e
                    ))
                })?;

                (public.to_vec(), private.to_vec())
            }
            KeyType::EcdsaSecp256r1 => {
                // For now, use dummy keys for non-Ed25519/X25519 types
                let private = vec![0u8; 32];
                let public = vec![3u8; 65]; // Uncompressed
                (public, private)
            }
            KeyType::Bls12381G1 => {
                let private = vec![0u8; 32];
                let public = vec![4u8; 48];
                (public, private)
            }
            KeyType::Bls12381G2 => {
                let private = vec![0u8; 32];
                let public = vec![5u8; 96];
                (public, private)
            }
            KeyType::SLHDSA | KeyType::MLDSA65 | KeyType::P256 => {
                // Dummy keys for new quantum-resistant and P256 types
                let private = vec![0u8; 32];
                let public = vec![6u8; 64];
                (public, private)
            }
        };

        let key = Key {
            id: id.clone(),
            key_type,
            purpose,
            public_key,
            metadata: HashMap::new(),
        };

        let mut keys = self.keys.write().await;
        keys.insert(id, (key.clone(), private_key));

        Ok(key)
    }

    async fn get_key(&self, id: &str) -> agent_core::error::Result<Option<Key>> {
        let keys = self.keys.read().await;
        Ok(keys.get(id).map(|(key, _)| key.clone()))
    }

    async fn list_keys(&self) -> agent_core::error::Result<Vec<Key>> {
        let keys = self.keys.read().await;
        Ok(keys.values().map(|(key, _)| key.clone()).collect())
    }

    async fn delete_key(&self, id: &str) -> agent_core::error::Result<()> {
        let mut keys = self.keys.write().await;
        keys.remove(id);
        Ok(())
    }

    async fn sign(&self, key_id: &str, data: &[u8]) -> agent_core::error::Result<Signature> {
        let keys = self.keys.read().await;
        let (key, private) = keys
            .get(key_id)
            .ok_or_else(|| agent_core::error::AgentError::Other("Key not found".to_string()))?;

        // Real signature for Ed25519 (keys are real Askar keys) — consumers
        // like the OID4VP verifier do actual cryptographic verification, so a
        // dummy signature makes every signed-artifact test fail.
        let signature_bytes = match key.key_type {
            KeyType::Ed25519 => {
                use aries_askar::kms::{KeyAlg, LocalKey};
                let local_key = LocalKey::from_secret_bytes(KeyAlg::Ed25519, private)
                    .map_err(|e| agent_core::error::AgentError::Other(format!("Load key: {e}")))?;
                local_key
                    .sign_message(data, None)
                    .map_err(|e| agent_core::error::AgentError::Other(format!("Sign: {e}")))?
                    .to_vec()
            }
            // Non-signing / unimplemented key types keep the old dummy bytes.
            _ => vec![0xAA; 64],
        };

        Ok(Signature {
            bytes: signature_bytes,
            key_id: key_id.to_string(),
        })
    }

    async fn verify(
        &self,
        key_id: &str,
        data: &[u8],
        signature: &[u8],
    ) -> agent_core::error::Result<bool> {
        let keys = self.keys.read().await;
        let Some((key, private)) = keys.get(key_id) else {
            return Ok(false);
        };

        match key.key_type {
            KeyType::Ed25519 => {
                use aries_askar::kms::{KeyAlg, LocalKey};
                let local_key = LocalKey::from_secret_bytes(KeyAlg::Ed25519, private)
                    .map_err(|e| agent_core::error::AgentError::Other(format!("Load key: {e}")))?;
                Ok(local_key
                    .verify_signature(data, signature, None)
                    .unwrap_or(false))
            }
            _ => Ok(!signature.is_empty()),
        }
    }

    async fn get_secret_bytes(&self, key_id: &str) -> agent_core::error::Result<Vec<u8>> {
        let keys = self.keys.read().await;
        let (_key, private_bytes) = keys
            .get(key_id)
            .ok_or_else(|| agent_core::error::AgentError::Other("Key not found".to_string()))?;

        Ok(private_bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_storage() {
        let storage = InMemoryStorage::new();

        let record = Record {
            category: "TestCategory".to_string(),
            name: "test-1".to_string(),
            value: b"test data".to_vec(),
            tags: HashMap::new(),
        };

        // Save
        storage.save(&record).await.unwrap();

        // Find
        let found = storage.find("TestCategory", "test-1").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "test-1");

        // Delete
        storage.delete("TestCategory", "test-1").await.unwrap();
        let found = storage.find("TestCategory", "test-1").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_wallet() {
        let wallet = InMemoryWallet::new();

        // Create key
        let key = wallet
            .create_key(KeyType::Ed25519, KeyPurpose::General)
            .await
            .unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);

        // Get key
        let found = wallet.get_key(&key.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, key.id);

        // Sign
        let signature = wallet.sign(&key.id, b"test data").await.unwrap();
        assert!(!signature.bytes.is_empty());

        // Verify
        let valid = wallet
            .verify(&key.id, b"test data", &signature.bytes)
            .await
            .unwrap();
        assert!(valid);

        // Delete
        wallet.delete_key(&key.id).await.unwrap();
        let found = wallet.get_key(&key.id).await.unwrap();
        assert!(found.is_none());
    }
}
