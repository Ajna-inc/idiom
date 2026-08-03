//! Askar wallet provider implementation

use agent_core::traits::{Key, KeyPurpose, KeyType, Signature, WalletProvider};
use arc_swap::ArcSwap;
use aries_askar::kms::LocalKey;
use aries_askar::Store;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// Askar entry category used for raw quantum-resistant key material.
const KEY_CATEGORY: &str = "key";
/// Askar plaintext tag name that stores the serialized `Key` metadata.
const METADATA_TAG: &str = "metadata";

/// Wallet provider using Aries Askar
pub struct AskarWalletProvider {
    store: Arc<Store>,
    /// In-memory cache of loaded classical signing keys (key_id → LocalKey).
    ///
    /// Askar's `sign` otherwise opens a fresh store session and re-fetches the
    /// key on **every** signature; on a single-connection store (in-memory /
    /// sqlite) those sessions serialize, capping signing throughput. Signing
    /// keys are long-lived, so caching the loaded `LocalKey` lets repeat signs
    /// run as pure-CPU crypto (parallel across cores) with no store round-trip.
    /// `ArcSwap` gives **lock-free reads** (an atomic load), so cache hits on
    /// the hot signing path don't contend a read-write lock across cores;
    /// writes (cache misses, rare) are copy-on-write.
    signing_cache: ArcSwap<HashMap<String, Arc<LocalKey>>>,
    /// In-memory cache of key metadata (key_id → `Key`). `get_key` otherwise
    /// opens a store session per call; on a single-connection store (in-memory
    /// sqlite) those serialize — and hot paths like SD-JWT signing call
    /// `get_key` on every credential. Keys are long-lived, so the public
    /// metadata is safe to cache (lock-free reads via `ArcSwap`).
    key_cache: ArcSwap<HashMap<String, Key>>,
}

impl AskarWalletProvider {
    /// Create a new Askar wallet provider from an existing store
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            signing_cache: ArcSwap::from_pointee(HashMap::new()),
            key_cache: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Copy-on-write insert into a lock-free `ArcSwap` map (used on cache miss).
    fn cow_insert<V: Clone>(cache: &ArcSwap<HashMap<String, V>>, k: String, v: V) {
        let mut m = (**cache.load()).clone();
        m.insert(k, v);
        cache.store(Arc::new(m));
    }

    /// Get the underlying Askar store
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Create quantum-resistant key using ajna-crypto and store as raw bytes
    async fn create_quantum_key(
        &self,
        key_type: KeyType,
        purpose: KeyPurpose,
    ) -> agent_core::Result<Key> {
        let key_id = uuid::Uuid::new_v4().to_string();

        let (public_key_bytes, secret_key_bytes) = match key_type {
            KeyType::SLHDSA => {
                // Generate SLH-DSA keypair
                let (pubkey, seckey) = crypto::slhdsa::keypair();
                (pubkey.to_bytes().to_vec(), seckey.to_bytes().to_vec())
            }
            KeyType::MLDSA65 => {
                // Generate ML-DSA-65 keypair
                let (pubkey, seckey) = crypto::mldsa::keypair();
                (pubkey.to_bytes().to_vec(), seckey.to_bytes().to_vec())
            }
            _ => unreachable!("create_quantum_key called with non-quantum key type"),
        };

        // Create Key structure with purpose
        let key = Key::new(key_id.clone(), key_type, public_key_bytes).with_purpose(purpose);

        // Store in Askar as raw encrypted data (not a LocalKey)
        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::wallet(format!("Failed to create session: {}", e))
        })?;

        // Store key metadata as a tag
        let metadata = serde_json::to_string(&key).map_err(|e| {
            agent_core::AgentError::wallet(format!("Failed to serialize metadata: {}", e))
        })?;

        // Create an EntryTag for the metadata
        let tags = vec![aries_askar::entry::EntryTag::Plaintext(
            METADATA_TAG.to_string(),
            metadata,
        )];

        // Insert raw bytes as generic encrypted entry (category = "key")
        session
            .insert(
                KEY_CATEGORY,      // category
                &key_id,           // name
                &secret_key_bytes, // value (raw quantum key bytes)
                Some(&tags),       // tags
                None,              // expiry
            )
            .await
            .map_err(|e| {
                agent_core::AgentError::wallet(format!("Failed to store quantum key: {}", e))
            })?;

        Ok(key)
    }

    /// Create classical key using Askar's key generation
    async fn create_classical_key(
        &self,
        key_type: KeyType,
        purpose: KeyPurpose,
    ) -> agent_core::Result<Key> {
        use aries_askar::kms::{KeyAlg, LocalKey};

        let key_id = uuid::Uuid::new_v4().to_string();

        // Map KeyType to Askar's KeyAlg. `create_key` routes P256/secp256r1/BLS
        // here too, but only Ed25519/X25519 are actually implemented over Askar's
        // LocalKey — return an error rather than panicking on those.
        let key_alg = match key_type {
            KeyType::Ed25519 => KeyAlg::Ed25519,
            KeyType::X25519 => KeyAlg::X25519,
            other => {
                return Err(agent_core::AgentError::wallet(format!(
                    "Askar-backed key generation is not implemented for {:?} (only Ed25519/X25519 are supported)",
                    other
                )));
            }
        };

        // Generate LocalKey
        let local_key = LocalKey::generate_with_rng(key_alg, false).map_err(|e| {
            agent_core::AgentError::wallet(format!("Failed to generate local key: {}", e))
        })?;

        // Get public key bytes
        let public_key_bytes = local_key
            .to_public_bytes()
            .map_err(|e| {
                agent_core::AgentError::wallet(format!("Failed to extract public key: {}", e))
            })?
            .to_vec();

        // Create Key structure with purpose
        let key = Key::new(key_id.clone(), key_type, public_key_bytes).with_purpose(purpose);

        // Create session for storing
        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::wallet(format!("Failed to create session: {}", e))
        })?;

        // Store key metadata as a tag
        let full_metadata = serde_json::to_string(&key).map_err(|e| {
            agent_core::AgentError::wallet(format!("Failed to serialize key metadata: {}", e))
        })?;

        let tags = vec![aries_askar::entry::EntryTag::Plaintext(
            METADATA_TAG.to_string(),
            full_metadata,
        )];

        // Insert LocalKey into Askar store
        session
            .insert_key(&key_id, &local_key, None, None, Some(&tags), None)
            .await
            .map_err(|e| {
                agent_core::AgentError::wallet(format!("Failed to store classical key: {}", e))
            })?;

        Ok(key)
    }
}

#[async_trait]
impl WalletProvider for AskarWalletProvider {
    async fn create_key(&self, key_type: KeyType, purpose: KeyPurpose) -> agent_core::Result<Key> {
        // Validate that key type is allowed for this purpose
        if !purpose.validate_key_type(key_type) {
            return Err(agent_core::AgentError::wallet(
                format!(
                    "Key type {:?} cannot be used for purpose {:?}. Blockchain purposes require quantum keys.",
                    key_type, purpose
                )
            ));
        }

        // Route to appropriate implementation based on key type
        match key_type {
            KeyType::SLHDSA | KeyType::MLDSA65 => {
                // Quantum keys - use ajna-crypto
                self.create_quantum_key(key_type, purpose).await
            }
            KeyType::Ed25519
            | KeyType::X25519
            | KeyType::P256
            | KeyType::EcdsaSecp256r1
            | KeyType::Bls12381G1
            | KeyType::Bls12381G2 => {
                // Classical keys - use Askar's LocalKey
                self.create_classical_key(key_type, purpose).await
            }
        }
    }

    async fn get_key(&self, key_id: &str) -> agent_core::Result<Option<Key>> {
        // Fast path: cached metadata, no store session (so concurrent callers
        // don't serialize on a single-connection store).
        if let Some(k) = self.key_cache.load().get(key_id).cloned() {
            return Ok(Some(k));
        }

        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::wallet(format!("Failed to create session: {}", e))
        })?;

        // First try to fetch as a classical key (stored with insert_key)
        if let Ok(Some(key_entry)) = session.fetch_key(key_id, false).await {
            // Found a classical key, now get its metadata from tags
            // The tags contain the Key metadata structure
            for tag in key_entry.tags_as_slice() {
                if let aries_askar::entry::EntryTag::Plaintext(name, value) = tag {
                    if name == METADATA_TAG {
                        let key: Key = serde_json::from_str(value).map_err(|e| {
                            agent_core::AgentError::wallet(format!(
                                "Failed to parse key metadata: {}",
                                e
                            ))
                        })?;
                        Self::cow_insert(&self.key_cache, key_id.to_string(), key.clone());
                        return Ok(Some(key));
                    }
                }
            }
            // If we found the key but no metadata, return an error
            return Err(agent_core::AgentError::wallet(
                "Classical key found but metadata tag missing".to_string(),
            ));
        }

        // If not found as a classical key, try as a quantum key entry (category = "key")
        let entry = match session.fetch(KEY_CATEGORY, key_id, false).await {
            Ok(Some(entry)) => entry,
            Ok(None) => return Ok(None),
            Err(e) => {
                return Err(agent_core::AgentError::wallet(format!(
                    "Failed to fetch key: {}",
                    e
                )))
            }
        };

        // Parse tags to get the Key metadata structure
        if !entry.tags.is_empty() {
            // Find the "metadata" tag
            for tag in &entry.tags {
                if let aries_askar::entry::EntryTag::Plaintext(name, value) = tag {
                    if name == METADATA_TAG {
                        let key: Key = serde_json::from_str(value).map_err(|e| {
                            agent_core::AgentError::wallet(format!(
                                "Failed to parse key metadata: {}",
                                e
                            ))
                        })?;
                        return Ok(Some(key));
                    }
                }
            }
            // No metadata tag found
            Err(agent_core::AgentError::wallet(
                "Key metadata tag not found. Only quantum-resistant keys (SLHDSA, MLDSA65) with metadata are supported.".to_string()
            ))
        } else {
            // No tags - cannot determine quantum key type
            Err(agent_core::AgentError::wallet(
                "Key metadata missing. Only quantum-resistant keys (SLHDSA, MLDSA65) with metadata are supported.".to_string()
            ))
        }
    }

    async fn list_keys(&self) -> agent_core::Result<Vec<Key>> {
        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::wallet(format!("Failed to create session: {}", e))
        })?;

        let mut keys = Vec::new();

        // 1. Fetch quantum keys stored in the "key" category
        let entries = session
            .fetch_all(
                Some(KEY_CATEGORY), // category
                None,               // tag_filter
                None,               // limit
                None,               // order_by
                false,              // descending
                false,              // for_update
            )
            .await
            .map_err(|e| agent_core::AgentError::wallet(format!("Failed to list keys: {}", e)))?;

        for entry in entries {
            // Parse tags to get the Key metadata
            for tag in &entry.tags {
                if let aries_askar::entry::EntryTag::Plaintext(name, value) = tag {
                    if name == METADATA_TAG {
                        if let Ok(key) = serde_json::from_str::<Key>(value) {
                            keys.push(key);
                            break; // Found the metadata, move to next entry
                        }
                    }
                }
            }
        }

        // 2. Fetch classical keys stored using Askar's key storage
        // These are created with insert_key and have metadata in tags
        let key_names = session
            .fetch_all_keys(
                None,  // algorithm filter
                None,  // thumbprint filter
                None,  // tag_filter
                None,  // limit
                false, // for_update
            )
            .await
            .map_err(|e| {
                agent_core::AgentError::wallet(format!("Failed to list Askar keys: {}", e))
            })?;

        for key_name in key_names {
            // Fetch the key entry to get its tags
            if let Ok(Some(key_entry)) = session.fetch_key(key_name.name(), false).await {
                // Extract tags from key entry
                let tags = key_entry.tags_as_slice();
                for tag in tags {
                    if let aries_askar::entry::EntryTag::Plaintext(name, value) = tag {
                        if name == METADATA_TAG {
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
        // Drop any cached key material/metadata for a deleted key.
        {
            let mut m = (**self.signing_cache.load()).clone();
            m.remove(key_id);
            self.signing_cache.store(Arc::new(m));
            let mut k = (**self.key_cache.load()).clone();
            k.remove(key_id);
            self.key_cache.store(Arc::new(k));
        }
        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::wallet(format!("Failed to create session: {}", e))
        })?;

        // Check if key exists first (idempotent operation)
        match session.fetch(KEY_CATEGORY, key_id, false).await {
            Ok(Some(_)) => {
                // Key exists, delete it
                session.remove(KEY_CATEGORY, key_id).await.map_err(|e| {
                    agent_core::AgentError::wallet(format!("Failed to delete key: {}", e))
                })?;
            }
            Ok(None) => {
                // Key doesn't exist, that's fine (idempotent)
            }
            Err(e) => {
                return Err(agent_core::AgentError::wallet(format!(
                    "Failed to check key existence: {}",
                    e
                )));
            }
        }

        Ok(())
    }

    async fn sign(&self, key_id: &str, data: &[u8]) -> agent_core::Result<Signature> {
        // Fast path: a previously-loaded classical signing key. Pure CPU, no
        // store session — so concurrent signs parallelize across cores instead
        // of serializing on a single store connection.
        if let Some(local_key) = self.signing_cache.load().get(key_id).cloned() {
            let signature_bytes = local_key.sign_message(data, None).map_err(|e| {
                agent_core::AgentError::wallet(format!("Classical signing failed: {}", e))
            })?;
            return Ok(Signature {
                bytes: signature_bytes.to_vec(),
                key_id: key_id.to_string(),
            });
        }

        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::wallet(format!("Failed to create session: {}", e))
        })?;

        // First, try to fetch as a classical key (stored with insert_key)
        if let Ok(Some(key_entry)) = session.fetch_key(key_id, false).await {
            // Found a classical key, get its metadata to determine key type
            let mut key_metadata = None;
            for tag in key_entry.tags_as_slice() {
                if let aries_askar::entry::EntryTag::Plaintext(name, value) = tag {
                    if name == METADATA_TAG {
                        key_metadata = Some(serde_json::from_str::<Key>(value).map_err(|e| {
                            agent_core::AgentError::wallet(format!(
                                "Failed to parse key metadata: {}",
                                e
                            ))
                        })?);
                        break;
                    }
                }
            }

            let _key = key_metadata.ok_or_else(|| {
                agent_core::AgentError::wallet(
                    "Classical key found but metadata missing".to_string(),
                )
            })?;

            // Sign with classical key, then cache the loaded key so subsequent
            // signs take the pure-CPU fast path above (no store session).
            let local_key = Arc::new(key_entry.load_local_key().map_err(|e| {
                agent_core::AgentError::wallet(format!("Failed to load local key: {}", e))
            })?);

            let signature_bytes = local_key.sign_message(data, None).map_err(|e| {
                agent_core::AgentError::wallet(format!("Classical signing failed: {}", e))
            })?;
            Self::cow_insert(&self.signing_cache, key_id.to_string(), local_key);

            return Ok(Signature {
                bytes: signature_bytes.to_vec(),
                key_id: key_id.to_string(),
            });
        }

        // If not found as classical key, try as quantum key entry
        let entry = session
            .fetch(KEY_CATEGORY, key_id, false)
            .await
            .map_err(|e| agent_core::AgentError::wallet(format!("Failed to fetch key: {}", e)))?
            .ok_or_else(|| agent_core::AgentError::wallet(format!("Key not found: {}", key_id)))?;

        // Get secret key bytes (raw quantum key material)
        let secret_bytes = entry.value.as_ref();

        // Parse tags to get key type
        let mut key = None;
        for tag in &entry.tags {
            if let aries_askar::entry::EntryTag::Plaintext(name, value) = tag {
                if name == METADATA_TAG {
                    key = Some(serde_json::from_str::<Key>(value).map_err(|e| {
                        agent_core::AgentError::wallet(format!(
                            "Failed to parse key metadata: {}",
                            e
                        ))
                    })?);
                    break;
                }
            }
        }

        let key = key.ok_or_else(|| {
            agent_core::AgentError::wallet("Key metadata not found in tags".to_string())
        })?;

        // Sign based on key type
        match key.key_type {
            KeyType::SLHDSA => {
                // Deserialize into SLH-DSA secret key
                let seckey =
                    crypto::slhdsa::UserSecretKey::from_bytes(secret_bytes).map_err(|e| {
                        agent_core::AgentError::wallet(format!("Invalid SLH-DSA secret key: {}", e))
                    })?;

                // Sign the data (with empty domain for wallet operations)
                let signature = crypto::slhdsa::sign(data, &seckey, b"").map_err(|e| {
                    agent_core::AgentError::wallet(format!("SLH-DSA signing failed: {}", e))
                })?;

                Ok(Signature {
                    bytes: signature.to_bytes().to_vec(),
                    key_id: key_id.to_string(),
                })
            }
            KeyType::MLDSA65 => {
                // Deserialize into ML-DSA-65 secret key
                let seckey =
                    crypto::mldsa::ValidatorSecretKey::from_bytes(secret_bytes).map_err(|e| {
                        agent_core::AgentError::wallet(format!(
                            "Invalid ML-DSA-65 secret key: {}",
                            e
                        ))
                    })?;

                // Sign the data (with empty domain for wallet operations)
                let signature = crypto::mldsa::sign(data, &seckey, b"").map_err(|e| {
                    agent_core::AgentError::wallet(format!("ML-DSA-65 signing failed: {}", e))
                })?;

                Ok(Signature {
                    bytes: signature.to_bytes().to_vec(),
                    key_id: key_id.to_string(),
                })
            }
            KeyType::Ed25519
            | KeyType::X25519
            | KeyType::P256
            | KeyType::EcdsaSecp256r1
            | KeyType::Bls12381G1
            | KeyType::Bls12381G2 => {
                // This should not happen - classical keys are handled above
                Err(agent_core::AgentError::wallet(
                    "Classical key found in quantum key storage - inconsistent state".to_string(),
                ))
            }
        }
    }

    async fn verify(
        &self,
        key_id: &str,
        data: &[u8],
        signature: &[u8],
    ) -> agent_core::Result<bool> {
        // Fetch key to check type
        let key = self
            .get_key(key_id)
            .await?
            .ok_or_else(|| agent_core::AgentError::wallet(format!("Key not found: {}", key_id)))?;

        match key.key_type {
            KeyType::SLHDSA => {
                // Deserialize public key
                let pubkey =
                    crypto::slhdsa::UserPublicKey::from_bytes(&key.public_key).map_err(|e| {
                        agent_core::AgentError::wallet(format!("Invalid SLH-DSA public key: {}", e))
                    })?;

                // Deserialize signature
                let sig = crypto::slhdsa::UserSignature::from_bytes(signature).map_err(|e| {
                    agent_core::AgentError::wallet(format!("Invalid SLH-DSA signature: {}", e))
                })?;

                // Verify (with empty domain for wallet operations)
                let valid = crypto::slhdsa::verify(data, &sig, &pubkey, b"").map_err(|e| {
                    agent_core::AgentError::wallet(format!("SLH-DSA verification failed: {}", e))
                })?;
                Ok(valid)
            }
            KeyType::MLDSA65 => {
                // Deserialize public key
                let pubkey = crypto::mldsa::ValidatorPublicKey::from_bytes(&key.public_key)
                    .map_err(|e| {
                        agent_core::AgentError::wallet(format!(
                            "Invalid ML-DSA-65 public key: {}",
                            e
                        ))
                    })?;

                // Deserialize signature
                let sig =
                    crypto::mldsa::ValidatorSignature::from_bytes(signature).map_err(|e| {
                        agent_core::AgentError::wallet(format!(
                            "Invalid ML-DSA-65 signature: {}",
                            e
                        ))
                    })?;

                // Verify (with empty domain for wallet operations)
                let valid = crypto::mldsa::verify(data, &sig, &pubkey, b"").map_err(|e| {
                    agent_core::AgentError::wallet(format!("ML-DSA-65 verification failed: {}", e))
                })?;
                Ok(valid)
            }
            KeyType::Ed25519
            | KeyType::X25519
            | KeyType::P256
            | KeyType::EcdsaSecp256r1
            | KeyType::Bls12381G1
            | KeyType::Bls12381G2 => {
                // Classical keys - use Askar's LocalKey for verification
                let mut session = self.store.session(None).await.map_err(|e| {
                    agent_core::AgentError::wallet(format!("Failed to create session: {}", e))
                })?;

                let key_entry = session
                    .fetch_key(key_id, false)
                    .await
                    .map_err(|e| {
                        agent_core::AgentError::wallet(format!(
                            "Failed to fetch classical key: {}",
                            e
                        ))
                    })?
                    .ok_or_else(|| {
                        agent_core::AgentError::wallet(format!(
                            "Classical key not found: {}",
                            key_id
                        ))
                    })?;

                // Load LocalKey from KeyEntry
                let local_key = key_entry.load_local_key().map_err(|e| {
                    agent_core::AgentError::wallet(format!("Failed to load local key: {}", e))
                })?;

                // Verify using LocalKey
                let is_valid = local_key
                    .verify_signature(data, signature, None)
                    .map_err(|e| {
                        agent_core::AgentError::wallet(format!(
                            "Classical verification failed: {}",
                            e
                        ))
                    })?;

                Ok(is_valid)
            }
        }
    }

    async fn get_secret_bytes(&self, key_id: &str) -> agent_core::Result<Vec<u8>> {
        // First, check the key type to determine how to fetch secret bytes
        let key = self
            .get_key(key_id)
            .await?
            .ok_or_else(|| agent_core::AgentError::wallet(format!("Key not found: {}", key_id)))?;

        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::wallet(format!("Failed to create session: {}", e))
        })?;

        match key.key_type {
            KeyType::SLHDSA | KeyType::MLDSA65 => {
                // Quantum keys - stored as raw bytes in generic entry
                let entry = session
                    .fetch(KEY_CATEGORY, key_id, false)
                    .await
                    .map_err(|e| {
                        agent_core::AgentError::wallet(format!(
                            "Failed to fetch quantum key: {}",
                            e
                        ))
                    })?
                    .ok_or_else(|| {
                        agent_core::AgentError::wallet(format!("Quantum key not found: {}", key_id))
                    })?;

                Ok(entry.value.to_vec())
            }
            KeyType::Ed25519
            | KeyType::X25519
            | KeyType::P256
            | KeyType::EcdsaSecp256r1
            | KeyType::Bls12381G1
            | KeyType::Bls12381G2 => {
                // Classical keys - stored as LocalKey, export secret bytes
                let key_entry = session
                    .fetch_key(key_id, false)
                    .await
                    .map_err(|e| {
                        agent_core::AgentError::wallet(format!(
                            "Failed to fetch classical key: {}",
                            e
                        ))
                    })?
                    .ok_or_else(|| {
                        agent_core::AgentError::wallet(format!(
                            "Classical key not found: {}",
                            key_id
                        ))
                    })?;

                // Load LocalKey from KeyEntry
                let local_key = key_entry.load_local_key().map_err(|e| {
                    agent_core::AgentError::wallet(format!("Failed to load local key: {}", e))
                })?;

                // Export secret key bytes from LocalKey
                let secret_bytes = local_key.to_secret_bytes().map_err(|e| {
                    agent_core::AgentError::wallet(format!("Failed to export secret bytes: {}", e))
                })?;

                Ok(secret_bytes.to_vec())
            }
        }
    }
}
