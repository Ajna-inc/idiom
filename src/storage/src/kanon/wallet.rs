//! `KanonWalletProvider` — `WalletProvider` over the kanon `kanon_key` table.
//!
//! Persistence is the kanon Postgres schema (encrypted `secret_ciphertext` +
//! `nonce`), matching ACA-Py's plugin so at-rest cost is comparable. The actual
//! cryptography **reuses idiom's existing primitives** so keys and signatures
//! are byte-identical to the askar wallet (true drop-in):
//! - classical (Ed25519 / X25519) → askar `LocalKey`
//! - quantum (SLH-DSA / ML-DSA-65) → the `crypto` crate
//!
//! Secrets are sealed with AES-256-GCM under a key derived from a passphrase,
//! bound to `key_id + profile_id` as AEAD associated data.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce};
use agent_core::traits::{Key, KeyPurpose, KeyType, Signature, WalletProvider};
use agent_core::{AgentError, Result};
use aries_askar::kms::{KeyAlg, LocalKey};
use async_trait::async_trait;
use dashmap::DashMap;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use std::sync::Arc;

/// Decrypted signing material held in the in-memory cache: the key metadata
/// plus its plaintext secret bytes, so repeated signs skip both the Postgres
/// `SELECT` and the AES-GCM unseal. Same trust model as the askar wallet's
/// signing cache (secret key material resident in process memory).
type KeyMaterial = Arc<(Key, Vec<u8>)>;

/// Pool size for the kanon Postgres connections. Overridable so deployments can
/// widen concurrency; the historical default of 16 caps in-flight DB ops.
pub(crate) fn pool_size() -> u32 {
    std::env::var("KANON_PG_POOL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32)
}

use super::provider::map_sqlx;
use super::DEFAULT_PROFILE_ID;

fn wallet_err(msg: impl Into<String>) -> AgentError {
    AgentError::wallet(msg.into())
}

/// Wallet provider backed by the kanon Postgres schema. See module docs.
pub struct KanonWalletProvider {
    pool: PgPool,
    profile_id: String,
    cipher: Aes256Gcm,
    /// key_id → decrypted signing material. Populated lazily on first use;
    /// invalidated on delete. Removes the per-sign DB round-trip that otherwise
    /// serializes DIDComm response packing under load.
    sign_cache: DashMap<String, KeyMaterial>,
}

impl KanonWalletProvider {
    /// Connect to Postgres, provision the key schema, and derive the wallet key
    /// from `passphrase`.
    pub async fn connect(database_url: &str, passphrase: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(pool_size())
            .connect(database_url)
            .await
            .map_err(map_sqlx)?;
        Self::from_pool(pool, DEFAULT_PROFILE_ID, passphrase).await
    }

    /// Build from an existing pool (shareable with [`super::KanonStorageProvider`]).
    pub async fn from_pool(pool: PgPool, profile_id: &str, passphrase: &str) -> Result<Self> {
        super::provider::provision(&pool, super::KEY_DDL).await?;
        let key_bytes = Sha256::digest(passphrase.as_bytes());
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key_bytes));
        Ok(Self {
            pool,
            profile_id: profile_id.to_string(),
            cipher,
            sign_cache: DashMap::new(),
        })
    }

    /// Fetch decrypted signing material, using the in-memory cache when present.
    /// On a miss, loads the row from Postgres, unseals it, and memoizes it.
    async fn material(&self, key_id: &str) -> Result<KeyMaterial> {
        if let Some(m) = self.sign_cache.get(key_id) {
            return Ok(m.clone());
        }
        let (_, nonce, ct, key) = self
            .fetch_row(key_id)
            .await?
            .ok_or_else(|| wallet_err(format!("Key not found: {key_id}")))?;
        let secret = self.open(key_id, &nonce, &ct)?;
        let material: KeyMaterial = Arc::new((key, secret));
        self.sign_cache.insert(key_id.to_string(), material.clone());
        Ok(material)
    }

    fn aad(&self, key_id: &str) -> Vec<u8> {
        format!("{key_id}:{}", self.profile_id).into_bytes()
    }

    fn seal(&self, key_id: &str, secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let aad = self.aad(key_id);
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|e| wallet_err(format!("seal failed: {e}")))?;
        Ok((nonce.to_vec(), ct))
    }

    fn open(&self, key_id: &str, nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let aad = self.aad(key_id);
        self.cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|e| wallet_err(format!("open failed: {e}")))
    }

    /// Fetch (key_alg, nonce, ciphertext, metadata) for a key id.
    async fn fetch_row(&self, key_id: &str) -> Result<Option<(String, Vec<u8>, Vec<u8>, Key)>> {
        let row = sqlx::query(
            "SELECT key_alg, nonce, secret_ciphertext, metadata_json \
             FROM kanon_key WHERE profile_id = $1 AND id = $2",
        )
        .bind(&self.profile_id)
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(row) = row else { return Ok(None) };
        let key_alg: String = row.get("key_alg");
        let nonce: Vec<u8> = row.get("nonce");
        let ct: Vec<u8> = row.get("secret_ciphertext");
        let meta: serde_json::Value = row.get("metadata_json");
        let key: Key = serde_json::from_value(meta)
            .map_err(|e| wallet_err(format!("bad key metadata: {e}")))?;
        Ok(Some((key_alg, nonce, ct, key)))
    }
}

/// idiom `KeyType` → the `key_alg` string stored in the row (serde lowercase).
fn key_alg_str(kt: KeyType) -> &'static str {
    match kt {
        KeyType::SLHDSA => "slhdsa",
        KeyType::MLDSA65 => "mldsa65",
        KeyType::Ed25519 => "ed25519",
        KeyType::X25519 => "x25519",
        KeyType::P256 => "p256",
        KeyType::EcdsaSecp256r1 => "ecdsa_secp256r1",
        KeyType::Bls12381G1 => "bls12381g1",
        KeyType::Bls12381G2 => "bls12381g2",
    }
}

/// Classical key types map to an askar `LocalKey` algorithm.
fn askar_alg(kt: KeyType) -> Option<KeyAlg> {
    match kt {
        KeyType::Ed25519 => Some(KeyAlg::Ed25519),
        KeyType::X25519 => Some(KeyAlg::X25519),
        _ => None,
    }
}

/// Generate a keypair, returning `(public_bytes, secret_bytes)`. Mirrors the
/// askar wallet: classical via `LocalKey`, quantum via the `crypto` crate.
fn generate(key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>)> {
    match key_type {
        KeyType::SLHDSA => {
            let (pk, sk) = crypto::slhdsa::keypair();
            Ok((pk.to_bytes().to_vec(), sk.to_bytes().to_vec()))
        }
        KeyType::MLDSA65 => {
            let (pk, sk) = crypto::mldsa::keypair();
            Ok((pk.to_bytes().to_vec(), sk.to_bytes().to_vec()))
        }
        KeyType::Ed25519 | KeyType::X25519 => {
            let alg = askar_alg(key_type).unwrap();
            let lk = LocalKey::generate_with_rng(alg, false)
                .map_err(|e| wallet_err(format!("keygen failed: {e}")))?;
            let public = lk
                .to_public_bytes()
                .map_err(|e| wallet_err(format!("public export failed: {e}")))?
                .to_vec();
            let secret = lk
                .to_secret_bytes()
                .map_err(|e| wallet_err(format!("secret export failed: {e}")))?
                .to_vec();
            Ok((public, secret))
        }
        other => Err(wallet_err(format!(
            "kanon wallet does not implement key type {other:?} (Ed25519/X25519/SLHDSA/MLDSA65 only)"
        ))),
    }
}

#[async_trait]
impl WalletProvider for KanonWalletProvider {
    async fn create_key(&self, key_type: KeyType, purpose: KeyPurpose) -> Result<Key> {
        if !purpose.validate_key_type(key_type) {
            return Err(wallet_err(format!(
                "Key type {key_type:?} cannot be used for purpose {purpose:?}"
            )));
        }
        let (public, secret) = generate(key_type)?;
        let key_id = uuid::Uuid::new_v4().to_string();
        let key = Key::new(key_id.clone(), key_type, public).with_purpose(purpose);
        let (nonce, ct) = self.seal(&key_id, &secret)?;
        let metadata = serde_json::to_value(&key)
            .map_err(|e| wallet_err(format!("serialize key metadata: {e}")))?;

        sqlx::query(
            "INSERT INTO kanon_key \
             (id, profile_id, key_alg, secret_ciphertext, nonce, metadata_json) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&key_id)
        .bind(&self.profile_id)
        .bind(key_alg_str(key_type))
        .bind(ct)
        .bind(nonce)
        .bind(metadata)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(key)
    }

    async fn get_key(&self, key_id: &str) -> Result<Option<Key>> {
        Ok(self.fetch_row(key_id).await?.map(|(_, _, _, key)| key))
    }

    async fn list_keys(&self) -> Result<Vec<Key>> {
        let rows = sqlx::query("SELECT metadata_json FROM kanon_key WHERE profile_id = $1")
            .bind(&self.profile_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        let mut keys = Vec::with_capacity(rows.len());
        for row in rows {
            let meta: serde_json::Value = row.get("metadata_json");
            if let Ok(key) = serde_json::from_value::<Key>(meta) {
                keys.push(key);
            }
        }
        Ok(keys)
    }

    async fn delete_key(&self, key_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM kanon_key WHERE profile_id = $1 AND id = $2")
            .bind(&self.profile_id)
            .bind(key_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        self.sign_cache.remove(key_id);
        Ok(())
    }

    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Signature> {
        let material = self.material(key_id).await?;
        let key = &material.0;
        let secret: &[u8] = &material.1;

        let bytes = match key.key_type {
            KeyType::Ed25519 => {
                let lk = LocalKey::from_secret_bytes(KeyAlg::Ed25519, secret)
                    .map_err(|e| wallet_err(format!("load key failed: {e}")))?;
                lk.sign_message(data, None)
                    .map_err(|e| wallet_err(format!("signing failed: {e}")))?
                    .to_vec()
            }
            KeyType::SLHDSA => {
                let sk = crypto::slhdsa::UserSecretKey::from_bytes(secret)
                    .map_err(|e| wallet_err(format!("invalid SLH-DSA secret: {e}")))?;
                crypto::slhdsa::sign(data, &sk, b"")
                    .map_err(|e| wallet_err(format!("SLH-DSA signing failed: {e}")))?
                    .to_bytes()
                    .to_vec()
            }
            KeyType::MLDSA65 => {
                let sk = crypto::mldsa::ValidatorSecretKey::from_bytes(secret)
                    .map_err(|e| wallet_err(format!("invalid ML-DSA secret: {e}")))?;
                crypto::mldsa::sign(data, &sk, b"")
                    .map_err(|e| wallet_err(format!("ML-DSA signing failed: {e}")))?
                    .to_bytes()
                    .to_vec()
            }
            other => {
                return Err(wallet_err(format!(
                    "kanon wallet cannot sign with key type {other:?}"
                )))
            }
        };

        Ok(Signature {
            bytes,
            key_id: key_id.to_string(),
        })
    }

    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool> {
        let key = self
            .get_key(key_id)
            .await?
            .ok_or_else(|| wallet_err(format!("Key not found: {key_id}")))?;

        match key.key_type {
            KeyType::Ed25519 => {
                let lk = LocalKey::from_public_bytes(KeyAlg::Ed25519, &key.public_key)
                    .map_err(|e| wallet_err(format!("load public key failed: {e}")))?;
                Ok(lk.verify_signature(data, signature, None).unwrap_or(false))
            }
            KeyType::SLHDSA => {
                let pk = crypto::slhdsa::UserPublicKey::from_bytes(&key.public_key)
                    .map_err(|e| wallet_err(format!("invalid SLH-DSA public: {e}")))?;
                let sig = crypto::slhdsa::UserSignature::from_bytes(signature)
                    .map_err(|e| wallet_err(format!("invalid SLH-DSA signature: {e}")))?;
                crypto::slhdsa::verify(data, &sig, &pk, b"")
                    .map_err(|e| wallet_err(format!("SLH-DSA verify failed: {e}")))
            }
            KeyType::MLDSA65 => {
                let pk = crypto::mldsa::ValidatorPublicKey::from_bytes(&key.public_key)
                    .map_err(|e| wallet_err(format!("invalid ML-DSA public: {e}")))?;
                let sig = crypto::mldsa::ValidatorSignature::from_bytes(signature)
                    .map_err(|e| wallet_err(format!("invalid ML-DSA signature: {e}")))?;
                crypto::mldsa::verify(data, &sig, &pk, b"")
                    .map_err(|e| wallet_err(format!("ML-DSA verify failed: {e}")))
            }
            other => Err(wallet_err(format!(
                "kanon wallet cannot verify with key type {other:?}"
            ))),
        }
    }

    async fn get_secret_bytes(&self, key_id: &str) -> Result<Vec<u8>> {
        Ok(self.material(key_id).await?.1.clone())
    }
}
