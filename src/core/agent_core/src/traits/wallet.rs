//! Wallet provider trait for key management
//!
//! This module provides platform-aware async traits:
//! - Native: Uses `Send + Sync` bounds for multi-threaded environments
//! - WASM: No thread safety bounds (single-threaded)

use crate::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Key types supported by the wallet (hybrid: quantum + classical)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    // === Quantum-Resistant Keys (Blockchain Layer) ===
    /// SLH-DSA-SHAKE-128s (quantum-resistant, NIST FIPS 205)
    /// - Public key: 32 bytes
    /// - Secret key: 64 bytes
    /// - Signature: 7856 bytes
    /// - Security level: 128-bit quantum-safe
    /// - Use for: User signatures, blockchain transactions
    #[serde(rename = "slhdsa")]
    SLHDSA,

    /// ML-DSA-65 (quantum-resistant, NIST FIPS 204)
    /// - Public key: 1952 bytes
    /// - Secret key: 4032 bytes
    /// - Signature: 3309 bytes
    /// - Security level: ~128-bit quantum-safe
    /// - Use for: Validator signatures, consensus operations
    #[serde(rename = "mldsa65")]
    MLDSA65,

    // === Classical Keys (SSI Agent Layer - Interoperability) ===
    /// Ed25519 (classical signature scheme)
    /// - Public key: 32 bytes
    /// - Secret key: 64 bytes
    /// - Signature: 64 bytes
    /// - Security level: 128-bit classical
    /// - Use for: DIDComm v1, did:peer, agent messaging
    /// - Note: NOT quantum-resistant, for interoperability only
    #[serde(rename = "ed25519")]
    Ed25519,

    /// X25519 (classical key agreement)
    /// - Public key: 32 bytes
    /// - Secret key: 32 bytes
    /// - Security level: 128-bit classical
    /// - Use for: DIDComm v1 encryption, ECDH
    /// - Note: NOT quantum-resistant, for interoperability only
    #[serde(rename = "x25519")]
    X25519,

    /// P-256 / ECDSA secp256r1 (NIST P-256 curve)
    /// - Public key: 65 bytes (uncompressed) or 33 bytes (compressed)
    /// - Signature: ~64-72 bytes (DER encoded)
    /// - Security level: 128-bit classical
    /// - Use for: mDocs, ISO 18013-5 compatibility, W3C VC-JWT
    /// - Note: NOT quantum-resistant, for interoperability only
    #[serde(rename = "p256")]
    P256,

    /// ECDSA secp256r1 (alias for P256)
    /// - Same as P256, different naming convention
    /// - Use for: Legacy system compatibility
    /// - Note: NOT quantum-resistant, for interoperability only
    #[serde(rename = "ecdsa_secp256r1")]
    EcdsaSecp256r1,

    /// BLS12-381 G1 (pairing-friendly curve)
    /// - Public key: 48 bytes (G1)
    /// - Signature: 96 bytes (G2)
    /// - Security level: 128-bit classical
    /// - Use for: BBS+ signatures, selective disclosure credentials
    /// - Note: NOT quantum-resistant, for interoperability only
    #[serde(rename = "bls12381g1")]
    Bls12381G1,

    /// BLS12-381 G2 (pairing-friendly curve, alternative configuration)
    /// - Public key: 96 bytes (G2)
    /// - Signature: 48 bytes (G1)
    /// - Security level: 128-bit classical
    /// - Use for: BBS+ signatures with G2 public keys
    /// - Note: NOT quantum-resistant, for interoperability only
    #[serde(rename = "bls12381g2")]
    Bls12381G2,
}

impl KeyType {
    /// Check if this is a quantum-resistant key type
    pub fn is_quantum(&self) -> bool {
        matches!(self, KeyType::SLHDSA | KeyType::MLDSA65)
    }

    /// Check if this is a classical (non-quantum) key type
    pub fn is_classical(&self) -> bool {
        matches!(
            self,
            KeyType::Ed25519
                | KeyType::X25519
                | KeyType::P256
                | KeyType::EcdsaSecp256r1
                | KeyType::Bls12381G1
                | KeyType::Bls12381G2
        )
    }

    /// Check if this key type can be used for signing
    pub fn can_sign(&self) -> bool {
        !matches!(self, KeyType::X25519)
    }
}

/// Key purpose - defines where and how a key can be used
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    /// Blockchain consensus operations (validators only)
    /// - MUST use: MLDSA65
    /// - Used for: Block signing, vote signing, DA attestations
    BlockchainConsensus,

    /// Blockchain user operations
    /// - MUST use: SLHDSA
    /// - Used for: Transaction signing, DID anchoring
    BlockchainUser,

    /// Agent messaging (DIDComm, peer communication)
    /// - Can use: Ed25519, X25519 (for DIDComm v1 compatibility)
    /// - Used for: DIDComm pack/unpack, peer authentication
    AgentMessaging,

    /// Agent DID operations (did:peer, did:key)
    /// - Can use: Ed25519 (for did:peer compatibility)
    /// - Used for: DID document verification methods
    AgentDID,

    /// General purpose (no restrictions)
    /// - Can use: Any key type
    General,
}

impl KeyPurpose {
    /// Check if this purpose requires quantum-resistant keys
    pub fn requires_quantum(&self) -> bool {
        matches!(
            self,
            KeyPurpose::BlockchainConsensus | KeyPurpose::BlockchainUser
        )
    }

    /// Check if this purpose allows classical keys
    pub fn allows_classical(&self) -> bool {
        matches!(
            self,
            KeyPurpose::AgentMessaging | KeyPurpose::AgentDID | KeyPurpose::General
        )
    }

    /// Validate that a key type is allowed for this purpose
    pub fn validate_key_type(&self, key_type: KeyType) -> bool {
        match self {
            // Blockchain operations MUST use quantum-resistant keys
            KeyPurpose::BlockchainConsensus => key_type == KeyType::MLDSA65,
            KeyPurpose::BlockchainUser => key_type == KeyType::SLHDSA,

            // Agent operations CAN use classical keys for interoperability
            KeyPurpose::AgentMessaging => matches!(
                key_type,
                KeyType::Ed25519 | KeyType::X25519 | KeyType::P256 | KeyType::EcdsaSecp256r1
            ),
            KeyPurpose::AgentDID => matches!(
                key_type,
                KeyType::Ed25519 | KeyType::P256 | KeyType::EcdsaSecp256r1
            ),

            // General purpose allows any key type
            KeyPurpose::General => true,
        }
    }
}

/// Cryptographic key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    /// Key identifier
    pub id: String,

    /// Key type
    pub key_type: KeyType,

    /// Key purpose (defines usage constraints)
    #[serde(default = "default_key_purpose")]
    pub purpose: KeyPurpose,

    /// Public key bytes
    pub public_key: Vec<u8>,

    /// Optional key metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

fn default_key_purpose() -> KeyPurpose {
    KeyPurpose::General
}

impl Key {
    pub fn new(id: impl Into<String>, key_type: KeyType, public_key: Vec<u8>) -> Self {
        Self {
            id: id.into(),
            key_type,
            purpose: KeyPurpose::General,
            public_key,
            metadata: Default::default(),
        }
    }

    pub fn with_purpose(mut self, purpose: KeyPurpose) -> Self {
        self.purpose = purpose;
        self
    }

    pub fn with_metadata(mut self, metadata: std::collections::HashMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Validate that this key can be used for the given purpose
    pub fn validate_purpose(&self, purpose: KeyPurpose) -> bool {
        purpose.validate_key_type(self.key_type)
    }
}

/// Digital signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Signature bytes
    pub bytes: Vec<u8>,

    /// Key ID that created the signature
    pub key_id: String,
}

/// Wallet provider trait for key management operations.
///
/// Implementations provide secure key storage and cryptographic operations.
///
/// # Example
///
/// ```rust,no_run
/// # use agent_core::traits::{WalletProvider, KeyType, KeyPurpose};
/// # use agent_core::Result;
/// # async fn example(wallet: impl WalletProvider) -> Result<()> {
/// // Create a new key for agent messaging
/// let key = wallet.create_key(KeyType::Ed25519, KeyPurpose::AgentMessaging).await?;
///
/// // Or create with automatic type selection
/// let key2 = wallet.create_key_for_purpose(KeyPurpose::BlockchainUser).await?;
///
/// // Sign data
/// let data = b"hello world";
/// let signature = wallet.sign(&key.id, data).await?;
///
/// // Verify signature
/// let valid = wallet.verify(&key.id, data, &signature.bytes).await?;
/// assert!(valid);
/// # Ok(())
/// # }
/// ```

#[async_trait]
pub trait WalletProvider: Send + Sync {
    /// Create a new key with specified type and purpose
    async fn create_key(&self, key_type: KeyType, purpose: KeyPurpose) -> Result<Key>;

    /// Get a key by ID
    async fn get_key(&self, key_id: &str) -> Result<Option<Key>>;

    /// List all keys
    async fn list_keys(&self) -> Result<Vec<Key>>;

    /// Delete a key
    async fn delete_key(&self, key_id: &str) -> Result<()>;

    /// Sign data with a key
    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Signature>;

    /// Verify a signature
    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool>;

    /// Get the secret/private key bytes for a given key ID
    async fn get_secret_bytes(&self, key_id: &str) -> Result<Vec<u8>>;

    /// Find keys by purpose
    async fn find_keys_by_purpose(&self, purpose: KeyPurpose) -> Result<Vec<Key>> {
        let all_keys = self.list_keys().await?;
        Ok(all_keys
            .into_iter()
            .filter(|k| k.purpose == purpose)
            .collect())
    }

    /// Find first key matching purpose and key type
    async fn find_key(
        &self,
        purpose: KeyPurpose,
        key_type: Option<KeyType>,
    ) -> Result<Option<Key>> {
        let keys = self.find_keys_by_purpose(purpose).await?;
        Ok(keys
            .into_iter()
            .find(|k| key_type.is_none_or(|kt| k.key_type == kt)))
    }

    /// Create a key with automatic type selection based on purpose
    async fn create_key_for_purpose(&self, purpose: KeyPurpose) -> Result<Key> {
        let key_type = match purpose {
            KeyPurpose::BlockchainConsensus => KeyType::MLDSA65,
            KeyPurpose::BlockchainUser => KeyType::SLHDSA,
            KeyPurpose::AgentMessaging => KeyType::Ed25519,
            KeyPurpose::AgentDID => KeyType::Ed25519,
            KeyPurpose::General => KeyType::SLHDSA,
        };
        self.create_key(key_type, purpose).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_creation() {
        let key = Key::new("key-123", KeyType::SLHDSA, vec![1, 2, 3, 4]);
        assert_eq!(key.id, "key-123");
        assert_eq!(key.key_type, KeyType::SLHDSA);
        assert_eq!(key.public_key, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_key_type_serialization() {
        let key_type = KeyType::SLHDSA;
        let json = serde_json::to_string(&key_type).unwrap();
        assert_eq!(json, "\"slhdsa\"");

        let deserialized: KeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, KeyType::SLHDSA);
    }

    #[test]
    fn test_mldsa65_serialization() {
        let key_type = KeyType::MLDSA65;
        let json = serde_json::to_string(&key_type).unwrap();
        assert_eq!(json, "\"mldsa65\"");

        let deserialized: KeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, KeyType::MLDSA65);
    }
}
