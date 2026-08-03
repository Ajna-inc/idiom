//! `KanonChain` — the on-chain operations the registry needs, abstracted so
//! the AnonCreds integration, ID derivation, encoding, and persistence layers
//! are testable without a live Besu node. `AlloyKanonChain` (feature `besu`)
//! is the production impl; `MockKanonChain` backs unit tests.

use async_trait::async_trait;

use crate::error::Result;
use crate::ids::Bytes32;

/// Schema record as stored by `SchemaRegistry`.
#[derive(Debug, Clone)]
pub struct OnChainSchema {
    pub issuer_org: Bytes32,
    pub schema_hash: Bytes32,
    pub uri: String,
    pub created_at: u64,
    pub deprecated: bool,
}

/// Cred-def record as stored by `CredentialDefinitionRegistry`.
#[derive(Debug, Clone)]
pub struct OnChainCredDef {
    pub schema_id: Bytes32,
    pub issuer_org: Bytes32,
    pub issuer_pub_key: Vec<u8>,
    pub policy_mask: u8,
    pub created_at: u64,
    pub deprecated: bool,
    pub uri: String,
}

/// Args for `CredentialDefinitionRegistry.registerCredentialDefinition`.
#[derive(Debug, Clone)]
pub struct RegisterCredDef {
    pub cred_def_id: Bytes32,
    pub schema_id: Bytes32,
    pub issuer_pub_key: Vec<u8>,
    pub policy_mask: u8,
    pub uri: String,
    /// BabyJubjub Tier-2 key coords (0 for Tier-1-only), big-endian bytes32.
    pub zk_pub_key_ax: Bytes32,
    pub zk_pub_key_ay: Bytes32,
}

/// Args for `MerkleStateRegistry.batchUpdate` (Tier-2).
#[derive(Debug, Clone)]
pub struct BatchUpdate {
    pub cred_def_id: Bytes32,
    pub added_keccak: Vec<Bytes32>,
    pub added_poseidon: Vec<Bytes32>,
    pub revoked_keccak: Vec<Bytes32>,
    pub revoked_poseidon: Vec<Bytes32>,
    pub new_root_keccak: Bytes32,
    pub new_root_poseidon: Bytes32,
}

/// Merkle state as stored by `MerkleStateRegistry` (Tier-2).
#[derive(Debug, Clone)]
pub struct MerkleState {
    pub root_keccak: Bytes32,
    pub root_poseidon: Bytes32,
    pub epoch: u64,
    pub last_updated: u64,
    pub issued_count: u64,
    pub revoked_count: u64,
}

/// Per-credential status (`AnonCredsStatusRegistry`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredStatus {
    Unknown = 0,
    Issued = 1,
    Revoked = 2,
}

#[async_trait]
pub trait KanonChain: Send + Sync {
    // --- Schema (SchemaRegistry) ---
    async fn register_schema(
        &self,
        org_id: Bytes32,
        schema_id: Bytes32,
        schema_hash: Bytes32,
        uri: &str,
    ) -> Result<String>; // tx hash
    async fn get_schema(&self, schema_id: Bytes32) -> Result<Option<OnChainSchema>>;

    // --- Credential definition (CredentialDefinitionRegistry) ---
    async fn register_cred_def(&self, args: RegisterCredDef) -> Result<String>;
    async fn get_cred_def(&self, cred_def_id: Bytes32) -> Result<Option<OnChainCredDef>>;

    // --- Tier-1 revocation (AnonCredsStatusRegistry) ---
    async fn issue_credential(&self, cred_def_id: Bytes32, cred_id_hash: Bytes32)
        -> Result<String>;
    async fn revoke_credential(
        &self,
        cred_def_id: Bytes32,
        cred_id_hash: Bytes32,
    ) -> Result<String>;
    async fn get_status(&self, cred_def_id: Bytes32, cred_id_hash: Bytes32) -> Result<CredStatus>;

    // --- Tier-2 revocation (MerkleStateRegistry) ---
    async fn init_merkle_state(
        &self,
        cred_def_id: Bytes32,
        root_keccak: Bytes32,
        root_poseidon: Bytes32,
    ) -> Result<String>;
    async fn batch_update(&self, args: BatchUpdate) -> Result<String>;
    async fn get_merkle_state(&self, cred_def_id: Bytes32) -> Result<Option<MerkleState>>;
}

/// In-memory `KanonChain` for tests — models the four registries' storage.
#[cfg(any(test, feature = "mock"))]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct MockKanonChain {
        schemas: Mutex<HashMap<Bytes32, OnChainSchema>>,
        cred_defs: Mutex<HashMap<Bytes32, OnChainCredDef>>,
        status: Mutex<HashMap<(Bytes32, Bytes32), CredStatus>>,
        merkle: Mutex<HashMap<Bytes32, MerkleState>>,
    }

    impl MockKanonChain {
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl KanonChain for MockKanonChain {
        async fn register_schema(
            &self,
            org_id: Bytes32,
            schema_id: Bytes32,
            schema_hash: Bytes32,
            uri: &str,
        ) -> Result<String> {
            self.schemas.lock().unwrap().insert(
                schema_id,
                OnChainSchema {
                    issuer_org: org_id,
                    schema_hash,
                    uri: uri.to_string(),
                    created_at: 1,
                    deprecated: false,
                },
            );
            Ok("0xmocktx".into())
        }

        async fn get_schema(&self, schema_id: Bytes32) -> Result<Option<OnChainSchema>> {
            Ok(self.schemas.lock().unwrap().get(&schema_id).cloned())
        }

        async fn register_cred_def(&self, a: RegisterCredDef) -> Result<String> {
            self.cred_defs.lock().unwrap().insert(
                a.cred_def_id,
                OnChainCredDef {
                    schema_id: a.schema_id,
                    issuer_org: [0u8; 32],
                    issuer_pub_key: a.issuer_pub_key,
                    policy_mask: a.policy_mask,
                    created_at: 1,
                    deprecated: false,
                    uri: a.uri,
                },
            );
            Ok("0xmocktx".into())
        }

        async fn get_cred_def(&self, cred_def_id: Bytes32) -> Result<Option<OnChainCredDef>> {
            Ok(self.cred_defs.lock().unwrap().get(&cred_def_id).cloned())
        }

        async fn issue_credential(&self, cd: Bytes32, cid: Bytes32) -> Result<String> {
            self.status
                .lock()
                .unwrap()
                .insert((cd, cid), CredStatus::Issued);
            Ok("0xmocktx".into())
        }

        async fn revoke_credential(&self, cd: Bytes32, cid: Bytes32) -> Result<String> {
            self.status
                .lock()
                .unwrap()
                .insert((cd, cid), CredStatus::Revoked);
            Ok("0xmocktx".into())
        }

        async fn get_status(&self, cd: Bytes32, cid: Bytes32) -> Result<CredStatus> {
            Ok(self
                .status
                .lock()
                .unwrap()
                .get(&(cd, cid))
                .copied()
                .unwrap_or(CredStatus::Unknown))
        }

        async fn init_merkle_state(
            &self,
            cred_def_id: Bytes32,
            root_keccak: Bytes32,
            root_poseidon: Bytes32,
        ) -> Result<String> {
            self.merkle.lock().unwrap().insert(
                cred_def_id,
                MerkleState {
                    root_keccak,
                    root_poseidon,
                    epoch: 0,
                    last_updated: 1,
                    issued_count: 0,
                    revoked_count: 0,
                },
            );
            Ok("0xmocktx".into())
        }

        async fn batch_update(&self, a: BatchUpdate) -> Result<String> {
            let mut m = self.merkle.lock().unwrap();
            let st = m.entry(a.cred_def_id).or_insert(MerkleState {
                root_keccak: [0u8; 32],
                root_poseidon: [0u8; 32],
                epoch: 0,
                last_updated: 0,
                issued_count: 0,
                revoked_count: 0,
            });
            st.root_keccak = a.new_root_keccak;
            st.root_poseidon = a.new_root_poseidon;
            st.epoch += 1;
            st.issued_count += a.added_keccak.len() as u64;
            st.revoked_count += a.revoked_keccak.len() as u64;
            Ok("0xmocktx".into())
        }

        async fn get_merkle_state(&self, cred_def_id: Bytes32) -> Result<Option<MerkleState>> {
            Ok(self.merkle.lock().unwrap().get(&cred_def_id).cloned())
        }
    }
}
