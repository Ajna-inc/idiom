//! Live Besu client for the Kanon registries via alloy (feature `besu`).
//!
//! Resolves the seven registry proxies from the KanonAddressBook, then
//! implements [`KanonChain`] over the Schema / CredentialDefinition /
//! AnonCredsStatus / MerkleState registries. Also exposes the
//! OrganizationRegistry lifecycle (register/approve/query) as inherent
//! methods — those are admin ops, not part of the AnonCreds flow.

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use async_trait::async_trait;

use crate::chain::{
    BatchUpdate, CredStatus, KanonChain, MerkleState, OnChainCredDef, OnChainSchema,
    RegisterCredDef,
};
use crate::config::KanonConfig;
use crate::error::{KanonError, Result};
use crate::ids::{parse_bytes32, Bytes32};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    AddressBook,
    "abis/address_book.json"
);
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SchemaRegistry,
    "abis/schema_registry.json"
);
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CredDefRegistry,
    "abis/cred_def_registry.json"
);
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    StatusRegistry,
    "abis/status_registry.json"
);
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MerkleRegistry,
    "abis/merkle_state_registry.json"
);
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OrgRegistry,
    "abis/organization_registry.json"
);

/// Resolved registry addresses (subset the client uses).
#[derive(Debug, Clone)]
pub struct RegistryAddresses {
    pub organization: Address,
    pub schema: Address,
    pub cred_def: Address,
    pub merkle_state: Address,
    pub status: Address,
}

pub struct AlloyKanonChain {
    provider: DynProvider,
    addrs: RegistryAddresses,
    /// True when an operator key is configured (writes possible).
    signer_address: Option<Address>,
    /// Legacy gas price for writes (0 on Kanon's free-gas Besu).
    gas_price: u128,
    /// Serializes on-chain writes from the shared operator key. Even with the
    /// pending-based SimpleNonceManager, concurrent `send()`s (e.g. a batch of
    /// schema+cred-def registrations issued in parallel) can fetch the same
    /// pending nonce before either reaches the mempool → "Nonce too low". This
    /// lock makes each write's nonce-fetch-and-broadcast atomic.
    write_lock: tokio::sync::Mutex<()>,
}

fn b32(b: Bytes32) -> FixedBytes<32> {
    FixedBytes::<32>::from(b)
}
fn from_fb(b: &FixedBytes<32>) -> Bytes32 {
    b.0
}

impl AlloyKanonChain {
    /// Connect to Besu and resolve the registry addresses from the
    /// KanonAddressBook.
    pub async fn connect(config: &KanonConfig) -> Result<Self> {
        let address_book: Address = config
            .address_book
            .parse()
            .map_err(|e| KanonError::Config(format!("bad address_book: {e}")))?;

        let (provider, signer_address): (DynProvider, Option<Address>) =
            if let Some(key) = &config.operator_key {
                let signer: PrivateKeySigner = key
                    .parse()
                    .map_err(|e| KanonError::Config(format!("bad operator_key: {e}")))?;
                let addr = signer.address();
                let wallet = EthereumWallet::from(signer);
                // Replace the recommended CachedNonceManager (which desyncs and
                // yields "Nonce too low" across restarts and rapid schema+cred-def
                // batches) with the pending-based SimpleNonceManager: it fetches
                // get_transaction_count(pending) for every send, so sequential
                // writes self-correct without waiting for a block. Keep the gas and
                // chain-id fillers that the recommended set would have provided.
                let p = ProviderBuilder::new()
                    .disable_recommended_fillers()
                    .with_gas_estimation()
                    .with_simple_nonce_management()
                    .fetch_chain_id()
                    .wallet(wallet)
                    .connect(&config.rpc_url)
                    .await
                    .map_err(|e| KanonError::Chain(format!("connect: {e}")))?;
                // Besu mines ~2s blocks; alloy's default ~7s poll makes every
                // get_receipt() wait a full poll cycle. Match the block time so
                // schema/cred-def writes confirm promptly.
                p.client()
                    .set_poll_interval(std::time::Duration::from_millis(400));
                (p.erased(), Some(addr))
            } else {
                let p = ProviderBuilder::new()
                    .connect(&config.rpc_url)
                    .await
                    .map_err(|e| KanonError::Chain(format!("connect: {e}")))?;
                p.client()
                    .set_poll_interval(std::time::Duration::from_millis(400));
                (p.erased(), None)
            };

        let book = AddressBook::new(address_book, provider.clone());
        let regs = book
            .registries()
            .call()
            .await
            .map_err(|e| KanonError::Chain(format!("registries(): {e}")))?;

        // registries() returns a plain 7-tuple (ABI has no internalType struct
        // names): (org, did, schema, credDef, merkle, status, halo2).
        let addrs = RegistryAddresses {
            organization: regs.0,
            schema: regs.2,
            cred_def: regs.3,
            merkle_state: regs.4,
            status: regs.5,
        };

        Ok(Self {
            provider,
            addrs,
            signer_address,
            gas_price: config.gas_price,
            write_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn addresses(&self) -> &RegistryAddresses {
        &self.addrs
    }

    pub fn signer_address(&self) -> Option<Address> {
        self.signer_address
    }

    // --- OrganizationRegistry (admin lifecycle) --------------------------

    /// `registerOrg(did, admin) -> orgId`. Returns the assigned bytes32 org id.
    pub async fn register_org(&self, did: &str, admin: Address) -> Result<Bytes32> {
        let _write = self.write_lock.lock().await;
        let org = OrgRegistry::new(self.addrs.organization, self.provider.clone());
        let receipt = org
            .registerOrg(did.to_string(), admin)
            .gas_price(self.gas_price)
            .send()
            .await
            .map_err(|e| KanonError::Chain(format!("registerOrg send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| KanonError::Chain(format!("registerOrg receipt: {e}")))?;
        // The org id is emitted in the OrgRegistered event; decode from logs.
        for log in receipt.inner.logs() {
            if let Ok(ev) = log.log_decode::<OrgRegistry::OrgRegistered>() {
                return Ok(from_fb(&ev.inner.data.orgId));
            }
        }
        Err(KanonError::Chain(
            "registerOrg: OrgRegistered event not found".into(),
        ))
    }

    pub async fn approve_org(&self, org_id: Bytes32) -> Result<String> {
        let _write = self.write_lock.lock().await;
        let org = OrgRegistry::new(self.addrs.organization, self.provider.clone());
        let receipt = org
            .approveOrg(b32(org_id))
            .gas_price(self.gas_price)
            .send()
            .await
            .map_err(|e| KanonError::Chain(format!("approveOrg send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| KanonError::Chain(format!("approveOrg receipt: {e}")))?;
        Ok(receipt.transaction_hash.to_string())
    }

    pub async fn add_member(&self, org_id: Bytes32, member: Address) -> Result<String> {
        let _write = self.write_lock.lock().await;
        let org = OrgRegistry::new(self.addrs.organization, self.provider.clone());
        let receipt = org
            .addMember(b32(org_id), member)
            .gas_price(self.gas_price)
            .send()
            .await
            .map_err(|e| KanonError::Chain(format!("addMember send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| KanonError::Chain(format!("addMember receipt: {e}")))?;
        Ok(receipt.transaction_hash.to_string())
    }

    pub async fn is_approved_and_active(&self, org_id: Bytes32) -> Result<bool> {
        let org = OrgRegistry::new(self.addrs.organization, self.provider.clone());
        org.isApprovedAndActive(b32(org_id))
            .call()
            .await
            .map_err(|e| KanonError::Chain(format!("isApprovedAndActive: {e}")))
    }

    pub async fn is_member(&self, org_id: Bytes32, who: Address) -> Result<bool> {
        let org = OrgRegistry::new(self.addrs.organization, self.provider.clone());
        org.isMember(b32(org_id), who)
            .call()
            .await
            .map_err(|e| KanonError::Chain(format!("isMember: {e}")))
    }
}

#[async_trait]
impl KanonChain for AlloyKanonChain {
    async fn register_schema(
        &self,
        org_id: Bytes32,
        schema_id: Bytes32,
        schema_hash: Bytes32,
        uri: &str,
    ) -> Result<String> {
        let reg = SchemaRegistry::new(self.addrs.schema, self.provider.clone());
        let _write = self.write_lock.lock().await;
        let receipt = reg
            .registerSchema(
                b32(org_id),
                b32(schema_id),
                b32(schema_hash),
                uri.to_string(),
            )
            .gas_price(self.gas_price)
            .send()
            .await
            .map_err(|e| KanonError::Chain(format!("registerSchema send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| KanonError::Chain(format!("registerSchema receipt: {e}")))?;
        Ok(receipt.transaction_hash.to_string())
    }

    async fn get_schema(&self, schema_id: Bytes32) -> Result<Option<OnChainSchema>> {
        let reg = SchemaRegistry::new(self.addrs.schema, self.provider.clone());
        if !reg
            .exists(b32(schema_id))
            .call()
            .await
            .map_err(|e| KanonError::Chain(format!("schema exists: {e}")))?
        {
            return Ok(None);
        }
        let s = reg
            .getSchema(b32(schema_id))
            .call()
            .await
            .map_err(|e| KanonError::Chain(format!("getSchema: {e}")))?;
        // getSchema(): (issuerOrg, schemaHash, uri, createdAt, deprecated)
        Ok(Some(OnChainSchema {
            issuer_org: from_fb(&s.0),
            schema_hash: from_fb(&s.1),
            uri: s.2,
            created_at: s.3,
            deprecated: s.4,
        }))
    }

    async fn register_cred_def(&self, a: RegisterCredDef) -> Result<String> {
        let reg = CredDefRegistry::new(self.addrs.cred_def, self.provider.clone());
        let _write = self.write_lock.lock().await;
        let receipt = reg
            .registerCredentialDefinition(
                b32(a.cred_def_id),
                b32(a.schema_id),
                Bytes::from(a.issuer_pub_key),
                a.policy_mask,
                a.uri,
                U256::from_be_bytes(a.zk_pub_key_ax),
                U256::from_be_bytes(a.zk_pub_key_ay),
            )
            .gas_price(self.gas_price)
            .send()
            .await
            .map_err(|e| KanonError::Chain(format!("registerCredDef send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| KanonError::Chain(format!("registerCredDef receipt: {e}")))?;
        Ok(receipt.transaction_hash.to_string())
    }

    async fn get_cred_def(&self, cred_def_id: Bytes32) -> Result<Option<OnChainCredDef>> {
        let reg = CredDefRegistry::new(self.addrs.cred_def, self.provider.clone());
        if !reg
            .exists(b32(cred_def_id))
            .call()
            .await
            .map_err(|e| KanonError::Chain(format!("cred_def exists: {e}")))?
        {
            return Ok(None);
        }
        let c = reg
            .getCredentialDefinition(b32(cred_def_id))
            .call()
            .await
            .map_err(|e| KanonError::Chain(format!("getCredentialDefinition: {e}")))?;
        // getCredentialDefinition(): (schemaId, issuerOrg, issuerPubKey,
        // policyMask, createdAt, deprecated, uri)
        Ok(Some(OnChainCredDef {
            schema_id: from_fb(&c.0),
            issuer_org: from_fb(&c.1),
            issuer_pub_key: c.2.to_vec(),
            policy_mask: c.3,
            created_at: c.4,
            deprecated: c.5,
            uri: c.6,
        }))
    }

    async fn issue_credential(
        &self,
        cred_def_id: Bytes32,
        cred_id_hash: Bytes32,
    ) -> Result<String> {
        let reg = StatusRegistry::new(self.addrs.status, self.provider.clone());
        let _write = self.write_lock.lock().await;
        let receipt = reg
            .issueCredential(b32(cred_def_id), b32(cred_id_hash))
            .gas_price(self.gas_price)
            .send()
            .await
            .map_err(|e| KanonError::Chain(format!("issueCredential send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| KanonError::Chain(format!("issueCredential receipt: {e}")))?;
        Ok(receipt.transaction_hash.to_string())
    }

    async fn revoke_credential(
        &self,
        cred_def_id: Bytes32,
        cred_id_hash: Bytes32,
    ) -> Result<String> {
        let reg = StatusRegistry::new(self.addrs.status, self.provider.clone());
        let _write = self.write_lock.lock().await;
        let receipt = reg
            .revokeCredential(b32(cred_def_id), b32(cred_id_hash))
            .gas_price(self.gas_price)
            .send()
            .await
            .map_err(|e| KanonError::Chain(format!("revokeCredential send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| KanonError::Chain(format!("revokeCredential receipt: {e}")))?;
        Ok(receipt.transaction_hash.to_string())
    }

    async fn get_status(&self, cred_def_id: Bytes32, cred_id_hash: Bytes32) -> Result<CredStatus> {
        let reg = StatusRegistry::new(self.addrs.status, self.provider.clone());
        let s = reg
            .getStatus(b32(cred_def_id), b32(cred_id_hash))
            .call()
            .await
            .map_err(|e| KanonError::Chain(format!("getStatus: {e}")))?;
        Ok(match s {
            1 => CredStatus::Issued,
            2 => CredStatus::Revoked,
            _ => CredStatus::Unknown,
        })
    }

    async fn init_merkle_state(
        &self,
        cred_def_id: Bytes32,
        root_keccak: Bytes32,
        root_poseidon: Bytes32,
    ) -> Result<String> {
        let reg = MerkleRegistry::new(self.addrs.merkle_state, self.provider.clone());
        let _write = self.write_lock.lock().await;
        let receipt = reg
            .initializeCredDefState(b32(cred_def_id), b32(root_keccak), b32(root_poseidon))
            .gas_price(self.gas_price)
            .send()
            .await
            .map_err(|e| KanonError::Chain(format!("initMerkleState send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| KanonError::Chain(format!("initMerkleState receipt: {e}")))?;
        Ok(receipt.transaction_hash.to_string())
    }

    async fn batch_update(&self, a: BatchUpdate) -> Result<String> {
        let reg = MerkleRegistry::new(self.addrs.merkle_state, self.provider.clone());
        let to_vec = |v: Vec<Bytes32>| v.into_iter().map(b32).collect::<Vec<_>>();
        let _write = self.write_lock.lock().await;
        let receipt = reg
            .batchUpdate(
                b32(a.cred_def_id),
                to_vec(a.added_keccak),
                to_vec(a.added_poseidon),
                to_vec(a.revoked_keccak),
                to_vec(a.revoked_poseidon),
                b32(a.new_root_keccak),
                b32(a.new_root_poseidon),
            )
            .gas_price(self.gas_price)
            .send()
            .await
            .map_err(|e| KanonError::Chain(format!("batchUpdate send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| KanonError::Chain(format!("batchUpdate receipt: {e}")))?;
        Ok(receipt.transaction_hash.to_string())
    }

    async fn get_merkle_state(&self, cred_def_id: Bytes32) -> Result<Option<MerkleState>> {
        let reg = MerkleRegistry::new(self.addrs.merkle_state, self.provider.clone());
        // The minimal ABI has no `isInitialized`; getState reverts (or returns
        // a zeroed state) for an uninitialized cred-def — treat either as None.
        let s = match reg.getState(b32(cred_def_id)).call().await {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };
        if s.3 == 0 && s.0 == FixedBytes::<32>::ZERO {
            return Ok(None);
        }
        // getState(): (rootKeccak, rootPoseidon, epoch, lastUpdated,
        // issuedCount, revokedCount)
        Ok(Some(MerkleState {
            root_keccak: from_fb(&s.0),
            root_poseidon: from_fb(&s.1),
            epoch: s.2,
            last_updated: s.3,
            issued_count: u256_to_u64(s.4),
            revoked_count: u256_to_u64(s.5),
        }))
    }
}

/// Helper to parse a `0x`-address from config where needed.
pub fn parse_address(s: &str) -> Result<Address> {
    s.parse()
        .map_err(|e| KanonError::Config(format!("bad address {s}: {e}")))
}

/// Convenience: parse a bytes32 org id from a `0x…` string.
pub fn parse_org_id(s: &str) -> Result<Bytes32> {
    parse_bytes32(s)
}

fn u256_to_u64(v: U256) -> u64 {
    v.try_into().unwrap_or(u64::MAX)
}
