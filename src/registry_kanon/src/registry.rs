//! `KanonRegistry` — an `anoncreds_core::AnonCredsRegistry` backed by the
//! Kanon Besu contracts (Layer 1, authoritative + shared) plus a local Askar
//! sidecar (Layer 2, for rev-reg meta / cred index / caches).
//!
//! Drop it into `AnonCredsModule::with_registry_and_storage(cfg, registry,
//! storage)` — no changes to the issuer/holder/verifier or exchange services.

use std::sync::Arc;

use anoncreds_core::registry::AnonCredsRegistry;
use anoncreds_core::revocation::{RevocationRegistryDefinition, RevocationStatusList};
use anoncreds_core::types::{
    clone_cred_def, CredDefRegistration, CredentialDefinition, Schema, SchemaRegistration,
};
use anoncreds_core::AnonCredsError;
use async_trait::async_trait;

use crate::chain::{KanonChain, RegisterCredDef};
use crate::config::KanonConfig;
use crate::encoding::{from_data_uri, to_data_uri};
use crate::error::{KanonError, Result};
use crate::ids::{
    canonical_json, cred_def_resource_id, cred_id_hash, issuer_org_id, keccak256,
    resource_id_to_bytes32, rev_reg_id as make_rev_reg_id, schema_resource_id,
};
use crate::state::{KanonState, RevRegMeta};
use crate::zk::{NoZk, ZkProvisioner};

pub struct KanonRegistry {
    chain: Arc<dyn KanonChain>,
    state: KanonState,
    config: KanonConfig,
    zk: Arc<dyn ZkProvisioner>,
}

impl KanonRegistry {
    pub fn new(
        chain: Arc<dyn KanonChain>,
        storage: Arc<dyn agent_core::traits::StorageProvider>,
        config: KanonConfig,
    ) -> Self {
        Self {
            chain,
            state: KanonState::new(storage),
            config,
            zk: Arc::new(NoZk),
        }
    }

    /// Swap in a Tier-2 ZK provisioner.
    pub fn with_zk(mut self, zk: Arc<dyn ZkProvisioner>) -> Self {
        self.zk = zk;
        self
    }

    // -- issuance bridge (not on the trait) --------------------------------
    //
    // The `AnonCredsRegistry` trait has no per-credential issuance hook, but
    // Kanon needs `AnonCredsStatusRegistry.issueCredential` at issue time
    // (revocation later requires a prior issue). The API / issuer layer calls
    // this when a credential is issued, passing the Kanon cred-id and, if the
    // cred-def is revocable, the `(rev_reg_id, cred_rev_id)` so the index is
    // recorded for later revocation.
    pub async fn on_credential_issued(
        &self,
        cred_def_id: &str,
        kanon_cred_id: &str,
        rev_reg_id: Option<&str>,
        cred_rev_id: Option<u32>,
    ) -> Result<String> {
        let cd = resource_id_to_bytes32(cred_def_id);
        let tx = self
            .chain
            .issue_credential(cd, cred_id_hash(kanon_cred_id))
            .await?;
        if let (Some(rr), Some(idx)) = (rev_reg_id, cred_rev_id) {
            self.state.put_cred_index(rr, idx, kanon_cred_id).await?;
        }
        Ok(tx)
    }

    fn schema_tag_from_id(schema_id: &str) -> String {
        let parts: Vec<&str> = schema_id.split('/').collect();
        if let Some(pos) = parts.iter().position(|p| *p == "SCHEMA") {
            if let Some(name) = parts.get(pos + 1) {
                return (*name).to_string();
            }
        }
        schema_id.replace('/', "_")
    }

    /// Register a cred-def on-chain with an explicit revocation policy mask.
    /// `override_mask` (from the caller) wins; `None` uses the configured
    /// default. If a Tier-2 (ZK) bit is set but no ZK provisioner supplies an
    /// issuer key, the ZK bit is downgraded to Tier-1.
    async fn register_cred_def_with_mask(
        &self,
        issuer_id: &str,
        cred_def: &CredentialDefinition,
        override_mask: Option<u8>,
    ) -> std::result::Result<CredDefRegistration, AnonCredsError> {
        let _org_id = issuer_org_id(issuer_id)?;
        let schema_tag = Self::schema_tag_from_id(&cred_def.schema_id.0);
        let cred_def_id = cred_def_resource_id(issuer_id, &schema_tag, &cred_def.tag);
        let cred_def_b32 = resource_id_to_bytes32(&cred_def_id);

        let v = serde_json::to_value(cred_def)
            .map_err(|e| KanonError::Encoding(format!("serialize cred_def: {e}")))?;
        let canonical = canonical_json(&v);
        let uri = to_data_uri(&canonical);
        // Integrity anchor stored on-chain as `issuerPubKey`.
        let issuer_pub_key = keccak256(canonical.as_bytes()).to_vec();

        // Per-cred-def mask (caller override), else the configured default.
        // Resolve Tier-2 key; downgrade to Tier-1 if unavailable.
        let mut policy_mask = override_mask.unwrap_or(self.config.default_policy_mask);
        let (mut ax, mut ay) = ([0u8; 32], [0u8; 32]);
        if policy_mask & crate::config::TIER_ZK_SNARK != 0 {
            match self.zk.issuer_zk_pub_key(&cred_def_b32)? {
                Some((x, y)) => {
                    ax = x;
                    ay = y;
                }
                None => {
                    tracing::warn!(
                        cred_def = %cred_def_id,
                        "Tier-2 requested but no ZK provisioner; downgrading to Tier-1"
                    );
                    policy_mask &= !crate::config::TIER_ZK_SNARK;
                    if policy_mask == 0 {
                        policy_mask = crate::config::TIER_ONE_TIME;
                    }
                }
            }
        }

        self.chain
            .register_cred_def(RegisterCredDef {
                cred_def_id: cred_def_b32,
                schema_id: resource_id_to_bytes32(&cred_def.schema_id.0),
                issuer_pub_key,
                policy_mask,
                uri,
                zk_pub_key_ax: ax,
                zk_pub_key_ay: ay,
            })
            .await?;

        // Layer-2 body cache for fast resolution.
        self.state
            .cache_cred_def_body(&cred_def_id, canonical.as_bytes())
            .await?;

        Ok(CredDefRegistration {
            cred_def_id,
            credential_definition: clone_cred_def(cred_def)?,
        })
    }
}

#[async_trait]
impl AnonCredsRegistry for KanonRegistry {
    fn method_name(&self) -> &str {
        "kanon"
    }

    fn supports_identifier(&self, id: &str) -> bool {
        id.starts_with("did:kanon:")
    }

    async fn register_schema(
        &self,
        issuer_id: &str,
        schema: &Schema,
    ) -> std::result::Result<SchemaRegistration, AnonCredsError> {
        let org_id = issuer_org_id(issuer_id)?;
        let v = serde_json::to_value(schema)
            .map_err(|e| KanonError::Encoding(format!("serialize schema: {e}")))?;
        let name = v
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or_else(|| KanonError::Invalid("schema.name missing".into()))?;
        let version = v
            .get("version")
            .and_then(|x| x.as_str())
            .ok_or_else(|| KanonError::Invalid("schema.version missing".into()))?;
        let mut attrs: Vec<String> = v
            .get("attrNames")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        attrs.sort();

        let schema_id = schema_resource_id(issuer_id, name, version);
        let body = serde_json::json!({
            "attrNames": attrs,
            "issuerId": issuer_id,
            "name": name,
            "version": version,
        });
        let canonical = canonical_json(&body);
        let uri = to_data_uri(&canonical);

        self.chain
            .register_schema(
                org_id,
                resource_id_to_bytes32(&schema_id),
                keccak256(canonical.as_bytes()),
                &uri,
            )
            .await?;

        Ok(SchemaRegistration {
            schema_id,
            schema: schema.clone(),
        })
    }

    async fn get_schema(&self, schema_id: &str) -> std::result::Result<Schema, AnonCredsError> {
        let onchain = self
            .chain
            .get_schema(resource_id_to_bytes32(schema_id))
            .await?
            .ok_or_else(|| KanonError::NotFound(format!("schema {schema_id}")))?;
        let bytes = from_data_uri(&onchain.uri)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| AnonCredsError::Schema(format!("decode schema {schema_id}: {e}")))
    }

    async fn register_credential_definition(
        &self,
        issuer_id: &str,
        cred_def: &CredentialDefinition,
    ) -> std::result::Result<CredDefRegistration, AnonCredsError> {
        self.register_cred_def_with_mask(issuer_id, cred_def, None)
            .await
    }

    /// Kanon honours a caller-supplied per-cred-def revocation policy mask
    /// (Tier-1 / Tier-2 / all); `None` falls back to the registry's configured
    /// default. Other registries ignore the mask (default trait impl).
    async fn register_credential_definition_with_policy(
        &self,
        issuer_id: &str,
        cred_def: &CredentialDefinition,
        policy_mask: Option<u8>,
    ) -> std::result::Result<CredDefRegistration, AnonCredsError> {
        self.register_cred_def_with_mask(issuer_id, cred_def, policy_mask)
            .await
    }

    async fn get_credential_definition(
        &self,
        cred_def_id: &str,
    ) -> std::result::Result<CredentialDefinition, AnonCredsError> {
        // Fast path: local body cache.
        let bytes = match self.state.cached_cred_def_body(cred_def_id).await? {
            Some(b) => b,
            None => {
                let onchain = self
                    .chain
                    .get_cred_def(resource_id_to_bytes32(cred_def_id))
                    .await?
                    .ok_or_else(|| KanonError::NotFound(format!("cred_def {cred_def_id}")))?;
                let b = from_data_uri(&onchain.uri)?;
                self.state.cache_cred_def_body(cred_def_id, &b).await?;
                b
            }
        };

        let mut v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| AnonCredsError::CredentialDefinition(format!("decode cred_def: {e}")))?;
        // Strip the CL revocation key — Kanon revokes on-chain, not via a CL
        // accumulator; leaving it would make anoncreds-rs expect a tails file.
        if let Some(value) = v.get_mut("value").and_then(|x| x.as_object_mut()) {
            value.remove("revocation");
        }
        serde_json::from_value(v)
            .map_err(|e| AnonCredsError::CredentialDefinition(format!("rebuild cred_def: {e}")))
    }

    // --- Revocation bridge (Tier-1) --------------------------------------

    async fn register_revocation_registry_def(
        &self,
        _issuer_id: &str,
        rev_reg_def: &RevocationRegistryDefinition,
    ) -> std::result::Result<String, AnonCredsError> {
        let v = serde_json::to_value(rev_reg_def)
            .map_err(|e| KanonError::Encoding(format!("serialize rev_reg_def: {e}")))?;
        let cred_def_id = v
            .get("credDefId")
            .or_else(|| v.get("cred_def_id"))
            .and_then(|x| x.as_str())
            .ok_or_else(|| KanonError::Invalid("rev_reg_def.credDefId missing".into()))?;
        let tag = v.get("tag").and_then(|x| x.as_str()).unwrap_or("default");
        let rev_reg_id = make_rev_reg_id(cred_def_id, tag);

        let meta = RevRegMeta {
            rev_reg_id: rev_reg_id.clone(),
            cred_def_id: cred_def_id.to_string(),
            policy_mask: self.config.default_policy_mask,
            max_cred_num: v
                .get("value")
                .and_then(|val| val.get("maxCredNum"))
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as u32,
            rev_reg_def_json: Some(serde_json::to_string(rev_reg_def).unwrap_or_default()),
            rev_list_json: None,
        };
        self.state.save_revreg_meta(&meta).await?;
        Ok(rev_reg_id)
    }

    async fn get_revocation_registry_def(
        &self,
        rev_reg_def_id: &str,
    ) -> std::result::Result<RevocationRegistryDefinition, AnonCredsError> {
        let meta = self
            .state
            .load_revreg_meta(rev_reg_def_id)
            .await?
            .ok_or_else(|| KanonError::NotFound(format!("rev_reg {rev_reg_def_id}")))?;
        let json = meta
            .rev_reg_def_json
            .ok_or_else(|| KanonError::NotFound(format!("rev_reg_def body {rev_reg_def_id}")))?;
        serde_json::from_str(&json)
            .map_err(|e| AnonCredsError::Registry(format!("decode rev_reg_def: {e}")))
    }

    async fn register_revocation_status_list(
        &self,
        rev_reg_def_id: &str,
        status_list: &RevocationStatusList,
    ) -> std::result::Result<(), AnonCredsError> {
        let mut meta = self
            .state
            .load_revreg_meta(rev_reg_def_id)
            .await?
            .ok_or_else(|| KanonError::NotFound(format!("rev_reg {rev_reg_def_id}")))?;

        let new_list = revoked_indices(status_list)?;
        let prev_list = match &meta.rev_list_json {
            Some(j) => {
                let v: serde_json::Value = serde_json::from_str(j).unwrap_or_default();
                revoked_indices_value(&v)
            }
            None => Vec::new(),
        };

        // Newly-revoked indices = set in new but not in prev.
        let cred_def_b32 = resource_id_to_bytes32(&meta.cred_def_id);
        for idx in &new_list {
            if prev_list.contains(idx) {
                continue;
            }
            let kanon_cred_id = self
                .state
                .get_cred_index(rev_reg_def_id, *idx)
                .await?
                .ok_or_else(|| {
                    KanonError::Invalid(format!(
                        "no cred-index for {rev_reg_def_id}:{idx}; issuance hook not called"
                    ))
                })?;
            // Ensure issued (idempotent) then revoke on-chain.
            let cid_hash = cred_id_hash(&kanon_cred_id);
            let _ = self.chain.issue_credential(cred_def_b32, cid_hash).await;
            self.chain.revoke_credential(cred_def_b32, cid_hash).await?;
        }

        meta.rev_list_json = Some(
            serde_json::to_string(status_list)
                .map_err(|e| KanonError::Encoding(format!("serialize status list: {e}")))?,
        );
        self.state.save_revreg_meta(&meta).await?;
        Ok(())
    }

    async fn get_revocation_status_list(
        &self,
        rev_reg_def_id: &str,
        _timestamp: Option<u64>,
    ) -> std::result::Result<RevocationStatusList, AnonCredsError> {
        let meta = self
            .state
            .load_revreg_meta(rev_reg_def_id)
            .await?
            .ok_or_else(|| KanonError::NotFound(format!("rev_reg {rev_reg_def_id}")))?;
        let json = meta
            .rev_list_json
            .ok_or_else(|| KanonError::NotFound(format!("status list {rev_reg_def_id}")))?;
        serde_json::from_str(&json)
            .map_err(|e| AnonCredsError::Registry(format!("decode status list: {e}")))
    }
}

/// Extract the set of revoked indices (1-bits) from a `RevocationStatusList`.
fn revoked_indices(list: &RevocationStatusList) -> Result<Vec<u32>> {
    let v = serde_json::to_value(list)
        .map_err(|e| KanonError::Encoding(format!("serialize status list: {e}")))?;
    Ok(revoked_indices_value(&v))
}

fn revoked_indices_value(v: &serde_json::Value) -> Vec<u32> {
    v.get("revocationList")
        .or_else(|| v.get("revocation_list"))
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .enumerate()
                .filter_map(|(i, bit)| {
                    if bit.as_u64() == Some(1) {
                        Some(i as u32)
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}
