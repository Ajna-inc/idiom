//! Layer-2 persistence — the local sidecar state the chain deliberately does
//! not hold, kept in the same Askar profile that backs the wallet (so it is
//! per-tenant scoped and survives restarts). Mirrors the ACA-Py BaseStorage
//! records the Python plugin maintains:
//!
//!   - `kanon_revreg_meta`   synthesized rev-reg definition + initial list
//!   - `kanon_revreg_index`  `cred_rev_id` -> `kanon_cred_id` mapping
//!   - `kanon_creddef_body`  cred-def body cache (fast path; source is chain)
//!
//! Layer 1 (authoritative, shared) is the Besu chain via `KanonChain`.

use std::sync::Arc;

use agent_core::traits::{Record, StorageProvider};
use serde::{Deserialize, Serialize};

use crate::error::{KanonError, Result};

const CAT_REVREG_META: &str = "kanon_revreg_meta";
const CAT_REVREG_INDEX: &str = "kanon_revreg_index";
const CAT_CREDDEF_BODY: &str = "kanon_creddef_body";

/// Synthesized rev-reg metadata (there is no on-chain rev-reg object).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevRegMeta {
    pub rev_reg_id: String,
    pub cred_def_id: String,
    pub policy_mask: u8,
    pub max_cred_num: u32,
    /// Serialized `RevocationRegistryDefinition` JSON.
    pub rev_reg_def_json: Option<String>,
    /// Serialized `RevocationStatusList` JSON (latest snapshot).
    pub rev_list_json: Option<String>,
}

pub struct KanonState {
    storage: Arc<dyn StorageProvider>,
}

impl KanonState {
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self { storage }
    }

    // --- rev-reg meta ---

    pub async fn save_revreg_meta(&self, meta: &RevRegMeta) -> Result<()> {
        let bytes = serde_json::to_vec(meta)
            .map_err(|e| KanonError::Storage(format!("serialize revreg meta: {e}")))?;
        let record = Record::new(CAT_REVREG_META, &meta.rev_reg_id, bytes);
        self.upsert(record).await
    }

    pub async fn load_revreg_meta(&self, rev_reg_id: &str) -> Result<Option<RevRegMeta>> {
        match self
            .storage
            .find(CAT_REVREG_META, rev_reg_id)
            .await
            .map_err(|e| KanonError::Storage(format!("find revreg meta: {e}")))?
        {
            Some(r) => serde_json::from_slice(&r.value)
                .map(Some)
                .map_err(|e| KanonError::Storage(format!("decode revreg meta: {e}"))),
            None => Ok(None),
        }
    }

    // --- cred_rev_id -> kanon_cred_id index ---

    pub async fn put_cred_index(
        &self,
        rev_reg_id: &str,
        cred_rev_id: u32,
        kanon_cred_id: &str,
    ) -> Result<()> {
        let name = index_key(rev_reg_id, cred_rev_id);
        let record = Record::new(CAT_REVREG_INDEX, &name, kanon_cred_id.as_bytes().to_vec());
        self.upsert(record).await
    }

    pub async fn get_cred_index(
        &self,
        rev_reg_id: &str,
        cred_rev_id: u32,
    ) -> Result<Option<String>> {
        let name = index_key(rev_reg_id, cred_rev_id);
        match self
            .storage
            .find(CAT_REVREG_INDEX, &name)
            .await
            .map_err(|e| KanonError::Storage(format!("find cred index: {e}")))?
        {
            Some(r) => Ok(Some(String::from_utf8(r.value).map_err(|e| {
                KanonError::Storage(format!("decode cred index: {e}"))
            })?)),
            None => Ok(None),
        }
    }

    // --- cred-def body cache ---

    pub async fn cache_cred_def_body(&self, cred_def_id: &str, body: &[u8]) -> Result<()> {
        let record = Record::new(CAT_CREDDEF_BODY, cred_def_id, body.to_vec());
        self.upsert(record).await
    }

    pub async fn cached_cred_def_body(&self, cred_def_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .storage
            .find(CAT_CREDDEF_BODY, cred_def_id)
            .await
            .map_err(|e| KanonError::Storage(format!("find cred def body: {e}")))?
            .map(|r| r.value))
    }

    async fn upsert(&self, record: Record) -> Result<()> {
        if self.storage.update(&record).await.is_err() {
            self.storage
                .save(&record)
                .await
                .map_err(|e| KanonError::Storage(format!("save {}: {e}", record.category)))?;
        }
        Ok(())
    }
}

fn index_key(rev_reg_id: &str, cred_rev_id: u32) -> String {
    format!("{rev_reg_id}:{cred_rev_id}")
}
