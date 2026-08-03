//! Storage-backed AnonCreds registry — persists schemas, credential
//! definitions, revocation registry definitions, and revocation status
//! lists via the `agent_core::StorageProvider` trait.
//!
//! For deployments where the verifiable data registry is itself a database
//! (rather than a public ledger), this implementation lets the same Askar
//! profile that backs the wallet also back the AnonCreds object store.
//! Issuers can publish, holders + verifiers can resolve.

use std::sync::RwLock;

use agent_core::traits::{Record, StorageProvider};
use async_trait::async_trait;
use std::sync::Arc;

use crate::error::AnonCredsError;
use crate::registry::AnonCredsRegistry;
use crate::revocation::{RevocationRegistryDefinition, RevocationStatusList};
use crate::types::*;

const CAT_SCHEMA: &str = "anoncreds_schema";
const CAT_CRED_DEF: &str = "anoncreds_cred_def";
const CAT_REV_REG_DEF: &str = "anoncreds_rev_reg_def";
const CAT_REV_STATUS_LIST: &str = "anoncreds_rev_status_list";

/// Storage-backed AnonCreds registry.
///
/// All four object types are serialized to JSON and written to the configured
/// `StorageProvider`. Revocation status lists are stored under composite
/// names `{rev_reg_def_id}::{timestamp}` so a verifier can look up the
/// snapshot at-or-before any timestamp.
pub struct StorageBackedRegistry {
    storage: Arc<dyn StorageProvider>,
    /// Cache of status-list timestamps per rev_reg_def_id so `get_revocation_status_list`
    /// can find the right snapshot without scanning records.
    rev_status_index: RwLock<std::collections::HashMap<String, Vec<u64>>>,
}

impl StorageBackedRegistry {
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self {
            storage,
            rev_status_index: RwLock::new(std::collections::HashMap::new()),
        }
    }

    fn status_list_name(rev_reg_def_id: &str, timestamp: u64) -> String {
        format!("{}::{:020}", rev_reg_def_id, timestamp)
    }

    fn parse_status_timestamp(name: &str) -> Option<u64> {
        name.rsplit_once("::").and_then(|(_, ts)| ts.parse().ok())
    }
}

#[async_trait]
impl AnonCredsRegistry for StorageBackedRegistry {
    fn method_name(&self) -> &str {
        "storage"
    }

    fn supports_identifier(&self, _id: &str) -> bool {
        true
    }

    async fn register_schema(
        &self,
        issuer_id: &str,
        schema: &Schema,
    ) -> Result<SchemaRegistration, AnonCredsError> {
        let schema_id = format!("{}:2:{}:{}", issuer_id, schema.name, schema.version);
        let bytes = serde_json::to_vec(schema)
            .map_err(|e| AnonCredsError::Storage(format!("serialize schema: {}", e)))?;
        let record = Record::new(CAT_SCHEMA, &schema_id, bytes);
        if self.storage.update(&record).await.is_err() {
            self.storage
                .save(&record)
                .await
                .map_err(|e| AnonCredsError::Storage(format!("save schema: {}", e)))?;
        }
        Ok(SchemaRegistration {
            schema_id,
            schema: schema.clone(),
        })
    }

    async fn get_schema(&self, schema_id: &str) -> Result<Schema, AnonCredsError> {
        let record = self
            .storage
            .find(CAT_SCHEMA, schema_id)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("find schema: {}", e)))?
            .ok_or_else(|| AnonCredsError::NotFound(format!("schema {}", schema_id)))?;
        serde_json::from_slice(&record.value)
            .map_err(|e| AnonCredsError::Storage(format!("decode schema: {}", e)))
    }

    async fn register_credential_definition(
        &self,
        issuer_id: &str,
        cred_def: &CredentialDefinition,
    ) -> Result<CredDefRegistration, AnonCredsError> {
        let cred_def_id = format!(
            "{}:3:CL:{}:{}",
            issuer_id, cred_def.schema_id.0, cred_def.tag
        );
        let bytes = serde_json::to_vec(cred_def)
            .map_err(|e| AnonCredsError::Storage(format!("serialize cred_def: {}", e)))?;
        let record = Record::new(CAT_CRED_DEF, &cred_def_id, bytes.clone());
        if self.storage.update(&record).await.is_err() {
            self.storage
                .save(&record)
                .await
                .map_err(|e| AnonCredsError::Storage(format!("save cred_def: {}", e)))?;
        }
        let cred_def_copy: CredentialDefinition = serde_json::from_slice(&bytes)
            .map_err(|e| AnonCredsError::Storage(format!("clone cred_def: {}", e)))?;
        Ok(CredDefRegistration {
            cred_def_id,
            credential_definition: cred_def_copy,
        })
    }

    async fn get_credential_definition(
        &self,
        cred_def_id: &str,
    ) -> Result<CredentialDefinition, AnonCredsError> {
        let record = self
            .storage
            .find(CAT_CRED_DEF, cred_def_id)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("find cred_def: {}", e)))?
            .ok_or_else(|| AnonCredsError::NotFound(format!("cred_def {}", cred_def_id)))?;
        serde_json::from_slice(&record.value)
            .map_err(|e| AnonCredsError::Storage(format!("decode cred_def: {}", e)))
    }

    async fn register_revocation_registry_def(
        &self,
        issuer_id: &str,
        rev_reg_def: &RevocationRegistryDefinition,
    ) -> Result<String, AnonCredsError> {
        let rev_reg_def_id = format!(
            "{}:4:{}:CL_ACCUM:{}",
            issuer_id, rev_reg_def.cred_def_id.0, rev_reg_def.tag
        );
        let bytes = serde_json::to_vec(rev_reg_def)
            .map_err(|e| AnonCredsError::Storage(format!("serialize rev_reg_def: {}", e)))?;
        let record = Record::new(CAT_REV_REG_DEF, &rev_reg_def_id, bytes);
        if self.storage.update(&record).await.is_err() {
            self.storage
                .save(&record)
                .await
                .map_err(|e| AnonCredsError::Storage(format!("save rev_reg_def: {}", e)))?;
        }
        Ok(rev_reg_def_id)
    }

    async fn get_revocation_registry_def(
        &self,
        rev_reg_def_id: &str,
    ) -> Result<RevocationRegistryDefinition, AnonCredsError> {
        let record = self
            .storage
            .find(CAT_REV_REG_DEF, rev_reg_def_id)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("find rev_reg_def: {}", e)))?
            .ok_or_else(|| AnonCredsError::NotFound(format!("rev_reg_def {}", rev_reg_def_id)))?;
        serde_json::from_slice(&record.value)
            .map_err(|e| AnonCredsError::Storage(format!("decode rev_reg_def: {}", e)))
    }

    async fn register_revocation_status_list(
        &self,
        rev_reg_def_id: &str,
        status_list: &RevocationStatusList,
    ) -> Result<(), AnonCredsError> {
        let timestamp = serde_json::to_value(status_list)
            .ok()
            .and_then(|v| v.get("timestamp").and_then(|t| t.as_u64()))
            .ok_or_else(|| {
                AnonCredsError::InvalidInput(
                    "RevocationStatusList must carry a timestamp before persisting".into(),
                )
            })?;
        let name = Self::status_list_name(rev_reg_def_id, timestamp);
        let bytes = serde_json::to_vec(status_list)
            .map_err(|e| AnonCredsError::Storage(format!("serialize status_list: {}", e)))?;
        let record = Record::new(CAT_REV_STATUS_LIST, &name, bytes);
        if self.storage.update(&record).await.is_err() {
            self.storage
                .save(&record)
                .await
                .map_err(|e| AnonCredsError::Storage(format!("save status_list: {}", e)))?;
        }

        // Update in-memory index so resolution doesn't have to scan all records.
        let mut index = self
            .rev_status_index
            .write()
            .map_err(|e| AnonCredsError::Storage(format!("rev_status_index poisoned: {}", e)))?;
        let entry = index.entry(rev_reg_def_id.to_string()).or_default();
        if !entry.contains(&timestamp) {
            entry.push(timestamp);
            entry.sort();
        }
        Ok(())
    }

    async fn get_revocation_status_list(
        &self,
        rev_reg_def_id: &str,
        timestamp: Option<u64>,
    ) -> Result<RevocationStatusList, AnonCredsError> {
        // Try the in-memory index first; if cold, rebuild it by querying
        // storage for all status-list records under this rev_reg_def_id.
        let timestamps = {
            let index = self.rev_status_index.read().map_err(|e| {
                AnonCredsError::Storage(format!("rev_status_index poisoned: {}", e))
            })?;
            index.get(rev_reg_def_id).cloned()
        };
        let timestamps = match timestamps {
            Some(t) if !t.is_empty() => t,
            _ => {
                let all = self
                    .storage
                    .find_all(CAT_REV_STATUS_LIST, &Default::default())
                    .await
                    .map_err(|e| AnonCredsError::Storage(format!("scan status_lists: {}", e)))?;
                let mut found: Vec<u64> = all
                    .iter()
                    .filter(|r| r.name.starts_with(&format!("{}::", rev_reg_def_id)))
                    .filter_map(|r| Self::parse_status_timestamp(&r.name))
                    .collect();
                found.sort();
                if found.is_empty() {
                    return Err(AnonCredsError::NotFound(format!(
                        "no status lists for {}",
                        rev_reg_def_id
                    )));
                }
                let mut index = self.rev_status_index.write().map_err(|e| {
                    AnonCredsError::Storage(format!("rev_status_index poisoned: {}", e))
                })?;
                index.insert(rev_reg_def_id.to_string(), found.clone());
                found
            }
        };

        // Pick the largest timestamp <= request (or the latest, when no
        // constraint is given).
        let picked_ts = match timestamp {
            Some(target) => timestamps
                .iter()
                .rev()
                .find(|t| **t <= target)
                .copied()
                .ok_or_else(|| {
                    AnonCredsError::NotFound(format!(
                        "no status list at or before {} for {}",
                        target, rev_reg_def_id
                    ))
                })?,
            None => *timestamps.last().unwrap(),
        };

        let name = Self::status_list_name(rev_reg_def_id, picked_ts);
        let record = self
            .storage
            .find(CAT_REV_STATUS_LIST, &name)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("find status_list: {}", e)))?
            .ok_or_else(|| AnonCredsError::NotFound(format!("status_list {}", name)))?;
        serde_json::from_slice(&record.value)
            .map_err(|e| AnonCredsError::Storage(format!("decode status_list: {}", e)))
    }
}

#[cfg(test)]
mod tests {

    // Placeholder — integration tests live in tests/storage_registry.rs so
    // they can pull storage_memory as a dev-dep.
    #[test]
    fn module_compiles() {}
}
