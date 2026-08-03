/// StorageProvider-backed AnonCreds store
///
/// Implements AnonCredsStore using agent_core::StorageProvider for
/// durable persistence via Askar (SQLite/Postgres) or in-memory storage.
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use agent_core::traits::{Query, Record, StorageProvider};

use crate::error::{AnonCredsError, Result};
use crate::store::{AnonCredsStore, StoredCredentialRecord};

// Storage categories
const LINK_SECRET_CATEGORY: &str = "anoncreds_link_secret";
const LINK_SECRET_NAME: &str = "default";
const CREDENTIAL_CATEGORY: &str = "anoncreds_credential";
const CRED_DEF_PRIVATE_CATEGORY: &str = "anoncreds_cred_def_private";
const KEY_CORRECTNESS_CATEGORY: &str = "anoncreds_key_correctness";
const REQUEST_METADATA_CATEGORY: &str = "anoncreds_request_metadata";

/// AnonCreds store backed by StorageProvider
pub struct StorageBackedAnonCredsStore {
    storage: Arc<dyn StorageProvider>,
}

impl StorageBackedAnonCredsStore {
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self { storage }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl AnonCredsStore for StorageBackedAnonCredsStore {
    async fn load_link_secret(&self) -> Result<Option<(String, String)>> {
        let record = self
            .storage
            .find(LINK_SECRET_CATEGORY, LINK_SECRET_NAME)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Load link secret: {}", e)))?;

        match record {
            Some(r) => {
                let secret_dec = String::from_utf8(r.value)
                    .map_err(|e| AnonCredsError::Storage(format!("Parse link secret: {}", e)))?;
                let id = r
                    .tags
                    .get("id")
                    .cloned()
                    .unwrap_or_else(|| "default".to_string());
                Ok(Some((secret_dec, id)))
            }
            None => Ok(None),
        }
    }

    async fn save_link_secret(&self, secret_dec: &str, id: &str) -> Result<()> {
        let mut tags = HashMap::new();
        tags.insert("id".to_string(), id.to_string());

        let record = Record {
            category: LINK_SECRET_CATEGORY.to_string(),
            name: LINK_SECRET_NAME.to_string(),
            value: secret_dec.as_bytes().to_vec(),
            tags,
        };

        // Try save first, update if already exists
        match self.storage.save(&record).await {
            Ok(()) => Ok(()),
            Err(_) => self
                .storage
                .update(&record)
                .await
                .map_err(|e| AnonCredsError::Storage(format!("Save link secret: {}", e))),
        }
    }

    async fn save_credential(&self, cred: &StoredCredentialRecord) -> Result<()> {
        let value = serde_json::to_vec(cred)
            .map_err(|e| AnonCredsError::Storage(format!("Serialize credential: {}", e)))?;

        let mut tags = HashMap::new();
        tags.insert("schema_id".to_string(), cred.schema_id.clone());
        tags.insert("cred_def_id".to_string(), cred.cred_def_id.clone());

        // Attribute tags for restriction matching
        for (name, val) in &cred.attributes {
            tags.insert(format!("attr::{}::value", name), val.clone());
            tags.insert(format!("attr::{}::marker", name), "1".to_string());
        }

        let record = Record {
            category: CREDENTIAL_CATEGORY.to_string(),
            name: cred.credential_id.clone(),
            value,
            tags,
        };

        self.storage
            .save(&record)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Save credential: {}", e)))
    }

    async fn load_all_credentials(&self) -> Result<Vec<StoredCredentialRecord>> {
        let query = Query::new();
        let records = self
            .storage
            .find_all(CREDENTIAL_CATEGORY, &query)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Load credentials: {}", e)))?;

        let mut creds = Vec::new();
        for r in records {
            match serde_json::from_slice::<StoredCredentialRecord>(&r.value) {
                Ok(cred) => creds.push(cred),
                Err(e) => tracing::warn!("Skip corrupt credential record {}: {}", r.name, e),
            }
        }
        Ok(creds)
    }

    async fn delete_credential(&self, credential_id: &str) -> Result<()> {
        self.storage
            .delete(CREDENTIAL_CATEGORY, credential_id)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Delete credential: {}", e)))
    }

    async fn save_cred_def_private(&self, cred_def_id: &str, json: &[u8]) -> Result<()> {
        let record = Record::new(CRED_DEF_PRIVATE_CATEGORY, cred_def_id, json.to_vec());
        self.storage
            .save(&record)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Save cred def private: {}", e)))
    }

    async fn load_all_cred_def_privates(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let query = Query::new();
        let records = self
            .storage
            .find_all(CRED_DEF_PRIVATE_CATEGORY, &query)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Load cred def privates: {}", e)))?;
        Ok(records.into_iter().map(|r| (r.name, r.value)).collect())
    }

    async fn save_key_correctness_proof(&self, cred_def_id: &str, json: &[u8]) -> Result<()> {
        let record = Record::new(KEY_CORRECTNESS_CATEGORY, cred_def_id, json.to_vec());
        self.storage
            .save(&record)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Save key correctness proof: {}", e)))
    }

    async fn load_all_key_correctness_proofs(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let query = Query::new();
        let records = self
            .storage
            .find_all(KEY_CORRECTNESS_CATEGORY, &query)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Load key correctness proofs: {}", e)))?;
        Ok(records.into_iter().map(|r| (r.name, r.value)).collect())
    }

    async fn save_request_metadata(&self, thread_id: &str, json: &[u8]) -> Result<()> {
        let record = Record::new(REQUEST_METADATA_CATEGORY, thread_id, json.to_vec());
        self.storage
            .save(&record)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Save request metadata: {}", e)))
    }

    async fn load_request_metadata(&self, thread_id: &str) -> Result<Option<Vec<u8>>> {
        let record = self
            .storage
            .find(REQUEST_METADATA_CATEGORY, thread_id)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Load request metadata: {}", e)))?;
        Ok(record.map(|r| r.value))
    }

    async fn delete_request_metadata(&self, thread_id: &str) -> Result<()> {
        self.storage
            .delete(REQUEST_METADATA_CATEGORY, thread_id)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Delete request metadata: {}", e)))
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl AnonCredsStore for StorageBackedAnonCredsStore {
    // Same implementation as above but without Send bounds
    async fn load_link_secret(&self) -> Result<Option<(String, String)>> {
        let record = self
            .storage
            .find(LINK_SECRET_CATEGORY, LINK_SECRET_NAME)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Load link secret: {}", e)))?;
        match record {
            Some(r) => {
                let secret_dec = String::from_utf8(r.value)
                    .map_err(|e| AnonCredsError::Storage(format!("Parse link secret: {}", e)))?;
                let id = r
                    .tags
                    .get("id")
                    .cloned()
                    .unwrap_or_else(|| "default".to_string());
                Ok(Some((secret_dec, id)))
            }
            None => Ok(None),
        }
    }

    async fn save_link_secret(&self, secret_dec: &str, id: &str) -> Result<()> {
        let mut tags = HashMap::new();
        tags.insert("id".to_string(), id.to_string());
        let record = Record {
            category: LINK_SECRET_CATEGORY.to_string(),
            name: LINK_SECRET_NAME.to_string(),
            value: secret_dec.as_bytes().to_vec(),
            tags,
        };
        match self.storage.save(&record).await {
            Ok(()) => Ok(()),
            Err(_) => self
                .storage
                .update(&record)
                .await
                .map_err(|e| AnonCredsError::Storage(format!("Save link secret: {}", e))),
        }
    }

    async fn save_credential(&self, cred: &StoredCredentialRecord) -> Result<()> {
        let value = serde_json::to_vec(cred)
            .map_err(|e| AnonCredsError::Storage(format!("Serialize credential: {}", e)))?;
        let mut tags = HashMap::new();
        tags.insert("schema_id".to_string(), cred.schema_id.clone());
        tags.insert("cred_def_id".to_string(), cred.cred_def_id.clone());
        for (name, val) in &cred.attributes {
            tags.insert(format!("attr::{}::value", name), val.clone());
            tags.insert(format!("attr::{}::marker", name), "1".to_string());
        }
        let record = Record {
            category: CREDENTIAL_CATEGORY.to_string(),
            name: cred.credential_id.clone(),
            value,
            tags,
        };
        self.storage
            .save(&record)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Save credential: {}", e)))
    }

    async fn load_all_credentials(&self) -> Result<Vec<StoredCredentialRecord>> {
        let query = Query::new();
        let records = self
            .storage
            .find_all(CREDENTIAL_CATEGORY, &query)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Load credentials: {}", e)))?;
        let mut creds = Vec::new();
        for r in records {
            if let Ok(cred) = serde_json::from_slice::<StoredCredentialRecord>(&r.value) {
                creds.push(cred);
            }
        }
        Ok(creds)
    }

    async fn delete_credential(&self, credential_id: &str) -> Result<()> {
        self.storage
            .delete(CREDENTIAL_CATEGORY, credential_id)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Delete credential: {}", e)))
    }

    async fn save_cred_def_private(&self, cred_def_id: &str, json: &[u8]) -> Result<()> {
        let record = Record::new(CRED_DEF_PRIVATE_CATEGORY, cred_def_id, json.to_vec());
        self.storage
            .save(&record)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Save cred def private: {}", e)))
    }

    async fn load_all_cred_def_privates(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let query = Query::new();
        let records = self
            .storage
            .find_all(CRED_DEF_PRIVATE_CATEGORY, &query)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Load cred def privates: {}", e)))?;
        Ok(records.into_iter().map(|r| (r.name, r.value)).collect())
    }

    async fn save_key_correctness_proof(&self, cred_def_id: &str, json: &[u8]) -> Result<()> {
        let record = Record::new(KEY_CORRECTNESS_CATEGORY, cred_def_id, json.to_vec());
        self.storage
            .save(&record)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Save key correctness proof: {}", e)))
    }

    async fn load_all_key_correctness_proofs(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let query = Query::new();
        let records = self
            .storage
            .find_all(KEY_CORRECTNESS_CATEGORY, &query)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Load key correctness proofs: {}", e)))?;
        Ok(records.into_iter().map(|r| (r.name, r.value)).collect())
    }

    async fn save_request_metadata(&self, thread_id: &str, json: &[u8]) -> Result<()> {
        let record = Record::new(REQUEST_METADATA_CATEGORY, thread_id, json.to_vec());
        self.storage
            .save(&record)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Save request metadata: {}", e)))
    }

    async fn load_request_metadata(&self, thread_id: &str) -> Result<Option<Vec<u8>>> {
        let record = self
            .storage
            .find(REQUEST_METADATA_CATEGORY, thread_id)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Load request metadata: {}", e)))?;
        Ok(record.map(|r| r.value))
    }

    async fn delete_request_metadata(&self, thread_id: &str) -> Result<()> {
        self.storage
            .delete(REQUEST_METADATA_CATEGORY, thread_id)
            .await
            .map_err(|e| AnonCredsError::Storage(format!("Delete request metadata: {}", e)))
    }
}
