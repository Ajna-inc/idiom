/// AnonCreds persistence trait
///
/// Abstracts storage operations for holder/issuer data.
/// Implementations back onto StorageProvider (Askar/Memory).
use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Stored credential record (public version of the holder's internal credential)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredentialRecord {
    pub credential_id: String,
    pub credential_json: serde_json::Value,
    pub schema_id: String,
    pub cred_def_id: String,
    pub attributes: HashMap<String, String>,
    /// Revocation registry id this credential was issued under, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rev_reg_id: Option<String>,
    /// Index this credential occupies in the revocation accumulator, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cred_rev_index: Option<u32>,
}

/// Storage trait for AnonCreds holder/issuer data.
///
/// Services accept `Option<Arc<dyn AnonCredsStore>>`:
/// - `None` = pure in-memory (tests, backward-compatible)
/// - `Some` = persistent (production)
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait AnonCredsStore: Send + Sync {
    // --- Link Secret ---

    /// Load the persisted link secret (decimal string) and its ID.
    async fn load_link_secret(&self) -> Result<Option<(String, String)>>;

    /// Persist the link secret (decimal string) and its ID.
    async fn save_link_secret(&self, secret_dec: &str, id: &str) -> Result<()>;

    // --- Holder Credentials ---

    /// Save a credential record.
    async fn save_credential(&self, record: &StoredCredentialRecord) -> Result<()>;

    /// Load all credentials.
    async fn load_all_credentials(&self) -> Result<Vec<StoredCredentialRecord>>;

    /// Delete a credential by ID.
    async fn delete_credential(&self, credential_id: &str) -> Result<()>;

    // --- Issuer Private Keys ---

    /// Save a credential definition private key (serialized JSON bytes).
    async fn save_cred_def_private(&self, cred_def_id: &str, json: &[u8]) -> Result<()>;

    /// Load all credential definition private keys.
    async fn load_all_cred_def_privates(&self) -> Result<Vec<(String, Vec<u8>)>>;

    // --- Issuer Key Correctness Proofs ---

    /// Save a key correctness proof (serialized JSON bytes).
    async fn save_key_correctness_proof(&self, cred_def_id: &str, json: &[u8]) -> Result<()>;

    /// Load all key correctness proofs.
    async fn load_all_key_correctness_proofs(&self) -> Result<Vec<(String, Vec<u8>)>>;

    // --- Request Metadata (in-flight exchanges only) ---

    /// Save request metadata for a thread.
    async fn save_request_metadata(&self, thread_id: &str, json: &[u8]) -> Result<()>;

    /// Load request metadata for a thread.
    async fn load_request_metadata(&self, thread_id: &str) -> Result<Option<Vec<u8>>>;

    /// Delete request metadata for a thread.
    async fn delete_request_metadata(&self, thread_id: &str) -> Result<()>;
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait AnonCredsStore {
    async fn load_link_secret(&self) -> Result<Option<(String, String)>>;
    async fn save_link_secret(&self, secret_dec: &str, id: &str) -> Result<()>;
    async fn save_credential(&self, record: &StoredCredentialRecord) -> Result<()>;
    async fn load_all_credentials(&self) -> Result<Vec<StoredCredentialRecord>>;
    async fn delete_credential(&self, credential_id: &str) -> Result<()>;
    async fn save_cred_def_private(&self, cred_def_id: &str, json: &[u8]) -> Result<()>;
    async fn load_all_cred_def_privates(&self) -> Result<Vec<(String, Vec<u8>)>>;
    async fn save_key_correctness_proof(&self, cred_def_id: &str, json: &[u8]) -> Result<()>;
    async fn load_all_key_correctness_proofs(&self) -> Result<Vec<(String, Vec<u8>)>>;
    async fn save_request_metadata(&self, thread_id: &str, json: &[u8]) -> Result<()>;
    async fn load_request_metadata(&self, thread_id: &str) -> Result<Option<Vec<u8>>>;
    async fn delete_request_metadata(&self, thread_id: &str) -> Result<()>;
}
