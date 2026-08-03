/// AnonCreds Holder Service
///
/// Wraps anoncreds::prover functions for credential request creation,
/// credential processing, and presentation generation.
///
/// Supports optional persistence via `AnonCredsStore` — when provided,
/// link secrets, credentials, and request metadata survive restarts.
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{AnonCredsError, Result};
use crate::registry::AnonCredsRegistry;
use crate::revocation::{self, CredentialRevocationState};
use crate::store::{AnonCredsStore, StoredCredentialRecord};
use crate::types::*;

/// Per-credential revocation context supplied by the caller when building a
/// presentation that needs to include non-revocation proofs.
pub struct CredentialRevocationContext {
    /// Revocation registry definition id this credential lives in.
    pub rev_reg_id: String,
    /// Holder-side revocation state (witness + accumulator value).
    pub state: CredentialRevocationState,
    /// Timestamp of the status list used to build `state`.
    pub timestamp: u64,
}

/// Holder service for requesting, storing, and presenting credentials.
pub struct AnonCredsHolderService {
    registry: Arc<dyn AnonCredsRegistry>,
    /// Optional persistent store (None = pure in-memory)
    store: Option<Arc<dyn AnonCredsStore>>,
    /// Link secret (one per holder)
    link_secret: RwLock<Option<LinkSecret>>,
    /// Link secret ID
    link_secret_id: RwLock<String>,
    /// Stored credentials — None = not loaded from store yet
    credentials: RwLock<Option<HashMap<String, StoredCredentialRecord>>>,
    /// Stored credential request metadata (thread_id -> JSON)
    request_metadata: RwLock<HashMap<String, serde_json::Value>>,
}

impl AnonCredsHolderService {
    /// Create a new holder service (pure in-memory, no persistence)
    pub fn new(registry: Arc<dyn AnonCredsRegistry>) -> Self {
        Self {
            registry,
            store: None,
            link_secret: RwLock::new(None),
            link_secret_id: RwLock::new("default".to_string()),
            credentials: RwLock::new(Some(HashMap::new())),
            request_metadata: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new holder service with persistent store
    pub fn new_with_store(
        registry: Arc<dyn AnonCredsRegistry>,
        store: Arc<dyn AnonCredsStore>,
    ) -> Self {
        Self {
            registry,
            store: Some(store),
            link_secret: RwLock::new(None),
            link_secret_id: RwLock::new("default".to_string()),
            credentials: RwLock::new(None), // None = lazy-load from store
            request_metadata: RwLock::new(HashMap::new()),
        }
    }

    /// Ensure credentials cache is loaded from store
    async fn ensure_credentials_loaded(&self) -> Result<()> {
        // Quick check under read lock
        {
            let creds = self
                .credentials
                .read()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            if creds.is_some() {
                return Ok(());
            }
        }

        // Load from store (no lock held)
        let loaded = if let Some(store) = &self.store {
            let records = store.load_all_credentials().await?;
            let mut map = HashMap::new();
            for r in records {
                map.insert(r.credential_id.clone(), r);
            }
            if !map.is_empty() {
                tracing::info!("Loaded {} AnonCreds credentials from storage", map.len());
            }
            map
        } else {
            HashMap::new()
        };

        // Populate cache
        {
            let mut creds = self
                .credentials
                .write()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            if creds.is_none() {
                *creds = Some(loaded);
            }
        }

        Ok(())
    }

    /// Create or load the link secret
    pub async fn ensure_link_secret(&self) -> Result<()> {
        // Quick check if already in memory
        {
            let ls = self
                .link_secret
                .read()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            if ls.is_some() {
                return Ok(());
            }
        }

        // Try loading from store (no lock held)
        if let Some(store) = &self.store {
            if let Some((secret_dec, id)) = store.load_link_secret().await? {
                let secret = LinkSecret::try_from(secret_dec.as_str())
                    .map_err(|e| AnonCredsError::Storage(format!("Parse link secret: {}", e)))?;

                let mut ls = self
                    .link_secret
                    .write()
                    .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
                *ls = Some(secret);

                let mut ls_id = self
                    .link_secret_id
                    .write()
                    .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
                *ls_id = id;

                tracing::info!("Loaded link secret from storage");
                return Ok(());
            }
        }

        // Create new link secret
        let secret = anoncreds::prover::create_link_secret()?;

        // Persist if store available
        if let Some(store) = &self.store {
            let secret_for_store = secret
                .try_clone()
                .map_err(|e| AnonCredsError::AnoncredsLib(format!("Clone link secret: {}", e)))?;
            let secret_dec: String = secret_for_store
                .try_into()
                .map_err(|e| AnonCredsError::Storage(format!("Serialize link secret: {}", e)))?;
            let id = {
                let ls_id = self
                    .link_secret_id
                    .read()
                    .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
                ls_id.clone()
            };
            store.save_link_secret(&secret_dec, &id).await?;
            tracing::info!("Created and persisted new link secret");
        }

        let mut ls = self
            .link_secret
            .write()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        *ls = Some(secret);

        Ok(())
    }

    /// Set link secret from an existing value (e.g., loaded from wallet)
    pub fn set_link_secret(&self, secret: LinkSecret, id: &str) -> Result<()> {
        let mut ls = self
            .link_secret
            .write()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        *ls = Some(secret);

        let mut ls_id = self
            .link_secret_id
            .write()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        *ls_id = id.to_string();

        Ok(())
    }

    fn get_link_secret(&self) -> Result<LinkSecret> {
        let ls = self
            .link_secret
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        let link_secret = ls
            .as_ref()
            .ok_or_else(|| AnonCredsError::InvalidInput("Link secret not initialized".into()))?;
        link_secret
            .try_clone()
            .map_err(|e| AnonCredsError::AnoncredsLib(format!("Clone link secret: {}", e)))
    }

    fn get_link_secret_id(&self) -> Result<String> {
        let id = self
            .link_secret_id
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        Ok(id.clone())
    }

    /// Create a credential request in response to a credential offer
    pub async fn create_credential_request(
        &self,
        thread_id: &str,
        cred_offer: &CredentialOffer,
        cred_def_id: &str,
        entropy: &str,
    ) -> Result<CredentialRequest> {
        self.ensure_link_secret().await?;

        let cred_def = self.registry.get_credential_definition(cred_def_id).await?;
        let link_secret = self.get_link_secret()?;
        let link_secret_id = self.get_link_secret_id()?;

        let (cred_request, cred_request_metadata) = anoncreds::prover::create_credential_request(
            Some(entropy),
            None,
            &cred_def,
            &link_secret,
            &link_secret_id,
            cred_offer,
        )?;

        // Store metadata as JSON
        let metadata_json = serde_json::to_value(&cred_request_metadata)
            .map_err(|e| AnonCredsError::Storage(format!("Serialize metadata: {}", e)))?;

        {
            let mut metadata = self
                .request_metadata
                .write()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            metadata.insert(thread_id.to_string(), metadata_json.clone());
        }

        // Persist metadata if store available
        if let Some(store) = &self.store {
            let metadata_bytes = serde_json::to_vec(&metadata_json)
                .map_err(|e| AnonCredsError::Storage(format!("Serialize metadata: {}", e)))?;
            store
                .save_request_metadata(thread_id, &metadata_bytes)
                .await?;
        }

        Ok(cred_request)
    }

    /// Process a received credential (complete the blind signature)
    pub async fn process_credential(
        &self,
        thread_id: &str,
        credential: &mut Credential,
        cred_def_id: &str,
    ) -> Result<String> {
        let cred_def = self.registry.get_credential_definition(cred_def_id).await?;
        let link_secret = self.get_link_secret()?;

        // Load metadata from in-memory first, fall back to store
        let cached_metadata = {
            let metadata_map = self
                .request_metadata
                .read()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            metadata_map.get(thread_id).cloned()
        }; // Lock dropped here

        let cred_request_metadata: CredentialRequestMetadata = if let Some(metadata_json) =
            cached_metadata
        {
            serde_json::from_value(metadata_json)
                .map_err(|e| AnonCredsError::Storage(format!("Deserialize metadata: {}", e)))?
        } else if let Some(store) = &self.store {
            if let Some(bytes) = store.load_request_metadata(thread_id).await? {
                serde_json::from_slice(&bytes)
                    .map_err(|e| AnonCredsError::Storage(format!("Deserialize metadata: {}", e)))?
            } else {
                return Err(AnonCredsError::NotFound(format!(
                    "Credential request metadata not found for thread: {}",
                    thread_id
                )));
            }
        } else {
            return Err(AnonCredsError::NotFound(format!(
                "Credential request metadata not found for thread: {}",
                thread_id
            )));
        };

        // If the credential carries a rev_reg_id, resolve the matching
        // revocation registry definition so the prover can finalise the
        // witness. Falling back to None for non-revocable credentials.
        let rev_reg_def = if let Some(rev_reg_id) = credential.rev_reg_id.as_ref() {
            Some(
                self.registry
                    .get_revocation_registry_def(&rev_reg_id.0)
                    .await?,
            )
        } else {
            None
        };

        anoncreds::prover::process_credential(
            credential,
            &cred_request_metadata,
            &link_secret,
            &cred_def,
            rev_reg_def.as_ref(),
        )?;

        // Store the processed credential
        self.ensure_credentials_loaded().await?;

        let credential_id = uuid::Uuid::new_v4().to_string();
        let schema_id = credential.schema_id.0.clone();

        let mut attributes = HashMap::new();
        for (name, attr) in credential.values.0.iter() {
            attributes.insert(name.clone(), attr.raw.clone());
        }

        let credential_json = serde_json::to_value(&*credential)
            .map_err(|e| AnonCredsError::Storage(format!("Serialize credential: {}", e)))?;

        let rev_reg_id = credential.rev_reg_id.as_ref().map(|r| r.0.clone());

        let stored = StoredCredentialRecord {
            credential_id: credential_id.clone(),
            credential_json,
            schema_id,
            cred_def_id: cred_def_id.to_string(),
            attributes,
            rev_reg_id,
            // The accumulator index is not recoverable from the witness alone
            // without the registry's tails — the caller must supply it via
            // `set_cred_rev_index` once known (typically from the issuer).
            cred_rev_index: None,
        };

        // Write to cache
        {
            let mut creds = self
                .credentials
                .write()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            creds
                .as_mut()
                .unwrap()
                .insert(credential_id.clone(), stored.clone());
        }

        // Persist credential
        if let Some(store) = &self.store {
            store.save_credential(&stored).await?;
        }

        // Clean up request metadata (cache + store)
        {
            let mut metadata = self
                .request_metadata
                .write()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            metadata.remove(thread_id);
        }

        if let Some(store) = &self.store {
            let _ = store.delete_request_metadata(thread_id).await;
        }

        Ok(credential_id)
    }

    /// Deserialize a stored credential
    fn load_credential(stored: &StoredCredentialRecord) -> Result<Credential> {
        serde_json::from_value(stored.credential_json.clone())
            .map_err(|e| AnonCredsError::Storage(format!("Deserialize credential: {}", e)))
    }

    /// Record the accumulator index a stored credential occupies in its
    /// revocation registry. The issuer is the source of truth for this
    /// value and must communicate it to the holder out-of-band (typically
    /// via a free-form field on the issue-credential message). Without it
    /// the holder cannot build a non-revocation proof.
    pub async fn set_cred_rev_index(&self, credential_id: &str, cred_rev_index: u32) -> Result<()> {
        self.ensure_credentials_loaded().await?;
        let updated = {
            let mut creds = self
                .credentials
                .write()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            let stored = creds
                .as_mut()
                .unwrap()
                .get_mut(credential_id)
                .ok_or_else(|| {
                    AnonCredsError::NotFound(format!("Credential not found: {}", credential_id))
                })?;
            stored.cred_rev_index = Some(cred_rev_index);
            stored.clone()
        };
        if let Some(store) = &self.store {
            store.save_credential(&updated).await?;
        }
        Ok(())
    }

    /// Build a holder-side revocation state for a stored credential by
    /// fetching its tails file (via `tails_location` on the rev_reg_def)
    /// and the latest status list from the registry.
    ///
    /// Returns the state plus the timestamp it was computed against; the
    /// caller passes both into `create_presentation_with_revocation`.
    pub async fn build_revocation_state(
        &self,
        credential_id: &str,
        previous: Option<&CredentialRevocationState>,
    ) -> Result<CredentialRevocationContext> {
        self.ensure_credentials_loaded().await?;

        let (rev_reg_id, cred_rev_index) = {
            let creds = self
                .credentials
                .read()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            let stored = creds.as_ref().unwrap().get(credential_id).ok_or_else(|| {
                AnonCredsError::NotFound(format!("Credential not found: {}", credential_id))
            })?;
            let rev_reg_id = stored.rev_reg_id.clone().ok_or_else(|| {
                AnonCredsError::InvalidInput(format!(
                    "Credential {} has no rev_reg_id — issued without revocation",
                    credential_id
                ))
            })?;
            let cred_rev_index = stored.cred_rev_index.ok_or_else(|| {
                AnonCredsError::InvalidInput(format!(
                    "Credential {} has no cred_rev_index — call set_cred_rev_index first",
                    credential_id
                ))
            })?;
            (rev_reg_id, cred_rev_index)
        };

        let rev_reg_def = self
            .registry
            .get_revocation_registry_def(&rev_reg_id)
            .await?;
        let status_list = self
            .registry
            .get_revocation_status_list(&rev_reg_id, None)
            .await?;

        let state = revocation::create_or_update_revocation_state(
            &rev_reg_def.value.tails_location,
            &rev_reg_def,
            &status_list,
            cred_rev_index,
            previous,
            None,
        )?;

        // Pull timestamp out of the status list JSON so callers can
        // include it on each `PresentCredentials` entry.
        let timestamp = serde_json::to_value(&status_list)
            .ok()
            .and_then(|v| v.get("timestamp").and_then(|t| t.as_u64()))
            .unwrap_or(0);

        Ok(CredentialRevocationContext {
            rev_reg_id,
            state,
            timestamp,
        })
    }

    /// Create a presentation (proof) for a proof request
    pub async fn create_presentation(
        &self,
        pres_request: &PresentationRequest,
        credential_ids: &HashMap<String, (String, bool)>, // referent -> (credential_id, revealed)
        self_attested: Option<HashMap<String, String>>,
    ) -> Result<Presentation> {
        self.ensure_link_secret().await?;
        self.ensure_credentials_loaded().await?;

        let link_secret = self.get_link_secret()?;

        // Group referents by credential_id
        let mut cred_referents: HashMap<String, Vec<(String, bool)>> = HashMap::new();
        for (referent, (cred_id, revealed)) in credential_ids {
            cred_referents
                .entry(cred_id.clone())
                .or_default()
                .push((referent.clone(), *revealed));
        }

        // Load credentials and their registry IDs from the lock, then drop it
        let mut loaded_credentials: HashMap<String, Credential> = HashMap::new();
        let mut cred_registry_ids: HashMap<String, (String, String)> = HashMap::new();

        {
            let creds = self
                .credentials
                .read()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            let creds_map = creds.as_ref().unwrap();

            for cred_id in cred_referents.keys() {
                let stored = creds_map.get(cred_id).ok_or_else(|| {
                    AnonCredsError::NotFound(format!("Credential not found: {}", cred_id))
                })?;

                let credential = Self::load_credential(stored)?;
                loaded_credentials.insert(cred_id.clone(), credential);
                cred_registry_ids.insert(
                    cred_id.clone(),
                    (stored.schema_id.clone(), stored.cred_def_id.clone()),
                );
            }
        } // Lock dropped here

        // Now resolve schemas and cred_defs from registry (async calls)
        let mut schemas: HashMap<SchemaId, Schema> = HashMap::new();
        let mut cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition> = HashMap::new();

        for (schema_id_str, cred_def_id_str) in cred_registry_ids.values() {
            let schema_id = SchemaId::new_unchecked(schema_id_str);
            if let std::collections::hash_map::Entry::Vacant(e) = schemas.entry(schema_id) {
                let schema = self.registry.get_schema(schema_id_str).await?;
                e.insert(schema);
            }

            let cred_def_id = CredentialDefinitionId::new_unchecked(cred_def_id_str);
            if let std::collections::hash_map::Entry::Vacant(e) = cred_defs.entry(cred_def_id) {
                let cred_def = self
                    .registry
                    .get_credential_definition(cred_def_id_str)
                    .await?;
                e.insert(cred_def);
            }
        }

        // Build PresentCredentials
        let mut present_creds = PresentCredentials::default();

        for (cred_id, referents) in &cred_referents {
            let credential = loaded_credentials.get(cred_id).unwrap();

            let mut add_cred = present_creds.add_credential(
                credential, None, // No timestamp (no revocation)
                None, // No revocation state
            );

            for (referent, revealed) in referents {
                let payload = pres_request.value();
                if payload.requested_attributes.contains_key(referent) {
                    add_cred.add_requested_attribute(referent.clone(), *revealed);
                } else if payload.requested_predicates.contains_key(referent) {
                    add_cred.add_requested_predicate(referent.clone());
                }
            }
        }

        let presentation = anoncreds::prover::create_presentation(
            pres_request,
            present_creds,
            self_attested,
            &link_secret,
            &schemas,
            &cred_defs,
        )?;

        Ok(presentation)
    }

    /// Create a presentation that includes non-revocation proofs for selected
    /// credentials. `revocation_contexts` maps `credential_id` to the
    /// pre-computed revocation state (built via `build_revocation_state`).
    /// Credentials not present in the map are presented without an NRP, so a
    /// caller can mix revocable and non-revocable credentials in one
    /// presentation.
    pub async fn create_presentation_with_revocation(
        &self,
        pres_request: &PresentationRequest,
        credential_ids: &HashMap<String, (String, bool)>,
        self_attested: Option<HashMap<String, String>>,
        revocation_contexts: &HashMap<String, CredentialRevocationContext>,
    ) -> Result<Presentation> {
        self.ensure_link_secret().await?;
        self.ensure_credentials_loaded().await?;

        let link_secret = self.get_link_secret()?;

        let mut cred_referents: HashMap<String, Vec<(String, bool)>> = HashMap::new();
        for (referent, (cred_id, revealed)) in credential_ids {
            cred_referents
                .entry(cred_id.clone())
                .or_default()
                .push((referent.clone(), *revealed));
        }

        let mut loaded_credentials: HashMap<String, Credential> = HashMap::new();
        let mut cred_registry_ids: HashMap<String, (String, String)> = HashMap::new();
        {
            let creds = self
                .credentials
                .read()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            let creds_map = creds.as_ref().unwrap();
            for cred_id in cred_referents.keys() {
                let stored = creds_map.get(cred_id).ok_or_else(|| {
                    AnonCredsError::NotFound(format!("Credential not found: {}", cred_id))
                })?;
                let credential = Self::load_credential(stored)?;
                loaded_credentials.insert(cred_id.clone(), credential);
                cred_registry_ids.insert(
                    cred_id.clone(),
                    (stored.schema_id.clone(), stored.cred_def_id.clone()),
                );
            }
        }

        let mut schemas: HashMap<SchemaId, Schema> = HashMap::new();
        let mut cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition> = HashMap::new();
        for (schema_id_str, cred_def_id_str) in cred_registry_ids.values() {
            let schema_id = SchemaId::new_unchecked(schema_id_str);
            if let std::collections::hash_map::Entry::Vacant(e) = schemas.entry(schema_id) {
                let schema = self.registry.get_schema(schema_id_str).await?;
                e.insert(schema);
            }
            let cred_def_id = CredentialDefinitionId::new_unchecked(cred_def_id_str);
            if let std::collections::hash_map::Entry::Vacant(e) = cred_defs.entry(cred_def_id) {
                let cred_def = self
                    .registry
                    .get_credential_definition(cred_def_id_str)
                    .await?;
                e.insert(cred_def);
            }
        }

        let mut present_creds = PresentCredentials::default();
        for (cred_id, referents) in &cred_referents {
            let credential = loaded_credentials.get(cred_id).unwrap();
            let rev_ctx = revocation_contexts.get(cred_id);

            let timestamp = rev_ctx.map(|c| c.timestamp);
            let rev_state = rev_ctx.map(|c| &c.state);

            let mut add_cred = present_creds.add_credential(credential, timestamp, rev_state);
            for (referent, revealed) in referents {
                let payload = pres_request.value();
                if payload.requested_attributes.contains_key(referent) {
                    add_cred.add_requested_attribute(referent.clone(), *revealed);
                } else if payload.requested_predicates.contains_key(referent) {
                    add_cred.add_requested_predicate(referent.clone());
                }
            }
        }

        let presentation = anoncreds::prover::create_presentation(
            pres_request,
            present_creds,
            self_attested,
            &link_secret,
            &schemas,
            &cred_defs,
        )?;

        Ok(presentation)
    }

    /// Get stored credential attributes by ID
    pub async fn get_credential_attributes(
        &self,
        credential_id: &str,
    ) -> Result<HashMap<String, String>> {
        self.ensure_credentials_loaded().await?;

        let creds = self
            .credentials
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        let stored = creds.as_ref().unwrap().get(credential_id).ok_or_else(|| {
            AnonCredsError::NotFound(format!("Credential not found: {}", credential_id))
        })?;
        Ok(stored.attributes.clone())
    }

    /// List all stored credential IDs with their schema/cred_def info
    pub async fn list_credentials(&self) -> Result<Vec<(String, String, String)>> {
        self.ensure_credentials_loaded().await?;

        let creds = self
            .credentials
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        Ok(creds
            .as_ref()
            .unwrap()
            .values()
            .map(|s| {
                (
                    s.credential_id.clone(),
                    s.schema_id.clone(),
                    s.cred_def_id.clone(),
                )
            })
            .collect())
    }

    /// Find credentials matching requested attributes
    pub async fn find_credentials_for_request(
        &self,
        pres_request: &PresentationRequest,
    ) -> Result<HashMap<String, Vec<String>>> {
        self.ensure_credentials_loaded().await?;

        let creds = self
            .credentials
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        let creds_map = creds.as_ref().unwrap();

        let payload = pres_request.value();
        let mut result: HashMap<String, Vec<String>> = HashMap::new();

        for (referent, attr_info) in &payload.requested_attributes {
            let mut matching_cred_ids = Vec::new();

            for (cred_id, stored) in creds_map.iter() {
                let matches = if let Some(name) = &attr_info.name {
                    stored.attributes.contains_key(name)
                } else if let Some(names) = &attr_info.names {
                    names.iter().all(|n| stored.attributes.contains_key(n))
                } else {
                    false
                };

                if matches {
                    matching_cred_ids.push(cred_id.clone());
                }
            }

            result.insert(referent.clone(), matching_cred_ids);
        }

        for (referent, pred_info) in &payload.requested_predicates {
            let mut matching_cred_ids = Vec::new();

            for (cred_id, stored) in creds_map.iter() {
                if stored.attributes.contains_key(&pred_info.name) {
                    matching_cred_ids.push(cred_id.clone());
                }
            }

            result.insert(referent.clone(), matching_cred_ids);
        }

        Ok(result)
    }
}
