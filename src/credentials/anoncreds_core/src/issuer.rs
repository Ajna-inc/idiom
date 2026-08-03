/// AnonCreds Issuer Service
///
/// Wraps anoncreds::issuer functions with registry integration for
/// schema and credential definition management.
///
/// Supports optional persistence via `AnonCredsStore` — when provided,
/// private keys and correctness proofs survive restarts.
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{AnonCredsError, Result};
use crate::registry::AnonCredsRegistry;
use crate::revocation::{
    self, CredentialRevocationConfig, RevocationRegistryDefinition, RevocationRegistryDefinitionId,
    RevocationRegistryDefinitionPrivate, RevocationStatusList,
};
use crate::store::AnonCredsStore;
use crate::types::*;

/// Issuer service for creating schemas, credential definitions, and issuing credentials.
pub struct AnonCredsIssuerService {
    registry: Arc<dyn AnonCredsRegistry>,
    /// Optional persistent store
    store: Option<Arc<dyn AnonCredsStore>>,
    /// Credential definition private keys — None = not loaded from store yet
    cred_def_privates: RwLock<Option<HashMap<String, CredentialDefinitionPrivate>>>,
    /// Key correctness proofs — None = not loaded from store yet
    key_correctness_proofs: RwLock<Option<HashMap<String, CredentialKeyCorrectnessProof>>>,
}

impl AnonCredsIssuerService {
    /// Create a new issuer service (pure in-memory)
    pub fn new(registry: Arc<dyn AnonCredsRegistry>) -> Self {
        Self {
            registry,
            store: None,
            cred_def_privates: RwLock::new(Some(HashMap::new())),
            key_correctness_proofs: RwLock::new(Some(HashMap::new())),
        }
    }

    /// Create a new issuer service with persistent store
    pub fn new_with_store(
        registry: Arc<dyn AnonCredsRegistry>,
        store: Arc<dyn AnonCredsStore>,
    ) -> Self {
        Self {
            registry,
            store: Some(store),
            cred_def_privates: RwLock::new(None), // lazy-load from store
            key_correctness_proofs: RwLock::new(None),
        }
    }

    /// Ensure private keys are loaded from store
    async fn ensure_privates_loaded(&self) -> Result<()> {
        {
            let privates = self
                .cred_def_privates
                .read()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            if privates.is_some() {
                return Ok(());
            }
        }

        let loaded = if let Some(store) = &self.store {
            let entries = store.load_all_cred_def_privates().await?;
            let mut map = HashMap::new();
            for (id, bytes) in entries {
                match serde_json::from_slice::<CredentialDefinitionPrivate>(&bytes) {
                    Ok(private) => {
                        map.insert(id, private);
                    }
                    Err(e) => tracing::warn!("Skip corrupt cred def private {}: {}", id, e),
                }
            }
            if !map.is_empty() {
                tracing::info!("Loaded {} cred def private keys from storage", map.len());
            }
            map
        } else {
            HashMap::new()
        };

        {
            let mut privates = self
                .cred_def_privates
                .write()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            if privates.is_none() {
                *privates = Some(loaded);
            }
        }

        Ok(())
    }

    /// Ensure correctness proofs are loaded from store
    async fn ensure_proofs_loaded(&self) -> Result<()> {
        {
            let proofs = self
                .key_correctness_proofs
                .read()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            if proofs.is_some() {
                return Ok(());
            }
        }

        let loaded = if let Some(store) = &self.store {
            let entries = store.load_all_key_correctness_proofs().await?;
            let mut map = HashMap::new();
            for (id, bytes) in entries {
                match serde_json::from_slice::<CredentialKeyCorrectnessProof>(&bytes) {
                    Ok(proof) => {
                        map.insert(id, proof);
                    }
                    Err(e) => tracing::warn!("Skip corrupt key correctness proof {}: {}", id, e),
                }
            }
            if !map.is_empty() {
                tracing::info!("Loaded {} key correctness proofs from storage", map.len());
            }
            map
        } else {
            HashMap::new()
        };

        {
            let mut proofs = self
                .key_correctness_proofs
                .write()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            if proofs.is_none() {
                *proofs = Some(loaded);
            }
        }

        Ok(())
    }

    /// Create and register a new schema
    pub async fn create_schema(
        &self,
        issuer_id: &str,
        name: &str,
        version: &str,
        attributes: Vec<String>,
    ) -> Result<SchemaRegistration> {
        let schema = anoncreds::issuer::create_schema(
            name,
            version,
            IssuerId::new_unchecked(issuer_id),
            AttributeNames::from(attributes),
        )?;

        let registration = self.registry.register_schema(issuer_id, &schema).await?;

        Ok(registration)
    }

    /// Create and register a new credential definition
    pub async fn create_credential_definition(
        &self,
        issuer_id: &str,
        schema_id: &str,
        tag: &str,
        support_revocation: bool,
    ) -> Result<CredDefRegistration> {
        self.create_credential_definition_with_policy(
            issuer_id,
            schema_id,
            tag,
            support_revocation,
            None,
        )
        .await
    }

    /// Like [`Self::create_credential_definition`], but forwards an explicit
    /// registry-specific `policy_mask` (e.g. Kanon revocation tiers) to the
    /// registry. `None` lets the registry pick its default.
    pub async fn create_credential_definition_with_policy(
        &self,
        issuer_id: &str,
        schema_id: &str,
        tag: &str,
        support_revocation: bool,
        policy_mask: Option<u8>,
    ) -> Result<CredDefRegistration> {
        self.ensure_privates_loaded().await?;
        self.ensure_proofs_loaded().await?;

        let schema = self.registry.get_schema(schema_id).await?;

        // CL credential-definition key generation is CPU-heavy (seconds). Run it
        // on the blocking pool so it never starves the async runtime (e.g. an
        // HTTP server sharing this runtime stays responsive).
        let schema_id_owned = schema_id.to_string();
        let issuer_id_owned = issuer_id.to_string();
        let tag_owned = tag.to_string();
        let (cred_def, cred_def_private, key_correctness_proof) =
            tokio::task::spawn_blocking(move || {
                anoncreds::issuer::create_credential_definition(
                    SchemaId::new_unchecked(schema_id_owned),
                    &schema,
                    IssuerId::new_unchecked(issuer_id_owned),
                    &tag_owned,
                    SignatureType::CL,
                    CredentialDefinitionConfig::new(support_revocation),
                )
            })
            .await
            .map_err(|e| AnonCredsError::Storage(format!("cred-def keygen task join: {e}")))??;

        let registration = self
            .registry
            .register_credential_definition_with_policy(issuer_id, &cred_def, policy_mask)
            .await?;

        // Persist private key and correctness proof
        if let Some(store) = &self.store {
            let private_bytes = serde_json::to_vec(&cred_def_private).map_err(|e| {
                AnonCredsError::Storage(format!("Serialize cred def private: {}", e))
            })?;
            store
                .save_cred_def_private(&registration.cred_def_id, &private_bytes)
                .await?;

            let proof_bytes = serde_json::to_vec(&key_correctness_proof).map_err(|e| {
                AnonCredsError::Storage(format!("Serialize key correctness proof: {}", e))
            })?;
            store
                .save_key_correctness_proof(&registration.cred_def_id, &proof_bytes)
                .await?;
        }

        // Store in cache
        {
            let mut privates = self
                .cred_def_privates
                .write()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            privates
                .as_mut()
                .unwrap()
                .insert(registration.cred_def_id.clone(), cred_def_private);
        }
        {
            let mut proofs = self
                .key_correctness_proofs
                .write()
                .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
            proofs
                .as_mut()
                .unwrap()
                .insert(registration.cred_def_id.clone(), key_correctness_proof);
        }

        Ok(registration)
    }

    /// Create a credential offer for a holder
    pub async fn create_credential_offer(
        &self,
        schema_id: &str,
        cred_def_id: &str,
    ) -> Result<CredentialOffer> {
        self.ensure_proofs_loaded().await?;

        // A cred-def references its schema, so schema_id is derivable from it.
        // Callers that only have the cred-def id (e.g. workflow templates that
        // patch in just cred_def_id) may pass "" — resolve it here.
        let schema_id: String = if schema_id.is_empty() {
            let cred_def = self.registry.get_credential_definition(cred_def_id).await?;
            cred_def.schema_id.to_string()
        } else {
            schema_id.to_string()
        };

        let proofs = self
            .key_correctness_proofs
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;

        let key_correctness_proof = proofs.as_ref().unwrap().get(cred_def_id).ok_or_else(|| {
            AnonCredsError::NotFound(format!(
                "Key correctness proof not found for cred_def: {}",
                cred_def_id
            ))
        })?;

        let offer = anoncreds::issuer::create_credential_offer(
            SchemaId::new_unchecked(schema_id),
            CredentialDefinitionId::new_unchecked(cred_def_id),
            key_correctness_proof,
        )?;

        Ok(offer)
    }

    /// Create a revocation registry definition for an existing credential
    /// definition and register it on the registry.
    ///
    /// Returns the registered `rev_reg_def_id`, the public definition (also
    /// stored on the registry), the issuer-only private half (caller must
    /// persist this to revoke later), and an initial status list snapshot.
    /// The tails file is written under `tails_dir` (or a tempdir when None).
    ///
    /// The CredentialDefinition referenced by `cred_def_id` must have been
    /// created with `support_revocation = true`.
    pub async fn create_revocation_registry(
        &self,
        cred_def_id: &str,
        tag: &str,
        max_cred_num: u32,
        tails_dir: Option<&str>,
    ) -> Result<(
        String,
        RevocationRegistryDefinition,
        RevocationRegistryDefinitionPrivate,
        RevocationStatusList,
    )> {
        let cred_def = self.registry.get_credential_definition(cred_def_id).await?;
        let issuer_id = cred_def.issuer_id.0.clone();

        let (rev_reg_def, rev_reg_def_priv) = revocation::create_revocation_registry_def(
            &cred_def,
            anoncreds::data_types::cred_def::CredentialDefinitionId::new_unchecked(cred_def_id),
            tag,
            max_cred_num,
            tails_dir,
        )?;

        let rev_reg_def_id = self
            .registry
            .register_revocation_registry_def(&issuer_id, &rev_reg_def)
            .await?;

        // Status lists must carry a timestamp — otherwise holders can't
        // compute their revocation state (anoncreds-rs requires it).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // `issuance_by_default = true` matches what anoncreds-rs's own demos
        // do: every slot is non-revoked from the start, so the accumulator
        // value is consistent and the issuer just flips bits when revoking.
        let initial_status = revocation::create_initial_status_list(
            &cred_def,
            RevocationRegistryDefinitionId::new_unchecked(&rev_reg_def_id),
            &rev_reg_def,
            &rev_reg_def_priv,
            true,
            Some(now),
        )?;

        self.registry
            .register_revocation_status_list(&rev_reg_def_id, &initial_status)
            .await?;

        Ok((
            rev_reg_def_id,
            rev_reg_def,
            rev_reg_def_priv,
            initial_status,
        ))
    }

    /// Revoke (or un-revoke) credentials by index and publish a new status
    /// list snapshot to the registry. `revoked` and `issued` accept index
    /// sets; an empty diff still bumps the timestamp.
    pub async fn update_status_list(
        &self,
        rev_reg_def_id: &str,
        rev_reg_def: &RevocationRegistryDefinition,
        rev_reg_priv: &RevocationRegistryDefinitionPrivate,
        cred_def_id: &str,
        timestamp: Option<u64>,
        issued: Option<std::collections::BTreeSet<u32>>,
        revoked: Option<std::collections::BTreeSet<u32>>,
    ) -> Result<RevocationStatusList> {
        let cred_def = self.registry.get_credential_definition(cred_def_id).await?;
        let prev = self
            .registry
            .get_revocation_status_list(rev_reg_def_id, None)
            .await?;
        let ts = timestamp.or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .ok()
        });
        let next = revocation::update_status_list(
            &cred_def,
            rev_reg_def,
            rev_reg_priv,
            &prev,
            ts,
            issued,
            revoked,
        )?;
        self.registry
            .register_revocation_status_list(rev_reg_def_id, &next)
            .await?;
        Ok(next)
    }

    /// Issue a credential with revocation support — caller provides the
    /// `rev_reg_def_id`, the matching def + priv, and the index this
    /// credential will occupy in the accumulator. The fresh status list is
    /// stored on the registry so verifiers can resolve it later.
    pub async fn create_credential_with_revocation(
        &self,
        cred_def_id: &str,
        cred_offer: &CredentialOffer,
        cred_request: &CredentialRequest,
        attributes: HashMap<String, String>,
        rev_reg_def_id: &str,
        rev_reg_def: &RevocationRegistryDefinition,
        rev_reg_priv: &RevocationRegistryDefinitionPrivate,
        cred_rev_index: u32,
    ) -> Result<(Credential, RevocationStatusList)> {
        self.ensure_privates_loaded().await?;
        let cred_def = self.registry.get_credential_definition(cred_def_id).await?;

        // Fetch the accumulator snapshot before taking the private-keys lock so
        // the (non-async-aware) guard is never held across an await point. With
        // `issuance_by_default = true` this is the same snapshot that lets any
        // holder/verifier successfully prove non-revocation.
        let current_status_list = self
            .registry
            .get_revocation_status_list(rev_reg_def_id, None)
            .await?;

        let mut cred_values = MakeCredentialValues::default();
        for (name, value) in &attributes {
            cred_values
                .add_raw(name, value)
                .map_err(|e| AnonCredsError::Credential(format!("attr {}: {}", name, e)))?;
        }

        let revocation_config = CredentialRevocationConfig {
            reg_def: rev_reg_def,
            reg_def_private: rev_reg_priv,
            registry_idx: cred_rev_index,
            status_list: &current_status_list,
        };

        // Held only across synchronous work — no await below this point.
        let privates = self
            .cred_def_privates
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        let cred_def_private = privates.as_ref().unwrap().get(cred_def_id).ok_or_else(|| {
            AnonCredsError::NotFound(format!(
                "Credential definition private key not found: {}",
                cred_def_id
            ))
        })?;

        let credential = anoncreds::issuer::create_credential(
            &cred_def,
            cred_def_private,
            cred_offer,
            cred_request,
            cred_values.into(),
            Some(revocation_config),
        )?;

        Ok((credential, current_status_list))
    }

    /// Issue a credential to a holder
    pub async fn create_credential(
        &self,
        cred_def_id: &str,
        cred_offer: &CredentialOffer,
        cred_request: &CredentialRequest,
        attributes: HashMap<String, String>,
    ) -> Result<Credential> {
        self.ensure_privates_loaded().await?;

        let cred_def = self.registry.get_credential_definition(cred_def_id).await?;

        let privates = self
            .cred_def_privates
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;

        let cred_def_private = privates.as_ref().unwrap().get(cred_def_id).ok_or_else(|| {
            AnonCredsError::NotFound(format!(
                "Credential definition private key not found: {}",
                cred_def_id
            ))
        })?;

        // Build credential values
        let mut cred_values = MakeCredentialValues::default();
        for (name, value) in &attributes {
            cred_values.add_raw(name, value).map_err(|e| {
                AnonCredsError::Credential(format!("Failed to add attribute {}: {}", name, e))
            })?;
        }

        let credential = anoncreds::issuer::create_credential(
            &cred_def,
            cred_def_private,
            cred_offer,
            cred_request,
            cred_values.into(),
            None, // No revocation
        )?;

        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_memory::InMemoryRegistry;

    #[tokio::test]
    async fn test_create_schema() {
        let registry = Arc::new(InMemoryRegistry::new());
        let issuer = AnonCredsIssuerService::new(registry);

        let reg = issuer
            .create_schema(
                "did:example:issuer",
                "TestSchema",
                "1.0",
                vec!["name".to_string(), "age".to_string()],
            )
            .await
            .unwrap();

        assert!(reg.schema_id.contains("TestSchema"));
        assert_eq!(reg.schema.name, "TestSchema");
    }

    #[tokio::test]
    async fn test_create_credential_definition() {
        let registry = Arc::new(InMemoryRegistry::new());
        let issuer = AnonCredsIssuerService::new(registry);

        let schema_reg = issuer
            .create_schema(
                "did:example:issuer",
                "TestSchema",
                "1.0",
                vec!["name".to_string(), "age".to_string()],
            )
            .await
            .unwrap();

        let cred_def_reg = issuer
            .create_credential_definition(
                "did:example:issuer",
                &schema_reg.schema_id,
                "default",
                false,
            )
            .await
            .unwrap();

        assert!(cred_def_reg.cred_def_id.contains("did:example:issuer"));
    }
}
