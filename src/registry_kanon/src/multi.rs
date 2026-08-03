//! `MultiRegistry` — run many AnonCreds registries at once (did:kanon +
//! did:web + did:ajna + in-memory …), dispatched by `supports_identifier`.
//!
//! It *is* an `AnonCredsRegistry`, so it injects into `AnonCredsModule`
//! exactly like a single registry. Reads route by the object id; writes route
//! by `issuer_id` (falling back to the first registry that claims it, then to
//! an optional default).
//!
//! ```ignore
//! let registry = MultiRegistry::new()
//!     .with(Arc::new(kanon_registry))     // did:kanon:* -> Besu
//!     .with(Arc::new(web_registry))       // did:web:*   -> HTTPS
//!     .with_default(Arc::new(InMemoryRegistry::new()));
//! let anoncreds = AnonCredsModule::with_registry_and_storage(cfg, Arc::new(registry), storage);
//! ```

use std::sync::Arc;

use anoncreds_core::registry::AnonCredsRegistry;
use anoncreds_core::revocation::{RevocationRegistryDefinition, RevocationStatusList};
use anoncreds_core::types::{
    CredDefRegistration, CredentialDefinition, Schema, SchemaRegistration,
};
use anoncreds_core::AnonCredsError;
use async_trait::async_trait;

#[derive(Default)]
pub struct MultiRegistry {
    registries: Vec<Arc<dyn AnonCredsRegistry>>,
    default: Option<Arc<dyn AnonCredsRegistry>>,
}

impl MultiRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, registry: Arc<dyn AnonCredsRegistry>) -> Self {
        self.registries.push(registry);
        self
    }

    /// Fallback for identifiers no registry claims (e.g. writes to a local
    /// store when the issuer DID method isn't Kanon/web).
    pub fn with_default(mut self, registry: Arc<dyn AnonCredsRegistry>) -> Self {
        self.default = Some(registry);
        self
    }

    fn route(&self, id: &str) -> std::result::Result<&Arc<dyn AnonCredsRegistry>, AnonCredsError> {
        self.registries
            .iter()
            .find(|r| r.supports_identifier(id))
            .or(self.default.as_ref())
            .ok_or_else(|| {
                AnonCredsError::Registry(format!("no registry handles identifier: {id}"))
            })
    }
}

#[async_trait]
impl AnonCredsRegistry for MultiRegistry {
    fn method_name(&self) -> &str {
        "multi"
    }

    fn supports_identifier(&self, id: &str) -> bool {
        self.registries.iter().any(|r| r.supports_identifier(id)) || self.default.is_some()
    }

    async fn register_schema(
        &self,
        issuer_id: &str,
        schema: &Schema,
    ) -> std::result::Result<SchemaRegistration, AnonCredsError> {
        self.route(issuer_id)?
            .register_schema(issuer_id, schema)
            .await
    }

    async fn get_schema(&self, schema_id: &str) -> std::result::Result<Schema, AnonCredsError> {
        self.route(schema_id)?.get_schema(schema_id).await
    }

    async fn register_credential_definition(
        &self,
        issuer_id: &str,
        cred_def: &CredentialDefinition,
    ) -> std::result::Result<CredDefRegistration, AnonCredsError> {
        self.route(issuer_id)?
            .register_credential_definition(issuer_id, cred_def)
            .await
    }

    async fn get_credential_definition(
        &self,
        cred_def_id: &str,
    ) -> std::result::Result<CredentialDefinition, AnonCredsError> {
        self.route(cred_def_id)?
            .get_credential_definition(cred_def_id)
            .await
    }

    async fn register_revocation_registry_def(
        &self,
        issuer_id: &str,
        rev_reg_def: &RevocationRegistryDefinition,
    ) -> std::result::Result<String, AnonCredsError> {
        self.route(issuer_id)?
            .register_revocation_registry_def(issuer_id, rev_reg_def)
            .await
    }

    async fn get_revocation_registry_def(
        &self,
        rev_reg_def_id: &str,
    ) -> std::result::Result<RevocationRegistryDefinition, AnonCredsError> {
        self.route(rev_reg_def_id)?
            .get_revocation_registry_def(rev_reg_def_id)
            .await
    }

    async fn register_revocation_status_list(
        &self,
        rev_reg_def_id: &str,
        status_list: &RevocationStatusList,
    ) -> std::result::Result<(), AnonCredsError> {
        self.route(rev_reg_def_id)?
            .register_revocation_status_list(rev_reg_def_id, status_list)
            .await
    }

    async fn get_revocation_status_list(
        &self,
        rev_reg_def_id: &str,
        timestamp: Option<u64>,
    ) -> std::result::Result<RevocationStatusList, AnonCredsError> {
        self.route(rev_reg_def_id)?
            .get_revocation_status_list(rev_reg_def_id, timestamp)
            .await
    }
}
