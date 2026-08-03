use crate::error::AnonCredsError;
use crate::revocation::{RevocationRegistryDefinition, RevocationStatusList};
use crate::types::*;
/// AnonCreds registry trait for storing and resolving schemas and credential definitions
use async_trait::async_trait;

/// Abstract registry for AnonCreds objects (schemas, credential definitions).
///
/// Implementations can store on-chain (Ajna blockchain), in-memory, or on any
/// other verifiable data registry. No Indy/Sovrin dependency.
#[async_trait]
pub trait AnonCredsRegistry: Send + Sync {
    /// Registry method name (e.g., "ajna", "web", "inMemory")
    fn method_name(&self) -> &str;

    /// Check if this registry can handle the given identifier
    fn supports_identifier(&self, id: &str) -> bool;

    // --- Schema operations ---

    /// Register a new schema
    async fn register_schema(
        &self,
        issuer_id: &str,
        schema: &Schema,
    ) -> Result<SchemaRegistration, AnonCredsError>;

    /// Retrieve a schema by ID
    async fn get_schema(&self, schema_id: &str) -> Result<Schema, AnonCredsError>;

    // --- Credential definition operations ---

    /// Register a new credential definition
    async fn register_credential_definition(
        &self,
        issuer_id: &str,
        cred_def: &CredentialDefinition,
    ) -> Result<CredDefRegistration, AnonCredsError>;

    /// Register a cred-def with an explicit, registry-specific policy mask
    /// (e.g. Kanon revocation tiers). Registries that don't model policy masks
    /// ignore it and delegate to [`register_credential_definition`].
    async fn register_credential_definition_with_policy(
        &self,
        issuer_id: &str,
        cred_def: &CredentialDefinition,
        _policy_mask: Option<u8>,
    ) -> Result<CredDefRegistration, AnonCredsError> {
        self.register_credential_definition(issuer_id, cred_def)
            .await
    }

    /// Retrieve a credential definition by ID
    async fn get_credential_definition(
        &self,
        cred_def_id: &str,
    ) -> Result<CredentialDefinition, AnonCredsError>;

    // --- Revocation operations ---
    //
    // Default implementations return `Unsupported` so existing registries
    // (e.g. the Ajna-blockchain one) don't have to opt in until they do.

    /// Publish a revocation registry definition, returning the identifier
    /// (typically `<issuer>:4:<cred_def_id>:CL_ACCUM:<tag>`) under which
    /// the definition is stored.
    async fn register_revocation_registry_def(
        &self,
        _issuer_id: &str,
        _rev_reg_def: &RevocationRegistryDefinition,
    ) -> Result<String, AnonCredsError> {
        Err(AnonCredsError::Unsupported(
            "register_revocation_registry_def not implemented by this registry".into(),
        ))
    }

    /// Fetch a revocation registry definition by id.
    async fn get_revocation_registry_def(
        &self,
        _rev_reg_def_id: &str,
    ) -> Result<RevocationRegistryDefinition, AnonCredsError> {
        Err(AnonCredsError::Unsupported(
            "get_revocation_registry_def not implemented by this registry".into(),
        ))
    }

    /// Publish a revocation status list (typically the latest snapshot).
    async fn register_revocation_status_list(
        &self,
        _rev_reg_def_id: &str,
        _status_list: &RevocationStatusList,
    ) -> Result<(), AnonCredsError> {
        Err(AnonCredsError::Unsupported(
            "register_revocation_status_list not implemented by this registry".into(),
        ))
    }

    /// Fetch the revocation status list at-or-before `timestamp`. When
    /// `timestamp` is `None` the implementation should return the latest
    /// snapshot.
    async fn get_revocation_status_list(
        &self,
        _rev_reg_def_id: &str,
        _timestamp: Option<u64>,
    ) -> Result<RevocationStatusList, AnonCredsError> {
        Err(AnonCredsError::Unsupported(
            "get_revocation_status_list not implemented by this registry".into(),
        ))
    }
}
