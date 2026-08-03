use async_trait::async_trait;
/// In-memory AnonCreds registry for testing and development
use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::AnonCredsError;
use crate::registry::AnonCredsRegistry;
use crate::revocation::{RevocationRegistryDefinition, RevocationStatusList};
use crate::types::*;

/// In-memory registry that stores schemas and credential definitions as JSON.
/// Suitable for testing and single-process deployments.
pub struct InMemoryRegistry {
    schemas: RwLock<HashMap<String, serde_json::Value>>,
    cred_defs: RwLock<HashMap<String, serde_json::Value>>,
    /// `rev_reg_def_id -> serialized RevocationRegistryDefinition`
    rev_reg_defs: RwLock<HashMap<String, serde_json::Value>>,
    /// `rev_reg_def_id -> chronological list of status lists`
    rev_status_lists: RwLock<HashMap<String, Vec<serde_json::Value>>>,
}

impl InMemoryRegistry {
    pub fn new() -> Self {
        Self {
            schemas: RwLock::new(HashMap::new()),
            cred_defs: RwLock::new(HashMap::new()),
            rev_reg_defs: RwLock::new(HashMap::new()),
            rev_status_lists: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AnonCredsRegistry for InMemoryRegistry {
    fn method_name(&self) -> &str {
        "inMemory"
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

        let json = serde_json::to_value(schema)
            .map_err(|e| AnonCredsError::Storage(format!("Serialize schema: {}", e)))?;

        let mut schemas = self
            .schemas
            .write()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        schemas.insert(schema_id.clone(), json);

        Ok(SchemaRegistration {
            schema_id,
            schema: schema.clone(),
        })
    }

    async fn get_schema(&self, schema_id: &str) -> Result<Schema, AnonCredsError> {
        let schemas = self
            .schemas
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;

        let json = schemas
            .get(schema_id)
            .ok_or_else(|| AnonCredsError::NotFound(format!("Schema not found: {}", schema_id)))?;

        serde_json::from_value(json.clone())
            .map_err(|e| AnonCredsError::Storage(format!("Deserialize schema: {}", e)))
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

        let json = serde_json::to_value(cred_def)
            .map_err(|e| AnonCredsError::Storage(format!("Serialize cred_def: {}", e)))?;

        let mut cred_defs = self
            .cred_defs
            .write()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        cred_defs.insert(cred_def_id.clone(), json);

        // Re-deserialize for the return value
        let cred_def_copy: CredentialDefinition = serde_json::from_value(
            serde_json::to_value(cred_def)
                .map_err(|e| AnonCredsError::Storage(format!("Serialize cred_def: {}", e)))?,
        )
        .map_err(|e| AnonCredsError::Storage(format!("Deserialize cred_def: {}", e)))?;

        Ok(CredDefRegistration {
            cred_def_id,
            credential_definition: cred_def_copy,
        })
    }

    async fn get_credential_definition(
        &self,
        cred_def_id: &str,
    ) -> Result<CredentialDefinition, AnonCredsError> {
        let cred_defs = self
            .cred_defs
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;

        let json = cred_defs.get(cred_def_id).ok_or_else(|| {
            AnonCredsError::NotFound(format!("Credential definition not found: {}", cred_def_id))
        })?;

        serde_json::from_value(json.clone())
            .map_err(|e| AnonCredsError::Storage(format!("Deserialize cred_def: {}", e)))
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
        let json = serde_json::to_value(rev_reg_def)
            .map_err(|e| AnonCredsError::Storage(format!("Serialize rev_reg_def: {}", e)))?;
        let mut map = self
            .rev_reg_defs
            .write()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        map.insert(rev_reg_def_id.clone(), json);
        Ok(rev_reg_def_id)
    }

    async fn get_revocation_registry_def(
        &self,
        rev_reg_def_id: &str,
    ) -> Result<RevocationRegistryDefinition, AnonCredsError> {
        let map = self
            .rev_reg_defs
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        let json = map.get(rev_reg_def_id).ok_or_else(|| {
            AnonCredsError::NotFound(format!(
                "Revocation registry definition not found: {}",
                rev_reg_def_id
            ))
        })?;
        serde_json::from_value(json.clone())
            .map_err(|e| AnonCredsError::Storage(format!("Deserialize rev_reg_def: {}", e)))
    }

    async fn register_revocation_status_list(
        &self,
        rev_reg_def_id: &str,
        status_list: &RevocationStatusList,
    ) -> Result<(), AnonCredsError> {
        let json = serde_json::to_value(status_list)
            .map_err(|e| AnonCredsError::Storage(format!("Serialize status_list: {}", e)))?;
        let mut map = self
            .rev_status_lists
            .write()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        map.entry(rev_reg_def_id.to_string())
            .or_default()
            .push(json);
        Ok(())
    }

    async fn get_revocation_status_list(
        &self,
        rev_reg_def_id: &str,
        timestamp: Option<u64>,
    ) -> Result<RevocationStatusList, AnonCredsError> {
        let map = self
            .rev_status_lists
            .read()
            .map_err(|e| AnonCredsError::Storage(format!("Lock poisoned: {}", e)))?;
        let history = map.get(rev_reg_def_id).ok_or_else(|| {
            AnonCredsError::NotFound(format!(
                "No revocation status lists registered for {}",
                rev_reg_def_id
            ))
        })?;

        // Pick the latest snapshot whose `timestamp` is <= the requested one,
        // or the most-recent one when no timestamp constraint is given.
        let pick = if let Some(ts_target) = timestamp {
            history
                .iter()
                .rev()
                .find(|entry| {
                    entry
                        .get("timestamp")
                        .and_then(|v| v.as_u64())
                        .is_none_or(|t| t <= ts_target)
                })
                .cloned()
        } else {
            history.last().cloned()
        };

        let json = pick.ok_or_else(|| {
            AnonCredsError::NotFound(format!(
                "No revocation status list matching timestamp constraint for {}",
                rev_reg_def_id
            ))
        })?;
        serde_json::from_value(json)
            .map_err(|e| AnonCredsError::Storage(format!("Deserialize status_list: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_schema_round_trip() {
        let registry = InMemoryRegistry::new();

        let schema = anoncreds::issuer::create_schema(
            "TestSchema",
            "1.0",
            IssuerId::new_unchecked("did:example:issuer"),
            AttributeNames::from(vec!["name".to_owned(), "age".to_owned()]),
        )
        .unwrap();

        let reg = registry
            .register_schema("did:example:issuer", &schema)
            .await
            .unwrap();
        let retrieved = registry.get_schema(&reg.schema_id).await.unwrap();

        assert_eq!(retrieved.name, "TestSchema");
        assert_eq!(retrieved.version, "1.0");
    }

    #[tokio::test]
    async fn test_schema_not_found() {
        let registry = InMemoryRegistry::new();
        let result = registry.get_schema("nonexistent").await;
        assert!(result.is_err());
    }
}
