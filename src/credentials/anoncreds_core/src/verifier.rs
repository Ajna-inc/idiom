/// AnonCreds Verifier Service
///
/// Wraps anoncreds::verifier functions for proof request creation
/// and presentation verification.
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{AnonCredsError, Result};
use crate::registry::AnonCredsRegistry;
use crate::revocation::{
    RevocationRegistryDefinition, RevocationRegistryDefinitionId, RevocationStatusList,
};
use crate::types::*;

/// Verifier service for creating proof requests and verifying presentations.
pub struct AnonCredsVerifierService {
    registry: Arc<dyn AnonCredsRegistry>,
}

impl AnonCredsVerifierService {
    pub fn new(registry: Arc<dyn AnonCredsRegistry>) -> Self {
        Self { registry }
    }

    /// Generate a nonce for a proof request
    pub fn generate_nonce() -> Result<Nonce> {
        anoncreds::verifier::generate_nonce()
            .map_err(|e| AnonCredsError::Presentation(format!("Failed to generate nonce: {}", e)))
    }

    /// Create a presentation request (proof request)
    pub fn create_presentation_request(
        name: &str,
        version: &str,
        requested_attributes: HashMap<String, AttributeInfo>,
        requested_predicates: HashMap<String, PredicateInfo>,
    ) -> Result<PresentationRequest> {
        let nonce = Self::generate_nonce()?;

        Ok(PresentationRequest::PresentationRequestV2(
            PresentationRequestPayload {
                nonce,
                name: name.to_string(),
                version: version.to_string(),
                requested_attributes,
                requested_predicates,
                non_revoked: None,
            },
        ))
    }

    /// Verify a presentation against a proof request
    pub async fn verify_presentation(
        &self,
        presentation: &Presentation,
        pres_request: &PresentationRequest,
    ) -> Result<bool> {
        // Resolve all schemas and cred_defs from identifiers in the presentation
        let mut schemas: HashMap<SchemaId, Schema> = HashMap::new();
        let mut cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition> = HashMap::new();

        for identifier in &presentation.identifiers {
            let schema_id = &identifier.schema_id;
            if !schemas.contains_key(schema_id) {
                let schema = self.registry.get_schema(&schema_id.0).await?;
                schemas.insert(schema_id.clone(), schema);
            }

            let cred_def_id = &identifier.cred_def_id;
            if !cred_defs.contains_key(cred_def_id) {
                let cred_def = self
                    .registry
                    .get_credential_definition(&cred_def_id.0)
                    .await?;
                cred_defs.insert(cred_def_id.clone(), cred_def);
            }
        }

        let valid = anoncreds::verifier::verify_presentation(
            presentation,
            pres_request,
            &schemas,
            &cred_defs,
            None, // No revocation registry definitions
            None, // No revocation status lists
            None, // No nonrevoke interval override
        )?;

        Ok(valid)
    }

    /// Verify a presentation against a proof request, including any non-revocation
    /// proofs it contains.
    ///
    /// Revocation registry definitions and status lists are resolved from the
    /// configured registry — one `RevocationStatusList` is fetched per unique
    /// `rev_reg_id` referenced by the presentation's identifiers (at the
    /// `timestamp` carried by each identifier when present, otherwise the
    /// latest snapshot).
    pub async fn verify_presentation_with_revocation(
        &self,
        presentation: &Presentation,
        pres_request: &PresentationRequest,
    ) -> Result<bool> {
        let mut schemas: HashMap<SchemaId, Schema> = HashMap::new();
        let mut cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition> = HashMap::new();
        let mut rev_reg_defs: HashMap<
            RevocationRegistryDefinitionId,
            RevocationRegistryDefinition,
        > = HashMap::new();
        let mut rev_status_lists: Vec<RevocationStatusList> = Vec::new();
        let mut seen_rev_reg_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for identifier in &presentation.identifiers {
            if !schemas.contains_key(&identifier.schema_id) {
                let schema = self.registry.get_schema(&identifier.schema_id.0).await?;
                schemas.insert(identifier.schema_id.clone(), schema);
            }
            if !cred_defs.contains_key(&identifier.cred_def_id) {
                let cred_def = self
                    .registry
                    .get_credential_definition(&identifier.cred_def_id.0)
                    .await?;
                cred_defs.insert(identifier.cred_def_id.clone(), cred_def);
            }

            if let Some(rev_reg_id) = &identifier.rev_reg_id {
                let rev_reg_id_str = rev_reg_id.0.clone();
                if seen_rev_reg_ids.insert(rev_reg_id_str.clone()) {
                    let rev_reg_def = self
                        .registry
                        .get_revocation_registry_def(&rev_reg_id_str)
                        .await?;
                    rev_reg_defs.insert(rev_reg_id.clone(), rev_reg_def);
                    let status_list = self
                        .registry
                        .get_revocation_status_list(&rev_reg_id_str, identifier.timestamp)
                        .await?;
                    rev_status_lists.push(status_list);
                }
            }
        }

        let rev_reg_defs_arg = if rev_reg_defs.is_empty() {
            None
        } else {
            Some(&rev_reg_defs)
        };
        let status_lists_arg = if rev_status_lists.is_empty() {
            None
        } else {
            Some(rev_status_lists)
        };

        let valid = anoncreds::verifier::verify_presentation(
            presentation,
            pres_request,
            &schemas,
            &cred_defs,
            rev_reg_defs_arg,
            status_lists_arg,
            None,
        )?;

        Ok(valid)
    }

    /// Extract revealed attributes from a verified presentation
    pub fn extract_revealed_attributes(presentation: &Presentation) -> HashMap<String, String> {
        let mut result = HashMap::new();

        for (referent, revealed) in &presentation.requested_proof.revealed_attrs {
            result.insert(referent.clone(), revealed.raw.clone());
        }

        // Also include revealed attribute groups
        for (referent, group) in &presentation.requested_proof.revealed_attr_groups {
            for (name, value) in &group.values {
                result.insert(format!("{}:{}", referent, name), value.raw.clone());
            }
        }

        // Include self-attested
        for (referent, value) in &presentation.requested_proof.self_attested_attrs {
            result.insert(referent.clone(), value.clone());
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nonce() {
        let nonce = AnonCredsVerifierService::generate_nonce().unwrap();
        // Nonce should be non-empty
        assert!(!nonce.to_string().is_empty());
    }

    #[test]
    fn test_create_presentation_request() {
        let mut attrs = HashMap::new();
        attrs.insert(
            "attr1_referent".to_string(),
            AttributeInfo {
                name: Some("name".to_string()),
                names: None,
                restrictions: None,
                non_revoked: None,
            },
        );

        let pres_req = AnonCredsVerifierService::create_presentation_request(
            "test-proof",
            "1.0",
            attrs,
            HashMap::new(),
        )
        .unwrap();

        let payload = pres_req.value();
        assert_eq!(payload.name, "test-proof");
        assert!(payload.requested_attributes.contains_key("attr1_referent"));
    }
}
