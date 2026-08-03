//! DCQL (DC API Query Language) support
//!
//! DCQL is a simpler alternative to Presentation Exchange used by Google Wallet

use super::error::{Oid4vpError, Result};
use super::types::MatchedCredential;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DCQL Query structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlQuery {
    pub credentials: Vec<DcqlCredentialQuery>,
}

/// Single credential query within DCQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlCredentialQuery {
    /// Unique ID for this credential query
    pub id: String,
    /// Format (e.g., "mso_mdoc")
    pub format: String,
    /// Metadata (e.g., doctype_value)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<DcqlMeta>,
    /// Requested claims
    pub claims: Vec<DcqlClaim>,
}

/// DCQL metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlMeta {
    /// Document type value for mso_mdoc
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype_value: Option<String>,
    /// VCT values for SD-JWT
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct_values: Option<Vec<String>>,
}

/// Single claim request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlClaim {
    /// Namespace (for mso_mdoc)
    pub namespace: String,
    /// Claim name
    pub claim_name: String,
}

/// DCQL query result
#[derive(Debug, Clone)]
pub struct DcqlQueryResult {
    /// Credentials that match the query
    pub matched_credentials: Vec<MatchedCredential>,
    /// Can the query be satisfied?
    pub can_be_satisfied: bool,
}

/// DCQL Service
pub struct DcqlService;

impl DcqlService {
    pub fn new() -> Self {
        Self
    }

    /// Validate DCQL query structure
    pub fn validate_dcql_query(&self, query: &DcqlQuery) -> Result<()> {
        // Validate each credential query
        for cred_query in &query.credentials {
            // Check format is supported
            if cred_query.format != "mso_mdoc" && !cred_query.format.starts_with("dc+sd-jwt") {
                return Err(Oid4vpError::UnsupportedFormat(cred_query.format.clone()));
            }

            // Check claims are present
            if cred_query.claims.is_empty() {
                return Err(Oid4vpError::DcqlError(format!(
                    "Credential query '{}' has no claims",
                    cred_query.id
                )));
            }

            // For mso_mdoc, require doctype_value in meta
            if cred_query.format == "mso_mdoc" {
                if let Some(meta) = &cred_query.meta {
                    if meta.doctype_value.is_none() {
                        return Err(Oid4vpError::DcqlError(format!(
                            "mso_mdoc format requires doctype_value in meta for query '{}'",
                            cred_query.id
                        )));
                    }
                } else {
                    return Err(Oid4vpError::DcqlError(format!(
                        "mso_mdoc format requires meta with doctype_value for query '{}'",
                        cred_query.id
                    )));
                }
            }
        }

        Ok(())
    }

    /// Match available credentials to DCQL query
    ///
    /// For Phase 1, we match based on doc_type and check if claims exist.
    /// The actual Document matching will be done when integrated with storage.
    pub fn match_query_to_documents(
        &self,
        query: &DcqlQuery,
        available_doc_types: &[(String, HashMap<String, Vec<String>>)], // (doc_type, namespace -> claims)
    ) -> Result<DcqlQueryResult> {
        let mut matched_credentials = Vec::new();
        let mut can_be_satisfied = false;

        // For each credential query
        for cred_query in &query.credentials {
            // Only handle mso_mdoc for Phase 1
            if cred_query.format != "mso_mdoc" {
                continue;
            }

            // Get expected doctype
            let expected_doctype = cred_query
                .meta
                .as_ref()
                .and_then(|m| m.doctype_value.as_ref())
                .ok_or_else(|| Oid4vpError::MissingParameter("doctype_value".to_string()))?;

            // Find matching documents
            for (doc_type, available_claims) in available_doc_types {
                // Check doctype matches
                if doc_type != expected_doctype {
                    continue;
                }

                // Check if all requested claims are available
                let mut all_claims_available = true;
                for dcql_claim in &cred_query.claims {
                    if let Some(namespace_claims) = available_claims.get(&dcql_claim.namespace) {
                        if !namespace_claims.contains(&dcql_claim.claim_name) {
                            all_claims_available = false;
                            break;
                        }
                    } else {
                        all_claims_available = false;
                        break;
                    }
                }

                // Add to matched credentials
                matched_credentials.push(MatchedCredential {
                    id: cred_query.id.clone(),
                    doc_type: doc_type.clone(),
                    available_claims: available_claims.clone(),
                    matches: all_claims_available,
                });

                if all_claims_available {
                    can_be_satisfied = true;
                }
            }
        }

        Ok(DcqlQueryResult {
            matched_credentials,
            can_be_satisfied,
        })
    }

    /// Create presentation submission for DCQL response
    pub fn create_presentation_submission(
        &self,
        _query: &DcqlQuery,
        selected_credentials: &[String],
    ) -> Result<super::types::PresentationSubmission> {
        // Create descriptor map
        let descriptor_map = selected_credentials
            .iter()
            .enumerate()
            .map(|(idx, id)| super::types::DescriptorMap {
                id: id.clone(),
                format: "mso_mdoc".to_string(),
                path: format!("$[{}]", idx),
            })
            .collect();

        Ok(super::types::PresentationSubmission {
            id: uuid::Uuid::new_v4().to_string(),
            definition_id: "dcql".to_string(),
            descriptor_map,
        })
    }
}

impl Default for DcqlService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_dcql_query() {
        let query = DcqlQuery {
            credentials: vec![DcqlCredentialQuery {
                id: "test".to_string(),
                format: "mso_mdoc".to_string(),
                meta: Some(DcqlMeta {
                    doctype_value: Some("org.iso.18013.5.1.mDL".to_string()),
                    vct_values: None,
                }),
                claims: vec![DcqlClaim {
                    namespace: "org.iso.18013.5.1".to_string(),
                    claim_name: "family_name".to_string(),
                }],
            }],
        };

        let service = DcqlService::new();
        assert!(service.validate_dcql_query(&query).is_ok());
    }

    #[test]
    fn test_validate_dcql_query_missing_doctype() {
        let query = DcqlQuery {
            credentials: vec![DcqlCredentialQuery {
                id: "test".to_string(),
                format: "mso_mdoc".to_string(),
                meta: None,
                claims: vec![DcqlClaim {
                    namespace: "org.iso.18013.5.1".to_string(),
                    claim_name: "family_name".to_string(),
                }],
            }],
        };

        let service = DcqlService::new();
        assert!(service.validate_dcql_query(&query).is_err());
    }

    #[test]
    fn test_match_query_to_documents() {
        let query = DcqlQuery {
            credentials: vec![DcqlCredentialQuery {
                id: "mdl_query".to_string(),
                format: "mso_mdoc".to_string(),
                meta: Some(DcqlMeta {
                    doctype_value: Some("org.iso.18013.5.1.mDL".to_string()),
                    vct_values: None,
                }),
                claims: vec![
                    DcqlClaim {
                        namespace: "org.iso.18013.5.1".to_string(),
                        claim_name: "family_name".to_string(),
                    },
                    DcqlClaim {
                        namespace: "org.iso.18013.5.1".to_string(),
                        claim_name: "given_name".to_string(),
                    },
                ],
            }],
        };

        // Mock available document
        let mut available_claims = HashMap::new();
        available_claims.insert(
            "org.iso.18013.5.1".to_string(),
            vec![
                "family_name".to_string(),
                "given_name".to_string(),
                "birth_date".to_string(),
            ],
        );

        let available_docs = vec![("org.iso.18013.5.1.mDL".to_string(), available_claims)];

        let service = DcqlService::new();
        let result = service
            .match_query_to_documents(&query, &available_docs)
            .unwrap();

        assert!(result.can_be_satisfied);
        assert_eq!(result.matched_credentials.len(), 1);
        assert!(result.matched_credentials[0].matches);
    }
}
