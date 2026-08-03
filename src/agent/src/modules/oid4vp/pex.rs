//! DIF Presentation Exchange 2.0 support for OID4VP.
//!
//! Matches holder credentials against `presentation_definition` constraints
//! and builds `presentation_submission` responses.

use serde::{Deserialize, Serialize};

// =============================================================================
// Presentation Definition (from Verifier)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationDefinition {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    pub input_descriptors: Vec<InputDescriptor>,
    #[serde(default)]
    pub format: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptor {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub format: Option<serde_json::Value>,
    #[serde(default)]
    pub constraints: Option<Constraints>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    #[serde(default)]
    pub limit_disclosure: Option<String>,
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub path: Vec<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub filter: Option<serde_json::Value>,
    #[serde(default)]
    pub optional: Option<bool>,
    /// AnonCreds predicate extension
    #[serde(default)]
    pub predicate: Option<serde_json::Value>,
}

// =============================================================================
// Presentation Submission (from Holder)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMapEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorMapEntry {
    pub id: String,
    pub format: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_nested: Option<Box<DescriptorMapEntry>>,
}

// =============================================================================
// Credential Matching
// =============================================================================

/// A credential that matched an input descriptor
#[derive(Debug, Clone)]
pub struct PexMatchedCredential {
    pub descriptor_id: String,
    pub credential_id: String,
    pub format: String,
    pub matched_fields: Vec<String>,
}

/// Match available credentials against a presentation definition.
///
/// Returns a list of matched credentials, one per input_descriptor.
/// If a required descriptor has no match, it's omitted from the result.
pub fn match_credentials(
    definition: &PresentationDefinition,
    available: &[(String, String, Vec<String>)], // (credential_id, format, attribute_names)
) -> Vec<PexMatchedCredential> {
    let mut matches = Vec::new();

    for descriptor in &definition.input_descriptors {
        let descriptor_format = descriptor
            .format
            .as_ref()
            .and_then(|f| {
                if f.get("ac_vc").is_some() || f.get("ac_vp").is_some() {
                    Some("ac_vp")
                } else if f.get("jwt_vp").is_some() || f.get("jwt_vc").is_some() {
                    Some("jwt_vp")
                } else if f.get("ldp_vp").is_some() {
                    Some("ldp_vp")
                } else {
                    None
                }
            })
            .unwrap_or("jwt_vp");

        let required_paths = descriptor
            .constraints
            .as_ref()
            .map(|c| {
                c.fields
                    .iter()
                    .filter(|f| !f.optional.unwrap_or(false))
                    .flat_map(|f| f.path.iter().cloned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Find first credential that matches all required fields
        for (cred_id, cred_format, attrs) in available {
            let format_matches = cred_format == descriptor_format
                || (descriptor_format == "ac_vp" && cred_format == "anoncreds");

            if !format_matches {
                continue;
            }

            let mut matched_fields = Vec::new();
            let mut all_match = true;

            for path in &required_paths {
                let attr = path
                    .strip_prefix("$.values.")
                    .or_else(|| path.strip_prefix("$."))
                    .unwrap_or(path);

                // Schema/cred_def paths are metadata, not attributes — skip matching
                if attr == "schema_id" || attr == "cred_def_id" {
                    matched_fields.push(attr.to_string());
                    continue;
                }

                if attrs.iter().any(|a| a == attr) {
                    matched_fields.push(attr.to_string());
                } else {
                    all_match = false;
                    break;
                }
            }

            if all_match {
                matches.push(PexMatchedCredential {
                    descriptor_id: descriptor.id.clone(),
                    credential_id: cred_id.clone(),
                    format: cred_format.clone(),
                    matched_fields,
                });
                break; // First match wins for this descriptor
            }
        }
    }

    matches
}

/// Build a presentation_submission for matched credentials.
pub fn build_presentation_submission(
    definition: &PresentationDefinition,
    matched: &[PexMatchedCredential],
) -> PresentationSubmission {
    PresentationSubmission {
        id: uuid::Uuid::new_v4().to_string(),
        definition_id: definition.id.clone(),
        descriptor_map: matched
            .iter()
            .enumerate()
            .map(|(i, m)| DescriptorMapEntry {
                id: m.descriptor_id.clone(),
                format: m.format.clone(),
                path: format!("$.verifiableCredential[{}]", i),
                path_nested: None,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_anoncreds_credential() {
        let definition = PresentationDefinition {
            id: "test".to_string(),
            name: None,
            purpose: None,
            format: None,
            input_descriptors: vec![InputDescriptor {
                id: "degree".to_string(),
                name: None,
                purpose: None,
                format: Some(serde_json::json!({ "ac_vp": { "proof_type": ["CLSignature2019"] } })),
                constraints: Some(Constraints {
                    limit_disclosure: Some("required".to_string()),
                    fields: vec![Field {
                        path: vec!["$.values.university".to_string()],
                        id: None,
                        name: None,
                        purpose: None,
                        filter: None,
                        optional: None,
                        predicate: None,
                    }],
                }),
            }],
        };

        let available = vec![(
            "cred-1".to_string(),
            "anoncreds".to_string(),
            vec![
                "name".to_string(),
                "university".to_string(),
                "gpa".to_string(),
            ],
        )];

        let matched = match_credentials(&definition, &available);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].credential_id, "cred-1");
        assert_eq!(matched[0].descriptor_id, "degree");
    }

    #[test]
    fn test_build_submission() {
        let definition = PresentationDefinition {
            id: "def-1".to_string(),
            name: None,
            purpose: None,
            format: None,
            input_descriptors: vec![],
        };
        let matched = vec![PexMatchedCredential {
            descriptor_id: "desc-1".to_string(),
            credential_id: "cred-1".to_string(),
            format: "anoncreds".to_string(),
            matched_fields: vec!["name".to_string()],
        }];
        let submission = build_presentation_submission(&definition, &matched);
        assert_eq!(submission.definition_id, "def-1");
        assert_eq!(submission.descriptor_map.len(), 1);
        assert_eq!(submission.descriptor_map[0].format, "anoncreds");
    }
}
