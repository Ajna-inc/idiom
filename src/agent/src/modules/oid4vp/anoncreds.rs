//! AnonCreds presentation support for OID4VP.
//!
//! Handles the `ac_vp` format in OID4VP authorization requests:
//! - Parse AnonCreds proof requests from presentation_definition
//! - Match holder credentials against requested attributes/predicates
//! - Build AnonCreds ZKP presentations for vp_token
//! - Support predicate proofs (>=, >, <=, <) for zero-knowledge range proofs

use serde::{Deserialize, Serialize};

/// AnonCreds format identifiers in OID4VP
pub const AC_VC_FORMAT: &str = "ac_vc";
pub const AC_VP_FORMAT: &str = "ac_vp";
pub const CL_SIGNATURE_PROOF_TYPE: &str = "CLSignature2019";

/// Check if a presentation_definition format block requests AnonCreds
pub fn is_anoncreds_format(format: &serde_json::Value) -> bool {
    format.get(AC_VC_FORMAT).is_some() || format.get(AC_VP_FORMAT).is_some()
}

/// Predicate types for AnonCreds ZKP range proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PredicateType {
    #[serde(rename = ">=")]
    GreaterOrEqual,
    #[serde(rename = ">")]
    Greater,
    #[serde(rename = "<=")]
    LessOrEqual,
    #[serde(rename = "<")]
    Less,
}

impl PredicateType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            ">=" => Some(Self::GreaterOrEqual),
            ">" => Some(Self::Greater),
            "<=" => Some(Self::LessOrEqual),
            "<" => Some(Self::Less),
            _ => None,
        }
    }

    pub fn to_anoncreds_str(&self) -> &str {
        match self {
            Self::GreaterOrEqual => ">=",
            Self::Greater => ">",
            Self::LessOrEqual => "<=",
            Self::Less => "<",
        }
    }
}

/// Parsed predicate constraint from presentation_definition
#[derive(Debug, Clone)]
pub struct PredicateConstraint {
    pub attribute_name: String,
    pub predicate_type: PredicateType,
    pub value: i64,
}

/// Parse predicate constraints from a presentation_definition field.
///
/// Looks for our extension format:
/// ```json
/// {
///   "path": ["$.values.gpa"],
///   "predicate": { "type": ">=", "value": 30 }
/// }
/// ```
pub fn parse_predicate_constraint(field: &serde_json::Value) -> Option<PredicateConstraint> {
    let predicate = field.get("predicate")?;
    let pred_type_str = predicate.get("type")?.as_str()?;
    let pred_type = PredicateType::from_str(pred_type_str)?;
    let value = predicate.get("value")?.as_i64()?;

    // Extract attribute name from path: "$.values.gpa" → "gpa"
    let path = field.get("path")?.as_array()?.first()?.as_str()?;
    let attr_name = path
        .strip_prefix("$.values.")
        .or_else(|| path.strip_prefix("$."))?
        .to_string();

    Some(PredicateConstraint {
        attribute_name: attr_name,
        predicate_type: pred_type,
        value,
    })
}

/// Extract revealed attribute names from a presentation_definition.
///
/// Fields without a `predicate` are revealed (selective disclosure).
/// Fields with a `predicate` are proven in zero-knowledge (not revealed).
pub fn extract_requested_attributes(
    input_descriptor: &serde_json::Value,
) -> (Vec<String>, Vec<PredicateConstraint>) {
    let mut revealed = Vec::new();
    let mut predicates = Vec::new();

    let fields = input_descriptor
        .get("constraints")
        .and_then(|c| c.get("fields"))
        .and_then(|f| f.as_array());

    if let Some(fields) = fields {
        for field in fields {
            // Skip schema/cred_def filters
            let path = field
                .get("path")
                .and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if path.starts_with("$.schema_id") || path.starts_with("$.cred_def_id") {
                continue;
            }

            if let Some(pred) = parse_predicate_constraint(field) {
                predicates.push(pred);
            } else if let Some(attr) = path.strip_prefix("$.values.") {
                revealed.push(attr.to_string());
            }
        }
    }

    (revealed, predicates)
}

/// Extract schema_id and cred_def_id constraints from input_descriptor
pub fn extract_credential_filter(
    input_descriptor: &serde_json::Value,
) -> (Option<String>, Option<String>) {
    let fields = input_descriptor
        .get("constraints")
        .and_then(|c| c.get("fields"))
        .and_then(|f| f.as_array());

    let mut schema_id = None;
    let mut cred_def_id = None;

    if let Some(fields) = fields {
        for field in fields {
            let path = field
                .get("path")
                .and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let filter_const = field
                .get("filter")
                .and_then(|f| f.get("const"))
                .and_then(|v| v.as_str());

            if path == "$.schema_id" {
                schema_id = filter_const.map(|s| s.to_string());
            } else if path == "$.cred_def_id" {
                cred_def_id = filter_const.map(|s| s.to_string());
            }
        }
    }

    (schema_id, cred_def_id)
}

/// Check if limit_disclosure is requested (selective disclosure mode)
pub fn is_limit_disclosure_required(input_descriptor: &serde_json::Value) -> bool {
    input_descriptor
        .get("constraints")
        .and_then(|c| c.get("limit_disclosure"))
        .and_then(|v| v.as_str())
        == Some("required")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_predicate() {
        let field = serde_json::json!({
            "path": ["$.values.gpa"],
            "predicate": { "type": ">=", "value": 30 }
        });
        let pred = parse_predicate_constraint(&field).unwrap();
        assert_eq!(pred.attribute_name, "gpa");
        assert_eq!(pred.value, 30);
        assert!(matches!(pred.predicate_type, PredicateType::GreaterOrEqual));
    }

    #[test]
    fn test_extract_attributes() {
        let descriptor = serde_json::json!({
            "constraints": {
                "limit_disclosure": "required",
                "fields": [
                    { "path": ["$.schema_id"], "filter": { "const": "did:ajna:...:2:degree:1.0" } },
                    { "path": ["$.values.university"] },
                    { "path": ["$.values.gpa"], "predicate": { "type": ">=", "value": 30 } }
                ]
            }
        });
        let (revealed, predicates) = extract_requested_attributes(&descriptor);
        assert_eq!(revealed, vec!["university"]);
        assert_eq!(predicates.len(), 1);
        assert_eq!(predicates[0].attribute_name, "gpa");
    }

    #[test]
    fn test_extract_credential_filter() {
        let descriptor = serde_json::json!({
            "constraints": {
                "fields": [
                    { "path": ["$.schema_id"], "filter": { "const": "schema:1" } },
                    { "path": ["$.cred_def_id"], "filter": { "const": "creddef:1" } }
                ]
            }
        });
        let (schema, cred_def) = extract_credential_filter(&descriptor);
        assert_eq!(schema.unwrap(), "schema:1");
        assert_eq!(cred_def.unwrap(), "creddef:1");
    }
}
