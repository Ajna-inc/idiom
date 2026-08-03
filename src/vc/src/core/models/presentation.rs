use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::credential::{CredentialContext, OneOrMany, Proof, W3cCredential, W3cV2Credential};

/// W3C Verifiable Presentation Data Model v1.1
/// https://www.w3.org/TR/vc-data-model/#presentations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct W3cPresentation {
    /// The JSON-LD context(s)
    #[serde(rename = "@context")]
    pub context: PresentationContext,

    /// Unique identifier for the presentation (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Types of the presentation (always includes "VerifiablePresentation")
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// The credentials being presented
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifiable_credential: Option<Vec<VerifiableCredential>>,

    /// The entity that created the presentation (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,

    /// Cryptographic proof(s) - required for verifiable presentation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
}

/// W3C Verifiable Presentation Data Model v2.0
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct W3cV2Presentation {
    /// The JSON-LD context(s)
    #[serde(rename = "@context")]
    pub context: PresentationContext,

    /// Unique identifier for the presentation (optional but recommended)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Types of the presentation
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// The credentials being presented
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifiable_credential: Option<Vec<VerifiableCredential>>,

    /// The entity that created the presentation (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,

    /// Cryptographic proof(s)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
}

/// Presentation context - similar to credential context
pub type PresentationContext = CredentialContext;

/// Verifiable credential in a presentation - can be JWT string or full credential object
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerifiableCredential {
    /// JWT format credential (compact serialization)
    Jwt(String),
    /// JSON-LD credential object
    JsonLd(W3cCredential),
    /// V2 JSON-LD credential object
    JsonLdV2(W3cV2Credential),
    /// Generic JSON value for other formats
    Json(Value),
}

/// Presentation submission for DIF Presentation Exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationSubmission {
    /// Unique identifier for the submission
    pub id: String,

    /// ID of the presentation definition being satisfied
    pub definition_id: String,

    /// Mapping of input descriptors to credentials
    pub descriptor_map: Vec<DescriptorMapping>,
}

/// Descriptor mapping for presentation submission
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DescriptorMapping {
    /// ID of the input descriptor from the presentation definition
    pub id: String,

    /// Format of the credential
    pub format: String,

    /// JSON path to the credential in the presentation
    pub path: String,

    /// Nested path within the credential (for selective disclosure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_nested: Option<NestedPath>,
}

/// Nested path for selective disclosure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NestedPath {
    /// Format of the nested credential
    pub format: String,

    /// Path within the credential
    pub path: String,
}

impl W3cPresentation {
    /// Create a minimal presentation with required fields
    pub fn new() -> Self {
        Self {
            context: PresentationContext::String(
                "https://www.w3.org/2018/credentials/v1".to_string(),
            ),
            id: None,
            type_: vec!["VerifiablePresentation".to_string()],
            verifiable_credential: None,
            holder: None,
            proof: None,
        }
    }

    /// Set the holder
    pub fn with_holder(mut self, holder: impl Into<String>) -> Self {
        self.holder = Some(holder.into());
        self
    }

    /// Add a credential to the presentation
    pub fn add_credential(mut self, credential: VerifiableCredential) -> Self {
        match &mut self.verifiable_credential {
            Some(creds) => creds.push(credential),
            None => self.verifiable_credential = Some(vec![credential]),
        }
        self
    }

    /// Add a JWT credential
    pub fn add_jwt_credential(self, jwt: impl Into<String>) -> Self {
        self.add_credential(VerifiableCredential::Jwt(jwt.into()))
    }

    /// Add a JSON-LD credential
    pub fn add_jsonld_credential(self, credential: W3cCredential) -> Self {
        self.add_credential(VerifiableCredential::JsonLd(credential))
    }

    /// Set all credentials at once
    pub fn with_credentials(mut self, credentials: Vec<VerifiableCredential>) -> Self {
        self.verifiable_credential = Some(credentials);
        self
    }

    /// Add a proof
    pub fn with_proof(mut self, proof: Proof) -> Self {
        self.proof = Some(OneOrMany::One(proof));
        self
    }

    /// Add multiple proofs
    pub fn with_proofs(mut self, proofs: Vec<Proof>) -> Self {
        self.proof = Some(OneOrMany::Many(proofs));
        self
    }
}

impl Default for W3cPresentation {
    fn default() -> Self {
        Self::new()
    }
}

impl W3cV2Presentation {
    /// Create a minimal v2 presentation with required fields
    pub fn new() -> Self {
        Self {
            context: PresentationContext::String(
                "https://www.w3.org/ns/credentials/v2".to_string(),
            ),
            id: None,
            type_: vec!["VerifiablePresentation".to_string()],
            verifiable_credential: None,
            holder: None,
            proof: None,
        }
    }

    /// Set the holder
    pub fn with_holder(mut self, holder: impl Into<String>) -> Self {
        self.holder = Some(holder.into());
        self
    }

    /// Add a credential to the presentation
    pub fn add_credential(mut self, credential: VerifiableCredential) -> Self {
        match &mut self.verifiable_credential {
            Some(creds) => creds.push(credential),
            None => self.verifiable_credential = Some(vec![credential]),
        }
        self
    }
}

impl Default for W3cV2Presentation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::credential::CredentialSubjectObject;
    use std::collections::HashMap;

    #[test]
    fn test_presentation_serialization() {
        let presentation = W3cPresentation::new()
            .with_holder("did:example:holder")
            .add_jwt_credential(
                "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJkaWQ6ZXhhbXBsZToxMjMifQ.signature",
            );

        let json = serde_json::to_string_pretty(&presentation).unwrap();
        assert!(json.contains("VerifiablePresentation"));
        assert!(json.contains("did:example:holder"));
        assert!(json.contains("eyJhbGciOiJFZERTQSJ9"));

        // Test roundtrip
        let parsed: W3cPresentation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.holder, Some("did:example:holder".to_string()));
    }

    #[test]
    fn test_presentation_with_jsonld_credential() {
        let subject = CredentialSubjectObject {
            id: Some("did:example:subject".to_string()),
            claims: HashMap::new(),
        };

        let credential = W3cCredential::new("did:example:issuer", subject);

        let presentation = W3cPresentation::new().add_jsonld_credential(credential);

        let json = serde_json::to_string(&presentation).unwrap();
        assert!(json.contains("did:example:issuer"));
        assert!(json.contains("did:example:subject"));
    }

    #[test]
    fn test_presentation_submission() {
        let submission = PresentationSubmission {
            id: "submission-1".to_string(),
            definition_id: "definition-1".to_string(),
            descriptor_map: vec![DescriptorMapping {
                id: "descriptor-1".to_string(),
                format: "jwt_vc".to_string(),
                path: "$.verifiableCredential[0]".to_string(),
                path_nested: None,
            }],
        };

        let json = serde_json::to_string(&submission).unwrap();
        assert!(json.contains("definition-1"));
        assert!(json.contains("$.verifiableCredential[0]"));
    }
}
