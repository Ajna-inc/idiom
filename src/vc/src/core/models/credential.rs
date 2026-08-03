use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// W3C Verifiable Credential Data Model v1.1
/// https://www.w3.org/TR/vc-data-model/
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct W3cCredential {
    /// The JSON-LD context(s)
    #[serde(rename = "@context")]
    pub context: CredentialContext,

    /// Unique identifier for the credential (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Types of the credential (always includes "VerifiableCredential")
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// The entity that issued the credential
    pub issuer: Issuer,

    /// When the credential was issued
    pub issuance_date: DateTime<Utc>,

    /// When the credential expires (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,

    /// The claims about the subject(s)
    pub credential_subject: CredentialSubject,

    /// Status information for revocation/suspension (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,

    /// Schema definition (optional). Either a
    /// single schema object or an array is allowed — OpenBadges v3 uses the
    /// array form, EBSI v1 uses the single form, so we accept both
    /// transparently via `OneOrMany`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<OneOrMany<CredentialSchema>>,

    /// Refresh service information (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_service: Option<RefreshService>,

    /// Cryptographic proof(s) - not included in JWT format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
}

/// W3C Verifiable Credential Data Model v2.0
/// https://www.w3.org/TR/vc-data-model-2.0/
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct W3cV2Credential {
    /// The JSON-LD context(s)
    #[serde(rename = "@context")]
    pub context: CredentialContext,

    /// Unique identifier for the credential (optional but recommended)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Types of the credential
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// The entity that issued the credential
    pub issuer: Issuer,

    /// When the credential becomes valid (v2.0 naming)
    pub valid_from: DateTime<Utc>,

    /// When the credential ceases to be valid (optional, v2.0 naming)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,

    /// The claims about the subject(s)
    pub credential_subject: CredentialSubject,

    /// Status information for revocation/suspension (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,

    /// Schema definition (optional). Same `OneOrMany` treatment as
    /// the v1 field — W3C VC v2 keeps the dual shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<OneOrMany<CredentialSchema>>,

    /// Related resources (v2.0 feature)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_resource: Option<Vec<RelatedResource>>,

    /// Cryptographic proof(s)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
}

/// Credential context - can be string or array of strings/objects
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialContext {
    String(String),
    Array(Vec<ContextValue>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContextValue {
    String(String),
    Object(HashMap<String, Value>),
}

/// Issuer - can be string (DID/URL) or object with id and properties
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Issuer {
    String(String),
    Object(IssuerObject),
}

impl std::fmt::Display for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Issuer::String(s) => f.write_str(s),
            Issuer::Object(obj) => f.write_str(&obj.id),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerObject {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

/// Credential subject - can be single or multiple subjects
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialSubject {
    Single(CredentialSubjectObject),
    Multiple(Vec<CredentialSubjectObject>),
}

impl CredentialSubject {
    /// Get the ID of the subject (from first if multiple)
    pub fn get_id(&self) -> Option<String> {
        match self {
            CredentialSubject::Single(subject) => subject.id.clone(),
            CredentialSubject::Multiple(subjects) => subjects.first().and_then(|s| s.id.clone()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubjectObject {
    /// Subject identifier (optional but recommended)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// All other claims about the subject
    #[serde(flatten)]
    pub claims: HashMap<String, Value>,
}

/// Credential status for revocation checking
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

/// Credential schema definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSchema {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

/// Refresh service for credential updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshService {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
}

/// Related resource (v2.0 feature)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelatedResource {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_sri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_multibase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

/// Cryptographic proof
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_: String,
    pub created: Option<DateTime<Utc>>,
    pub verification_method: String,
    pub proof_purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jws: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

/// Helper enum for fields that can be single value or array
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    pub fn to_vec(self) -> Vec<T> {
        match self {
            OneOrMany::One(val) => vec![val],
            OneOrMany::Many(vals) => vals,
        }
    }

    pub fn as_slice(&self) -> &[T] {
        match self {
            OneOrMany::One(val) => std::slice::from_ref(val),
            OneOrMany::Many(vals) => vals.as_slice(),
        }
    }
}

impl W3cCredential {
    /// Create a minimal credential with required fields
    pub fn new(issuer: impl Into<String>, credential_subject: CredentialSubjectObject) -> Self {
        Self {
            context: CredentialContext::String(
                "https://www.w3.org/2018/credentials/v1".to_string(),
            ),
            id: None,
            type_: vec!["VerifiableCredential".to_string()],
            issuer: Issuer::String(issuer.into()),
            issuance_date: Utc::now(),
            expiration_date: None,
            credential_subject: CredentialSubject::Single(credential_subject),
            credential_status: None,
            credential_schema: None,
            refresh_service: None,
            proof: None,
        }
    }

    /// Add a credential type
    pub fn add_type(mut self, type_: impl Into<String>) -> Self {
        self.type_.push(type_.into());
        self
    }

    /// Set the credential ID
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set expiration date
    pub fn with_expiration(mut self, expiration: DateTime<Utc>) -> Self {
        self.expiration_date = Some(expiration);
        self
    }

    /// Add a proof
    pub fn with_proof(mut self, proof: Proof) -> Self {
        self.proof = Some(OneOrMany::One(proof));
        self
    }
}

impl W3cV2Credential {
    /// Create a minimal v2 credential with required fields
    pub fn new(issuer: impl Into<String>, credential_subject: CredentialSubjectObject) -> Self {
        Self {
            context: CredentialContext::String("https://www.w3.org/ns/credentials/v2".to_string()),
            id: None,
            type_: vec!["VerifiableCredential".to_string()],
            issuer: Issuer::String(issuer.into()),
            valid_from: Utc::now(),
            valid_until: None,
            credential_subject: CredentialSubject::Single(credential_subject),
            credential_status: None,
            credential_schema: None,
            related_resource: None,
            proof: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_serialization() {
        let subject = CredentialSubjectObject {
            id: Some("did:example:subject".to_string()),
            claims: {
                let mut claims = HashMap::new();
                claims.insert("name".to_string(), Value::String("Alice".to_string()));
                claims.insert("age".to_string(), Value::Number(25.into()));
                claims
            },
        };

        let credential = W3cCredential::new("did:example:issuer", subject)
            .with_id("http://example.com/credentials/123")
            .add_type("UniversityDegreeCredential");

        let json = serde_json::to_string_pretty(&credential).unwrap();
        assert!(json.contains("VerifiableCredential"));
        assert!(json.contains("UniversityDegreeCredential"));

        // Test roundtrip
        let parsed: W3cCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.id,
            Some("http://example.com/credentials/123".to_string())
        );
    }

    #[test]
    fn test_v2_credential() {
        let subject = CredentialSubjectObject {
            id: None,
            claims: HashMap::new(),
        };

        let credential = W3cV2Credential::new("did:example:issuer", subject);

        let json = serde_json::to_string(&credential).unwrap();
        assert!(json.contains("validFrom"));
        assert!(json.contains("https://www.w3.org/ns/credentials/v2"));
    }
}
