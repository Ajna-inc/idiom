use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::{CredentialFormat, Issuer, W3cCredential, W3cV2Credential};
use agent_core::traits::Record;

/// Category name for credential records in storage
pub const CREDENTIAL_CATEGORY: &str = "credential";

/// Record wrapper for storing W3C credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// Unique record ID
    pub id: String,

    /// When the record was created
    pub created_at: DateTime<Utc>,

    /// When the record was last updated
    pub updated_at: DateTime<Utc>,

    /// The credential format (JWT, JSON-LD, SD-JWT, mDoc)
    pub format: CredentialFormat,

    /// The raw credential string (JWT, JSON, etc.)
    pub raw_credential: String,

    /// Parsed credential (v1 or v2). Nested (not flattened) because
    /// W3C credentials carry their own `id` field, which collided
    /// with the record's UUID `id` under `#[serde(flatten)]` and
    /// caused round-trip deserialize errors on OB v3 / EBSI v1
    /// credentials.
    pub credential: CredentialData,

    /// Additional metadata
    pub metadata: CredentialMetadata,
}

/// Credential data variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialData {
    V1(W3cCredential),
    V2(W3cV2Credential),
}

/// Metadata about the credential
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialMetadata {
    /// Tags for this credential (user-defined)
    #[serde(default)]
    pub tags: Vec<String>,

    /// Whether this credential has been verified
    #[serde(default)]
    pub verified: bool,

    /// When the credential was verified
    pub verified_at: Option<DateTime<Utc>>,

    /// Whether this credential is revoked (cached status)
    #[serde(default)]
    pub revoked: bool,

    /// When the revocation status was last checked
    pub revocation_checked_at: Option<DateTime<Utc>>,

    /// Source of the credential (e.g., "oid4vc", "didcomm", "manual")
    pub source: Option<String>,

    /// Connection/relationship ID associated with this credential
    pub connection_id: Option<String>,
}

impl CredentialRecord {
    /// Create a new credential record from a W3C credential
    pub fn from_credential(
        credential: W3cCredential,
        format: CredentialFormat,
        raw: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,
            format,
            raw_credential: raw,
            credential: CredentialData::V1(credential),
            metadata: CredentialMetadata::default(),
        }
    }

    /// Create a new credential record from a W3C v2 credential
    pub fn from_credential_v2(
        credential: W3cV2Credential,
        format: CredentialFormat,
        raw: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,
            format,
            raw_credential: raw,
            credential: CredentialData::V2(credential),
            metadata: CredentialMetadata::default(),
        }
    }

    /// Convert to a storage record
    pub fn to_storage_record(&self) -> Result<Record, serde_json::Error> {
        let value = serde_json::to_vec(self)?;
        let mut record = Record::new(CREDENTIAL_CATEGORY, &self.id, value);

        // Add queryable tags
        record = record
            .add_tag("format", self.format_tag())
            .add_tag("issuer", self.issuer_tag())
            .add_tag("subject", self.subject_tag())
            .add_tag("verified", self.metadata.verified.to_string());

        // Add credential type tags
        for cred_type in self.credential_types() {
            record = record.add_tag(format!("type:{}", cred_type), "true");
        }

        // Add user tags
        for tag in &self.metadata.tags {
            record = record.add_tag(format!("tag:{}", tag), "true");
        }

        // Add optional tags
        if let Some(connection_id) = &self.metadata.connection_id {
            record = record.add_tag("connection_id", connection_id);
        }

        if let Some(source) = &self.metadata.source {
            record = record.add_tag("source", source);
        }

        Ok(record)
    }

    /// Create from a storage record
    pub fn from_storage_record(record: &Record) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(&record.value)
    }

    /// Get the issuer as a tag value
    pub fn issuer_tag(&self) -> String {
        match &self.credential {
            CredentialData::V1(cred) => match &cred.issuer {
                Issuer::String(s) => s.clone(),
                Issuer::Object(obj) => obj.id.clone(),
            },
            CredentialData::V2(cred) => match &cred.issuer {
                Issuer::String(s) => s.clone(),
                Issuer::Object(obj) => obj.id.clone(),
            },
        }
    }

    /// Get the subject as a tag value
    fn subject_tag(&self) -> String {
        match &self.credential {
            CredentialData::V1(cred) => match &cred.credential_subject {
                crate::core::CredentialSubject::Single(subj) => {
                    subj.id.clone().unwrap_or_else(|| "anonymous".to_string())
                }
                crate::core::CredentialSubject::Multiple(subjects) => subjects
                    .first()
                    .and_then(|s| s.id.clone())
                    .unwrap_or_else(|| "anonymous".to_string()),
            },
            CredentialData::V2(cred) => match &cred.credential_subject {
                crate::core::CredentialSubject::Single(subj) => {
                    subj.id.clone().unwrap_or_else(|| "anonymous".to_string())
                }
                crate::core::CredentialSubject::Multiple(subjects) => subjects
                    .first()
                    .and_then(|s| s.id.clone())
                    .unwrap_or_else(|| "anonymous".to_string()),
            },
        }
    }

    /// Get the format as a tag value
    fn format_tag(&self) -> String {
        match self.format {
            CredentialFormat::JwtVc => "jwt-vc",
            CredentialFormat::JsonLd => "json-ld",
            CredentialFormat::SdJwt => "sd-jwt",
            CredentialFormat::Mdoc => "mdoc",
            CredentialFormat::AnonCreds => "anoncreds",
        }
        .to_string()
    }

    /// Get credential types
    fn credential_types(&self) -> &[String] {
        match &self.credential {
            CredentialData::V1(cred) => &cred.type_,
            CredentialData::V2(cred) => &cred.type_,
        }
    }

    /// Check if the credential is expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now();
        match &self.credential {
            CredentialData::V1(cred) => {
                if let Some(exp) = cred.expiration_date {
                    exp < now
                } else {
                    false
                }
            }
            CredentialData::V2(cred) => {
                if let Some(exp) = cred.valid_until {
                    exp < now
                } else {
                    false
                }
            }
        }
    }

    /// Update metadata
    pub fn update_metadata<F>(&mut self, updater: F) -> &mut Self
    where
        F: FnOnce(&mut CredentialMetadata),
    {
        updater(&mut self.metadata);
        self.updated_at = Utc::now();
        self
    }

    /// Mark as verified
    pub fn mark_verified(&mut self) -> &mut Self {
        self.metadata.verified = true;
        self.metadata.verified_at = Some(Utc::now());
        self.updated_at = Utc::now();
        self
    }

    /// Update revocation status
    pub fn update_revocation_status(&mut self, revoked: bool) -> &mut Self {
        self.metadata.revoked = revoked;
        self.metadata.revocation_checked_at = Some(Utc::now());
        self.updated_at = Utc::now();
        self
    }

    /// Add a user tag
    pub fn add_tag(&mut self, tag: impl Into<String>) -> &mut Self {
        self.metadata.tags.push(tag.into());
        self.updated_at = Utc::now();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::CredentialSubjectObject;
    use std::collections::HashMap;

    #[test]
    fn test_credential_record_creation() {
        let subject = CredentialSubjectObject {
            id: Some("did:example:subject".to_string()),
            claims: HashMap::new(),
        };

        let credential = W3cCredential::new("did:example:issuer", subject);

        let record = CredentialRecord::from_credential(
            credential,
            CredentialFormat::JwtVc,
            "eyJhbGc...".to_string(),
        );

        assert!(!record.id.is_empty());
        assert_eq!(record.format, CredentialFormat::JwtVc);
        assert!(!record.metadata.verified);
    }

    #[test]
    fn test_storage_record_conversion() {
        let subject = CredentialSubjectObject {
            id: Some("did:example:subject".to_string()),
            claims: HashMap::new(),
        };

        let credential = W3cCredential::new("did:example:issuer", subject);

        let mut cred_record = CredentialRecord::from_credential(
            credential,
            CredentialFormat::JwtVc,
            "eyJhbGc...".to_string(),
        );

        cred_record.add_tag("important");
        cred_record.metadata.connection_id = Some("conn-123".to_string());

        let storage_record = cred_record.to_storage_record().unwrap();

        assert_eq!(storage_record.category, CREDENTIAL_CATEGORY);
        assert_eq!(storage_record.name, cred_record.id);
        assert_eq!(
            storage_record.tags.get("issuer"),
            Some(&"did:example:issuer".to_string())
        );
        assert_eq!(
            storage_record.tags.get("subject"),
            Some(&"did:example:subject".to_string())
        );
        assert_eq!(
            storage_record.tags.get("format"),
            Some(&"jwt-vc".to_string())
        );
        assert_eq!(
            storage_record.tags.get("connection_id"),
            Some(&"conn-123".to_string())
        );
        assert_eq!(
            storage_record.tags.get("tag:important"),
            Some(&"true".to_string())
        );

        // Test round-trip
        let recovered = CredentialRecord::from_storage_record(&storage_record).unwrap();
        assert_eq!(recovered.id, cred_record.id);
        assert_eq!(recovered.format, cred_record.format);
    }
}
