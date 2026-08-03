use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::{CredentialFormat, W3cPresentation, W3cV2Presentation};
use agent_core::traits::Record;

/// Category name for presentation records in storage
pub const PRESENTATION_CATEGORY: &str = "presentation";

/// Record wrapper for storing W3C presentations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationRecord {
    /// Unique record ID
    pub id: String,

    /// When the record was created
    pub created_at: DateTime<Utc>,

    /// When the record was last updated
    pub updated_at: DateTime<Utc>,

    /// The presentation format
    pub format: CredentialFormat,

    /// The raw presentation string (JWT, JSON, etc.)
    pub raw_presentation: String,

    /// Parsed presentation (v1 or v2)
    #[serde(flatten)]
    pub presentation: PresentationData,

    /// Additional metadata
    pub metadata: PresentationMetadata,
}

/// Presentation data variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PresentationData {
    V1(W3cPresentation),
    V2(W3cV2Presentation),
}

/// Metadata about the presentation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PresentationMetadata {
    /// Tags for this presentation (user-defined)
    #[serde(default)]
    pub tags: Vec<String>,

    /// Whether this presentation has been verified
    #[serde(default)]
    pub verified: bool,

    /// When the presentation was verified
    pub verified_at: Option<DateTime<Utc>>,

    /// The verifier DID (who requested this presentation)
    pub verifier: Option<String>,

    /// The purpose of this presentation (e.g., "authentication", "proof")
    pub purpose: Option<String>,

    /// Challenge used in the presentation proof
    pub challenge: Option<String>,

    /// Domain for the presentation
    pub domain: Option<String>,

    /// Connection/relationship ID associated with this presentation
    pub connection_id: Option<String>,

    /// Presentation exchange thread ID
    pub thread_id: Option<String>,
}

impl PresentationRecord {
    /// Create a new presentation record from a W3C presentation
    pub fn from_presentation(
        presentation: W3cPresentation,
        format: CredentialFormat,
        raw: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,
            format,
            raw_presentation: raw,
            presentation: PresentationData::V1(presentation),
            metadata: PresentationMetadata::default(),
        }
    }

    /// Create a new presentation record from a W3C v2 presentation
    pub fn from_presentation_v2(
        presentation: W3cV2Presentation,
        format: CredentialFormat,
        raw: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,
            format,
            raw_presentation: raw,
            presentation: PresentationData::V2(presentation),
            metadata: PresentationMetadata::default(),
        }
    }

    /// Convert to a storage record
    pub fn to_storage_record(&self) -> Result<Record, serde_json::Error> {
        let value = serde_json::to_vec(self)?;
        let mut record = Record::new(PRESENTATION_CATEGORY, &self.id, value);

        // Add queryable tags
        record = record
            .add_tag("format", self.format_tag())
            .add_tag("holder", self.holder_tag())
            .add_tag("verified", self.metadata.verified.to_string());

        // Add optional tags
        if let Some(verifier) = &self.metadata.verifier {
            record = record.add_tag("verifier", verifier);
        }

        if let Some(purpose) = &self.metadata.purpose {
            record = record.add_tag("purpose", purpose);
        }

        if let Some(connection_id) = &self.metadata.connection_id {
            record = record.add_tag("connection_id", connection_id);
        }

        if let Some(thread_id) = &self.metadata.thread_id {
            record = record.add_tag("thread_id", thread_id);
        }

        // Add user tags
        for tag in &self.metadata.tags {
            record = record.add_tag(format!("tag:{}", tag), "true");
        }

        Ok(record)
    }

    /// Create from a storage record
    pub fn from_storage_record(record: &Record) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(&record.value)
    }

    /// Get the holder as a tag value
    fn holder_tag(&self) -> String {
        match &self.presentation {
            PresentationData::V1(pres) => pres
                .holder
                .clone()
                .unwrap_or_else(|| "anonymous".to_string()),
            PresentationData::V2(pres) => pres
                .holder
                .clone()
                .unwrap_or_else(|| "anonymous".to_string()),
        }
    }

    /// Get the format as a tag value
    fn format_tag(&self) -> String {
        match self.format {
            CredentialFormat::JwtVc => "jwt-vp",
            CredentialFormat::JsonLd => "json-ld",
            CredentialFormat::SdJwt => "sd-jwt",
            CredentialFormat::Mdoc => "mdoc",
            CredentialFormat::AnonCreds => "anoncreds",
        }
        .to_string()
    }

    /// Get the number of credentials in the presentation
    pub fn credential_count(&self) -> usize {
        match &self.presentation {
            PresentationData::V1(pres) => pres
                .verifiable_credential
                .as_ref()
                .map(|c| c.len())
                .unwrap_or(0),
            PresentationData::V2(pres) => pres
                .verifiable_credential
                .as_ref()
                .map(|c| c.len())
                .unwrap_or(0),
        }
    }

    /// Update metadata
    pub fn update_metadata<F>(&mut self, updater: F) -> &mut Self
    where
        F: FnOnce(&mut PresentationMetadata),
    {
        updater(&mut self.metadata);
        self.updated_at = Utc::now();
        self
    }

    /// Mark as verified
    pub fn mark_verified(&mut self, verifier: Option<String>) -> &mut Self {
        self.metadata.verified = true;
        self.metadata.verified_at = Some(Utc::now());
        if let Some(v) = verifier {
            self.metadata.verifier = Some(v);
        }
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

    #[test]
    fn test_presentation_record_creation() {
        let presentation = W3cPresentation::new().with_holder("did:example:holder");

        let record = PresentationRecord::from_presentation(
            presentation,
            CredentialFormat::JwtVc,
            "eyJhbGc...".to_string(),
        );

        assert!(!record.id.is_empty());
        assert_eq!(record.format, CredentialFormat::JwtVc);
        assert!(!record.metadata.verified);
        assert_eq!(record.credential_count(), 0);
    }

    #[test]
    fn test_storage_record_conversion() {
        let presentation = W3cPresentation::new().with_holder("did:example:holder");

        let mut pres_record = PresentationRecord::from_presentation(
            presentation,
            CredentialFormat::JwtVc,
            "eyJhbGc...".to_string(),
        );

        pres_record.metadata.verifier = Some("did:example:verifier".to_string());
        pres_record.metadata.purpose = Some("authentication".to_string());
        pres_record.add_tag("important");

        let storage_record = pres_record.to_storage_record().unwrap();

        assert_eq!(storage_record.category, PRESENTATION_CATEGORY);
        assert_eq!(storage_record.name, pres_record.id);
        assert_eq!(
            storage_record.tags.get("holder"),
            Some(&"did:example:holder".to_string())
        );
        assert_eq!(
            storage_record.tags.get("verifier"),
            Some(&"did:example:verifier".to_string())
        );
        assert_eq!(
            storage_record.tags.get("purpose"),
            Some(&"authentication".to_string())
        );
        assert_eq!(
            storage_record.tags.get("format"),
            Some(&"jwt-vp".to_string())
        );
        assert_eq!(
            storage_record.tags.get("tag:important"),
            Some(&"true".to_string())
        );

        // Test round-trip
        let recovered = PresentationRecord::from_storage_record(&storage_record).unwrap();
        assert_eq!(recovered.id, pres_record.id);
        assert_eq!(recovered.format, pres_record.format);
    }
}
