use async_trait::async_trait;
use std::sync::Arc;

use crate::core::{CredentialError, CredentialFormat, Result as VcResult};
use agent_core::traits::{Query as StorageQuery, StorageProvider};

use crate::storage::credential_record::{CredentialRecord, CREDENTIAL_CATEGORY};

/// Query builder for credentials
#[derive(Debug, Clone, Default)]
pub struct CredentialQuery {
    /// Filter by issuer DID
    pub issuer: Option<String>,

    /// Filter by subject DID
    pub subject: Option<String>,

    /// Filter by credential format
    pub format: Option<CredentialFormat>,

    /// Filter by credential type (e.g., "UniversityDegreeCredential")
    pub credential_type: Option<String>,

    /// Filter by verification status
    pub verified: Option<bool>,

    /// Filter by user tags
    pub tags: Vec<String>,

    /// Filter by connection ID
    pub connection_id: Option<String>,

    /// Filter by source
    pub source: Option<String>,

    /// Maximum number of results
    pub limit: Option<usize>,

    /// Skip N results
    pub skip: Option<usize>,
}

impl CredentialQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn with_format(mut self, format: CredentialFormat) -> Self {
        self.format = Some(format);
        self
    }

    pub fn with_type(mut self, credential_type: impl Into<String>) -> Self {
        self.credential_type = Some(credential_type.into());
        self
    }

    pub fn with_verified(mut self, verified: bool) -> Self {
        self.verified = Some(verified);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_connection_id(mut self, connection_id: impl Into<String>) -> Self {
        self.connection_id = Some(connection_id.into());
        self
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_skip(mut self, skip: usize) -> Self {
        self.skip = Some(skip);
        self
    }

    /// Convert to storage query
    fn to_storage_query(&self) -> StorageQuery {
        let mut query = StorageQuery::new();

        if let Some(issuer) = &self.issuer {
            query = query.with_tag("issuer", issuer);
        }

        if let Some(subject) = &self.subject {
            query = query.with_tag("subject", subject);
        }

        if let Some(format) = &self.format {
            let format_tag = match format {
                CredentialFormat::JwtVc => "jwt-vc",
                CredentialFormat::JsonLd => "json-ld",
                CredentialFormat::SdJwt => "sd-jwt",
                CredentialFormat::Mdoc => "mdoc",
                CredentialFormat::AnonCreds => "anoncreds",
            };
            query = query.with_tag("format", format_tag);
        }

        if let Some(credential_type) = &self.credential_type {
            query = query.with_tag(format!("type:{}", credential_type), "true");
        }

        if let Some(verified) = &self.verified {
            query = query.with_tag("verified", verified.to_string());
        }

        for tag in &self.tags {
            query = query.with_tag(format!("tag:{}", tag), "true");
        }

        if let Some(connection_id) = &self.connection_id {
            query = query.with_tag("connection_id", connection_id);
        }

        if let Some(source) = &self.source {
            query = query.with_tag("source", source);
        }

        if let Some(limit) = self.limit {
            query = query.with_limit(limit);
        }

        if let Some(skip) = self.skip {
            query = query.with_skip(skip);
        }

        query
    }
}

/// Repository for credential storage operations
pub struct CredentialRepository {
    storage: Arc<dyn StorageProvider>,
}

impl CredentialRepository {
    /// Create a new credential repository
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self { storage }
    }

    /// Save a credential record
    pub async fn save(&self, record: &CredentialRecord) -> VcResult<()> {
        let storage_record = record
            .to_storage_record()
            .map_err(CredentialError::JsonError)?;

        self.storage
            .save(&storage_record)
            .await
            .map_err(|e| CredentialError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Find a credential by ID
    pub async fn find_by_id(&self, id: &str) -> VcResult<Option<CredentialRecord>> {
        let record = self
            .storage
            .find(CREDENTIAL_CATEGORY, id)
            .await
            .map_err(|e| CredentialError::StorageError(e.to_string()))?;

        match record {
            Some(r) => {
                let credential = CredentialRecord::from_storage_record(&r)
                    .map_err(CredentialError::JsonError)?;
                Ok(Some(credential))
            }
            None => Ok(None),
        }
    }

    /// Find all credentials matching a query
    pub async fn find_all(&self, query: &CredentialQuery) -> VcResult<Vec<CredentialRecord>> {
        let storage_query = query.to_storage_query();
        let records = self
            .storage
            .find_all(CREDENTIAL_CATEGORY, &storage_query)
            .await
            .map_err(|e| CredentialError::StorageError(e.to_string()))?;

        let credentials: Result<Vec<_>, _> = records
            .iter()
            .map(CredentialRecord::from_storage_record)
            .collect();

        credentials.map_err(CredentialError::JsonError)
    }

    /// Update a credential record
    pub async fn update(&self, record: &CredentialRecord) -> VcResult<()> {
        let storage_record = record
            .to_storage_record()
            .map_err(CredentialError::JsonError)?;

        self.storage
            .update(&storage_record)
            .await
            .map_err(|e| CredentialError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Delete a credential by ID
    pub async fn delete(&self, id: &str) -> VcResult<()> {
        self.storage
            .delete(CREDENTIAL_CATEGORY, id)
            .await
            .map_err(|e| CredentialError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Count credentials matching a query
    pub async fn count(&self, query: &CredentialQuery) -> VcResult<usize> {
        let storage_query = query.to_storage_query();
        let count = self
            .storage
            .count(CREDENTIAL_CATEGORY, &storage_query)
            .await
            .map_err(|e| CredentialError::StorageError(e.to_string()))?;

        Ok(count)
    }

    /// Find credentials by issuer
    pub async fn find_by_issuer(&self, issuer: &str) -> VcResult<Vec<CredentialRecord>> {
        let query = CredentialQuery::new().with_issuer(issuer);
        self.find_all(&query).await
    }

    /// Find credentials by subject
    pub async fn find_by_subject(&self, subject: &str) -> VcResult<Vec<CredentialRecord>> {
        let query = CredentialQuery::new().with_subject(subject);
        self.find_all(&query).await
    }

    /// Find verified credentials
    pub async fn find_verified(&self) -> VcResult<Vec<CredentialRecord>> {
        let query = CredentialQuery::new().with_verified(true);
        self.find_all(&query).await
    }

    /// Find credentials by connection
    pub async fn find_by_connection(&self, connection_id: &str) -> VcResult<Vec<CredentialRecord>> {
        let query = CredentialQuery::new().with_connection_id(connection_id);
        self.find_all(&query).await
    }

    /// Delete all credentials (use with caution!)
    pub async fn delete_all(&self) -> VcResult<()> {
        self.storage
            .delete_all(CREDENTIAL_CATEGORY)
            .await
            .map_err(|e| CredentialError::StorageError(e.to_string()))?;

        Ok(())
    }
}

/// Trait for credential storage operations
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// Save a credential
    async fn save_credential(&self, record: &CredentialRecord) -> VcResult<()>;

    /// Find a credential by ID
    async fn get_credential(&self, id: &str) -> VcResult<Option<CredentialRecord>>;

    /// Find credentials matching a query
    async fn query_credentials(&self, query: &CredentialQuery) -> VcResult<Vec<CredentialRecord>>;

    /// Update a credential
    async fn update_credential(&self, record: &CredentialRecord) -> VcResult<()>;

    /// Delete a credential
    async fn delete_credential(&self, id: &str) -> VcResult<()>;
}

#[async_trait]
impl CredentialStore for CredentialRepository {
    async fn save_credential(&self, record: &CredentialRecord) -> VcResult<()> {
        self.save(record).await
    }

    async fn get_credential(&self, id: &str) -> VcResult<Option<CredentialRecord>> {
        self.find_by_id(id).await
    }

    async fn query_credentials(&self, query: &CredentialQuery) -> VcResult<Vec<CredentialRecord>> {
        self.find_all(query).await
    }

    async fn update_credential(&self, record: &CredentialRecord) -> VcResult<()> {
        self.update(record).await
    }

    async fn delete_credential(&self, id: &str) -> VcResult<()> {
        self.delete(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_query_builder() {
        let query = CredentialQuery::new()
            .with_issuer("did:example:issuer")
            .with_subject("did:example:subject")
            .with_format(CredentialFormat::JwtVc)
            .with_type("UniversityDegreeCredential")
            .with_verified(true)
            .with_tag("important")
            .with_connection_id("conn-123")
            .with_limit(10);

        assert_eq!(query.issuer, Some("did:example:issuer".to_string()));
        assert_eq!(query.subject, Some("did:example:subject".to_string()));
        assert_eq!(query.format, Some(CredentialFormat::JwtVc));
        assert_eq!(
            query.credential_type,
            Some("UniversityDegreeCredential".to_string())
        );
        assert_eq!(query.verified, Some(true));
        assert_eq!(query.tags, vec!["important"]);
        assert_eq!(query.connection_id, Some("conn-123".to_string()));
        assert_eq!(query.limit, Some(10));
    }

    #[test]
    fn test_query_to_storage_query() {
        let query = CredentialQuery::new()
            .with_issuer("did:example:issuer")
            .with_format(CredentialFormat::SdJwt)
            .with_tag("test");

        let storage_query = query.to_storage_query();

        assert_eq!(
            storage_query.tags.get("issuer"),
            Some(&"did:example:issuer".to_string())
        );
        assert_eq!(
            storage_query.tags.get("format"),
            Some(&"sd-jwt".to_string())
        );
        assert_eq!(
            storage_query.tags.get("tag:test"),
            Some(&"true".to_string())
        );
    }
}
