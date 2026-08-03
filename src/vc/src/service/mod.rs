use std::collections::HashMap;
use std::sync::Arc;

use crate::core::{
    CredentialData, CredentialError, CredentialFormat, CredentialFormatService, Result as VcResult,
    SignCredentialOptions, VerificationResult, VerifyCredentialOptions, W3cCredential,
    W3cPresentation, W3cV2Credential,
};
use crate::formats::JwtVcService;
use crate::storage::{CredentialQuery, CredentialRecord, CredentialRepository};

/// Options for creating a presentation
#[derive(Debug, Clone, Default)]
pub struct CreatePresentationOptions {
    /// Holder DID or identifier
    pub holder: Option<String>,

    /// Challenge for the proof
    pub challenge: Option<String>,

    /// Domain for the proof
    pub domain: Option<String>,

    /// Presentation ID
    pub id: Option<String>,
}

/// Unified W3C Credential Service
///
/// This service provides a unified interface for working with W3C Verifiable Credentials
/// across multiple formats (JWT-VC, JSON-LD, SD-JWT, mDoc).
pub struct W3cCredentialService {
    /// Format-specific services
    format_services: HashMap<CredentialFormat, Arc<dyn CredentialFormatService>>,

    /// Credential storage
    storage: Arc<CredentialRepository>,
}

impl W3cCredentialService {
    /// Create a new credential service with default JWT-VC support
    pub fn new(storage: Arc<CredentialRepository>) -> Self {
        let mut format_services = HashMap::new();

        // Add JWT-VC service by default
        format_services.insert(
            CredentialFormat::JwtVc,
            Arc::new(JwtVcService::new()) as Arc<dyn CredentialFormatService>,
        );

        Self {
            format_services,
            storage,
        }
    }

    /// Builder pattern for creating a service with specific format support
    pub fn builder(storage: Arc<CredentialRepository>) -> W3cCredentialServiceBuilder {
        W3cCredentialServiceBuilder::new(storage)
    }

    /// Register a format service
    pub fn register_format_service(
        &mut self,
        format: CredentialFormat,
        service: Arc<dyn CredentialFormatService>,
    ) {
        self.format_services.insert(format, service);
    }

    /// Get a format service
    fn get_format_service(
        &self,
        format: CredentialFormat,
    ) -> VcResult<&Arc<dyn CredentialFormatService>> {
        self.format_services
            .get(&format)
            .ok_or_else(|| CredentialError::UnsupportedFormat(format!("{:?}", format)))
    }

    /// Detect credential format from a credential string
    fn detect_format(&self, credential: &str) -> Option<CredentialFormat> {
        // Try each format service to see if it can handle the credential
        for (format, service) in &self.format_services {
            if service.can_handle(credential) {
                return Some(*format);
            }
        }
        None
    }

    /// Sign a credential in the specified format
    pub async fn sign_credential(
        &self,
        credential: &W3cCredential,
        options: &SignCredentialOptions,
    ) -> VcResult<String> {
        let service = self.get_format_service(options.format)?;
        let signed = service.sign_credential(credential, options).await?;

        // Store the credential
        let record =
            CredentialRecord::from_credential(credential.clone(), options.format, signed.clone());
        self.storage.save(&record).await?;

        Ok(signed)
    }

    /// Sign a v2 credential in the specified format
    pub async fn sign_credential_v2(
        &self,
        credential: &W3cV2Credential,
        options: &SignCredentialOptions,
    ) -> VcResult<String> {
        let service = self.get_format_service(options.format)?;
        let signed = service.sign_credential_v2(credential, options).await?;

        // Store the credential
        let record = CredentialRecord::from_credential_v2(
            credential.clone(),
            options.format,
            signed.clone(),
        );
        self.storage.save(&record).await?;

        Ok(signed)
    }

    /// Verify a credential (auto-detects format)
    pub async fn verify_credential(
        &self,
        credential: &str,
        options: &VerifyCredentialOptions,
    ) -> VcResult<VerificationResult> {
        // Detect format
        let format = self.detect_format(credential).ok_or_else(|| {
            CredentialError::InvalidFormat("Unknown credential format".to_string())
        })?;

        // Get appropriate service
        let service = self.get_format_service(format)?;

        // Verify
        let result = service.verify_credential(credential, options).await?;

        // If valid, optionally update storage
        if result.is_valid {
            if let Some(cred_data) = &result.credential {
                // Try to find existing record by credential ID
                let cred_id = match cred_data {
                    CredentialData::V1(c) => c.id.as_ref(),
                    CredentialData::V2(c) => c.id.as_ref(),
                };

                if let Some(id) = cred_id {
                    if let Ok(Some(mut record)) = self.storage.find_by_id(id).await {
                        record.mark_verified();
                        if let Err(e) = self.storage.update(&record).await {
                            tracing::warn!(
                                credential_id = %id,
                                error = %e,
                                "failed to persist verified status for credential"
                            );
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Store a credential (with optional verification)
    pub async fn store_credential(
        &self,
        credential: &str,
        format: CredentialFormat,
        verify: bool,
    ) -> VcResult<String> {
        let mut record_id = None;

        if verify {
            let result = self
                .verify_credential(credential, &VerifyCredentialOptions::default())
                .await?;

            if !result.is_valid {
                return Err(CredentialError::SignatureVerificationFailed(
                    result.errors.join(", "),
                ));
            }

            // Create record from verified credential
            if let Some(cred_data) = result.credential {
                let mut record = match cred_data {
                    CredentialData::V1(c) => {
                        CredentialRecord::from_credential(c, format, credential.to_string())
                    }
                    CredentialData::V2(c) => {
                        CredentialRecord::from_credential_v2(c, format, credential.to_string())
                    }
                };

                record.mark_verified();
                record_id = Some(record.id.clone());
                self.storage.save(&record).await?;
            }
        } else {
            // Store without verification (parse first)
            let service = self.get_format_service(format)?;
            let result = service
                .verify_credential(credential, &VerifyCredentialOptions::default())
                .await?;

            if let Some(cred_data) = result.credential {
                let record = match cred_data {
                    CredentialData::V1(c) => {
                        CredentialRecord::from_credential(c, format, credential.to_string())
                    }
                    CredentialData::V2(c) => {
                        CredentialRecord::from_credential_v2(c, format, credential.to_string())
                    }
                };

                record_id = Some(record.id.clone());
                self.storage.save(&record).await?;
            }
        }

        record_id.ok_or_else(|| CredentialError::Other("Failed to store credential".to_string()))
    }

    /// Get a stored credential by ID
    pub async fn get_credential(&self, id: &str) -> VcResult<Option<CredentialRecord>> {
        self.storage.find_by_id(id).await
    }

    /// Query stored credentials
    pub async fn query_credentials(
        &self,
        query: &CredentialQuery,
    ) -> VcResult<Vec<CredentialRecord>> {
        self.storage.find_all(query).await
    }

    /// Delete a credential
    pub async fn delete_credential(&self, id: &str) -> VcResult<()> {
        self.storage.delete(id).await
    }

    /// Create a presentation from credentials
    pub async fn create_presentation(
        &self,
        credential_ids: Vec<String>,
        options: CreatePresentationOptions,
    ) -> VcResult<W3cPresentation> {
        // Retrieve credentials
        let mut credentials = Vec::new();
        for id in credential_ids {
            let record =
                self.storage.find_by_id(&id).await?.ok_or_else(|| {
                    CredentialError::Other(format!("Credential {} not found", id))
                })?;

            // Add raw credential to presentation
            credentials.push(crate::core::VerifiableCredential::Jwt(
                record.raw_credential,
            ));
        }

        // Build presentation
        let mut presentation = W3cPresentation::new();

        if let Some(holder) = options.holder {
            presentation = presentation.with_holder(holder);
        }

        if let Some(id) = options.id {
            presentation.id = Some(id);
        }

        for credential in credentials {
            presentation = presentation.add_credential(credential);
        }

        Ok(presentation)
    }

    /// Sign a presentation
    pub async fn sign_presentation(
        &self,
        presentation: &W3cPresentation,
        options: &SignCredentialOptions,
    ) -> VcResult<String> {
        let service = self.get_format_service(options.format)?;
        service
            .sign_presentation(presentation, options)
            .await
            .map_err(|e| CredentialError::Other(e.to_string()))
    }

    /// Verify a presentation
    pub async fn verify_presentation(
        &self,
        presentation: &str,
        options: &VerifyCredentialOptions,
    ) -> VcResult<VerificationResult> {
        // Detect format
        let format = self.detect_format(presentation).ok_or_else(|| {
            CredentialError::InvalidFormat("Unknown presentation format".to_string())
        })?;

        // Get appropriate service
        let service = self.get_format_service(format)?;

        // Verify
        service
            .verify_presentation(presentation, options)
            .await
            .map_err(|e| CredentialError::Other(e.to_string()))
    }
}

/// Builder for W3cCredentialService
pub struct W3cCredentialServiceBuilder {
    storage: Arc<CredentialRepository>,
    format_services: HashMap<CredentialFormat, Arc<dyn CredentialFormatService>>,
}

impl W3cCredentialServiceBuilder {
    pub fn new(storage: Arc<CredentialRepository>) -> Self {
        Self {
            storage,
            format_services: HashMap::new(),
        }
    }

    pub fn with_jwt_vc(mut self) -> Self {
        self.format_services
            .insert(CredentialFormat::JwtVc, Arc::new(JwtVcService::new()));
        self
    }

    pub fn with_format_service(
        mut self,
        format: CredentialFormat,
        service: Arc<dyn CredentialFormatService>,
    ) -> Self {
        self.format_services.insert(format, service);
        self
    }

    pub fn build(self) -> W3cCredentialService {
        W3cCredentialService {
            format_services: self.format_services,
            storage: self.storage,
        }
    }
}

// Type alias for backwards compatibility
pub type UnifiedCredentialService = W3cCredentialService;
pub type UnifiedCredentialServiceBuilder = W3cCredentialServiceBuilder;

#[cfg(test)]
mod tests {
    use super::*;

    use agent_core::traits::StorageProvider;
    use async_trait::async_trait;

    // Mock storage provider for testing
    struct MockStorage;

    #[async_trait]
    impl StorageProvider for MockStorage {
        async fn save(&self, _record: &agent_core::traits::Record) -> agent_core::Result<()> {
            Ok(())
        }

        async fn find(
            &self,
            _category: &str,
            _name: &str,
        ) -> agent_core::Result<Option<agent_core::traits::Record>> {
            Ok(None)
        }

        async fn find_all(
            &self,
            _category: &str,
            _query: &agent_core::traits::Query,
        ) -> agent_core::Result<Vec<agent_core::traits::Record>> {
            Ok(vec![])
        }

        async fn update(&self, _record: &agent_core::traits::Record) -> agent_core::Result<()> {
            Ok(())
        }

        async fn delete(&self, _category: &str, _name: &str) -> agent_core::Result<()> {
            Ok(())
        }

        async fn delete_all(&self, _category: &str) -> agent_core::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_service_creation() {
        let storage = Arc::new(MockStorage);
        let repo = Arc::new(CredentialRepository::new(storage));

        let service = W3cCredentialService::builder(repo).with_jwt_vc().build();

        assert!(service
            .format_services
            .contains_key(&CredentialFormat::JwtVc));
    }

    #[tokio::test]
    async fn test_format_detection() {
        let storage = Arc::new(MockStorage);
        let repo = Arc::new(CredentialRepository::new(storage));

        let service = W3cCredentialService::builder(repo).with_jwt_vc().build();

        // JWT format should be detected
        let jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
        assert_eq!(service.detect_format(jwt), Some(CredentialFormat::JwtVc));

        // Unknown format should return None
        assert_eq!(service.detect_format("not-a-credential"), None);
    }
}
