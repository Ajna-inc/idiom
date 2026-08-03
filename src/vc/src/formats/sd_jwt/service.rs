use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
/// SD-JWT Service implementing CredentialFormatService
use std::sync::Arc;

use crate::core::{
    CredentialData, CredentialFormat, CredentialFormatService, SignCredentialOptions,
    VerificationResult, VerifyCredentialOptions, W3cCredential, W3cPresentation,
};
use agent_core::traits::WalletProvider;
use did::registry::DidRegistry;

use super::compact::CompactSdJwt;
use super::disclosure::DisclosureFrame;
use super::holder::{PresentationBuilder, SdJwtHolder};
use super::issuer::SdJwtIssuer;
use super::types::SdJwtVc;
use super::verifier::{SdJwtVerifier, VerificationOptionsBuilder};

/// SD-JWT Service for credential operations
pub struct SdJwtService {
    issuer: SdJwtIssuer,
    holder: SdJwtHolder,
    verifier: SdJwtVerifier,
}

impl SdJwtService {
    /// Create a new SD-JWT service
    pub fn new(wallet: Arc<dyn WalletProvider>) -> Self {
        let issuer = SdJwtIssuer::new(wallet.clone());
        let holder = SdJwtHolder::new(wallet.clone());
        let verifier = SdJwtVerifier::new(wallet.clone());

        Self {
            issuer,
            holder,
            verifier,
        }
    }

    /// Create a new SD-JWT service with DID registry for real signature verification
    pub fn new_with_did_registry(
        wallet: Arc<dyn WalletProvider>,
        did_registry: Arc<DidRegistry>,
    ) -> Self {
        let issuer = SdJwtIssuer::new(wallet.clone());
        let holder = SdJwtHolder::new(wallet.clone());
        let verifier = SdJwtVerifier::new_with_did_registry(wallet.clone(), did_registry);

        Self {
            issuer,
            holder,
            verifier,
        }
    }

    /// Parse disclosure frame from options
    fn parse_disclosure_frame(&self, options: &SignCredentialOptions) -> DisclosureFrame {
        // Check for disclosure frame in additional options
        if let Some(frame_value) = options.additional.get("disclosureFrame") {
            if let Ok(frame) = serde_json::from_value::<DisclosureFrame>(frame_value.clone()) {
                return frame;
            }
        }

        // Check for disclosure paths
        if let Some(paths_value) = options.additional.get("disclosurePaths") {
            if let Some(paths_array) = paths_value.as_array() {
                let paths: Vec<Vec<String>> = paths_array
                    .iter()
                    .filter_map(|p| {
                        p.as_array().map(|arr| {
                            arr.iter()
                                .filter_map(|s| s.as_str().map(String::from))
                                .collect()
                        })
                    })
                    .collect();

                if !paths.is_empty() {
                    return DisclosureFrame::from_paths(&paths);
                }
            }
        }

        // Default: disclose nothing (issuer creates all as selectively disclosable)
        DisclosureFrame::disclose_none()
    }

    /// Extract holder binding key from options
    fn extract_holder_binding(&self, options: &SignCredentialOptions) -> Option<Value> {
        options.additional.get("holderBindingKey").cloned()
    }
}

#[async_trait]
impl CredentialFormatService for SdJwtService {
    /// Get the format this service handles
    fn format(&self) -> CredentialFormat {
        CredentialFormat::SdJwt
    }

    /// Check if this service can handle the given credential string
    fn can_handle(&self, credential: &str) -> bool {
        // SD-JWT uses tilde-separated format
        CompactSdJwt::validate_format(credential)
    }

    /// Sign a credential with selective disclosure
    async fn sign_credential(
        &self,
        credential: &W3cCredential,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Parse disclosure frame
        let disclosure_frame = self.parse_disclosure_frame(options);

        // Extract holder binding key if present
        let holder_binding = self.extract_holder_binding(options);

        // Issue the SD-JWT VC
        let sd_jwt_vc = self
            .issuer
            .issue_credential(
                credential,
                &disclosure_frame,
                &options.key_id,
                holder_binding,
            )
            .await?;

        // Return as compact format
        Ok(sd_jwt_vc.to_compact())
    }

    /// Verify a credential
    async fn verify_credential(
        &self,
        credential_string: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        // Parse from compact format
        let sd_jwt_vc = CompactSdJwt::decode(credential_string)?;

        // Build verification options
        let mut verify_options = VerificationOptionsBuilder::new();

        if let Some(aud) = options
            .additional
            .get("expectedAudience")
            .and_then(|v| v.as_str())
        {
            verify_options = verify_options.with_audience(aud.to_string());
        }

        if let Some(nonce) = options
            .additional
            .get("expectedNonce")
            .and_then(|v| v.as_str())
        {
            verify_options = verify_options.with_nonce(nonce.to_string());
        }

        if options
            .additional
            .get("requireKeyBinding")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            verify_options = verify_options.require_key_binding();
        }

        if let Some(max_age) = options
            .additional
            .get("maxKeyBindingAge")
            .and_then(|v| v.as_i64())
        {
            verify_options = verify_options.with_max_kb_age(max_age);
        }

        // Verify the SD-JWT
        let result = self
            .verifier
            .verify(&sd_jwt_vc, &verify_options.build())
            .await?;

        // Convert to VerificationResult
        let mut details = HashMap::new();
        details.insert("format".to_string(), json!("sd-jwt"));

        if let Some(disclosed) = &result.disclosed_claims {
            details.insert("disclosedClaims".to_string(), disclosed.clone());
        }

        if let Some(kb_valid) = result.holder_binding_valid {
            details.insert("holderBindingValid".to_string(), json!(kb_valid));
        }

        // Extract credential from disclosed claims if available
        let credential_data = result
            .disclosed_claims
            .as_ref()
            .and_then(|claims| claims.get("vc"))
            .and_then(|vc| serde_json::from_value::<W3cCredential>(vc.clone()).ok())
            .map(CredentialData::V1);

        Ok(VerificationResult {
            is_valid: result.is_valid,
            format: Some(CredentialFormat::SdJwt),
            credential: credential_data,
            errors: result.errors,
            details,
        })
    }

    /// Sign a presentation (create SD-JWT presentation with selected disclosures)
    async fn sign_presentation(
        &self,
        presentation: &W3cPresentation,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // For SD-JWT, we expect the presentation to contain an SD-JWT VC
        // Extract it from the verifiable_credential field

        let sd_jwt_compact = presentation
            .verifiable_credential
            .as_ref()
            .and_then(|vcs| vcs.first())
            .and_then(|vc| match vc {
                crate::core::VerifiableCredential::Jwt(jwt) => Some(jwt.clone()),
                _ => None,
            })
            .ok_or("No SD-JWT found in presentation")?;

        // Parse the SD-JWT
        let sd_jwt_vc = CompactSdJwt::decode(&sd_jwt_compact)?;

        // Build presentation with selected disclosures
        let mut builder = PresentationBuilder::new(sd_jwt_vc);

        // Add disclosure paths from options
        if let Some(paths_value) = options.additional.get("disclosurePaths") {
            if let Some(paths_array) = paths_value.as_array() {
                for path_value in paths_array {
                    if let Some(path) = path_value.as_array() {
                        let path_strings: Vec<String> = path
                            .iter()
                            .filter_map(|s| s.as_str().map(String::from))
                            .collect();
                        builder = builder.disclose_claim(path_strings);
                    }
                }
            }
        }

        // Add nonce if provided
        if let Some(nonce) = options.additional.get("nonce").and_then(|v| v.as_str()) {
            builder = builder.with_nonce(nonce.to_string());
        }

        // Add audience if provided
        if let Some(audience) = options.additional.get("audience").and_then(|v| v.as_str()) {
            builder = builder.with_audience(audience.to_string());
        }

        // Add holder key for binding
        if options
            .additional
            .get("includeKeyBinding")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            builder = builder.with_holder_key(options.key_id.clone());
        }

        // Build the presentation
        let presentation_sd_jwt = builder.build(&self.holder).await?;

        // Return as compact format
        Ok(presentation_sd_jwt.to_compact())
    }

    /// Verify a presentation
    async fn verify_presentation(
        &self,
        presentation_string: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        // For SD-JWT, presentation verification is the same as credential verification
        // The difference is in the expected claims and key binding
        self.verify_credential(presentation_string, options).await
    }
}

/// Helper functions for SD-JWT operations
impl SdJwtService {
    /// Create an SD-JWT with custom claims
    pub async fn create_sd_jwt(
        &self,
        claims: Value,
        disclosure_frame: &DisclosureFrame,
        issuer_key_id: &str,
        holder_binding_key: Option<Value>,
    ) -> Result<SdJwtVc, Box<dyn std::error::Error + Send + Sync>> {
        self.issuer
            .issue(claims, disclosure_frame, issuer_key_id, holder_binding_key)
            .await
    }

    /// Parse and get disclosed claims from an SD-JWT
    pub fn get_disclosed_claims(
        &self,
        sd_jwt_compact: &str,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let sd_jwt_vc = CompactSdJwt::decode(sd_jwt_compact)?;
        self.holder.get_disclosed_claims(&sd_jwt_vc)
    }

    /// Create a presentation from an SD-JWT VC
    pub async fn create_presentation(
        &self,
        sd_jwt_compact: &str,
        disclosure_paths: Vec<Vec<String>>,
        nonce: Option<String>,
        audience: Option<String>,
        holder_key_id: Option<String>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let sd_jwt_vc = CompactSdJwt::decode(sd_jwt_compact)?;
        let frame = DisclosureFrame::from_paths(&disclosure_paths);

        let presentation = self
            .holder
            .create_presentation(&sd_jwt_vc, &frame, nonce, audience, holder_key_id)
            .await?;

        Ok(presentation.to_compact())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disclosure_frame_parsing() {
        let service = SdJwtService::new(Arc::new(MockWallet));

        let mut options = SignCredentialOptions {
            format: CredentialFormat::SdJwt,
            key_id: "test-key".to_string(),
            algorithm: None,
            proof_purpose: None,
            additional: HashMap::new(),
        };

        // Test with disclosure paths
        options.additional.insert(
            "disclosurePaths".to_string(),
            json!([["name"], ["address", "city"]]),
        );

        let frame = service.parse_disclosure_frame(&options);
        // Would need more detailed testing with actual frame structure
        assert!(matches!(frame, DisclosureFrame::Object(_)));
    }

    // Mock wallet for testing
    struct MockWallet;

    #[async_trait]
    impl WalletProvider for MockWallet {
        async fn create_key(
            &self,
            _key_type: agent_core::traits::KeyType,
            _purpose: agent_core::traits::KeyPurpose,
        ) -> Result<agent_core::traits::Key, agent_core::error::AgentError> {
            unimplemented!()
        }

        async fn get_key(
            &self,
            _key_id: &str,
        ) -> Result<Option<agent_core::traits::Key>, agent_core::error::AgentError> {
            unimplemented!()
        }

        async fn list_keys(
            &self,
        ) -> Result<Vec<agent_core::traits::Key>, agent_core::error::AgentError> {
            unimplemented!()
        }

        async fn delete_key(&self, _key_id: &str) -> Result<(), agent_core::error::AgentError> {
            unimplemented!()
        }

        async fn sign(
            &self,
            _key_id: &str,
            _data: &[u8],
        ) -> Result<agent_core::traits::Signature, agent_core::error::AgentError> {
            unimplemented!()
        }

        async fn verify(
            &self,
            _key_id: &str,
            _data: &[u8],
            _signature: &[u8],
        ) -> Result<bool, agent_core::error::AgentError> {
            unimplemented!()
        }

        async fn get_secret_bytes(
            &self,
            _key_id: &str,
        ) -> Result<Vec<u8>, agent_core::error::AgentError> {
            unimplemented!()
        }
    }
}
