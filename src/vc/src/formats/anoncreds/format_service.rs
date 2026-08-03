use async_trait::async_trait;
/// AnonCreds format service implementing CredentialFormatService
///
/// AnonCreds credentials are not W3C VCs — they use CL signatures with
/// zero-knowledge proofs. This service bridges the two models:
///
/// - sign_credential: Creates an AnonCreds credential (returns JSON string)
/// - verify_credential: Verifies an AnonCreds presentation
/// - The `additional` HashMap carries AnonCreds-specific parameters
use std::sync::Arc;

use crate::core::{
    CredentialFormat, CredentialFormatService, SignCredentialOptions, VerificationResult,
    VerifyCredentialOptions, W3cCredential, W3cPresentation,
};

use anoncreds_core::{AnonCredsHolderService, AnonCredsIssuerService, AnonCredsVerifierService};

/// AnonCreds format service that bridges W3C VC API with AnonCreds operations.
pub struct AnonCredsFormatService {
    issuer: Arc<AnonCredsIssuerService>,
    holder: Arc<AnonCredsHolderService>,
    verifier: Arc<AnonCredsVerifierService>,
}

impl AnonCredsFormatService {
    pub fn new(
        issuer: Arc<AnonCredsIssuerService>,
        holder: Arc<AnonCredsHolderService>,
        verifier: Arc<AnonCredsVerifierService>,
    ) -> Self {
        Self {
            issuer,
            holder,
            verifier,
        }
    }

    /// Get reference to the issuer service
    pub fn issuer(&self) -> &AnonCredsIssuerService {
        &self.issuer
    }

    /// Get reference to the holder service
    pub fn holder(&self) -> &AnonCredsHolderService {
        &self.holder
    }

    /// Get reference to the verifier service
    pub fn verifier(&self) -> &AnonCredsVerifierService {
        &self.verifier
    }
}

#[async_trait]
impl CredentialFormatService for AnonCredsFormatService {
    fn format(&self) -> CredentialFormat {
        CredentialFormat::AnonCreds
    }

    /// AnonCreds "signing" creates a credential using the issuer service.
    ///
    /// Expected `additional` keys in options:
    /// - `schema_id`: Schema ID
    /// - `cred_def_id`: Credential Definition ID
    /// - `cred_offer`: Serialized CredentialOffer JSON
    /// - `cred_request`: Serialized CredentialRequest JSON
    /// - `attributes`: JSON object of name->value pairs
    async fn sign_credential(
        &self,
        _credential: &W3cCredential,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let cred_def_id = options
            .additional
            .get("cred_def_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing cred_def_id in additional options")?;

        let cred_offer_json = options
            .additional
            .get("cred_offer")
            .ok_or("Missing cred_offer in additional options")?;
        let cred_offer: anoncreds_core::types::CredentialOffer =
            serde_json::from_value(cred_offer_json.clone())?;

        let cred_request_json = options
            .additional
            .get("cred_request")
            .ok_or("Missing cred_request in additional options")?;
        let cred_request: anoncreds_core::types::CredentialRequest =
            serde_json::from_value(cred_request_json.clone())?;

        let attrs_json = options
            .additional
            .get("attributes")
            .ok_or("Missing attributes in additional options")?;
        let attributes: std::collections::HashMap<String, String> =
            serde_json::from_value(attrs_json.clone())?;

        let credential = self
            .issuer
            .create_credential(cred_def_id, &cred_offer, &cred_request, attributes)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        Ok(serde_json::to_string(&credential)?)
    }

    /// Verify an AnonCreds presentation.
    ///
    /// The `credential` string should be a serialized AnonCreds Presentation JSON.
    /// Expected `additional` keys in options:
    /// - `pres_request`: Serialized PresentationRequest JSON
    async fn verify_credential(
        &self,
        credential: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        let pres_request_json = options
            .additional
            .get("pres_request")
            .ok_or("Missing pres_request in additional options")?;
        let pres_request: anoncreds_core::types::PresentationRequest =
            serde_json::from_value(pres_request_json.clone())?;

        let presentation: anoncreds_core::types::Presentation = serde_json::from_str(credential)?;

        let valid = self
            .verifier
            .verify_presentation(&presentation, &pres_request)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        if valid {
            Ok(VerificationResult {
                is_valid: true,
                format: Some(CredentialFormat::AnonCreds),
                credential: None, // AnonCreds doesn't map to W3C CredentialData
                errors: Vec::new(),
                details: std::collections::HashMap::new(),
            })
        } else {
            Ok(VerificationResult::invalid(
                "AnonCreds presentation verification failed",
            ))
        }
    }

    /// Sign a presentation (create AnonCreds proof).
    ///
    /// Expected `additional` keys in options:
    /// - `pres_request`: Serialized PresentationRequest JSON
    /// - `credential_map`: JSON object mapping referent -> [credential_id, revealed]
    async fn sign_presentation(
        &self,
        _presentation: &W3cPresentation,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let pres_request_json = options
            .additional
            .get("pres_request")
            .ok_or("Missing pres_request in additional options")?;
        let pres_request: anoncreds_core::types::PresentationRequest =
            serde_json::from_value(pres_request_json.clone())?;

        let cred_map_json = options
            .additional
            .get("credential_map")
            .ok_or("Missing credential_map in additional options")?;
        let credential_map: std::collections::HashMap<String, (String, bool)> =
            serde_json::from_value(cred_map_json.clone())?;

        let presentation = self
            .holder
            .create_presentation(&pres_request, &credential_map, None)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        Ok(serde_json::to_string(&presentation)?)
    }

    /// Verify a presentation
    async fn verify_presentation(
        &self,
        presentation: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        // Delegate to verify_credential which handles AnonCreds presentations
        self.verify_credential(presentation, options).await
    }

    /// Check if the given string looks like an AnonCreds credential/presentation
    fn can_handle(&self, credential: &str) -> bool {
        // AnonCreds credentials have schema_id and cred_def_id at the top level
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(credential) {
            value.get("schema_id").is_some() && value.get("cred_def_id").is_some()
        } else {
            false
        }
    }
}
