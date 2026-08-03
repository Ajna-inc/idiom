//! OID4VCI Holder Service — receives credentials from OID4VCI issuers.
//!
//! Implements the full credential issuance flow:
//! 1. Parse credential offer (QR code / deep link)
//! 2. Fetch issuer metadata
//! 3. Exchange pre-authorized code for access token
//! 4. Get c_nonce for proof binding
//! 5. Build credential request (with AnonCreds blinded link secret or JWT proof)
//! 6. Send credential request
//! 7. Process credential response

use super::error::{Oid4vciError, Result};
use super::transport::Oid4vciTransport;
use super::types::*;

/// OID4VCI Holder Service
pub struct Oid4vciHolderService {
    transport: Oid4vciTransport,
}

impl Oid4vciHolderService {
    pub fn new() -> Result<Self> {
        Ok(Self {
            transport: Oid4vciTransport::new()?,
        })
    }

    /// Parse and resolve a credential offer URI.
    ///
    /// The offer URI can be:
    /// - `openid-credential-offer://...` deep link
    /// - `https://issuer.example.com/offer?credential_offer=...`
    /// - Raw JSON credential offer
    pub async fn resolve_credential_offer(
        &self,
        offer_input: &str,
    ) -> Result<ResolvedCredentialOffer> {
        // Parse the credential offer
        let offer = self.parse_offer(offer_input)?;

        // Fetch issuer metadata
        let metadata = self
            .transport
            .fetch_issuer_metadata(&offer.credential_issuer)
            .await?;

        // Resolve token endpoint
        let token_endpoint = if let Some(ref ep) = metadata.token_endpoint {
            ep.clone()
        } else if let Some(ref auth_server) = metadata.authorization_server {
            let auth_meta = self
                .transport
                .fetch_auth_server_metadata(auth_server)
                .await?;
            auth_meta.token_endpoint
        } else {
            format!("{}/token", offer.credential_issuer.trim_end_matches('/'))
        };

        // Match credential configurations
        let mut configurations = Vec::new();
        for config_id in &offer.credential_configuration_ids {
            if let Some(config) = metadata.credential_configurations_supported.get(config_id) {
                configurations.push((config_id.clone(), config.clone()));
            }
        }

        if configurations.is_empty() {
            return Err(Oid4vciError::InvalidOffer(
                "No matching credential configurations found".to_string(),
            ));
        }

        Ok(ResolvedCredentialOffer {
            offer,
            metadata,
            token_endpoint,
            configurations,
        })
    }

    /// Request a credential using the pre-authorized code flow.
    ///
    /// For AnonCreds: builds blinded link secret proof using c_nonce.
    /// For JWT/SD-JWT: builds JWT key-possession proof.
    pub async fn request_credential(
        &self,
        resolved: &ResolvedCredentialOffer,
        config_id: &str,
        proof_builder: &dyn ProofBuilder,
    ) -> Result<IssuedCredential> {
        // 1. Get pre-authorized code
        let pre_auth = resolved.offer.grants.pre_authorized_code.as_ref().ok_or(
            Oid4vciError::MissingParameter("pre-authorized_code grant required".to_string()),
        )?;

        // 2. Exchange for access token
        let token = self
            .transport
            .request_token(&resolved.token_endpoint, &pre_auth.pre_authorized_code)
            .await?;

        // 3. Get c_nonce (from token response or nonce endpoint)
        let c_nonce = if let Some(ref nonce) = token.c_nonce {
            nonce.clone()
        } else if let Some(ref nonce_ep) = resolved.metadata.nonce_endpoint {
            self.transport
                .request_nonce(nonce_ep, &token.access_token)
                .await?
        } else {
            return Err(Oid4vciError::NonceError(
                "No c_nonce available (not in token response, no nonce endpoint)".to_string(),
            ));
        };

        // 4. Find credential configuration
        let config = resolved
            .configurations
            .iter()
            .find(|(id, _)| id == config_id)
            .map(|(_, c)| c)
            .ok_or(Oid4vciError::InvalidOffer(format!(
                "Configuration '{}' not found",
                config_id
            )))?;

        // 5. Build credential proof
        let proof = proof_builder.build_proof(&c_nonce, config).await?;

        // 6. Send credential request
        let request = CredentialRequest {
            format: config.format.clone(),
            credential_identifier: Some(config_id.to_string()),
            proof: Some(proof),
        };

        let response = self
            .transport
            .request_credential(
                &resolved.metadata.credential_endpoint,
                &token.access_token,
                &request,
            )
            .await?;

        // 7. Return issued credential
        Ok(IssuedCredential {
            format: response.format.clone(),
            credential: response.credential,
            credential_id: None,
        })
    }

    /// Parse a credential offer from various input formats.
    fn parse_offer(&self, input: &str) -> Result<CredentialOffer> {
        let input = input.trim();

        // Try direct JSON first
        if input.starts_with('{') {
            return serde_json::from_str(input)
                .map_err(|e| Oid4vciError::InvalidOffer(format!("Invalid JSON: {}", e)));
        }

        // Try URI with credential_offer parameter
        if let Some(json_part) = input
            .split("credential_offer=")
            .nth(1)
            .and_then(|s| s.split('&').next())
        {
            let decoded = urlencoding::decode(json_part)
                .map_err(|e| Oid4vciError::InvalidOffer(format!("URL decode: {}", e)))?;
            return serde_json::from_str(&decoded)
                .map_err(|e| Oid4vciError::InvalidOffer(format!("Invalid offer JSON: {}", e)));
        }

        // Try credential_offer_uri parameter (needs HTTP fetch)
        if let Some(uri) = input
            .split("credential_offer_uri=")
            .nth(1)
            .and_then(|s| s.split('&').next())
        {
            // Would need async HTTP fetch — return error for now
            return Err(Oid4vciError::InvalidOffer(format!(
                "credential_offer_uri not yet supported: {}",
                uri
            )));
        }

        Err(Oid4vciError::InvalidOffer(
            "Could not parse credential offer from input".to_string(),
        ))
    }
}

/// Trait for building credential proofs.
/// Implemented by format-specific proof builders (AnonCreds, JWT, etc.)
#[async_trait::async_trait]
pub trait ProofBuilder: Send + Sync {
    async fn build_proof(
        &self,
        c_nonce: &str,
        config: &CredentialConfiguration,
    ) -> Result<CredentialProof>;
}
