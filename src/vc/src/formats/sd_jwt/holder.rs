use chrono::Utc;
use serde_json::{json, Value};
/// SD-JWT Holder for creating presentations with selective disclosure
use std::sync::Arc;

use agent_core::traits::WalletProvider;

use super::disclosure::{Disclosure, DisclosureFrame};
use super::hasher::SdJwtHasher;
use super::types::{KeyBindingJwt, SdJwtError, SdJwtVc};
use crate::formats::jwt_vc::WalletBackedJwtVcService;

/// SD-JWT Holder
pub struct SdJwtHolder {
    hasher: SdJwtHasher,
    jwt_service: WalletBackedJwtVcService,
}

impl SdJwtHolder {
    /// Create a new SD-JWT holder
    pub fn new(wallet: Arc<dyn WalletProvider>) -> Self {
        let hasher = SdJwtHasher::default();
        let jwt_service = WalletBackedJwtVcService::new(wallet.clone());

        Self {
            hasher,
            jwt_service,
        }
    }

    /// Create a presentation from an SD-JWT VC with selected disclosures
    pub async fn create_presentation(
        &self,
        sd_jwt_vc: &SdJwtVc,
        disclosure_frame: &DisclosureFrame,
        nonce: Option<String>,
        audience: Option<String>,
        holder_key_id: Option<String>,
    ) -> Result<SdJwtVc, Box<dyn std::error::Error + Send + Sync>> {
        // Select disclosures based on frame
        let selected_disclosures =
            self.select_disclosures(&sd_jwt_vc.disclosures, disclosure_frame)?;

        // The KB-JWT's sd_hash must cover the PRESENTED form (selected
        // disclosures only, without the KB-JWT) — not the full issued
        // credential, or the verifier's hash can never match.
        let mut presentation = SdJwtVc {
            jwt: sd_jwt_vc.jwt.clone(),
            disclosures: selected_disclosures,
            key_binding_jwt: None,
        };

        // Create key binding JWT if holder key is provided
        presentation.key_binding_jwt = if let Some(key_id) = holder_key_id {
            if let (Some(nonce), Some(aud)) = (nonce, audience) {
                Some(
                    self.create_key_binding_jwt(
                        &presentation.kb_hash_input(),
                        &key_id,
                        &nonce,
                        &aud,
                    )
                    .await?,
                )
            } else {
                None
            }
        } else {
            None
        };

        Ok(presentation)
    }

    /// Select disclosures based on disclosure frame
    fn select_disclosures(
        &self,
        all_disclosures: &[String],
        frame: &DisclosureFrame,
    ) -> Result<Vec<String>, SdJwtError> {
        // Decode all disclosures to understand what they contain
        let decoded: Vec<(String, Disclosure)> = all_disclosures
            .iter()
            .map(|encoded| Disclosure::decode(encoded).map(|d| (encoded.clone(), d)))
            .collect::<Result<Vec<_>, _>>()?;

        // Filter based on frame
        let selected = decoded
            .into_iter()
            .filter(|(_, disclosure)| self.should_include_disclosure(disclosure, frame))
            .map(|(encoded, _)| encoded)
            .collect();

        Ok(selected)
    }

    /// Check if a disclosure should be included based on frame
    fn should_include_disclosure(&self, disclosure: &Disclosure, frame: &DisclosureFrame) -> bool {
        match frame {
            DisclosureFrame::Boolean(true) => true,   // Include all
            DisclosureFrame::Boolean(false) => false, // Include none
            DisclosureFrame::Object(map) => {
                // Check if this disclosure's claim is in the frame
                if let Some(claim_name) = &disclosure.claim_name {
                    map.contains_key(claim_name)
                } else {
                    false
                }
            }
            DisclosureFrame::Array(_) => {
                // Array disclosures need more context
                // For simplicity, include if frame is not false
                true
            }
        }
    }

    /// Create a key binding JWT
    async fn create_key_binding_jwt(
        &self,
        sd_jwt: &str,
        holder_key_id: &str,
        nonce: &str,
        audience: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Hash the SD-JWT
        let sd_hash = self.hasher.hash_sd_jwt(sd_jwt);

        // Create key binding claims
        let kb_claims = KeyBindingJwt {
            nonce: nonce.to_string(),
            aud: audience.to_string(),
            iat: Utc::now().timestamp(),
            sd_hash,
            additional: std::collections::HashMap::new(),
        };

        use crate::core::SignatureAlgorithm;

        // Create header for key binding JWT
        let header = json!({
            "typ": "kb+jwt",
            "alg": "EdDSA",
        });

        // Convert to JSON for signing
        let payload = serde_json::to_value(&kb_claims)?;

        // Sign with holder's key
        self.jwt_service
            .sign_jwt(&header, &payload, holder_key_id, SignatureAlgorithm::EdDSA)
            .await
    }

    /// Parse and validate a received SD-JWT VC
    pub fn parse_sd_jwt_vc(&self, compact: &str) -> Result<SdJwtVc, SdJwtError> {
        SdJwtVc::from_compact(compact)
    }

    /// Get all disclosed claims from an SD-JWT VC
    pub fn get_disclosed_claims(
        &self,
        sd_jwt_vc: &SdJwtVc,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        use super::disclosure::DisclosureProcessor;

        // Parse the JWT to get the base claims
        let parts: Vec<&str> = sd_jwt_vc.jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(Box::new(SdJwtError::InvalidFormat(
                "Invalid JWT format".to_string(),
            )));
        }

        // Decode the payload
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
        let payload: Value = serde_json::from_slice(&payload_bytes)?;

        // Apply disclosures
        let processor = DisclosureProcessor::new(self.hasher.clone());
        let disclosed = processor.apply_disclosures(&payload, &sd_jwt_vc.disclosures)?;

        Ok(disclosed)
    }
}

/// Builder for creating presentations with specific requirements
pub struct PresentationBuilder {
    sd_jwt_vc: SdJwtVc,
    disclosure_paths: Vec<Vec<String>>,
    nonce: Option<String>,
    audience: Option<String>,
    holder_key_id: Option<String>,
}

impl PresentationBuilder {
    /// Create a new presentation builder
    pub fn new(sd_jwt_vc: SdJwtVc) -> Self {
        Self {
            sd_jwt_vc,
            disclosure_paths: Vec::new(),
            nonce: None,
            audience: None,
            holder_key_id: None,
        }
    }

    /// Add a claim path to disclose
    pub fn disclose_claim(mut self, path: Vec<String>) -> Self {
        self.disclosure_paths.push(path);
        self
    }

    /// Set the nonce for freshness
    pub fn with_nonce(mut self, nonce: String) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set the audience (verifier)
    pub fn with_audience(mut self, audience: String) -> Self {
        self.audience = Some(audience);
        self
    }

    /// Set the holder's key ID for binding
    pub fn with_holder_key(mut self, key_id: String) -> Self {
        self.holder_key_id = Some(key_id);
        self
    }

    /// Build the presentation
    pub async fn build(
        self,
        holder: &SdJwtHolder,
    ) -> Result<SdJwtVc, Box<dyn std::error::Error + Send + Sync>> {
        let frame = if self.disclosure_paths.is_empty() {
            DisclosureFrame::disclose_all()
        } else {
            DisclosureFrame::from_paths(&self.disclosure_paths)
        };

        holder
            .create_presentation(
                &self.sd_jwt_vc,
                &frame,
                self.nonce,
                self.audience,
                self.holder_key_id,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presentation_builder() {
        let sd_jwt_vc = SdJwtVc {
            jwt: "eyJ...".to_string(),
            disclosures: vec!["disc1".to_string(), "disc2".to_string()],
            key_binding_jwt: None,
        };

        let builder = PresentationBuilder::new(sd_jwt_vc)
            .disclose_claim(vec!["name".to_string()])
            .disclose_claim(vec!["address".to_string(), "city".to_string()])
            .with_nonce("nonce123".to_string())
            .with_audience("https://verifier.example".to_string())
            .with_holder_key("holder-key-1".to_string());

        assert!(builder.nonce.is_some());
        assert_eq!(builder.disclosure_paths.len(), 2);
    }
}
