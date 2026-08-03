use chrono::Utc;
use serde_json::{json, Value};
/// SD-JWT Issuer for creating selectively disclosable JWTs
use std::sync::Arc;

use crate::core::models::{Issuer as VcIssuer, W3cCredential};
use agent_core::traits::WalletProvider;

use super::disclosure::{DisclosureFrame, DisclosureProcessor};
use super::hasher::SdJwtHasher;
use super::types::{SdJwtClaims, SdJwtError, SdJwtVc};
use crate::formats::jwt_vc::WalletBackedJwtVcService;

/// SD-JWT Issuer
pub struct SdJwtIssuer {
    hasher: SdJwtHasher,
    jwt_service: WalletBackedJwtVcService,
}

impl SdJwtIssuer {
    /// Create a new SD-JWT issuer
    pub fn new(wallet: Arc<dyn WalletProvider>) -> Self {
        let hasher = SdJwtHasher::default();
        let jwt_service = WalletBackedJwtVcService::new(wallet.clone());

        Self {
            hasher,
            jwt_service,
        }
    }

    /// Issue an SD-JWT VC from a W3C credential
    pub async fn issue_credential(
        &self,
        credential: &W3cCredential,
        disclosure_frame: &DisclosureFrame,
        issuer_key_id: &str,
        holder_binding_key: Option<Value>, // JWK for cnf claim
    ) -> Result<SdJwtVc, Box<dyn std::error::Error + Send + Sync>> {
        // Convert credential to claims
        let mut claims = self.credential_to_claims(credential)?;

        // Add holder binding if provided
        if let Some(jwk) = holder_binding_key {
            claims.insert("cnf".to_string(), json!({ "jwk": jwk }));
        }

        // Process selective disclosure
        let processor = DisclosureProcessor::new(self.hasher.clone());
        let (processed_claims, disclosures) =
            processor.process_claims(&json!(claims), disclosure_frame)?;

        // Convert to SdJwtClaims
        let sd_jwt_claims = self.to_sd_jwt_claims(processed_claims)?;

        // Sign the JWT
        let jwt = self.sign_sd_jwt(&sd_jwt_claims, issuer_key_id).await?;

        // Encode disclosures
        let encoded_disclosures: Vec<String> = disclosures.iter().map(|d| d.encode()).collect();

        Ok(SdJwtVc {
            jwt,
            disclosures: encoded_disclosures,
            key_binding_jwt: None, // Holder will add this
        })
    }

    /// Issue a simple SD-JWT with custom claims
    pub async fn issue(
        &self,
        claims: Value,
        disclosure_frame: &DisclosureFrame,
        issuer_key_id: &str,
        holder_binding_key: Option<Value>,
    ) -> Result<SdJwtVc, Box<dyn std::error::Error + Send + Sync>> {
        // Process selective disclosure
        let processor = DisclosureProcessor::new(self.hasher.clone());
        let (mut processed_claims, disclosures) =
            processor.process_claims(&claims, disclosure_frame)?;

        // Add holder binding if provided
        if let Some(jwk) = holder_binding_key {
            if let Value::Object(ref mut map) = processed_claims {
                map.insert("cnf".to_string(), json!({ "jwk": jwk }));
            }
        }

        // Convert to SdJwtClaims
        let sd_jwt_claims = self.to_sd_jwt_claims(processed_claims)?;

        // Sign the JWT
        let jwt = self.sign_sd_jwt(&sd_jwt_claims, issuer_key_id).await?;

        // Encode disclosures
        let encoded_disclosures: Vec<String> = disclosures.iter().map(|d| d.encode()).collect();

        Ok(SdJwtVc {
            jwt,
            disclosures: encoded_disclosures,
            key_binding_jwt: None,
        })
    }

    /// Convert W3C credential to claims
    fn credential_to_claims(
        &self,
        credential: &W3cCredential,
    ) -> Result<serde_json::Map<String, Value>, SdJwtError> {
        let mut claims = serde_json::Map::new();

        // Standard JWT claims
        if let VcIssuer::String(iss) = &credential.issuer {
            claims.insert("iss".to_string(), json!(iss));
        }

        if let Some(id) = &credential.id {
            claims.insert("jti".to_string(), json!(id));
        }

        claims.insert("iat".to_string(), json!(Utc::now().timestamp()));
        claims.insert(
            "nbf".to_string(),
            json!(credential.issuance_date.timestamp()),
        );

        if let Some(exp) = credential.expiration_date {
            claims.insert("exp".to_string(), json!(exp.timestamp()));
        }

        // VC claims
        let vc_claims = json!({
            "@context": credential.context,
            "type": credential.type_,
            "credentialSubject": credential.credential_subject,
        });

        claims.insert("vc".to_string(), vc_claims);

        Ok(claims)
    }

    /// Convert processed claims to SdJwtClaims
    fn to_sd_jwt_claims(&self, processed: Value) -> Result<SdJwtClaims, SdJwtError> {
        if let Value::Object(map) = processed {
            let mut sd_jwt_claims = SdJwtClaims {
                iss: map.get("iss").and_then(|v| v.as_str()).map(String::from),
                sub: map.get("sub").and_then(|v| v.as_str()).map(String::from),
                aud: map.get("aud").and_then(|v| v.as_str()).map(String::from),
                exp: map.get("exp").and_then(|v| v.as_i64()),
                nbf: map.get("nbf").and_then(|v| v.as_i64()),
                iat: map.get("iat").and_then(|v| v.as_i64()),
                jti: map.get("jti").and_then(|v| v.as_str()).map(String::from),
                sd: map.get("_sd").and_then(|v| {
                    v.as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                }),
                sd_alg: map
                    .get("_sd_alg")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                cnf: map.get("cnf").cloned(),
                vc: map.get("vc").cloned(),
                additional: std::collections::HashMap::new(),
            };

            // Add remaining claims to additional
            for (key, value) in map {
                if ![
                    "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "_sd", "_sd_alg", "cnf", "vc",
                ]
                .contains(&key.as_str())
                {
                    sd_jwt_claims.additional.insert(key, value);
                }
            }

            Ok(sd_jwt_claims)
        } else {
            Err(SdJwtError::InvalidFormat(
                "Claims must be an object".to_string(),
            ))
        }
    }

    /// Sign the SD-JWT
    async fn sign_sd_jwt(
        &self,
        claims: &SdJwtClaims,
        key_id: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        use crate::core::SignatureAlgorithm;

        // Create header
        let header = json!({
            "typ": "sd+jwt",
            "alg": "EdDSA",
        });

        // Convert claims to JSON for signing
        let payload = serde_json::to_value(claims)?;

        // Use the wallet JWT service with proper parameters
        self.jwt_service
            .sign_jwt(&header, &payload, key_id, SignatureAlgorithm::EdDSA)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_issue_simple_sd_jwt() {
        // This would need a mock wallet for testing
        // For now, we just test the structure

        let _claims = json!({
            "name": "Alice",
            "age": 30,
            "address": {
                "street": "123 Main St",
                "city": "Springfield"
            }
        });

        let _frame = DisclosureFrame::from_paths(&[
            vec!["name".to_string()],
            vec!["address".to_string(), "street".to_string()],
        ]);

        // Test would continue with mock wallet...
    }
}
