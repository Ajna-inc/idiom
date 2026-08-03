use serde_json::{json, Value};
/// Cross-format transformation between credential formats
/// Enables conversion between JWT-VC, JSON-LD, and other formats
use std::sync::Arc;

use crate::core::{
    CredentialFormat, CredentialFormatService, CredentialSubject, CredentialSubjectObject,
    SignCredentialOptions, W3cCredential,
};
use agent_core::traits::WalletProvider;
use did::registry::DidRegistry;

use crate::formats::jsonld_vc::JsonLdVcService;
use crate::formats::jwt_vc::EnhancedJwtVcServiceV2;

/// Error types for format transformation
#[derive(Debug, thiserror::Error)]
pub enum TransformError {
    #[error("Unsupported source format: {0:?}")]
    UnsupportedSourceFormat(CredentialFormat),

    #[error("Unsupported target format: {0:?}")]
    UnsupportedTargetFormat(CredentialFormat),

    #[error("Invalid JWT format: {0}")]
    InvalidJwt(String),

    #[error("Invalid JSON-LD format: {0}")]
    InvalidJsonLd(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Transformation error: {0}")]
    TransformationError(String),
}

/// Format transformer for converting between credential formats
pub struct FormatTransformer {
    jwt_service: EnhancedJwtVcServiceV2,
    jsonld_service: Option<JsonLdVcService>,
}

impl FormatTransformer {
    /// Create a new format transformer with JWT-VC support
    pub fn new(wallet: Arc<dyn WalletProvider>, did_registry: Arc<DidRegistry>) -> Self {
        Self {
            jwt_service: EnhancedJwtVcServiceV2::new_with_did_registry(
                wallet.clone(),
                did_registry,
            ),
            jsonld_service: None, // Will be added when JSON-LD service is ready
        }
    }

    /// Transform a credential from one format to another
    pub async fn transform(
        &self,
        credential: &str,
        source_format: CredentialFormat,
        target_format: CredentialFormat,
        sign_options: &SignCredentialOptions,
    ) -> Result<String, TransformError> {
        // If formats are the same, return as-is
        if source_format == target_format {
            return Ok(credential.to_string());
        }

        match (source_format, target_format) {
            (CredentialFormat::JwtVc, CredentialFormat::JwtVc) => Ok(credential.to_string()),
            (CredentialFormat::JwtVc, CredentialFormat::JsonLd) => {
                self.jwt_to_jsonld(credential, sign_options).await
            }
            (CredentialFormat::JsonLd, CredentialFormat::JwtVc) => {
                self.jsonld_to_jwt(credential, sign_options).await
            }
            _ => Err(TransformError::UnsupportedTargetFormat(target_format)),
        }
    }

    /// Convert JWT-VC to JSON-LD VC
    async fn jwt_to_jsonld(
        &self,
        jwt: &str,
        _sign_options: &SignCredentialOptions,
    ) -> Result<String, TransformError> {
        // 1. Decode JWT and extract W3C credential
        let w3c_credential = self.decode_jwt_to_w3c(jwt)?;

        // 2. Convert to JSON-LD format (add @context, reorganize structure)
        let jsonld_doc = self.w3c_to_jsonld_document(&w3c_credential)?;

        // 3. If JSON-LD service is available, sign it
        if let Some(_jsonld_service) = &self.jsonld_service {
            // TODO: Sign with JSON-LD service when available
            Ok(serde_json::to_string_pretty(&jsonld_doc)
                .map_err(|e| TransformError::TransformationError(e.to_string()))?)
        } else {
            // Return unsigned JSON-LD document
            Ok(serde_json::to_string_pretty(&jsonld_doc)
                .map_err(|e| TransformError::TransformationError(e.to_string()))?)
        }
    }

    /// Convert JSON-LD VC to JWT-VC
    async fn jsonld_to_jwt(
        &self,
        jsonld: &str,
        sign_options: &SignCredentialOptions,
    ) -> Result<String, TransformError> {
        // 1. Parse JSON-LD document
        let jsonld_doc: Value = serde_json::from_str(jsonld)
            .map_err(|e| TransformError::InvalidJsonLd(e.to_string()))?;

        // 2. Extract W3C credential from JSON-LD
        let w3c_credential = self.jsonld_document_to_w3c(&jsonld_doc)?;

        // 3. Sign as JWT-VC
        let jwt = self
            .jwt_service
            .sign_credential(&w3c_credential, sign_options)
            .await
            .map_err(|e| TransformError::TransformationError(e.to_string()))?;

        Ok(jwt)
    }

    /// Decode JWT to W3C credential
    fn decode_jwt_to_w3c(&self, jwt: &str) -> Result<W3cCredential, TransformError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        // Split JWT into parts
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(TransformError::InvalidJwt(
                "JWT must have 3 parts".to_string(),
            ));
        }

        // Decode payload
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| TransformError::InvalidJwt(format!("Failed to decode payload: {}", e)))?;

        let payload: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| TransformError::InvalidJwt(format!("Failed to parse payload: {}", e)))?;

        // Extract issuer
        let issuer = payload
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TransformError::MissingField("iss".to_string()))?;

        // Extract vc claim
        let vc = payload
            .get("vc")
            .ok_or_else(|| TransformError::MissingField("vc".to_string()))?;

        // Extract credential subject
        let subject_value = vc
            .get("credentialSubject")
            .ok_or_else(|| TransformError::MissingField("credentialSubject".to_string()))?;

        let subject_id = subject_value
            .get("id")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Extract all claims except 'id'
        let mut claims = std::collections::HashMap::new();
        if let Some(obj) = subject_value.as_object() {
            for (key, value) in obj {
                if key != "id" {
                    claims.insert(key.clone(), value.clone());
                }
            }
        }

        let credential_subject = CredentialSubjectObject {
            id: subject_id,
            claims,
        };

        Ok(W3cCredential::new(issuer, credential_subject))
    }

    /// Convert W3C credential to JSON-LD document
    fn w3c_to_jsonld_document(&self, credential: &W3cCredential) -> Result<Value, TransformError> {
        let mut doc = json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "type": ["VerifiableCredential"],
            "issuer": credential.issuer.to_string(),
            "issuanceDate": credential.issuance_date.to_rfc3339(),
            "credentialSubject": {}
        });

        // Add ID if present
        if let Some(id) = &credential.id {
            doc["id"] = json!(id);
        }

        // Add expiration if present
        if let Some(exp) = credential.expiration_date {
            doc["expirationDate"] = json!(exp.to_rfc3339());
        }

        // Add credential subject
        if let CredentialSubject::Single(subject) = &credential.credential_subject {
            let mut subject_obj = json!({});

            if let Some(id) = &subject.id {
                subject_obj["id"] = json!(id);
            }

            for (key, value) in &subject.claims {
                subject_obj[key] = value.clone();
            }

            doc["credentialSubject"] = subject_obj;
        }

        // Add proof if present
        if let Some(proof_one_or_many) = &credential.proof {
            // Handle OneOrMany<Proof>
            use crate::core::OneOrMany;
            match proof_one_or_many {
                OneOrMany::One(proof) => {
                    doc["proof"] = json!({
                        "type": proof.type_,
                        "created": proof.created.as_ref().map(|d| d.to_rfc3339()),
                        "verificationMethod": proof.verification_method,
                        "proofPurpose": proof.proof_purpose,
                        "proofValue": proof.proof_value
                    });
                }
                OneOrMany::Many(proofs) => {
                    let proof_array: Vec<Value> = proofs
                        .iter()
                        .map(|proof| {
                            json!({
                                "type": proof.type_,
                                "created": proof.created.as_ref().map(|d| d.to_rfc3339()),
                                "verificationMethod": proof.verification_method,
                                "proofPurpose": proof.proof_purpose,
                                "proofValue": proof.proof_value
                            })
                        })
                        .collect();
                    doc["proof"] = json!(proof_array);
                }
            }
        }

        Ok(doc)
    }

    /// Convert JSON-LD document to W3C credential
    fn jsonld_document_to_w3c(&self, doc: &Value) -> Result<W3cCredential, TransformError> {
        // Extract issuer
        let issuer_str = doc
            .get("issuer")
            .and_then(|v| v.as_str())
            .or_else(|| {
                doc.get("issuer")
                    .and_then(|v| v.get("id"))
                    .and_then(|v| v.as_str())
            })
            .ok_or_else(|| TransformError::MissingField("issuer".to_string()))?;

        // Extract credential subject
        let subject_value = doc
            .get("credentialSubject")
            .ok_or_else(|| TransformError::MissingField("credentialSubject".to_string()))?;

        let subject_id = subject_value
            .get("id")
            .and_then(|v| v.as_str())
            .map(String::from);

        let mut claims = std::collections::HashMap::new();
        if let Some(obj) = subject_value.as_object() {
            for (key, value) in obj {
                if key != "id" {
                    claims.insert(key.clone(), value.clone());
                }
            }
        }

        let credential_subject = CredentialSubjectObject {
            id: subject_id,
            claims,
        };

        Ok(W3cCredential::new(issuer_str, credential_subject))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    // Minimal wallet stub — `w3c_to_jsonld_document` is a pure transformation
    // that never touches the wallet/JWT service, so no key ops are exercised.
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

    #[test]
    fn test_w3c_to_jsonld_conversion() {
        let mut claims = std::collections::HashMap::new();
        claims.insert("name".to_string(), json!("Alice"));

        let subject = CredentialSubjectObject {
            id: Some("did:example:123".to_string()),
            claims,
        };

        let credential = W3cCredential::new("did:example:issuer", subject);

        // Build a real transformer instead of `todo!()`. The JSON-LD conversion
        // is fully implemented and does not depend on the wallet/JWT service.
        let wallet: Arc<dyn WalletProvider> = Arc::new(MockWallet);
        let registry = Arc::new(DidRegistry::new());
        let transformer = FormatTransformer::new(wallet, registry);

        let doc = transformer
            .w3c_to_jsonld_document(&credential)
            .expect("W3C -> JSON-LD conversion should succeed");

        // Verify the JSON-LD shape.
        assert_eq!(
            doc["@context"][0],
            json!("https://www.w3.org/2018/credentials/v1")
        );
        assert_eq!(doc["type"], json!(["VerifiableCredential"]));
        assert_eq!(doc["issuer"], json!("did:example:issuer"));
        assert_eq!(doc["credentialSubject"]["id"], json!("did:example:123"));
        assert_eq!(doc["credentialSubject"]["name"], json!("Alice"));
    }
}
