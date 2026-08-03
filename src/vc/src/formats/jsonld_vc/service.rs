/// JSON-LD Verifiable Credentials Service
/// Implements signing and verification of JSON-LD credentials with Data Integrity Proofs
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::core::{
    CredentialData, CredentialFormat, CredentialFormatService, Proof, SignCredentialOptions,
    VerificationResult, VerifyCredentialOptions, W3cCredential, W3cPresentation, W3cV2Credential,
};
use agent_core::traits::WalletProvider;

use super::{
    context_loader::ContextLoader,
    data_integrity::{resolve_did_web_key, verify_data_integrity_proof},
    signature_suites::{
        Ed25519Signature2018Suite, Ed25519Signature2020Suite, ProofOptions, ProofPurpose,
        SignatureSuite,
    },
};

/// JSON-LD VC Service
pub struct JsonLdVcService {
    wallet: Arc<dyn WalletProvider>,
    context_loader: Arc<ContextLoader>,
}

impl JsonLdVcService {
    /// Create new JSON-LD VC service
    pub fn new(wallet: Arc<dyn WalletProvider>) -> Self {
        let context_loader = Arc::new(ContextLoader::new());

        Self {
            wallet,
            context_loader,
        }
    }

    /// Select signature suite based on algorithm
    fn select_suite(&self, algorithm: &str, key_id: &str) -> Box<dyn SignatureSuite> {
        match algorithm {
            "Ed25519Signature2020" => Box::new(Ed25519Signature2020Suite::new(
                self.wallet.clone(),
                key_id.to_string(),
            )),
            _ => {
                // Default to Ed25519Signature2018
                Box::new(Ed25519Signature2018Suite::new(
                    self.wallet.clone(),
                    key_id.to_string(),
                ))
            }
        }
    }

    /// Convert a W3C VC v2.0 credential into its JSON-LD form (uses
    /// `validFrom`/`validUntil` and the v2 context). Public so callers can
    /// hand the document to any signer or upload as-is.
    pub fn v2_credential_to_jsonld(&self, credential: &W3cV2Credential) -> Value {
        let mut doc = json!({
            "@context": credential.context.clone(),
            "type": credential.type_.clone(),
            "issuer": credential.issuer.clone(),
            "validFrom": credential.valid_from.to_rfc3339(),
            "credentialSubject": credential.credential_subject.clone(),
        });
        if let Some(id) = &credential.id {
            doc["id"] = json!(id);
        }
        if let Some(vu) = &credential.valid_until {
            doc["validUntil"] = json!(vu.to_rfc3339());
        }
        if let Some(status) = &credential.credential_status {
            doc["credentialStatus"] = serde_json::to_value(status).unwrap_or(json!(null));
        }
        if let Some(schema) = &credential.credential_schema {
            doc["credentialSchema"] = serde_json::to_value(schema).unwrap_or(json!(null));
        }
        if let Some(related) = &credential.related_resource {
            doc["relatedResource"] = serde_json::to_value(related).unwrap_or(json!([]));
        }
        doc
    }

    /// Sign a v2 credential. Internally lowers to JSON-LD and runs the same
    /// signature suite selection as `sign_credential` (for v1).
    pub async fn sign_v2_credential(
        &self,
        credential: &W3cV2Credential,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let document = self.v2_credential_to_jsonld(credential);
        self.sign_jsonld_document(document, options).await
    }

    /// Shared signing path used by both v1 and v2 credentials. Takes an
    /// already-built JSON-LD document and runs the configured suite.
    async fn sign_jsonld_document(
        &self,
        mut document: Value,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let algorithm = options
            .algorithm
            .as_deref()
            .unwrap_or("Ed25519Signature2018");
        let suite = self.select_suite(algorithm, &options.key_id);

        let proof_purpose = options
            .proof_purpose
            .as_deref()
            .map(|p| match p {
                "authentication" => ProofPurpose::Authentication,
                _ => ProofPurpose::AssertionMethod,
            })
            .unwrap_or(ProofPurpose::AssertionMethod);

        let proof_options = ProofOptions {
            verification_method: options.key_id.clone(),
            proof_purpose,
            created: Some(chrono::Utc::now()),
            domain: None,
            challenge: None,
            nonce: None,
        };

        let proof = suite
            .create_proof(&document, &proof_options)
            .await
            .map_err(|e| format!("Failed to create proof: {}", e))?;

        document["proof"] = serde_json::to_value(&proof)?;
        Ok(serde_json::to_string(&document)?)
    }

    /// Convert W3cCredential to JSON-LD document
    fn credential_to_jsonld(&self, credential: &W3cCredential) -> Value {
        let mut doc = json!({
            "@context": credential.context.clone(),
            "type": credential.type_.clone(),
            "issuer": credential.issuer.clone(),
            "issuanceDate": credential.issuance_date.to_rfc3339(),
            "credentialSubject": credential.credential_subject.clone(),
        });

        if let Some(id) = &credential.id {
            doc["id"] = json!(id);
        }

        if let Some(exp) = &credential.expiration_date {
            doc["expirationDate"] = json!(exp.to_rfc3339());
        }

        if let Some(status) = &credential.credential_status {
            doc["credentialStatus"] = serde_json::to_value(status).unwrap_or(json!(null));
        }

        if let Some(schema) = &credential.credential_schema {
            doc["credentialSchema"] = serde_json::to_value(schema).unwrap_or(json!(null));
        }

        doc
    }

    /// Convert W3cPresentation to JSON-LD document
    fn presentation_to_jsonld(&self, presentation: &W3cPresentation) -> Value {
        let mut doc = json!({
            "@context": presentation.context.clone(),
            "type": presentation.type_.clone(),
        });

        if let Some(id) = &presentation.id {
            doc["id"] = json!(id);
        }

        if let Some(holder) = &presentation.holder {
            doc["holder"] = json!(holder);
        }

        if let Some(credentials) = &presentation.verifiable_credential {
            doc["verifiableCredential"] = serde_json::to_value(credentials).unwrap_or(json!([]));
        }

        doc
    }

    /// Parse a JSON-LD VC document into the right `CredentialData`
    /// variant based on which date field is present:
    ///
    /// - `validFrom`     → W3C VC v2.0 (OpenBadges v3, EBSI v2, …)
    /// - `issuanceDate`  → W3C VC v1.1 (classic ldp_vc, EBSI v1, …)
    ///
    /// Returning the union means the caller can build a
    /// `VerificationResult` without needing to know which model was
    /// on the wire. Errors with both attempted shapes when the
    /// document fits neither.
    fn jsonld_to_credential_data(
        &self,
        doc: &Value,
    ) -> Result<CredentialData, Box<dyn std::error::Error + Send + Sync>> {
        let has_valid_from = doc.get("validFrom").is_some();
        if has_valid_from {
            match serde_json::from_value::<W3cV2Credential>(doc.clone()) {
                Ok(v2) => Ok(CredentialData::V2(v2)),
                Err(v2_err) => {
                    // Some hybrids (EBSI v1.5, BBS demo) ship both
                    // fields. Fall back to v1 so the credential
                    // doesn't lose its way to storage.
                    match serde_json::from_value::<W3cCredential>(doc.clone()) {
                        Ok(v1) => Ok(CredentialData::V1(v1)),
                        Err(_) => Err(v2_err.into()),
                    }
                }
            }
        } else {
            let v1: W3cCredential = serde_json::from_value(doc.clone())?;
            Ok(CredentialData::V1(v1))
        }
    }

    /// Sign credential with JSON-LD Data Integrity proof
    async fn sign_credential_internal(
        &self,
        credential: &W3cCredential,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Convert credential to JSON-LD document
        let mut document = self.credential_to_jsonld(credential);

        // Select signature suite
        let algorithm = options
            .algorithm
            .as_deref()
            .unwrap_or("Ed25519Signature2018");
        let suite = self.select_suite(algorithm, &options.key_id);

        // Create proof options
        let proof_purpose = options
            .proof_purpose
            .as_deref()
            .map(|p| match p {
                "authentication" => ProofPurpose::Authentication,
                _ => ProofPurpose::AssertionMethod,
            })
            .unwrap_or(ProofPurpose::AssertionMethod);

        let proof_options = ProofOptions {
            verification_method: options.key_id.clone(),
            proof_purpose,
            created: None,
            challenge: options
                .additional
                .get("challenge")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            domain: options
                .additional
                .get("domain")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            nonce: options
                .additional
                .get("nonce")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        };

        // Create proof
        let proof = suite.create_proof(&document, &proof_options).await?;

        // Add proof to document
        document["proof"] = serde_json::to_value(proof)?;

        // Return as JSON string
        Ok(serde_json::to_string(&document)?)
    }

    /// Verify credential with JSON-LD Data Integrity proof.
    ///
    /// Two W3C shapes accepted for the `proof` field:
    /// - single object (legacy convention used by EBSI v1, BBS demos)
    /// - array of proof objects (used by OpenBadges v3 + most modern
    ///   ldp_vc issuers — issuers commonly emit the array form)
    ///
    /// For the array case we verify the *first* proof block. Multi-
    /// proof verification (matching by purpose / verifier policy) is
    /// left as future work; one matching proof is enough for the
    /// data-model contract.
    async fn verify_credential_internal(
        &self,
        credential_json: &str,
        _options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        // Parse JSON document
        let mut document: Value = serde_json::from_str(credential_json)?;

        // Extract proof — collapse array → first element so the
        // downstream `Proof` deserializer (which is single-object)
        // still works.
        let raw_proof = document
            .get("proof")
            .ok_or("Missing proof in credential")?
            .clone();
        let proof_value = match raw_proof {
            Value::Array(mut a) if !a.is_empty() => a.remove(0),
            Value::Array(_) => return Err("proof array is empty".into()),
            other => other,
        };
        let proof: Proof = serde_json::from_value(proof_value)?;

        // Remove proof from document for verification
        document
            .as_object_mut()
            .ok_or("Document is not an object")?
            .remove("proof");

        // Select signature suite based on proof type. `DataIntegrityProof`
        // takes the new path: resolve the issuer key via DID, then
        // verify Ed25519 over `SHA-256(canonProofConfig) ||
        // SHA-256(canonDoc)` for the W3C eddsa-* cryptosuites.
        let cryptosuite = proof
            .additional
            .get("cryptosuite")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let is_data_integrity = proof.type_ == "DataIntegrityProof";

        let mut details = HashMap::new();
        details.insert("proofType".to_string(), json!(proof.type_));
        details.insert(
            "verificationMethod".to_string(),
            json!(proof.verification_method),
        );
        if let Some(suite_name) = &cryptosuite {
            details.insert("cryptosuite".to_string(), json!(suite_name));
        }

        let (is_valid, errors) = if is_data_integrity {
            // Reconstruct the proof block as a Value (we already had
            // `proof: Proof`; round-trip via serde so the data_integrity
            // module sees the same on-wire shape, with proofValue +
            // cryptosuite + verificationMethod intact).
            let proof_value = serde_json::to_value(&proof).map_err(Box::new)?;
            // Resolve the issuer key (DID:web for the demo; the
            // resolver also accepts the same URL inside the DID doc's
            // verificationMethod array).
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(Box::new)?;
            match resolve_did_web_key(&proof.verification_method, &client).await {
                Ok(pubkey) => {
                    let outcome = verify_data_integrity_proof(
                        &document,
                        &proof_value,
                        &pubkey,
                        self.context_loader.clone(),
                    )
                    .await;
                    if let Some(e) = &outcome.error {
                        details.insert("verifyError".to_string(), json!(e));
                    }
                    let errs = if outcome.is_valid {
                        vec![]
                    } else {
                        vec![outcome.error.unwrap_or_else(|| {
                            "DataIntegrityProof verification failed".to_string()
                        })]
                    };
                    (outcome.is_valid, errs)
                }
                Err(e) => {
                    details.insert("resolveError".to_string(), json!(e));
                    (
                        false,
                        vec![format!("resolve issuer key from did:web: {}", e)],
                    )
                }
            }
        } else {
            let suite = self.select_suite(&proof.type_, "");
            let is_valid = suite.verify_proof(&document, &proof).await?;
            let errs = if is_valid {
                vec![]
            } else {
                vec!["Invalid signature".to_string()]
            };
            (is_valid, errs)
        };

        // Parse credential (auto-detects V1 vs V2 based on date field)
        let credential_data = self.jsonld_to_credential_data(&document)?;

        Ok(VerificationResult {
            is_valid,
            format: Some(CredentialFormat::JsonLd),
            credential: Some(credential_data),
            errors,
            details,
        })
    }

    /// Sign presentation with JSON-LD Data Integrity proof
    async fn sign_presentation_internal(
        &self,
        presentation: &W3cPresentation,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Convert presentation to JSON-LD document
        let mut document = self.presentation_to_jsonld(presentation);

        // Select signature suite
        let algorithm = options
            .algorithm
            .as_deref()
            .unwrap_or("Ed25519Signature2018");
        let suite = self.select_suite(algorithm, &options.key_id);

        // Create proof options (authentication for presentations)
        let proof_options = ProofOptions {
            verification_method: options.key_id.clone(),
            proof_purpose: ProofPurpose::Authentication,
            created: None,
            challenge: options
                .additional
                .get("challenge")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            domain: options
                .additional
                .get("domain")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            nonce: options
                .additional
                .get("nonce")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        };

        // Create proof
        let proof = suite.create_proof(&document, &proof_options).await?;

        // Add proof to document
        document["proof"] = serde_json::to_value(proof)?;

        // Return as JSON string
        Ok(serde_json::to_string(&document)?)
    }

    /// Verify presentation with JSON-LD Data Integrity proof
    async fn verify_presentation_internal(
        &self,
        presentation_json: &str,
        _options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        // Parse JSON document
        let mut document: Value = serde_json::from_str(presentation_json)?;

        // Extract proof
        let proof_value = document
            .get("proof")
            .ok_or("Missing proof in presentation")?
            .clone();

        let proof: Proof = serde_json::from_value(proof_value)?;

        // Remove proof from document for verification
        document
            .as_object_mut()
            .ok_or("Document is not an object")?
            .remove("proof");

        // Select signature suite based on proof type
        let suite = self.select_suite(&proof.type_, "");

        // Verify proof
        let is_valid = suite.verify_proof(&document, &proof).await?;

        Ok(VerificationResult {
            is_valid,
            format: Some(CredentialFormat::JsonLd),
            credential: None, // Presentations don't have credential field
            errors: if is_valid {
                vec![]
            } else {
                vec!["Invalid signature".to_string()]
            },
            details: {
                let mut details = HashMap::new();
                details.insert("proofType".to_string(), json!(proof.type_));
                details.insert(
                    "verificationMethod".to_string(),
                    json!(proof.verification_method),
                );
                details.insert("presentation".to_string(), document);
                details
            },
        })
    }
}

#[async_trait]
impl CredentialFormatService for JsonLdVcService {
    fn format(&self) -> CredentialFormat {
        CredentialFormat::JsonLd
    }

    async fn sign_credential(
        &self,
        credential: &W3cCredential,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        self.sign_credential_internal(credential, options).await
    }

    async fn verify_credential(
        &self,
        credential_json: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        self.verify_credential_internal(credential_json, options)
            .await
    }

    async fn sign_presentation(
        &self,
        presentation: &W3cPresentation,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        self.sign_presentation_internal(presentation, options).await
    }

    async fn verify_presentation(
        &self,
        presentation_json: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        self.verify_presentation_internal(presentation_json, options)
            .await
    }

    fn can_handle(&self, credential: &str) -> bool {
        // Check if it's JSON
        if let Ok(doc) = serde_json::from_str::<Value>(credential) {
            // Check for JSON-LD indicators
            if doc.get("@context").is_some() {
                // The proof block may be a single object or an array
                // (W3C allows both). Inspect each candidate.
                if let Some(proof) = doc.get("proof") {
                    let candidates: Vec<&Value> = match proof {
                        Value::Array(a) => a.iter().collect(),
                        v => vec![v],
                    };
                    for p in candidates {
                        let Some(ptype) = p.get("type").and_then(|t| t.as_str()) else {
                            continue;
                        };
                        // Legacy proof suite names: `Ed25519Signature2018`,
                        // `Ed25519Signature2020`, `JsonWebSignature2020`,
                        // `BbsBlsSignature2020`, ...
                        // Modern VCDM 2.0: `DataIntegrityProof` with a
                        // `cryptosuite` discriminator. Both are valid
                        // ldp_vc proofs and we own the routing — even
                        // if our suite implementation doesn't yet
                        // support the cryptosuite, parsing the
                        // credential and persisting it is the right
                        // behaviour (the user can still see + present
                        // it; verification is a separate check).
                        if ptype.contains("Signature") || ptype == "DataIntegrityProof" {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_handle_jsonld() {
        use storage::askar::{AskarConfig, AskarStorageProvider};
        use wallet::askar::AskarWalletProvider;

        let config = AskarConfig::builder()
            .in_memory()
            .pass_key("test")
            .create_if_missing(true)
            .build()
            .unwrap();

        let storage = tokio_test::block_on(AskarStorageProvider::new(config)).unwrap();
        let wallet = Arc::new(AskarWalletProvider::new(storage.store().clone()));

        let service = JsonLdVcService::new(wallet);

        // Valid JSON-LD with proof
        let valid_jsonld = r#"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "proof": {
                "type": "Ed25519Signature2018"
            }
        }"#;
        assert!(service.can_handle(valid_jsonld));

        // JSON without @context
        let no_context = r#"{"type": "VerifiableCredential"}"#;
        assert!(!service.can_handle(no_context));

        // JSON-LD without proof
        let no_proof = r#"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential"
        }"#;
        assert!(!service.can_handle(no_proof));

        // Not JSON
        let not_json = "not.json.content";
        assert!(!service.can_handle(not_json));
    }
}
