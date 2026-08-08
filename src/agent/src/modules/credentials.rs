//! Credentials Module
//!
//! High-level API for managing verifiable credentials

use crate::error::{AgentError, Result};
use std::collections::HashMap;
use std::sync::Arc;

use agent_core::traits::{StorageProvider, WalletProvider};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use vc::core::{
    CredentialFormat, SignCredentialOptions, VerifyCredentialOptions, W3cCredential,
    W3cPresentation,
};
use vc::formats::jsonld_vc::JsonLdVcService;
use vc::formats::jwt_vc::EnhancedJwtVcService;
use vc::service::UnifiedCredentialService;
use vc::storage::{CredentialRecord, CredentialRepository};

/// Credentials module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsConfig {
    /// Default credential format to use
    #[serde(default = "default_format")]
    pub default_format: CredentialFormat,

    /// Whether to auto-verify received credentials
    #[serde(default = "default_auto_verify")]
    pub auto_verify: bool,

    /// Whether to check revocation status
    #[serde(default = "default_check_revocation")]
    pub check_revocation: bool,
}

fn default_format() -> CredentialFormat {
    CredentialFormat::JwtVc
}

fn default_auto_verify() -> bool {
    true
}

fn default_check_revocation() -> bool {
    false
}

impl Default for CredentialsConfig {
    fn default() -> Self {
        Self {
            default_format: default_format(),
            auto_verify: default_auto_verify(),
            check_revocation: default_check_revocation(),
        }
    }
}

/// Lazily-built credential service + repository, constructed from the agent's
/// wallet/storage in [`AgentModule::register`].
struct CredentialsInner {
    service: UnifiedCredentialService,
    repository: CredentialRepository,
}

/// Credentials Module
///
/// Provides high-level API for managing verifiable credentials.
///
/// Config-only: holds only its [`CredentialsConfig`] at construction. Its
/// credential service + repository are built lazily in
/// [`AgentModule::register`] from `ctx.wallet` / `ctx.storage`.
pub struct CredentialsModule {
    config: CredentialsConfig,
    inner: once_cell::sync::OnceCell<CredentialsInner>,
}

impl CredentialsModule {
    /// Config-only constructor (no agent deps). The credential service is
    /// built when the module is registered with an agent.
    pub fn new(config: CredentialsConfig) -> Self {
        Self {
            config,
            inner: once_cell::sync::OnceCell::new(),
        }
    }

    /// Build the credential service + repository from wallet/storage. Idempotent.
    fn ensure_built(&self, wallet: Arc<dyn WalletProvider>, storage: Arc<dyn StorageProvider>) {
        self.inner.get_or_init(|| {
            // Create repository
            let repository = CredentialRepository::new(storage.clone());
            let repository_arc = Arc::new(repository);

            // Create credential service with wallet integration.
            // We register both JWT-VC and JSON-LD VC up-front so OpenBadges
            // v3 / `ldp_vc` credentials issued via OID4VCI route through
            // `JsonLdVcService::can_handle` (recognises `@context` +
            // `proof.type` ending in `Signature`) — without this, every
            // ldp_vc credential dies in `verify_credential` with the
            // generic "Unknown credential format" error.
            let jwt_service = Arc::new(EnhancedJwtVcService::with_wallet(wallet.clone()));
            let jsonld_service = Arc::new(JsonLdVcService::new(wallet.clone()));
            // SD-JWT VC: a first-class format for selective-disclosure wallets.
            // Registering it here means the unified sign/verify path (and the
            // FFI `credentials.*` domain) handle `vc+sd-jwt` credentials
            // directly, not only through the dedicated store/verify shim.
            let sd_jwt_service = Arc::new(vc::formats::sd_jwt::SdJwtService::new(wallet.clone()));
            let mut builder = UnifiedCredentialService::builder(repository_arc.clone())
                .with_format_service(CredentialFormat::JwtVc, jwt_service)
                .with_format_service(CredentialFormat::JsonLd, jsonld_service)
                .with_format_service(CredentialFormat::SdJwt, sd_jwt_service);

            // AnonCreds: only compiled when the `anoncreds` feature is on
            // (mobile/light builds skip the CL-signature stack). Services are
            // backed by the same StorageProvider as records, so cred-defs /
            // schemas resolve from the agent's own store.
            #[cfg(feature = "anoncreds")]
            {
                use anoncreds_core::{
                    AnonCredsHolderService, AnonCredsIssuerService, AnonCredsVerifierService,
                    StorageBackedRegistry,
                };
                let registry = Arc::new(StorageBackedRegistry::new(storage.clone()));
                let anoncreds_service =
                    Arc::new(vc::formats::anoncreds::AnonCredsFormatService::new(
                        Arc::new(AnonCredsIssuerService::new(registry.clone())),
                        Arc::new(AnonCredsHolderService::new(registry.clone())),
                        Arc::new(AnonCredsVerifierService::new(registry)),
                    ));
                builder = builder.with_format_service(CredentialFormat::AnonCreds, anoncreds_service);
            }

            let service = builder.build();

            // Create another repository for the module (since we moved the first into Arc)
            let repository = CredentialRepository::new(storage.clone());

            CredentialsInner {
                service,
                repository,
            }
        });
    }

    /// Accessor for the lazily-built inner. Panics if used before the module is
    /// registered with an agent.
    fn inner(&self) -> &CredentialsInner {
        self.inner
            .get()
            .expect("CredentialsModule used before register (service not built)")
    }

    /// Initialize the module (for any async operations)
    /// Modules are initialized after construction
    pub async fn initialize(&self) -> Result<()> {
        // Any async initialization can happen here
        // For now, we don't have any async initialization needed
        Ok(())
    }

    /// Issue a credential
    pub async fn issue_credential(
        &self,
        credential: W3cCredential,
        format: Option<CredentialFormat>,
        key_id: String,
    ) -> Result<String> {
        let format = format.unwrap_or(self.config.default_format);

        // Create signing options
        let options = SignCredentialOptions {
            format,
            key_id: key_id.clone(),
            algorithm: match format {
                CredentialFormat::JwtVc => Some("EdDSA".to_string()),
                CredentialFormat::JsonLd => Some("Ed25519Signature2020".to_string()),
                _ => None,
            },
            proof_purpose: Some("assertionMethod".to_string()),
            additional: HashMap::new(),
        };

        // Sign credential
        let signed = self
            .inner()
            .service
            .sign_credential(&credential, &options)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))?;

        // Store issued credential
        let record = CredentialRecord::from_credential(credential.clone(), format, signed.clone());
        self.inner()
            .repository
            .save(&record)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))?;

        Ok(signed)
    }

    /// Store a received credential.
    ///
    /// Auto-detects the format by inspecting the raw bytes:
    /// - `<jwt>~<disclosure>~…` → SD-JWT VC (IETF SD-JWT VC, the
    ///   `vc+sd-jwt` issuance format). Handled by a dedicated
    ///   `store_sd_jwt_credential` path because the W3C verifier
    ///   service can't parse the SD-JWT envelope.
    /// - `<header>.<payload>.<signature>` (3 dot-separated parts and
    ///   no `~`) → JWT-VC (W3C)
    /// - valid JSON → JSON-LD VC
    /// - anything else → error
    pub async fn store_credential(&self, raw_credential: String) -> Result<String> {
        // SD-JWT VC handling — `~`-separated disclosures distinguish it
        // from plain JWT-VC. Route through the dedicated path because
        // the W3C credential service can't parse the SD-JWT envelope.
        if raw_credential.contains('~') && raw_credential.split('.').count() >= 3 {
            return self.store_sd_jwt_credential(raw_credential).await;
        }

        // Try to detect format by parsing (W3cCredentialService doesn't have public detect_format)
        // For now, try JWT first as it's the default
        let format = if raw_credential.split('.').count() == 3 {
            CredentialFormat::JwtVc
        } else {
            // Try JSON parsing for other formats
            if serde_json::from_str::<Value>(&raw_credential).is_ok() {
                CredentialFormat::JsonLd
            } else {
                return Err(AgentError::Other("Unknown credential format".into()));
            }
        };

        // Parse and optionally verify
        let verification = if self.config.auto_verify {
            let options = VerifyCredentialOptions::default();
            Some(
                self.inner()
                    .service
                    .verify_credential(&raw_credential, &options)
                    .await
                    .map_err(|e| AgentError::Other(e.to_string()))?,
            )
        } else {
            None
        };

        // Create record based on verification result
        let mut record = if let Some(result) = &verification {
            if let Some(credential_data) = &result.credential {
                match credential_data {
                    vc::core::CredentialData::V1(cred) => CredentialRecord::from_credential(
                        cred.clone(),
                        format,
                        raw_credential.clone(),
                    ),
                    vc::core::CredentialData::V2(cred) => CredentialRecord::from_credential_v2(
                        cred.clone(),
                        format,
                        raw_credential.clone(),
                    ),
                }
            } else {
                return Err(AgentError::Other("Failed to parse credential".into()));
            }
        } else {
            // Parse without verification for storage - verify with no checks to get parsed data
            let verify_result = self
                .inner()
                .service
                .verify_credential(&raw_credential, &VerifyCredentialOptions::default())
                .await
                .map_err(|e| AgentError::Other(e.to_string()))?;

            let parsed = verify_result
                .credential
                .ok_or_else(|| AgentError::Other("Failed to parse credential".into()))?;

            match parsed {
                vc::core::CredentialData::V1(cred) => {
                    CredentialRecord::from_credential(cred, format, raw_credential.clone())
                }
                vc::core::CredentialData::V2(cred) => {
                    CredentialRecord::from_credential_v2(cred, format, raw_credential.clone())
                }
            }
        };

        // Update verification status
        if let Some(result) = &verification {
            if result.is_valid {
                record.mark_verified();
            }
        }

        // Store credential
        self.inner()
            .repository
            .save(&record)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))?;

        Ok(record.id)
    }

    /// Store a raw SD-JWT VC string (`<jwt>~<disclosure>~…[~<kbjwt>]`).
    ///
    /// SD-JWT VC isn't a W3C VC, so we project the JWT payload's
    /// `vct`, `iss`, `iat`, and disclosed claims into a synthetic
    /// `W3cCredential` shaped record so it slots into the existing
    /// `CredentialRecord` index and renders in the wallet UI.
    /// `raw_credential` keeps the full SD-JWT envelope (JWT + every
    /// disclosure + optional KB-JWT) so the holder can re-emit the
    /// presentation later without losing selective-disclosure
    /// material.
    pub async fn store_sd_jwt_credential(&self, raw_credential: String) -> Result<String> {
        use base64::Engine;
        use chrono::TimeZone;
        use std::collections::HashMap;
        use vc::core::{CredentialContext, CredentialSubject, CredentialSubjectObject, Issuer};
        use vc::storage::CredentialRecord;

        // 1. Split out the JWT envelope. The portion before the first
        //    `~` is `<header>.<payload>.<signature>`.
        let jwt_part = raw_credential.split('~').next().unwrap_or("");
        let jwt_segments: Vec<&str> = jwt_part.split('.').collect();
        if jwt_segments.len() < 2 {
            return Err(AgentError::Other(
                "SD-JWT VC: missing JWT header/payload".to_string(),
            ));
        }

        // 2. Decode payload (segment 1 is the base64url JSON claims).
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwt_segments[1])
            .map_err(|e| AgentError::Other(format!("SD-JWT payload base64: {}", e)))?;
        let payload: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| AgentError::Other(format!("SD-JWT payload json: {}", e)))?;

        let payload_obj = payload
            .as_object()
            .ok_or_else(|| AgentError::Other("SD-JWT payload is not a JSON object".to_string()))?;

        let issuer_id = payload_obj
            .get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let vct = payload_obj
            .get("vct")
            .and_then(|v| v.as_str())
            .unwrap_or("SdJwtVc")
            .to_string();
        let subject_id = payload_obj
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let iat = payload_obj
            .get("iat")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        let exp = payload_obj.get("exp").and_then(|v| v.as_i64());

        // 3. Build credentialSubject from the non-reserved claims.
        const RESERVED: &[&str] = &[
            "iss", "vct", "iat", "exp", "nbf", "sub", "cnf", "status", "_sd", "_sd_alg",
        ];
        let mut subject_props: HashMap<String, Value> = HashMap::new();
        for (k, v) in payload_obj.iter() {
            if !RESERVED.contains(&k.as_str()) {
                subject_props.insert(k.clone(), v.clone());
            }
        }

        // 4. Decode disclosures and append the revealed claims to the
        //    subject. Each disclosure is base64url(JSON array): for
        //    object-claim disclosures it's `[salt, key, value]`, for
        //    array-element disclosures it's `[salt, value]`. We treat
        //    received disclosures as visible-to-the-holder by default
        //    so the wallet UI can render them.
        for segment in raw_credential.split('~').skip(1).filter(|s| !s.is_empty()) {
            let bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(segment) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let arr: Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(items) = arr.as_array() {
                if items.len() == 3 {
                    if let (Some(key), Some(value)) = (items[1].as_str(), items.get(2)) {
                        subject_props.insert(key.to_string(), value.clone());
                    }
                }
            }
        }

        let credential_subject = CredentialSubject::Single(CredentialSubjectObject {
            id: subject_id,
            claims: subject_props,
        });

        // 5. Synthesise a W3cCredential. Use the default credentials/v1
        //    context and stack the SD-JWT VC `vct` as a secondary type.
        let issuance_date = chrono::Utc
            .timestamp_opt(iat, 0)
            .single()
            .unwrap_or_else(chrono::Utc::now);
        let expiration_date = exp.and_then(|t| chrono::Utc.timestamp_opt(t, 0).single());

        let context =
            CredentialContext::String("https://www.w3.org/2018/credentials/v1".to_string());
        let type_ = vec!["VerifiableCredential".to_string(), vct];
        let issuer = Issuer::String(issuer_id);

        let synthetic = W3cCredential {
            context,
            id: None,
            type_,
            issuer,
            issuance_date,
            expiration_date,
            credential_subject,
            credential_status: None,
            credential_schema: None,
            refresh_service: None,
            proof: None,
        };

        let record =
            CredentialRecord::from_credential(synthetic, CredentialFormat::SdJwt, raw_credential);

        self.inner()
            .repository
            .save(&record)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))?;

        Ok(record.id)
    }

    /// Verify a credential
    pub async fn verify_credential(
        &self,
        credential_id: String,
    ) -> Result<vc::core::VerificationResult> {
        // Find credential
        let record = self
            .inner()
            .repository
            .find_by_id(&credential_id)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))?
            .ok_or_else(|| AgentError::Other("Credential not found".into()))?;

        // SD-JWT VC isn't handled by the W3C verifier service (only
        // `JwtVc` is registered there), so the default dispatch returns
        // "Unknown credential format". Detect the SD-JWT envelope and
        // route to the dedicated structural verifier — same detection
        // rule as `store_credential` uses for storage routing.
        let is_sd_jwt = matches!(record.format, CredentialFormat::SdJwt)
            || (record.raw_credential.contains('~')
                && record.raw_credential.split('.').count() >= 3);
        if is_sd_jwt {
            let result = Self::verify_sd_jwt_structure(&record.raw_credential)?;
            let mut updated = record.clone();
            if result.is_valid {
                updated.mark_verified();
                self.inner()
                    .repository
                    .update(&updated)
                    .await
                    .map_err(|e| AgentError::Other(e.to_string()))?;
            }
            return Ok(result);
        }

        // Verify
        let mut options = VerifyCredentialOptions::default();
        if self.config.check_revocation {
            options
                .additional
                .insert("check_revocation".to_string(), Value::Bool(true));
        }

        let result = self
            .inner()
            .service
            .verify_credential(&record.raw_credential, &options)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))?;

        // Update verification status
        let mut updated = record.clone();
        if result.is_valid {
            updated.mark_verified();
        }
        self.inner()
            .repository
            .update(&updated)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))?;

        Ok(result)
    }

    /// Structural verification for SD-JWT VC. Checks:
    ///
    /// 1. Envelope splits into `<jwt>~<disclosure>*~[kbjwt]` with a
    ///    well-formed 3-segment JWT.
    /// 2. Every disclosure decodes to a JSON array of length 2 or 3.
    /// 3. Every disclosure's SHA-256 digest (base64url-no-pad of the
    ///    disclosure segment bytes) appears in the JWT payload's
    ///    `_sd` array. This is the integrity check that proves
    ///    disclosures match what the issuer signed.
    /// 4. `_sd_alg` is either absent or `sha-256` (the only digest we
    ///    implement).
    ///
    /// JWS signature verification against the issuer DID is not yet
    /// wired in — it requires DID resolution + a JWS verifier per key
    /// type and is tracked separately. We report it explicitly in
    /// `details.signature_check` so a caller never confuses
    /// structural validity for cryptographic validity.
    fn verify_sd_jwt_structure(raw: &str) -> Result<vc::core::VerificationResult> {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        use vc::core::VerificationResult;

        let mut details: HashMap<String, Value> = HashMap::new();

        // 1. JWT envelope.
        let mut parts = raw.split('~');
        let jwt_part = parts.next().unwrap_or("");
        let jwt_segments: Vec<&str> = jwt_part.split('.').collect();
        if jwt_segments.len() != 3 {
            return Ok(VerificationResult::invalid(
                "SD-JWT VC: JWT envelope must have 3 segments",
            ));
        }
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwt_segments[1])
            .map_err(|e| AgentError::Other(format!("SD-JWT payload base64: {}", e)))?;
        let payload: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| AgentError::Other(format!("SD-JWT payload json: {}", e)))?;

        // 4. Digest algorithm sanity check.
        if let Some(alg) = payload.get("_sd_alg").and_then(|v| v.as_str()) {
            if alg != "sha-256" {
                return Ok(VerificationResult::invalid(format!(
                    "SD-JWT VC: unsupported _sd_alg: {}",
                    alg
                )));
            }
        }

        // 3. Collect the issuer-signed `_sd` digests (recursively, so
        //    nested objects with their own `_sd` arrays are covered).
        let mut sd_digests: std::collections::HashSet<String> = std::collections::HashSet::new();
        fn collect_sd(v: &Value, out: &mut std::collections::HashSet<String>) {
            match v {
                Value::Object(map) => {
                    if let Some(arr) = map.get("_sd").and_then(|v| v.as_array()) {
                        for d in arr {
                            if let Some(s) = d.as_str() {
                                out.insert(s.to_string());
                            }
                        }
                    }
                    for (_, child) in map.iter() {
                        collect_sd(child, out);
                    }
                }
                Value::Array(arr) => {
                    for child in arr {
                        collect_sd(child, out);
                    }
                }
                _ => {}
            }
        }
        collect_sd(&payload, &mut sd_digests);

        // 2/3. Walk disclosures. Last segment is `""` (trailing `~`)
        // or, when key-binding is used, a KB-JWT. Treat the KB-JWT as
        // anything that has 3 dot-segments; everything else is a
        // disclosure to digest-check.
        let mut disclosure_count = 0_usize;
        let mut kb_jwt_present = false;
        for segment in parts {
            if segment.is_empty() {
                continue;
            }
            if segment.matches('.').count() == 2 {
                // KB-JWT trailing segment.
                kb_jwt_present = true;
                continue;
            }
            let bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(segment) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(VerificationResult::invalid(
                        "SD-JWT VC: disclosure is not valid base64url",
                    ));
                }
            };
            let arr: Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(VerificationResult::invalid(
                        "SD-JWT VC: disclosure is not JSON",
                    ));
                }
            };
            let arr_len = arr.as_array().map(|a| a.len()).unwrap_or(0);
            if arr_len != 2 && arr_len != 3 {
                return Ok(VerificationResult::invalid(
                    "SD-JWT VC: disclosure must be JSON array of length 2 or 3",
                ));
            }
            // Digest the *segment text* (not the decoded bytes) — SD-JWT
            // specifies that disclosure digests are b64url-no-pad of the
            // SHA-256 of the *encoded* string.
            let digest = Sha256::digest(segment.as_bytes());
            let digest_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
            if !sd_digests.contains(&digest_b64) {
                return Ok(VerificationResult::invalid(format!(
                    "SD-JWT VC: disclosure digest {} not present in issuer _sd array",
                    &digest_b64[..digest_b64.len().min(16)],
                )));
            }
            disclosure_count += 1;
        }

        details.insert("format".into(), Value::String("vc+sd-jwt".into()));
        details.insert(
            "disclosures_verified".into(),
            Value::Number(disclosure_count.into()),
        );
        details.insert("kb_jwt_present".into(), Value::Bool(kb_jwt_present));
        // Be explicit about what *isn't* checked — caller must not
        // confuse "structurally valid" with "cryptographically valid".
        details.insert(
            "signature_check".into(),
            Value::String("not implemented for SD-JWT yet".into()),
        );
        if let Some(iss) = payload.get("iss").and_then(|v| v.as_str()) {
            details.insert("issuer".into(), Value::String(iss.to_string()));
        }
        if let Some(vct) = payload.get("vct").and_then(|v| v.as_str()) {
            details.insert("vct".into(), Value::String(vct.to_string()));
        }

        Ok(VerificationResult {
            is_valid: true,
            format: Some(CredentialFormat::SdJwt),
            credential: None,
            errors: Vec::new(),
            details,
        })
    }

    /// Create a presentation
    pub async fn create_presentation(
        &self,
        credential_ids: Vec<String>,
        holder_key_id: String,
        options: HashMap<String, Value>,
    ) -> Result<String> {
        // Fetch credentials
        let mut credentials = Vec::new();
        for id in &credential_ids {
            let record = self
                .inner()
                .repository
                .find_by_id(id)
                .await
                .map_err(|e| AgentError::Other(e.to_string()))?
                .ok_or_else(|| AgentError::Other(format!("Credential {} not found", id)))?;
            credentials.push(record.raw_credential.clone());
        }

        // Create presentation
        let presentation = W3cPresentation::new()
            .with_holder(holder_key_id.clone())
            .with_credentials(
                credentials
                    .into_iter()
                    .map(vc::core::VerifiableCredential::Jwt)
                    .collect(),
            );

        // Sign presentation
        let format = self.config.default_format;
        let sign_options = SignCredentialOptions {
            format,
            key_id: holder_key_id,
            algorithm: Some("EdDSA".to_string()),
            proof_purpose: Some("authentication".to_string()),
            additional: options,
        };

        let signed = self
            .inner()
            .service
            .sign_presentation(&presentation, &sign_options)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))?;

        Ok(signed)
    }

    /// Verify a presentation
    pub async fn verify_presentation(
        &self,
        presentation: String,
        options: HashMap<String, Value>,
    ) -> Result<vc::core::VerificationResult> {
        let verify_options = VerifyCredentialOptions {
            additional: options,
            ..Default::default()
        };

        let result = self
            .inner()
            .service
            .verify_presentation(&presentation, &verify_options)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))?;

        Ok(result)
    }

    /// Find credentials by query
    pub async fn find_credentials(
        &self,
        query: vc::storage::CredentialQuery,
    ) -> Result<Vec<CredentialRecord>> {
        self.inner()
            .repository
            .find_all(&query)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))
    }

    /// Get a credential by ID
    pub async fn get_credential(&self, id: &str) -> Result<Option<CredentialRecord>> {
        self.inner()
            .repository
            .find_by_id(id)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))
    }

    /// Delete a credential
    pub async fn delete_credential(&self, id: &str) -> Result<()> {
        self.inner()
            .repository
            .delete(id)
            .await
            .map_err(|e| AgentError::Other(e.to_string()))
    }
}
#[async_trait::async_trait]
impl agent_module::AgentModule for CredentialsModule {
    fn name(&self) -> &str {
        "credentials"
    }

    /// Builds the credential service + repository from `ctx.wallet` /
    /// `ctx.storage`.
    ///
    /// On builds **without** the `anoncreds` feature (mobile/FFI), this also
    /// registers the W3C / JWT-VC / SD-JWT DIDComm issue-credential handlers so
    /// credential issuance over a DIDComm connection works. On `anoncreds`
    /// builds the handlers are registered instead by
    /// [`Agent::setup_anoncreds_with_registry`] as format-dispatching
    /// composites (W3C + AnonCreds fallback) — registering here too would
    /// double-register the same message types, so it is feature-gated off.
    async fn register(&self, ctx: &agent_module::ModuleContext) -> agent_module::ModuleResult {
        self.ensure_built(ctx.wallet.clone(), ctx.storage.clone());

        #[cfg(not(feature = "anoncreds"))]
        {
            use protocol_credentials::{
                StorageBackedCredentialExchangeRepository, W3cCredentialExchangeService,
                W3cIssueCredentialHandler, W3cOfferCredentialHandler, W3cRequestCredentialHandler,
            };

            let wallet = ctx.wallet.clone();
            let jwt = Arc::new(EnhancedJwtVcService::with_wallet(wallet.clone()));
            let jsonld = Arc::new(JsonLdVcService::new(wallet.clone()));
            let sd_jwt = Arc::new(vc::formats::sd_jwt::SdJwtService::new(wallet.clone()));

            let repository = Arc::new(StorageBackedCredentialExchangeRepository::new(
                ctx.storage.clone(),
            ));
            let service = Arc::new(
                W3cCredentialExchangeService::builder(repository)
                    .with_format_service(jwt)
                    .with_format_service(jsonld)
                    .with_format_service(sd_jwt)
                    .with_event_bus(ctx.events.clone(), ctx.label.clone())
                    .build(),
            );

            // Auto-accept offers/requests: mirror the wallet's holder-side
            // convenience (issuers drive issue explicitly via the FFI/API).
            let mut registry = ctx.handler_registry.write().await;
            registry.register(Arc::new(W3cOfferCredentialHandler::new(service.clone(), true)));
            registry.register(Arc::new(W3cRequestCredentialHandler::new(service.clone(), true)));
            registry.register(Arc::new(W3cIssueCredentialHandler::new(service)));
            drop(registry);
            tracing::debug!("✓ [CredentialsModule] W3C DIDComm issue-credential handlers registered");
        }

        Ok(())
    }
}

/// Typed, decoupled access to the [`CredentialsModule`] from an [`crate::Agent`].
pub trait CredentialsExt {
    fn credentials_module(&self) -> Option<std::sync::Arc<CredentialsModule>>;
}

impl CredentialsExt for crate::Agent {
    fn credentials_module(&self) -> Option<std::sync::Arc<CredentialsModule>> {
        self.module::<CredentialsModule>()
    }
}
