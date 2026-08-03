//! OID4VP Holder Service
//!
//! Main service for wallet functionality in OpenID4VP

use super::{
    dcql::DcqlService,
    error::{Oid4vpError, Result},
    pex::PresentationDefinition,
    transport::Oid4vpTransport,
    types::*,
    uri::parse_authorization_request,
};
use agent_core::traits::WalletProvider;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// OID4VP Holder Service
pub struct Oid4vpHolderService {
    dcql_service: DcqlService,
    transport: Oid4vpTransport,
}

impl Oid4vpHolderService {
    /// Create new OID4VP holder service
    pub fn new() -> Result<Self> {
        Ok(Self {
            dcql_service: DcqlService::new(),
            transport: Oid4vpTransport::new()?,
        })
    }

    /// Resolve authorization request (from QR code or URI)
    ///
    /// # Arguments
    /// * `authorization_request` - QR code content, URI, or JWT
    /// * `available_doc_types` - Available document types with their claims
    /// * `origin` - Origin for session transcript (optional)
    ///
    /// # Returns
    /// Resolved authorization request with matched credentials
    pub async fn resolve_authorization_request(
        &self,
        authorization_request: &str,
        available_doc_types: Vec<(String, HashMap<String, Vec<String>>)>,
        origin: Option<String>,
    ) -> Result<ResolvedAuthorizationRequest> {
        tracing::info!("Resolving authorization request");

        // Step 1: Parse authorization request
        let auth_request = parse_authorization_request(authorization_request)?;

        // Step 2: Get payload (may require HTTP fetch)
        let payload = self.get_authorization_payload(auth_request).await?;

        // Step 3: Validate client_id and determine verifier info
        let verifier = self.validate_and_get_verifier_info(&payload)?;

        // Step 4: Match credentials to query
        let matched_credentials = if let Some(dcql_query) = &payload.dcql_query {
            // DCQL query
            self.dcql_service.validate_dcql_query(dcql_query)?;
            let result = self
                .dcql_service
                .match_query_to_documents(dcql_query, &available_doc_types)?;
            Some(result.matched_credentials)
        } else if payload.presentation_definition.is_some() {
            // TODO: Presentation Exchange (Phase 2)
            tracing::warn!(
                "Presentation Exchange not yet implemented, skipping credential matching"
            );
            None
        } else {
            None
        };

        Ok(ResolvedAuthorizationRequest {
            payload,
            verifier,
            matched_credentials,
            origin,
        })
    }

    /// Create and send authorization response
    ///
    /// # Arguments
    /// * `resolved_request` - Previously resolved authorization request
    /// * `vp_token` - Base64url-encoded DeviceResponse
    /// * `selected_credential_ids` - IDs of selected credentials for presentation submission
    ///
    /// # Returns
    /// Optional redirect URI if verifier provided one
    pub async fn send_authorization_response(
        &self,
        resolved_request: &ResolvedAuthorizationRequest,
        vp_token: String,
        selected_credential_ids: Vec<String>,
    ) -> Result<Option<String>> {
        tracing::info!("Sending authorization response");

        // Create presentation submission if needed
        let presentation_submission = if let Some(dcql_query) = &resolved_request.payload.dcql_query
        {
            Some(
                self.dcql_service
                    .create_presentation_submission(dcql_query, &selected_credential_ids)?,
            )
        } else {
            None
        };

        // Create authorization response
        let authorization_response = AuthorizationResponse {
            vp_token,
            presentation_submission,
            state: resolved_request.payload.state.clone(),
        };

        // Send response
        let direct_post_response = self
            .transport
            .send_direct_post(
                &resolved_request.payload.response_uri,
                &authorization_response,
            )
            .await?;

        tracing::info!("Authorization response sent successfully");

        Ok(direct_post_response.redirect_uri)
    }

    /// Present an SD-JWT VC against an OID4VP authorization request.
    ///
    /// Builds the holder side of the SD-JWT presentation:
    ///   1. Parse `presentation_definition` from the resolved request,
    ///      pick the first input descriptor and extract its
    ///      `fields[].path` constraints (which claim names the
    ///      verifier requires).
    ///   2. Parse the stored SD-JWT envelope (`<jwt>~<disclosure>~…`)
    ///      and select only the disclosures whose disclosed `key`
    ///      satisfies a requested path. This honours
    ///      `limit_disclosure: "required"` by default.
    ///   3. Sign a Key-Binding JWT (`typ=kb+jwt`) carrying the
    ///      verifier's `nonce`, the audience, and `sd_hash`
    ///      (base64url-sha256 of the JWT + selected disclosures with
    ///      a single trailing `~`).
    ///   4. Concatenate `<jwt>~<disc>…~<kb_jwt>` as the `vp_token`.
    ///   5. Build a single-entry `presentation_submission` and POST
    ///      to the verifier's `response_uri` via direct_post.
    ///
    /// `holder_kid` should be a fully-qualified verification method
    /// id (e.g. `did:key:z6Mk…#z6Mk…`) so the verifier can resolve
    /// the holder's signing key from the KB-JWT header.
    #[allow(clippy::too_many_arguments)]
    pub async fn present_sd_jwt_vc(
        &self,
        resolved: &ResolvedAuthorizationRequest,
        raw_sd_jwt: &str,
        wallet: &Arc<dyn WalletProvider>,
        signing_key_id: &str,
        holder_kid: &str,
    ) -> Result<Option<String>> {
        // 1. Locate the input descriptor.
        let pd_value = resolved
            .payload
            .presentation_definition
            .as_ref()
            .ok_or_else(|| {
                Oid4vpError::InvalidRequest("no presentation_definition on request".to_string())
            })?;
        let pd: PresentationDefinition = serde_json::from_value(pd_value.clone())
            .map_err(|e| Oid4vpError::InvalidRequest(format!("parse pd: {}", e)))?;
        let descriptor = pd.input_descriptors.first().ok_or_else(|| {
            Oid4vpError::InvalidRequest(
                "presentation_definition has no input_descriptors".to_string(),
            )
        })?;
        let required_paths: Vec<String> = descriptor
            .constraints
            .as_ref()
            .map(|c| {
                c.fields
                    .iter()
                    .filter(|f| !f.optional.unwrap_or(false))
                    .flat_map(|f| f.path.iter().cloned())
                    .collect()
            })
            .unwrap_or_default();
        let required_claim_names: Vec<String> = required_paths
            .iter()
            .filter_map(|p| {
                p.strip_prefix("$.")
                    .or_else(|| p.strip_prefix("$"))
                    .map(|s| s.trim_start_matches('.').to_string())
            })
            .collect();

        // 2. Split the SD-JWT envelope. Anything after the last `~`
        //    that doesn't look like a base64url JSON-array disclosure
        //    is a pre-existing KB-JWT we must drop (we rebuild it).
        let parts: Vec<&str> = raw_sd_jwt.trim_end_matches('~').split('~').collect();
        if parts.is_empty() {
            return Err(Oid4vpError::InvalidRequest(
                "SD-JWT envelope is empty".to_string(),
            ));
        }
        let jwt = parts[0];
        let tail = &parts[1..];

        // Decode each candidate disclosure into `(raw_segment,
        // disclosed_key)`. Skip anything that doesn't parse — likely
        // the KB-JWT from a prior verification attempt.
        let mut selected_disclosures: Vec<String> = Vec::new();
        for seg in tail {
            let bytes = match URL_SAFE_NO_PAD.decode(seg) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let arr: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(items) = arr.as_array() else {
                continue;
            };
            // Object-claim disclosures are [salt, key, value].
            // Array-element disclosures are [salt, value] — keep
            // them so array selective disclosure still works.
            let claim_name = match items.len() {
                3 => items[1].as_str().map(|s| s.to_string()),
                2 => None,
                _ => continue,
            };
            let keep = match claim_name {
                Some(name) => required_claim_names.iter().any(|p| p == &name),
                // Array element disclosures get bundled if the parent
                // path was requested — without per-path index parsing
                // we can't tell; keep them all rather than drop
                // information the verifier might require.
                None => true,
            };
            if keep {
                selected_disclosures.push((*seg).to_string());
            }
        }

        // 3. Build envelope WITHOUT the KB-JWT — that's what the
        //    sd_hash binds. SD-JWT VC hashes the
        //    full string including the trailing `~`.
        let mut envelope_for_hash = String::with_capacity(raw_sd_jwt.len());
        envelope_for_hash.push_str(jwt);
        for d in &selected_disclosures {
            envelope_for_hash.push('~');
            envelope_for_hash.push_str(d);
        }
        envelope_for_hash.push('~');
        let sd_hash = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(envelope_for_hash.as_bytes()));

        // 4. Build + sign the KB-JWT.
        let kb_header = serde_json::json!({
            "typ": "kb+jwt",
            "alg": "EdDSA",
            "kid": holder_kid,
        });
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let kb_payload = serde_json::json!({
            "iat": now,
            "aud": resolved.payload.client_id,
            "nonce": resolved.payload.nonce,
            "sd_hash": sd_hash,
        });
        let kb_header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&kb_header)
                .map_err(|e| Oid4vpError::InvalidRequest(format!("kb header: {}", e)))?,
        );
        let kb_payload_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&kb_payload)
                .map_err(|e| Oid4vpError::InvalidRequest(format!("kb payload: {}", e)))?,
        );
        let kb_signing_input = format!("{}.{}", kb_header_b64, kb_payload_b64);
        let kb_sig = wallet
            .sign(signing_key_id, kb_signing_input.as_bytes())
            .await
            .map_err(|e| Oid4vpError::InvalidRequest(format!("kb sign: {}", e)))?;
        let kb_jwt = format!(
            "{}.{}",
            kb_signing_input,
            URL_SAFE_NO_PAD.encode(&kb_sig.bytes)
        );

        // 5. Final vp_token: <jwt>~<disc>…~<kb_jwt>
        let vp_token = format!("{}{}", envelope_for_hash, kb_jwt);

        // 6. Build presentation_submission for a single SD-JWT VC.
        //    Use the oid4vp::types variant — it's the one
        //    AuthorizationResponse holds and what gets serialized on
        //    the wire. (pex::PresentationSubmission supports
        //    path_nested but isn't the type the response wraps.)
        let submission = PresentationSubmission {
            id: uuid::Uuid::new_v4().to_string(),
            definition_id: pd.id.clone(),
            descriptor_map: vec![DescriptorMap {
                id: descriptor.id.clone(),
                format: "vc+sd-jwt".to_string(),
                path: "$".to_string(),
            }],
        };

        let response = AuthorizationResponse {
            vp_token,
            presentation_submission: Some(submission),
            state: resolved.payload.state.clone(),
        };

        let direct_post_response = self
            .transport
            .send_direct_post(&resolved.payload.response_uri, &response)
            .await?;

        tracing::info!(
            "Presented SD-JWT VC ({} disclosures revealed)",
            selected_disclosures.len()
        );
        Ok(direct_post_response.redirect_uri)
    }

    // ===== Private Helper Methods =====

    /// Get authorization payload (may require fetching request_uri)
    async fn get_authorization_payload(
        &self,
        auth_request: AuthorizationRequest,
    ) -> Result<AuthorizationRequestPayload> {
        match auth_request {
            AuthorizationRequest::Object(payload) => Ok(payload),

            AuthorizationRequest::Uri(_uri) => {
                // Already parsed in parse_authorization_request
                Err(Oid4vpError::InvalidRequest(
                    "URI should be parsed already".to_string(),
                ))
            }

            AuthorizationRequest::RequestUri { request_uri } => {
                // Fetch from request_uri
                let content = self.transport.fetch_request_uri(&request_uri).await?;

                // Try to parse as JWT or JSON
                if content.starts_with("eyJ") {
                    // It's a JWT - decode it (Phase 2: JAR verification)
                    self.decode_jwt_payload(&content)
                } else {
                    // It's JSON
                    serde_json::from_str(&content).map_err(|e| {
                        Oid4vpError::EncodingError(format!(
                            "Failed to parse request payload: {}",
                            e
                        ))
                    })
                }
            }

            AuthorizationRequest::Jwt(jwt) => {
                // Decode JWT (Phase 2: JAR verification)
                self.decode_jwt_payload(&jwt)
            }
        }
    }

    /// Decode JWT payload (placeholder for Phase 2)
    fn decode_jwt_payload(&self, jwt: &str) -> Result<AuthorizationRequestPayload> {
        // TODO: Phase 2 - implement JAR verification
        // For now, just decode without verification (INSECURE - Phase 1 only)

        tracing::warn!(
            "JWT verification not implemented - accepting without verification (INSECURE)"
        );

        // Simple base64 decode of payload (middle part of JWT)
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(Oid4vpError::InvalidJwt("Invalid JWT format".to_string()));
        }

        let payload_b64 = parts[1];
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| Oid4vpError::InvalidJwt(format!("Failed to decode JWT payload: {}", e)))?;

        let payload: AuthorizationRequestPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| Oid4vpError::InvalidJwt(format!("Failed to parse JWT payload: {}", e)))?;

        Ok(payload)
    }

    /// Validate client_id and get verifier information
    fn validate_and_get_verifier_info(
        &self,
        payload: &AuthorizationRequestPayload,
    ) -> Result<VerifierInfo> {
        // Parse client_id scheme
        let (scheme, effective_id) = if payload.client_id.starts_with("https://") {
            // redirect_uri scheme
            (ClientIdScheme::RedirectUri, payload.client_id.clone())
        } else if payload.client_id.starts_with("did:") {
            // DID scheme
            (ClientIdScheme::Did, payload.client_id.clone())
        } else if payload.client_id.contains('.') {
            // x509_san_dns scheme (domain name)
            (ClientIdScheme::X509SanDns, payload.client_id.clone())
        } else {
            // Pre-registered
            (ClientIdScheme::PreRegistered, payload.client_id.clone())
        };

        // Get display name from metadata
        let name = payload
            .client_metadata
            .as_ref()
            .and_then(|m| m.client_name.clone());

        Ok(VerifierInfo {
            client_id_scheme: scheme,
            effective_client_id: effective_id,
            name,
        })
    }
}

impl Default for Oid4vpHolderService {
    fn default() -> Self {
        Self::new().expect("Failed to create Oid4vpHolderService")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_service() {
        let service = Oid4vpHolderService::new();
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_resolve_simple_authorization_request() {
        let service = Oid4vpHolderService::new().unwrap();

        let auth_request = "openid4vp://?client_id=https://verifier.com&response_uri=https://verifier.com/response&nonce=abc123";

        let result = service
            .resolve_authorization_request(auth_request, vec![], None)
            .await;

        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(
            resolved.verifier.effective_client_id,
            "https://verifier.com"
        );
        assert_eq!(
            resolved.verifier.client_id_scheme,
            ClientIdScheme::RedirectUri
        );
    }
}
