//! OID4VP Verifier service — the server-side counterpart to `holder.rs`.
//!
//! Design is a session record with a strict state machine, request-object
//! hosting, and ordered response validation, scoped to what this stack
//! speaks today: unsigned request objects
//! (`redirect_uri` client-id scheme), DIF PEX (no DCQL yet), `direct_post`
//! responses, and SD-JWT / JWT-VC vp_tokens. mDoc and JARM come later.
//!
//! Transport-neutral: an HTTP layer serves two public endpoints and delegates
//! here — GET request-object (`get_request_object`) and POST response
//! (`verify_response`).
//!
//! Session lifecycle:
//! `request-created → request-retrieved → response-verified | error`

use std::sync::Arc;
use std::time::Duration;

use agent_core::traits::{Record, StorageProvider, WalletProvider};
use chrono::{DateTime, Utc};
use did::registry::DidRegistry;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use vc::formats::jwt_vc::DidJwtVerifier;
use vc::formats::sd_jwt::verifier::SdJwtVerificationOptions;
use vc::formats::sd_jwt::{SdJwtVc, SdJwtVerifier};

use super::pex::{Field, PresentationDefinition, PresentationSubmission};
use super::types::{AuthorizationRequestPayload, ClientMetadata};

const SESSION_CATEGORY: &str = "oid4vp_verification_session";
const DEFAULT_EXPIRY_SECS: u64 = 300;

// ─── Records ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationSessionState {
    #[serde(rename = "request-created")]
    RequestCreated,
    #[serde(rename = "request-retrieved")]
    RequestRetrieved,
    #[serde(rename = "response-verified")]
    ResponseVerified,
    #[serde(rename = "error")]
    Error,
}

/// One verification flow: request out, presentation back, verdict stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationSessionRecord {
    /// Session id — doubles as the OAuth2 `state` parameter, so the response
    /// can always be correlated without a separate index.
    pub id: String,
    /// Caller's presentation-definition reference (opaque to the protocol).
    pub pres_def_id: String,
    pub state: VerificationSessionState,
    pub nonce: String,
    /// The unsigned request object served from the request_uri.
    pub payload: AuthorizationRequestPayload,
    /// `openid4vp://` URI handed to the wallet (QR / deep link).
    pub authorization_request_uri: String,
    /// Verdict after `verify_response`.
    #[serde(default)]
    pub verified: Option<bool>,
    /// Disclosed claims per input-descriptor id.
    #[serde(default)]
    pub verified_claims: Option<Value>,
    #[serde(default)]
    pub error: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Options ────────────────────────────────────────────────────────────────

pub struct CreateRequestOptions {
    pub presentation_definition: PresentationDefinition,
    /// Caller's reference for the definition (stored on the session).
    pub pres_def_id: String,
    /// Pre-assigned session id — callers embed it in the response/request
    /// URIs before creating the session. Generated when absent.
    pub session_id: Option<String>,
    /// Public URL the wallet POSTs the response to (also the client_id under
    /// the `redirect_uri` scheme). Should already include the session id.
    pub response_uri: String,
    /// Public URL the request object is served from.
    pub request_uri: String,
    pub client_name: Option<String>,
    pub expires_in: Option<Duration>,
}

/// Parsed `direct_post` response body.
pub struct AuthorizationResponseParams {
    pub vp_token: String,
    pub presentation_submission: Option<PresentationSubmission>,
    pub state: Option<String>,
}

// ─── Service ────────────────────────────────────────────────────────────────

pub struct Oid4vpVerifierService {
    storage: Arc<dyn StorageProvider>,
    wallet: Arc<dyn WalletProvider>,
    did_registry: Arc<DidRegistry>,
    event_bus: Option<Arc<agent_events::EventBus>>,
    agent_id: String,
}

impl Oid4vpVerifierService {
    pub fn new(
        storage: Arc<dyn StorageProvider>,
        wallet: Arc<dyn WalletProvider>,
        did_registry: Arc<DidRegistry>,
        event_bus: Option<Arc<agent_events::EventBus>>,
        agent_id: String,
    ) -> Self {
        Self {
            storage,
            wallet,
            did_registry,
            event_bus,
            agent_id,
        }
    }

    // ─── Request creation ───────────────────────────────────────────────

    pub async fn create_request(
        &self,
        opts: CreateRequestOptions,
    ) -> Result<VerificationSessionRecord, String> {
        let id = opts
            .session_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let nonce = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let now = Utc::now();
        let expires_in = opts
            .expires_in
            .unwrap_or(Duration::from_secs(DEFAULT_EXPIRY_SECS));

        let payload = AuthorizationRequestPayload {
            // Unsigned request → redirect_uri client-id scheme: the client_id
            // IS the response endpoint.
            client_id: opts.response_uri.clone(),
            response_uri: opts.response_uri,
            response_mode: Some("direct_post".to_string()),
            nonce: nonce.clone(),
            state: Some(id.clone()),
            presentation_definition: Some(
                serde_json::to_value(&opts.presentation_definition).map_err(|e| e.to_string())?,
            ),
            dcql_query: None,
            client_metadata: Some(ClientMetadata {
                client_name: opts.client_name,
                logo_uri: None,
                client_purpose: opts.presentation_definition.purpose.clone(),
            }),
        };

        let authorization_request_uri = format!(
            "openid4vp://?client_id={}&request_uri={}",
            pct_encode(&payload.client_id),
            pct_encode(&opts.request_uri),
        );

        let record = VerificationSessionRecord {
            id: id.clone(),
            pres_def_id: opts.pres_def_id,
            state: VerificationSessionState::RequestCreated,
            nonce,
            payload,
            authorization_request_uri,
            verified: None,
            verified_claims: None,
            error: None,
            expires_at: now + chrono::Duration::from_std(expires_in).unwrap_or_default(),
            created_at: now,
            updated_at: now,
        };
        self.save(&record, true).await?;
        self.emit_state_changed(&record, None).await;
        Ok(record)
    }

    /// Serve the unsigned request object (wallet GET on the request_uri).
    /// First retrieval transitions the session.
    pub async fn get_request_object(
        &self,
        session_id: &str,
    ) -> Result<AuthorizationRequestPayload, String> {
        let mut record = self.get_session(session_id).await?;
        if Utc::now() > record.expires_at {
            return Err("verification session expired".into());
        }
        match record.state {
            VerificationSessionState::RequestCreated => {
                let prev = record.state;
                record.state = VerificationSessionState::RequestRetrieved;
                record.updated_at = Utc::now();
                self.save(&record, false).await?;
                self.emit_state_changed(&record, Some(prev)).await;
            }
            VerificationSessionState::RequestRetrieved => {}
            _ => return Err("verification session already completed".into()),
        }
        Ok(record.payload)
    }

    // ─── Response verification ──────────────────────────────────────────

    /// Ordered validation: session state → expiry → state
    /// param → submission-vs-definition structure → per-credential signature
    /// + holder binding (nonce/aud) → descriptor completeness. Any failure
    /// lands the session in `error` with the message persisted.
    pub async fn verify_response(
        &self,
        session_id: &str,
        params: AuthorizationResponseParams,
    ) -> Result<VerificationSessionRecord, String> {
        let mut record = self.get_session(session_id).await?;

        let outcome = self.verify_response_inner(&record, &params).await;
        let prev = record.state;
        record.updated_at = Utc::now();
        match outcome {
            Ok(claims) => {
                record.state = VerificationSessionState::ResponseVerified;
                record.verified = Some(true);
                record.verified_claims = Some(claims);
                record.error = None;
            }
            Err(e) => {
                record.state = VerificationSessionState::Error;
                record.verified = Some(false);
                record.error = Some(e.clone());
            }
        }
        self.save(&record, false).await?;
        self.emit_state_changed(&record, Some(prev)).await;
        match &record.error {
            Some(e) => Err(e.clone()),
            None => Ok(record),
        }
    }

    async fn verify_response_inner(
        &self,
        record: &VerificationSessionRecord,
        params: &AuthorizationResponseParams,
    ) -> Result<Value, String> {
        if !matches!(
            record.state,
            VerificationSessionState::RequestCreated | VerificationSessionState::RequestRetrieved
        ) {
            return Err("verification session is not awaiting a response".into());
        }
        if Utc::now() > record.expires_at {
            return Err("verification session expired".into());
        }
        if let Some(state) = &params.state {
            if Some(state) != record.payload.state.as_ref() {
                return Err("state parameter does not match session".into());
            }
        }

        let definition: PresentationDefinition = record
            .payload
            .presentation_definition
            .clone()
            .ok_or("session has no presentation definition")
            .and_then(|v| serde_json::from_value(v).map_err(|_| "invalid stored definition"))
            .map_err(String::from)?;

        let submission = params
            .presentation_submission
            .as_ref()
            .ok_or("missing presentation_submission")?;
        if submission.definition_id != definition.id {
            return Err(format!(
                "presentation_submission.definition_id `{}` does not match definition `{}`",
                submission.definition_id, definition.id
            ));
        }

        // vp_token: single compact credential string or a JSON array of them.
        let vp_token: Value = serde_json::from_str(&params.vp_token)
            .unwrap_or_else(|_| Value::String(params.vp_token.clone()));

        let mut claims_by_descriptor = serde_json::Map::new();
        for entry in &submission.descriptor_map {
            let credential = resolve_vp_token_path(&vp_token, &entry.path)
                .ok_or_else(|| format!("descriptor path `{}` not found in vp_token", entry.path))?;
            let claims = self
                .verify_credential(&credential, &record.nonce, &record.payload.client_id)
                .await
                .map_err(|e| format!("descriptor `{}`: {e}", entry.id))?;
            claims_by_descriptor.insert(entry.id.clone(), claims);
        }

        // Every input descriptor must be satisfied by verified claims.
        for descriptor in &definition.input_descriptors {
            let claims = claims_by_descriptor.get(&descriptor.id).ok_or_else(|| {
                format!("no presentation for input descriptor `{}`", descriptor.id)
            })?;
            if let Some(constraints) = &descriptor.constraints {
                for field in &constraints.fields {
                    if field.optional == Some(true) {
                        continue;
                    }
                    if !field_satisfied(claims, field) {
                        return Err(format!(
                            "descriptor `{}`: required field {:?} not disclosed",
                            descriptor.id, field.path
                        ));
                    }
                }
            }
        }

        Ok(Value::Object(claims_by_descriptor))
    }

    /// Verify one credential from the vp_token; returns its (disclosed) claims.
    async fn verify_credential(
        &self,
        credential: &str,
        nonce: &str,
        client_id: &str,
    ) -> Result<Value, String> {
        if credential.contains('~') {
            // SD-JWT compact. Holder binding (KB-JWT) is checked against this
            // session's nonce + client_id when present.
            let sd_jwt = SdJwtVc::from_compact(credential).map_err(|e| e.to_string())?;
            let verifier = SdJwtVerifier::new_with_did_registry(
                self.wallet.clone(),
                self.did_registry.clone(),
            );
            let options = SdJwtVerificationOptions {
                expected_nonce: Some(nonce.to_string()),
                expected_audience: Some(client_id.to_string()),
                require_key_binding: false,
                max_kb_age: None,
            };
            let result = verifier
                .verify(&sd_jwt, &options)
                .await
                .map_err(|e| e.to_string())?;
            if !result.is_valid {
                return Err(format!(
                    "sd-jwt verification failed: {}",
                    result.errors.join("; ")
                ));
            }
            let mut claims = result.disclosed_claims.unwrap_or_else(|| json!({}));
            // Strip SD plumbing from the claim set handed to policy checks.
            if let Some(obj) = claims.as_object_mut() {
                obj.remove("_sd");
                obj.remove("_sd_alg");
            }
            Ok(claims)
        } else if credential.split('.').count() == 3 {
            // Plain JWT (JWT-VC or JWT-VP): resolve `iss` and verify.
            let payload = decode_jwt_payload(credential)?;
            let issuer = payload
                .get("iss")
                .and_then(Value::as_str)
                .ok_or("jwt missing iss claim")?
                .to_string();
            let verifier = DidJwtVerifier::new(self.did_registry.clone());
            verifier
                .verify_jwt(credential, &issuer)
                .await
                .map_err(|e| format!("jwt verification failed: {e}"))?;
            if let Some(jwt_nonce) = payload.get("nonce").and_then(Value::as_str) {
                if jwt_nonce != nonce {
                    return Err("jwt nonce does not match session nonce".into());
                }
            }
            // Prefer the embedded VC claims; fall back to the raw payload.
            Ok(payload
                .pointer("/vc/credentialSubject")
                .cloned()
                .map(|subject| {
                    let mut merged = payload.clone();
                    if let (Some(m), Some(s)) = (merged.as_object_mut(), subject.as_object()) {
                        for (k, v) in s {
                            m.entry(k.clone()).or_insert_with(|| v.clone());
                        }
                    }
                    merged
                })
                .unwrap_or(payload))
        } else {
            Err("unsupported credential format in vp_token (expected sd-jwt or jwt)".into())
        }
    }

    // ─── Session store ──────────────────────────────────────────────────

    pub async fn get_session(&self, id: &str) -> Result<VerificationSessionRecord, String> {
        self.storage
            .find(SESSION_CATEGORY, id)
            .await
            .map_err(|e| e.to_string())?
            .and_then(|r| serde_json::from_slice(&r.value).ok())
            .ok_or_else(|| format!("verification session {id} not found"))
    }

    pub async fn list_sessions(&self) -> Vec<VerificationSessionRecord> {
        match self
            .storage
            .find_all(SESSION_CATEGORY, &agent_core::traits::Query::new())
            .await
        {
            Ok(records) => records
                .iter()
                .filter_map(|r| serde_json::from_slice(&r.value).ok())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    async fn save(&self, record: &VerificationSessionRecord, new: bool) -> Result<(), String> {
        let bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        let rec = Record::new(SESSION_CATEGORY, record.id.clone(), bytes);
        if new {
            self.storage.save(&rec).await.map_err(|e| e.to_string())
        } else {
            self.storage.update(&rec).await.map_err(|e| e.to_string())
        }
    }

    async fn emit_state_changed(
        &self,
        record: &VerificationSessionRecord,
        previous: Option<VerificationSessionState>,
    ) {
        let Some(bus) = &self.event_bus else { return };
        let ev = agent_events::Event::new(
            &self.agent_id,
            "oid4vp",
            "state_changed",
            json!({
                "presentation_id": record.id,
                "pres_def_id": record.pres_def_id,
                "state": record.state,
                "previous_state": previous,
                "verified": record.verified,
                "error": record.error,
            }),
        );
        let _ = bus.publish(ev).await;
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Resolve a descriptor-map path into the vp_token: `$` (single credential)
/// or `$[n]` (array element). Nested VP paths aren't produced by this stack.
fn resolve_vp_token_path(vp_token: &Value, path: &str) -> Option<String> {
    let at = |v: &Value| v.as_str().map(String::from);
    match path {
        "$" => at(vp_token),
        _ => {
            let idx: usize = path.strip_prefix("$[")?.strip_suffix(']')?.parse().ok()?;
            at(vp_token.as_array()?.get(idx)?)
        }
    }
}

/// Minimal JSONPath for PEX `Field.path` entries: `$.a.b`, `$.a[0].b`.
fn resolve_json_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    let trimmed = path.strip_prefix('$')?;
    for segment in trimmed.split('.').filter(|s| !s.is_empty()) {
        // `name[0]` → key then index; bare `[0]` → index only.
        let (key, indexes) = match segment.find('[') {
            Some(pos) => (&segment[..pos], &segment[pos..]),
            None => (segment, ""),
        };
        if !key.is_empty() {
            current = current.get(key)?;
        }
        for idx_part in indexes.split('[').filter(|s| !s.is_empty()) {
            let idx: usize = idx_part.strip_suffix(']')?.parse().ok()?;
            current = current.get(idx)?;
        }
    }
    Some(current)
}

/// A field is satisfied when any of its paths resolves. SD-JWT claims are
/// flat while definitions often address `$.vc.credentialSubject.x` /
/// `$.credentialSubject.x` — also try the flattened tail as a fallback.
fn field_satisfied(claims: &Value, field: &Field) -> bool {
    field.path.iter().any(|p| {
        if resolve_json_path(claims, p).is_some() {
            return true;
        }
        for prefix in ["$.vc.credentialSubject.", "$.credentialSubject."] {
            if let Some(rest) = p.strip_prefix(prefix) {
                if resolve_json_path(claims, &format!("$.{rest}")).is_some() {
                    return true;
                }
            }
        }
        false
    })
}

fn decode_jwt_payload(jwt: &str) -> Result<Value, String> {
    use base64::Engine;
    let payload_b64 = jwt.split('.').nth(1).ok_or("malformed jwt")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

/// Percent-encode a URI component (RFC 3986 unreserved set kept).
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vp_token_paths_resolve_single_and_array() {
        let single = Value::String("cred~".into());
        assert_eq!(
            resolve_vp_token_path(&single, "$").as_deref(),
            Some("cred~")
        );
        let arr = json!(["a", "b"]);
        assert_eq!(resolve_vp_token_path(&arr, "$[1]").as_deref(), Some("b"));
        assert!(resolve_vp_token_path(&arr, "$[2]").is_none());
    }

    #[test]
    fn json_path_resolves_nested_and_indexed() {
        let doc = json!({ "a": { "b": [ { "c": 1 } ] } });
        assert_eq!(resolve_json_path(&doc, "$.a.b[0].c"), Some(&json!(1)));
        assert!(resolve_json_path(&doc, "$.a.x").is_none());
    }

    #[test]
    fn field_satisfied_falls_back_to_flat_sd_jwt_claims() {
        let claims = json!({ "given_name": "Ada" });
        let field = Field {
            path: vec!["$.vc.credentialSubject.given_name".into()],
            id: None,
            name: None,
            purpose: None,
            filter: None,
            optional: None,
            predicate: None,
        };
        assert!(field_satisfied(&claims, &field));
    }

    #[test]
    fn pct_encode_is_rfc3986() {
        assert_eq!(
            pct_encode("https://x.y/z?a=b"),
            "https%3A%2F%2Fx.y%2Fz%3Fa%3Db"
        );
    }

    fn test_service() -> Oid4vpVerifierService {
        use crate::test_utils::{InMemoryStorage, InMemoryWallet};
        Oid4vpVerifierService::new(
            Arc::new(InMemoryStorage::new()),
            Arc::new(InMemoryWallet::new()),
            Arc::new(DidRegistry::new()),
            None,
            "test-tenant".into(),
        )
    }

    fn test_definition() -> PresentationDefinition {
        serde_json::from_value(json!({
            "id": "def-1",
            "input_descriptors": [{
                "id": "card",
                "constraints": { "fields": [{ "path": ["$.given_name"] }] }
            }]
        }))
        .unwrap()
    }

    fn test_options() -> CreateRequestOptions {
        CreateRequestOptions {
            presentation_definition: test_definition(),
            pres_def_id: "pd-1".into(),
            session_id: Some("sess-1".into()),
            response_uri: "https://v.example/oid4vp/pub/t/response/sess-1".into(),
            request_uri: "https://v.example/oid4vp/pub/t/request/sess-1".into(),
            client_name: Some("Test Verifier".into()),
            expires_in: None,
        }
    }

    #[tokio::test]
    async fn session_lifecycle_create_retrieve_and_fail_closed() {
        let svc = test_service();

        // Create: state request-created, wallet URI carries both params.
        let record = svc.create_request(test_options()).await.unwrap();
        assert_eq!(record.id, "sess-1");
        assert_eq!(record.state, VerificationSessionState::RequestCreated);
        assert!(record
            .authorization_request_uri
            .starts_with("openid4vp://?client_id="));
        assert!(record.authorization_request_uri.contains("request_uri="));
        assert_eq!(record.payload.state.as_deref(), Some("sess-1"));

        // Wallet fetches the request object → request-retrieved (idempotent).
        let payload = svc.get_request_object("sess-1").await.unwrap();
        assert_eq!(payload.nonce, record.nonce);
        let _ = svc.get_request_object("sess-1").await.unwrap();
        assert_eq!(
            svc.get_session("sess-1").await.unwrap().state,
            VerificationSessionState::RequestRetrieved
        );

        // Garbage vp_token → session lands in error with the message kept.
        let err = svc
            .verify_response(
                "sess-1",
                AuthorizationResponseParams {
                    vp_token: "not-a-credential".into(),
                    presentation_submission: Some(
                        serde_json::from_value(json!({
                            "id": "sub-1",
                            "definition_id": "def-1",
                            "descriptor_map": [{ "id": "card", "format": "vc+sd-jwt", "path": "$" }]
                        }))
                        .unwrap(),
                    ),
                    state: Some("sess-1".into()),
                },
            )
            .await
            .unwrap_err();
        assert!(
            err.contains("card"),
            "error should name the descriptor: {err}"
        );
        let session = svc.get_session("sess-1").await.unwrap();
        assert_eq!(session.state, VerificationSessionState::Error);
        assert_eq!(session.verified, Some(false));
        assert!(session.error.is_some());

        // Completed (errored) sessions refuse further responses and request fetches.
        let again = svc
            .verify_response(
                "sess-1",
                AuthorizationResponseParams {
                    vp_token: "x".into(),
                    presentation_submission: None,
                    state: None,
                },
            )
            .await
            .unwrap_err();
        assert!(again.contains("not awaiting"));
        assert!(svc.get_request_object("sess-1").await.is_err());
    }

    #[tokio::test]
    async fn response_rejects_wrong_state_and_definition_id() {
        let svc = test_service();
        svc.create_request(test_options()).await.unwrap();

        // Wrong OAuth2 state param.
        let err = svc
            .verify_response(
                "sess-1",
                AuthorizationResponseParams {
                    vp_token: "x~".into(),
                    presentation_submission: None,
                    state: Some("other".into()),
                },
            )
            .await
            .unwrap_err();
        assert!(err.contains("state parameter"));

        // Fresh session; wrong definition_id in the submission.
        let mut opts = test_options();
        opts.session_id = Some("sess-2".into());
        svc.create_request(opts).await.unwrap();
        let err = svc
            .verify_response(
                "sess-2",
                AuthorizationResponseParams {
                    vp_token: "x~".into(),
                    presentation_submission: Some(
                        serde_json::from_value(json!({
                            "id": "sub-1",
                            "definition_id": "wrong-def",
                            "descriptor_map": []
                        }))
                        .unwrap(),
                    ),
                    state: Some("sess-2".into()),
                },
            )
            .await
            .unwrap_err();
        assert!(err.contains("definition"));
    }
}
