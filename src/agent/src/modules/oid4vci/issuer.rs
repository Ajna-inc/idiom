//! OID4VCI Issuer service.
//!
//! Server-side counterpart to the holder module. Issuers create credential
//! *offers*, exchange pre-authorized codes for access tokens, mint c_nonces,
//! and finally hand the holder a signed credential when they POST to the
//! credential endpoint.
//!
//! This module provides a transport-neutral service. Wire up the four
//! endpoints (metadata, token, nonce, credential) in an outer HTTP layer
//! (axum, actix, …) and delegate to the methods below.

use super::types::{
    CredentialConfiguration, CredentialOffer, CredentialOfferGrants, CredentialRequest,
    CredentialResponse, IssuerMetadata, PreAuthorizedCodeGrant, TokenResponse,
};
use agent_core::traits::{Record, StorageProvider};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Persistent storage key for the issuer session snapshot. The store is small
/// and infrequently written, so we serialize the entire snapshot to one
/// Askar record per save — simpler than per-key entries.
const ISSUER_SESSION_STORAGE_KEY: &str = "oid4vci_issuer_session_store";
const ISSUER_SESSION_STORAGE_CATEGORY: &str = "oid4vci";

/// Issuer-side session state. Pre-auth codes, access tokens, and c_nonces
/// are kept in memory for fast lookup; if a `StorageProvider` is attached,
/// every mutation is also persisted so the issuer can survive restarts.
pub struct IssuerSessionStore {
    /// Sharded concurrent maps (not a single `Mutex`): different tokens/nonces
    /// hash to different shards, so concurrent issuance doesn't serialize on one
    /// lock — the difference between using ~5 and all cores under load.
    pre_auth_codes: DashMap<String, PreAuthSession>,
    access_tokens: DashMap<String, IssuedToken>,
    c_nonces: DashMap<String, (String, DateTime<Utc>)>,
    storage: Option<Arc<dyn StorageProvider>>,
    /// Unix-millis of the last expiry sweep. GC scans every session (O(n)), so
    /// running it on every request serializes issuance once sessions accumulate.
    /// Throttle it to at most once/second — between sweeps the per-request path
    /// is O(1) and issuance parallelizes across cores.
    last_gc_ms: std::sync::atomic::AtomicI64,
}

impl IssuerSessionStore {
    /// Snapshot the sessions into the serializable DTO (for persistence).
    fn snapshot(&self) -> IssuerSessionStoreInner {
        IssuerSessionStoreInner {
            pre_auth_codes: self
                .pre_auth_codes
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            access_tokens: self
                .access_tokens
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            c_nonces: self
                .c_nonces
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
        }
    }

    /// Replace all sessions from a restored DTO.
    fn load_snapshot(&self, dto: IssuerSessionStoreInner) {
        self.pre_auth_codes.clear();
        self.access_tokens.clear();
        self.c_nonces.clear();
        for (k, v) in dto.pre_auth_codes {
            self.pre_auth_codes.insert(k, v);
        }
        for (k, v) in dto.access_tokens {
            self.access_tokens.insert(k, v);
        }
        for (k, v) in dto.c_nonces {
            self.c_nonces.insert(k, v);
        }
    }
}

impl Default for IssuerSessionStore {
    fn default() -> Self {
        Self {
            pre_auth_codes: DashMap::new(),
            access_tokens: DashMap::new(),
            c_nonces: DashMap::new(),
            storage: None,
            last_gc_ms: std::sync::atomic::AtomicI64::new(0),
        }
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
struct IssuerSessionStoreInner {
    /// `pre_auth_code -> session info`. Sessions expire and are GC'd.
    pre_auth_codes: HashMap<String, PreAuthSession>,
    /// `access_token -> session info` (after token exchange).
    access_tokens: HashMap<String, IssuedToken>,
    /// `c_nonce -> (access_token, issued_at)`
    c_nonces: HashMap<String, (String, DateTime<Utc>)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PreAuthSession {
    pub credential_configuration_ids: Vec<String>,
    /// Caller-defined identifier (e.g. user id) used when minting the credential.
    pub subject_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IssuedToken {
    pub credential_configuration_ids: Vec<String>,
    pub subject_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Outcome of `accept_token_request` — caller relays this to the wallet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenIssuance {
    pub response: TokenResponse,
    /// Internal session handle — pass back into `accept_credential_request`.
    pub session_token: String,
}

/// Configuration carried by the issuer service: who we are, what we issue,
/// and where the endpoints live.
#[derive(Clone, Debug)]
pub struct Oid4vciIssuerConfig {
    pub issuer_url: String,
    pub credential_issuer_did: String,
    pub credential_endpoint: String,
    pub token_endpoint: String,
    pub nonce_endpoint: Option<String>,
    pub authorization_server: Option<String>,
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,
    /// How long pre-authorized codes remain valid.
    pub pre_auth_code_ttl: Duration,
    /// How long access tokens remain valid.
    pub access_token_ttl: Duration,
    /// How long c_nonces remain valid.
    pub c_nonce_ttl: Duration,
}

impl Default for Oid4vciIssuerConfig {
    fn default() -> Self {
        Self {
            issuer_url: "https://issuer.example.com".to_string(),
            credential_issuer_did: "did:web:issuer.example.com".to_string(),
            credential_endpoint: "https://issuer.example.com/credential".to_string(),
            token_endpoint: "https://issuer.example.com/token".to_string(),
            nonce_endpoint: Some("https://issuer.example.com/nonce".to_string()),
            authorization_server: None,
            credential_configurations_supported: HashMap::new(),
            pre_auth_code_ttl: Duration::from_secs(15 * 60),
            access_token_ttl: Duration::from_secs(60 * 60),
            c_nonce_ttl: Duration::from_secs(5 * 60),
        }
    }
}

/// Pluggable credential minter — invoked once a credential request has been
/// validated. Implementations sign and return the credential in whatever
/// format the configuration specifies (vc+sd-jwt, anoncreds, mso_mdoc, …).
#[async_trait::async_trait]
pub trait Oid4vciCredentialMinter: Send + Sync {
    async fn mint(
        &self,
        configuration_id: &str,
        subject_id: Option<&str>,
        request: &CredentialRequest,
    ) -> Result<serde_json::Value, String>;
}

pub struct Oid4vciIssuerService {
    config: Oid4vciIssuerConfig,
    sessions: Arc<IssuerSessionStore>,
    minter: Arc<dyn Oid4vciCredentialMinter>,
}

impl Oid4vciIssuerService {
    pub fn new(config: Oid4vciIssuerConfig, minter: Arc<dyn Oid4vciCredentialMinter>) -> Self {
        Self {
            config,
            sessions: Arc::new(IssuerSessionStore::default()),
            minter,
        }
    }

    /// Construct an issuer that persists its session store to the given
    /// `StorageProvider`. Sessions written by an earlier process run are
    /// restored asynchronously via `restore_sessions()`.
    pub fn new_with_storage(
        config: Oid4vciIssuerConfig,
        minter: Arc<dyn Oid4vciCredentialMinter>,
        storage: Arc<dyn StorageProvider>,
    ) -> Self {
        Self {
            config,
            sessions: Arc::new(IssuerSessionStore {
                pre_auth_codes: DashMap::new(),
                access_tokens: DashMap::new(),
                c_nonces: DashMap::new(),
                storage: Some(storage),
                last_gc_ms: std::sync::atomic::AtomicI64::new(0),
            }),
            minter,
        }
    }

    /// Reload sessions from `StorageProvider` (no-op if storage isn't
    /// attached). Call this once at startup so in-flight flows survive a
    /// process restart.
    pub async fn restore_sessions(&self) -> Result<(), String> {
        let Some(storage) = self.sessions.storage.clone() else {
            return Ok(());
        };
        match storage
            .find(ISSUER_SESSION_STORAGE_CATEGORY, ISSUER_SESSION_STORAGE_KEY)
            .await
        {
            Ok(Some(record)) => {
                let restored: IssuerSessionStoreInner = serde_json::from_slice(&record.value)
                    .map_err(|e| format!("issuer session store decode: {}", e))?;
                self.sessions.load_snapshot(restored);
                self.gc_expired_locked();
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) => Err(format!("issuer session store load: {}", e)),
        }
    }

    /// Return the public issuer metadata document served from
    /// `/.well-known/openid-credential-issuer`.
    pub fn metadata(&self) -> IssuerMetadata {
        IssuerMetadata {
            credential_issuer: self.config.issuer_url.clone(),
            credential_endpoint: self.config.credential_endpoint.clone(),
            nonce_endpoint: self.config.nonce_endpoint.clone(),
            token_endpoint: Some(self.config.token_endpoint.clone()),
            authorization_server: self.config.authorization_server.clone(),
            credential_configurations_supported: self
                .config
                .credential_configurations_supported
                .clone(),
            display: None,
        }
    }

    /// Create a fresh credential offer (pre-authorized code grant).
    /// `subject_id` is opaque to the protocol — caller uses it later to
    /// produce the right credential at mint time.
    pub fn create_offer(
        &self,
        credential_configuration_ids: Vec<String>,
        subject_id: Option<String>,
    ) -> CredentialOffer {
        let pre_auth_code = generate_secure_token();
        self.gc_expired();
        self.sessions.pre_auth_codes.insert(
            pre_auth_code.clone(),
            PreAuthSession {
                credential_configuration_ids: credential_configuration_ids.clone(),
                subject_id,
                created_at: Utc::now(),
            },
        );
        self.spawn_persist();

        CredentialOffer {
            credential_issuer: self.config.issuer_url.clone(),
            credential_configuration_ids,
            grants: CredentialOfferGrants {
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: pre_auth_code,
                    tx_code: None,
                }),
                authorization_code: None,
            },
        }
    }

    /// Best-effort fire-and-forget persistence. We deliberately don't await
    /// — the public methods are sync (no `&mut self`), and persist failures
    /// are non-fatal (sessions live in memory; persistence is only needed
    /// across restarts).
    fn spawn_persist(&self) {
        if self.sessions.storage.is_none() {
            return;
        }
        let snapshot = self.sessions.snapshot();
        let storage = self.sessions.storage.clone().unwrap();
        tokio::spawn(async move {
            let bytes = match serde_json::to_vec(&snapshot) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("oid4vci issuer session persist encode: {}", e);
                    return;
                }
            };
            let record = Record::new(
                ISSUER_SESSION_STORAGE_CATEGORY,
                ISSUER_SESSION_STORAGE_KEY,
                bytes,
            );
            // Try update-first (existing key) and fall back to save (first run).
            if storage.update(&record).await.is_err() {
                if let Err(e) = storage.save(&record).await {
                    tracing::warn!("oid4vci issuer session persist write: {}", e);
                }
            }
        });
    }

    /// Exchange a pre-authorized code for an access token + c_nonce.
    /// Returns `Err` if the code is unknown, expired, or already redeemed.
    pub fn accept_token_request(&self, pre_authorized_code: &str) -> Result<TokenIssuance, String> {
        self.gc_expired();
        let result = {
            let (_, session) = self
                .sessions
                .pre_auth_codes
                .remove(pre_authorized_code)
                .ok_or_else(|| "unknown or expired pre-authorized code".to_string())?;

            if elapsed(session.created_at) > self.config.pre_auth_code_ttl {
                return Err("pre-authorized code expired".to_string());
            }

            let access_token = generate_secure_token();
            let c_nonce = generate_secure_token();
            self.sessions.access_tokens.insert(
                access_token.clone(),
                IssuedToken {
                    credential_configuration_ids: session.credential_configuration_ids,
                    subject_id: session.subject_id,
                    created_at: Utc::now(),
                },
            );
            self.sessions
                .c_nonces
                .insert(c_nonce.clone(), (access_token.clone(), Utc::now()));

            TokenIssuance {
                response: TokenResponse {
                    access_token: access_token.clone(),
                    token_type: "Bearer".to_string(),
                    expires_in: Some(self.config.access_token_ttl.as_secs()),
                    c_nonce: Some(c_nonce),
                    c_nonce_expires_in: Some(self.config.c_nonce_ttl.as_secs()),
                },
                session_token: access_token,
            }
        };
        self.spawn_persist();
        Ok(result)
    }

    /// Mint a fresh c_nonce against an active access token. Lets wallets
    /// recover when the original c_nonce expires before they finish their
    /// proof of possession.
    pub fn mint_nonce(&self, access_token: &str) -> Result<String, String> {
        self.gc_expired();
        let nonce = {
            if !self.sessions.access_tokens.contains_key(access_token) {
                return Err("invalid access token".to_string());
            }
            let nonce = generate_secure_token();
            self.sessions
                .c_nonces
                .insert(nonce.clone(), (access_token.to_string(), Utc::now()));
            nonce
        };
        self.spawn_persist();
        Ok(nonce)
    }

    /// Validate an incoming credential request and mint the credential.
    /// `access_token` is the Bearer token from the wallet; the caller
    /// already extracted it from the HTTP Authorization header.
    pub async fn accept_credential_request(
        &self,
        access_token: &str,
        request: &CredentialRequest,
    ) -> Result<CredentialResponse, String> {
        self.gc_expired();

        // Concurrent lookups (sharded maps) — no shared lock across requests.
        let (configuration_id, subject_id) = {
            let token = self
                .sessions
                .access_tokens
                .get(access_token)
                .ok_or_else(|| "invalid access token".to_string())?;
            if elapsed(token.created_at) > self.config.access_token_ttl {
                drop(token);
                self.sessions.access_tokens.remove(access_token);
                return Err("access token expired".to_string());
            }
            let cfg = request
                .credential_identifier
                .as_deref()
                .or_else(|| {
                    token
                        .credential_configuration_ids
                        .first()
                        .map(|s| s.as_str())
                })
                .ok_or_else(|| {
                    "no credential configuration determined for this request".to_string()
                })?
                .to_string();
            let subj = token.subject_id.clone();
            drop(token);
            if let Some(proof) = &request.proof {
                if let Some(nonce_str) = proof_nonce(proof) {
                    let (_, (bound_token, issued_at)) =
                        self.sessions
                            .c_nonces
                            .remove(&nonce_str)
                            .ok_or_else(|| "unknown c_nonce in proof".to_string())?;
                    if bound_token != access_token {
                        return Err("c_nonce not bound to this access token".to_string());
                    }
                    if elapsed(issued_at) > self.config.c_nonce_ttl {
                        return Err("c_nonce expired".to_string());
                    }
                }
            }
            (cfg, subj)
        };
        self.spawn_persist();

        let credential = self
            .minter
            .mint(&configuration_id, subject_id.as_deref(), request)
            .await?;

        // Do NOT eagerly mint a fresh c_nonce here: it takes a second global
        // lock, allocates, and grows the nonce map on *every* credential — pure
        // overhead for single-shot issuance. Wallets that chain requests fetch a
        // fresh nonce from the /nonce endpoint (advertised in metadata), which
        // is spec-compliant.
        Ok(CredentialResponse {
            format: request.format.clone(),
            credential,
            c_nonce: None,
            c_nonce_expires_in: None,
        })
    }

    /// Drop expired sessions, access tokens, and c_nonces. Called at the start
    /// of every public method to keep memory bounded — but the sweep is O(n)
    /// under the lock, so it's throttled to at most once/second. Between sweeps
    /// the per-request path only does its own O(1) map ops, so concurrent
    /// issuance parallelizes instead of serializing on a full-store scan.
    fn gc_expired(&self) {
        use std::sync::atomic::Ordering;
        let now = chrono::Utc::now().timestamp_millis();
        let last = self.sessions.last_gc_ms.load(Ordering::Relaxed);
        if now - last < 1000 {
            return;
        }
        // Claim this sweep; if another thread beat us, skip (single sweeper).
        if self
            .sessions
            .last_gc_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.gc_expired_locked();
    }

    fn gc_expired_locked(&self) {
        let pre_ttl = self.config.pre_auth_code_ttl;
        self.sessions
            .pre_auth_codes
            .retain(|_, s| elapsed(s.created_at) <= pre_ttl);
        let tok_ttl = self.config.access_token_ttl;
        self.sessions
            .access_tokens
            .retain(|_, t| elapsed(t.created_at) <= tok_ttl);
        let nonce_ttl = self.config.c_nonce_ttl;
        self.sessions
            .c_nonces
            .retain(|_, (_, t)| elapsed(*t) <= nonce_ttl);
    }
}

fn elapsed(stamp: DateTime<Utc>) -> Duration {
    (Utc::now() - stamp)
        .to_std()
        .unwrap_or(Duration::from_secs(0))
}

fn generate_secure_token() -> String {
    use uuid::Uuid;
    // Two UUIDs glued together → 256 bits of randomness, base64url-safe-ish
    // since uuids are alphanumeric+dash. Plenty for opaque session tokens.
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn proof_nonce(proof: &super::types::CredentialProof) -> Option<String> {
    match proof {
        super::types::CredentialProof::Jwt { jwt } => {
            // Pull the `nonce` claim out of the JWT payload.
            let parts: Vec<&str> = jwt.splitn(3, '.').collect();
            if parts.len() < 2 {
                return None;
            }
            let payload =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
                    .ok()?;
            let v: serde_json::Value = serde_json::from_slice(&payload).ok()?;
            v.get("nonce")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        }
        super::types::CredentialProof::AnonCreds { nonce, .. } => Some(nonce.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoMinter;

    #[async_trait::async_trait]
    impl Oid4vciCredentialMinter for EchoMinter {
        async fn mint(
            &self,
            configuration_id: &str,
            subject_id: Option<&str>,
            _request: &CredentialRequest,
        ) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({
                "format": "vc+sd-jwt",
                "configuration_id": configuration_id,
                "subject_id": subject_id,
            }))
        }
    }

    fn make_issuer() -> Oid4vciIssuerService {
        let mut config = Oid4vciIssuerConfig::default();
        config.credential_configurations_supported.insert(
            "UniversityDegree".to_string(),
            CredentialConfiguration {
                format: "vc+sd-jwt".into(),
                scope: Some("UniversityDegree_JWT".into()),
                credential_signing_alg_values_supported: vec!["EdDSA".into()],
                anoncreds: None,
                display: None,
            },
        );
        Oid4vciIssuerService::new(config, Arc::new(EchoMinter))
    }

    #[test]
    fn offer_and_token_roundtrip() {
        let issuer = make_issuer();
        let offer = issuer.create_offer(vec!["UniversityDegree".into()], Some("user-1".into()));
        let pre_auth_code = offer
            .grants
            .pre_authorized_code
            .as_ref()
            .unwrap()
            .pre_authorized_code
            .clone();

        let issuance = issuer.accept_token_request(&pre_auth_code).unwrap();
        assert!(!issuance.response.access_token.is_empty());
        assert!(issuance.response.c_nonce.is_some());
        assert_eq!(issuance.session_token, issuance.response.access_token);
    }

    #[test]
    fn pre_auth_code_consumed_after_exchange() {
        let issuer = make_issuer();
        let offer = issuer.create_offer(vec!["UniversityDegree".into()], None);
        let pre_auth_code = offer
            .grants
            .pre_authorized_code
            .as_ref()
            .unwrap()
            .pre_authorized_code
            .clone();

        let _ = issuer.accept_token_request(&pre_auth_code).unwrap();
        // Second use must fail.
        assert!(issuer.accept_token_request(&pre_auth_code).is_err());
    }

    #[tokio::test]
    async fn credential_request_validates_access_token() {
        let issuer = make_issuer();
        let bogus_request = CredentialRequest {
            format: "vc+sd-jwt".into(),
            credential_identifier: Some("UniversityDegree".into()),
            proof: None,
        };
        let result = issuer
            .accept_credential_request("not-a-real-token", &bogus_request)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn full_issuance_flow() {
        let issuer = make_issuer();
        let offer = issuer.create_offer(vec!["UniversityDegree".into()], Some("alice".into()));
        let pre_auth_code = offer
            .grants
            .pre_authorized_code
            .as_ref()
            .unwrap()
            .pre_authorized_code
            .clone();

        let issuance = issuer.accept_token_request(&pre_auth_code).unwrap();
        let request = CredentialRequest {
            format: "vc+sd-jwt".into(),
            credential_identifier: Some("UniversityDegree".into()),
            proof: None,
        };
        let response = issuer
            .accept_credential_request(&issuance.session_token, &request)
            .await
            .unwrap();
        assert_eq!(response.format, "vc+sd-jwt");
        assert_eq!(
            response
                .credential
                .get("configuration_id")
                .and_then(|v| v.as_str()),
            Some("UniversityDegree")
        );
        assert_eq!(
            response
                .credential
                .get("subject_id")
                .and_then(|v| v.as_str()),
            Some("alice")
        );
    }

    #[test]
    fn nonce_can_be_refreshed() {
        let issuer = make_issuer();
        let offer = issuer.create_offer(vec!["UniversityDegree".into()], None);
        let pre_auth_code = offer
            .grants
            .pre_authorized_code
            .as_ref()
            .unwrap()
            .pre_authorized_code
            .clone();
        let issuance = issuer.accept_token_request(&pre_auth_code).unwrap();
        let nonce1 = issuer.mint_nonce(&issuance.session_token).unwrap();
        let nonce2 = issuer.mint_nonce(&issuance.session_token).unwrap();
        assert_ne!(nonce1, nonce2);
    }
}
