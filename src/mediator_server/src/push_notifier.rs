//! Mediator-side push notifier implementations.
//!
//! `protocol_push_notifications::PushNotifier` is the abstract hook called
//! by `ForwardService` after queueing a message that had no live WS
//! delivery. Two concrete impls live here:
//!
//! * [`FcmPushNotifier`] — Firebase Cloud Messaging HTTP v1. Loads a Google
//!   service-account JSON, signs an RS256 JWT, exchanges it for an OAuth2
//!   Bearer token at `oauth2.googleapis.com/token` (cached for ~55 min),
//!   then POSTs to `fcm.googleapis.com/v1/projects/{PROJECT}/messages:send`.
//!   The payload carries both `android:` and `apns:` blocks in one call so
//!   one notifier covers both platforms.
//! * [`WebhookPushNotifier`] — Trivial JSON POST of
//!   `{connection_id, device_token, device_platform}` to a configured URL.
//!   Intended for deployments that already run their own push relay.

use async_trait::async_trait;
use protocol_push_notifications::{
    DeviceInfoRecord, DeviceInfoRepositoryTrait, DevicePlatform, PushNotifier,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Configuration for the notification body sent to wallets.
#[derive(Clone, Debug)]
pub struct PushNotificationContent {
    pub title: String,
    pub body: String,
}

impl Default for PushNotificationContent {
    fn default() -> Self {
        Self {
            title: "New message".to_string(),
            body: "You have a new encrypted message".to_string(),
        }
    }
}

/// A push notifier that POSTs a small JSON document to a webhook URL.
///
/// Body: `{ "connectionId": "...", "deviceToken": "...", "devicePlatform": "ios"|"android" }`.
/// Useful when the wallet team already operates a push relay (or wants to
/// avoid mounting Firebase service-account JSON in the mediator pod).
pub struct WebhookPushNotifier {
    repo: Arc<dyn DeviceInfoRepositoryTrait>,
    url: String,
    client: reqwest::Client,
}

impl WebhookPushNotifier {
    pub fn new(repo: Arc<dyn DeviceInfoRepositoryTrait>, url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { repo, url, client }
    }

    pub fn with_client(
        repo: Arc<dyn DeviceInfoRepositoryTrait>,
        url: String,
        client: reqwest::Client,
    ) -> Self {
        Self { repo, url, client }
    }
}

#[async_trait]
impl PushNotifier for WebhookPushNotifier {
    async fn notify(&self, connection_id: &str) -> Result<(), String> {
        let record = self
            .repo
            .find_by_connection_id(connection_id)
            .await
            .map_err(|e| format!("device-info lookup: {}", e))?;

        let Some(record) = record else {
            // No registration → nothing to push. Not an error.
            tracing::debug!(
                connection_id = connection_id,
                "Webhook notifier: no device registration; skipping"
            );
            return Ok(());
        };

        let payload = serde_json::json!({
            "connectionId": connection_id,
            "deviceToken": record.device_token,
            "devicePlatform": record.device_platform.to_string(),
        });

        let resp = self
            .client
            .post(&self.url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("webhook POST: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(format!("webhook returned HTTP {}", status));
        }
        Ok(())
    }
}

// ============================================================================
// FCM v1
// ============================================================================

const FCM_AUDIENCE: &str = "https://oauth2.googleapis.com/token";
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// Tokens are valid for 1h. We cache up to 55 min so a clock-skewed mediator
/// still refreshes before Google returns 401.
const FCM_TOKEN_TTL: Duration = Duration::from_secs(55 * 60);

/// Parsed shape of the service-account JSON downloaded from the Firebase
/// console (Project Settings → Service Accounts → Generate new private key).
#[derive(Debug, Clone, Deserialize)]
pub struct FcmServiceAccount {
    #[serde(rename = "type")]
    pub key_type: String,
    pub project_id: String,
    pub private_key: String,
    pub client_email: String,
    #[serde(default)]
    pub token_uri: Option<String>,
}

impl FcmServiceAccount {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let bytes = std::fs::read(path.as_ref())
            .map_err(|e| format!("read service-account JSON: {}", e))?;
        let acct: FcmServiceAccount = serde_json::from_slice(&bytes)
            .map_err(|e| format!("parse service-account JSON: {}", e))?;
        if acct.key_type != "service_account" {
            return Err(format!(
                "expected 'service_account', got '{}'",
                acct.key_type
            ));
        }
        Ok(acct)
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        let acct: FcmServiceAccount =
            serde_json::from_str(json).map_err(|e| format!("parse service-account JSON: {}", e))?;
        Ok(acct)
    }
}

#[derive(Serialize)]
struct OauthAssertionClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct OauthTokenResponse {
    access_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    expires_in: u64,
}

/// FCM HTTP v1 push notifier. `notify()` does the full happy path:
/// repository lookup → access-token refresh (if needed) →
/// `fcm.googleapis.com/v1/projects/{project_id}/messages:send`.
pub struct FcmPushNotifier {
    repo: Arc<dyn DeviceInfoRepositoryTrait>,
    service_account: FcmServiceAccount,
    content: PushNotificationContent,
    client: reqwest::Client,
    cached_token: RwLock<Option<CachedToken>>,
    /// Overridable so tests can swap in a mock OAuth + FCM endpoint pair.
    oauth_endpoint: String,
    fcm_endpoint_template: String,
}

#[derive(Clone)]
struct CachedToken {
    access_token: String,
    expires_at: SystemTime,
}

impl FcmPushNotifier {
    pub fn new(
        repo: Arc<dyn DeviceInfoRepositoryTrait>,
        service_account: FcmServiceAccount,
        content: PushNotificationContent,
    ) -> Self {
        let token_uri = service_account
            .token_uri
            .clone()
            .unwrap_or_else(|| FCM_AUDIENCE.to_string());
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            repo,
            service_account,
            content,
            client,
            cached_token: RwLock::new(None),
            oauth_endpoint: token_uri,
            fcm_endpoint_template: "https://fcm.googleapis.com/v1/projects/{}/messages:send"
                .to_string(),
        }
    }

    /// Construct with explicit OAuth + FCM endpoints. Used by integration
    /// tests with fake servers (and by deployments behind a proxy that
    /// need a custom URL).
    pub fn with_endpoints(
        repo: Arc<dyn DeviceInfoRepositoryTrait>,
        service_account: FcmServiceAccount,
        content: PushNotificationContent,
        oauth_endpoint: String,
        fcm_endpoint_template: String,
    ) -> Self {
        Self {
            repo,
            service_account,
            content,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            cached_token: RwLock::new(None),
            oauth_endpoint,
            fcm_endpoint_template,
        }
    }

    async fn access_token(&self) -> Result<String, String> {
        if let Some(t) = self.cached_token.read().await.as_ref() {
            if t.expires_at > SystemTime::now() {
                return Ok(t.access_token.clone());
            }
        }
        let token = self.fetch_new_token().await?;
        let cached = CachedToken {
            access_token: token.clone(),
            expires_at: SystemTime::now() + FCM_TOKEN_TTL,
        };
        *self.cached_token.write().await = Some(cached);
        Ok(token)
    }

    async fn fetch_new_token(&self) -> Result<String, String> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let claims = OauthAssertionClaims {
            iss: &self.service_account.client_email,
            scope: FCM_SCOPE,
            aud: &self.oauth_endpoint,
            iat: now,
            exp: now + 3600,
        };

        let key = EncodingKey::from_rsa_pem(self.service_account.private_key.as_bytes())
            .map_err(|e| format!("load RSA private key: {}", e))?;
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("JWT".to_string());
        let assertion = encode(&header, &claims, &key)
            .map_err(|e| format!("sign service-account JWT: {}", e))?;

        let body = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ];
        let resp = self
            .client
            .post(&self.oauth_endpoint)
            .form(&body)
            .send()
            .await
            .map_err(|e| format!("OAuth POST: {}", e))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("OAuth exchange returned {}: {}", status, text));
        }
        let parsed: OauthTokenResponse = serde_json::from_str(&text)
            .map_err(|e| format!("parse OAuth response: {} ({})", e, text))?;
        Ok(parsed.access_token)
    }

    fn build_fcm_payload(&self, record: &DeviceInfoRecord) -> serde_json::Value {
        // One message envelope with both android: and apns: sub-blocks; FCM
        // dispatches only the relevant one per token. 
        // Data-only wake signal. We deliberately send NO top-level
        // `notification` block: the push is content-free (we only hold
        // encrypted blobs), and a single user action — a call in
        // particular — fans out into many forwarded DIDComm messages
        // (offer + N ICE candidates + …), plus background protocol chatter
        // (profile/sync/keylist). If we attached a `notification`, Android
        // would auto-display one generic banner PER forwarded message,
        // which the client can neither dedup nor relabel — the source of
        // the "multiple / spurious notifications" reports. Instead the
        // client wakes the agent, pulls + decrypts, and shows exactly one
        // notification of the right kind (incoming call vs chat message).
        let mut msg = serde_json::json!({
            "token": record.device_token,
            "data": {
                "type": "didcomm",
                "title": self.content.title,
                "body": self.content.body,
            },
        });

        match record.device_platform {
            DevicePlatform::Android => {
                // High priority + data-only → onMessageReceived fires even
                // in the background / after force-kill, so the client can
                // wake the agent and drive Pickup.
                msg["android"] = serde_json::json!({
                    "priority": "high",
                });
            }
            DevicePlatform::Ios => {
                msg["apns"] = serde_json::json!({
                    "headers": {
                        "apns-priority": "10",
                        "apns-push-type": "alert",
                    },
                    "payload": {
                        "aps": {
                            "alert": {
                                "title": self.content.title,
                                "body": self.content.body,
                            },
                            "sound": "default",
                            "mutable-content": 1,
                            "content-available": 1,
                        }
                    }
                });
            }
        }

        serde_json::json!({ "message": msg })
    }

    fn fcm_url(&self, project_id: &str) -> String {
        if self.fcm_endpoint_template.contains("{}") {
            self.fcm_endpoint_template.replace("{}", project_id)
        } else {
            self.fcm_endpoint_template.clone()
        }
    }
}

#[async_trait]
impl PushNotifier for FcmPushNotifier {
    async fn notify(&self, connection_id: &str) -> Result<(), String> {
        let record = self
            .repo
            .find_by_connection_id(connection_id)
            .await
            .map_err(|e| format!("device-info lookup: {}", e))?;

        let Some(record) = record else {
            tracing::debug!(
                connection_id = connection_id,
                "FCM notifier: no device registration; skipping"
            );
            return Ok(());
        };

        let project_id = record
            .firebase_project_id
            .clone()
            .unwrap_or_else(|| self.service_account.project_id.clone());

        let token = self.access_token().await?;
        let payload = self.build_fcm_payload(&record);
        let url = self.fcm_url(&project_id);

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("FCM POST: {}", e))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("FCM returned {}: {}", status, body));
        }
        tracing::debug!(
            connection_id = connection_id,
            project_id = project_id,
            "FCM notifier: delivered"
        );
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_push_notifications::DeviceInfoRepository;

    async fn repo_with(
        connection_id: &str,
        token: &str,
        platform: DevicePlatform,
    ) -> Arc<dyn DeviceInfoRepositoryTrait> {
        let r: Arc<dyn DeviceInfoRepositoryTrait> = Arc::new(DeviceInfoRepository::new());
        let upserted =
            DeviceInfoRecord::new(connection_id.to_string(), token.to_string(), platform);
        r.upsert(upserted).await.unwrap();
        r
    }

    fn dummy_account(project_id: &str) -> FcmServiceAccount {
        FcmServiceAccount {
            key_type: "service_account".to_string(),
            project_id: project_id.to_string(),
            private_key: "ignored-for-payload-only-tests".to_string(),
            client_email: "fake@fake.iam.gserviceaccount.com".to_string(),
            token_uri: None,
        }
    }

    #[tokio::test]
    async fn webhook_skips_when_no_registration() {
        let repo: Arc<dyn DeviceInfoRepositoryTrait> = Arc::new(DeviceInfoRepository::new());
        let n = WebhookPushNotifier::new(repo, "http://127.0.0.1:0/never".to_string());
        assert!(n.notify("missing-conn").await.is_ok());
    }

    #[tokio::test]
    async fn webhook_posts_json() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let received: Arc<tokio::sync::Mutex<Option<serde_json::Value>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let received_clone = received.clone();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let app = axum::Router::new().route(
            "/push",
            axum::routing::post(move |body: axum::Json<serde_json::Value>| {
                let received = received_clone.clone();
                let counter = counter_clone.clone();
                async move {
                    *received.lock().await = Some(body.0);
                    counter.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::OK
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let repo = repo_with("c1", "tok-1", DevicePlatform::Android).await;
        let url = format!("http://{}/push", addr);
        let n = WebhookPushNotifier::new(repo, url);

        n.notify("c1").await.unwrap();

        for _ in 0..20 {
            if counter.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let payload = received
            .lock()
            .await
            .clone()
            .expect("webhook should have been hit");
        assert_eq!(payload["connectionId"], "c1");
        assert_eq!(payload["deviceToken"], "tok-1");
        assert_eq!(payload["devicePlatform"], "android");
    }

    #[tokio::test]
    async fn webhook_returns_error_on_non_2xx() {
        let app = axum::Router::new().route(
            "/push",
            axum::routing::post(|_: axum::Json<serde_json::Value>| async {
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let repo = repo_with("c", "t", DevicePlatform::Ios).await;
        let n = WebhookPushNotifier::new(repo, format!("http://{}/push", addr));
        assert!(n.notify("c").await.is_err());
    }

    #[tokio::test]
    async fn fcm_payload_includes_apns_for_ios() {
        let repo = repo_with("c", "tok", DevicePlatform::Ios).await;
        let n = FcmPushNotifier::with_endpoints(
            repo.clone(),
            dummy_account("test-proj"),
            PushNotificationContent {
                title: "T".to_string(),
                body: "B".to_string(),
            },
            "http://localhost:0/oauth".to_string(),
            "http://localhost:0/fcm".to_string(),
        );
        let record = repo.find_by_connection_id("c").await.unwrap().unwrap();
        let payload = n.build_fcm_payload(&record);
        assert_eq!(payload["message"]["token"], "tok");
        // Data-only design: no top-level `notification` block; the title rides
        // in `data` (for the client to render) and in the iOS `apns` alert.
        assert!(payload["message"]["notification"].is_null());
        assert_eq!(payload["message"]["data"]["title"], "T");
        assert_eq!(
            payload["message"]["apns"]["payload"]["aps"]["alert"]["title"],
            "T"
        );
        assert!(payload["message"]["apns"].is_object());
        assert!(payload["message"]["android"].is_null());
        assert_eq!(payload["message"]["apns"]["headers"]["apns-priority"], "10");
    }

    #[tokio::test]
    async fn fcm_payload_includes_android_for_android() {
        let repo = repo_with("c", "tok", DevicePlatform::Android).await;
        let n = FcmPushNotifier::with_endpoints(
            repo.clone(),
            dummy_account("p"),
            PushNotificationContent::default(),
            "http://localhost:0/oauth".to_string(),
            "http://localhost:0/fcm".to_string(),
        );
        let record = repo.find_by_connection_id("c").await.unwrap().unwrap();
        let payload = n.build_fcm_payload(&record);
        assert!(payload["message"]["android"].is_object());
        assert!(payload["message"]["apns"].is_null());
        assert_eq!(payload["message"]["android"]["priority"], "high");
    }

    #[tokio::test]
    async fn fcm_skips_when_no_registration() {
        let repo: Arc<dyn DeviceInfoRepositoryTrait> = Arc::new(DeviceInfoRepository::new());
        let n = FcmPushNotifier::with_endpoints(
            repo,
            dummy_account("p"),
            PushNotificationContent::default(),
            "http://127.0.0.1:0/never".to_string(),
            "http://127.0.0.1:0/never/{}".to_string(),
        );
        assert!(n.notify("missing").await.is_ok());
    }

    /// Self-signed RSA private key. Generated once with:
    ///   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform PEM
    /// Used so the JWT signing path exercises a real key.
    const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnumkF/g2dchz9
zs68eysevtNYO5joxcsazjyoB3x5V8F9skBEKfBUfQRq4VOamUmaUyk3uA+SyiMH
Z3n4ah2C2WdoCfE5B+b8c85+9K8ao/19ZeuKcU7Op8OApzsOCmdYhzvstKv4aqee
h5j8qL1euzrz3j8tyLsTnt7hxsUPW6LWLD73cIbeWuhJHZI2Xp/E7xh9WSbT5Php
84MTl9Ppg5PvT0dIEY4LHBBQ+5U/gGLbCScCPtDLzekSTayzGbXOB/R9PjOWxZ9d
hBMFSQM+keADcZU9Md6xpnqD+IsCqfsW9yLJNOsMZwDj8KfW29VaX+Jf6UsMLDYU
NmjlTQofAgMBAAECggEADQU4BOqRZQEIRh2pR9Fp6gOXRXiu6Jb+KtEKvWKDY6oP
z7GoMoJs8SoZTzC5vD0dDRlakEQ+FT+S047RVZrrOo6k69slui8mW7+jrpBRDYjg
cz0XuVINc5ZrY0/YEkF1f1ZULQ5jcS/aXkCZfDefJ7zyGR9OGUBFYYMKO02iW4w5
2Z4QHGC/hTHxy15ILMIllLt1ZYU11GL7GU4wNuGO6vtRMRCEsKUTzp0hkO/wMUH0
eFX8XE+Nf5tj5ekpddrpSRsiANW+Qh42powEcHFR7mRO+Ot66X7Np01rFm8v8Jgu
yId3ziTo+4SxCeNmdvPg1TLug5bErhpMD+meoSa1hQKBgQDWVQPQFJvKMj8vVRI7
JIL20OgxTCc5sueok9W0fIIWaqVHTs980WxYSQNPM3v5DfOa1dFaZYsCIfPw0ECd
l8fvam98CmwdYmy2SzD4yUdnCXg2R8q399OAnxPv2xH9825lbaeTvrJNtg7vAQkg
3U736eK9AdXZzW6GVWW4WRHs+wKBgQDIVfz++ond6T+Gd5m966yx5BlQQpmkYyTW
pyD54vPviUXMMU7ROSQ+Z0xl7tonRDx1yKkotPXvw/97jSZTahnWfYoS2vG7ovNn
FVxJVdt/5GA3uRAQxizr0SdRBruCU8lqgHbEEnMpAJ279kFa07FbfFNlMlWMbI7U
scX4MGGGLQKBgQCxmVaEeF8zJ3ml3ecybKm8nRSZrNGgBPfif0WIvdcJfisgMFTL
x7jwWufMHAwxLndaKKzGK/gIt1usgtPYAiog3+ArN3Oo0aLlVt7od9ibr4QV7l0z
Hb77CFX73VpGRQ2ILFm8mjqjHCW5s/D9c4R49yvzk+7BAHICDAcyv1OUOwKBgQCM
/McCAvwHqmFEluMh37w3rVmLPHO4VvXUAuaYNfqKd0chvwnDAL3bFQOVMRViUQlj
swYpWcFDLeKc5uc0CRWJ9+u1/VPmQ3Wc9FFwYvYI+YYlcR43T+DJTPaodV59B85W
H3Z14q4dCwv2/gVckGLfCY3/R/8gxj12vm2ejx3zOQKBgBPcVCS/P6di+Tl9Nso9
/lqbvJ/xb3W8wkvr93z1f+FFWkF6W4YXL451xZgCpXUsUOdWdCdk0cRDxvn+Lgdy
z94oI9snGc+28wo/jGfN5C0WpVUpRkmz3VmANl4zfHWhhqCEcPqgtFei2BPmqPN3
5fKh/K81FkixTvuMItNiDQYd
-----END PRIVATE KEY-----
";

    #[tokio::test]
    async fn fcm_full_flow_against_fake_servers() {
        use axum::{Json, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};

        // ---- fake OAuth server ----
        let oauth_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let oauth_addr = oauth_listener.local_addr().unwrap();
        let oauth_hits = Arc::new(AtomicUsize::new(0));
        let oauth_hits_clone = oauth_hits.clone();
        tokio::spawn(async move {
            let app = Router::new().route(
                "/token",
                axum::routing::post(move || {
                    let counter = oauth_hits_clone.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({
                            "access_token": "fake-bearer-token",
                            "expires_in": 3600,
                            "token_type": "Bearer"
                        }))
                    }
                }),
            );
            axum::serve(oauth_listener, app).await.unwrap();
        });

        // ---- fake FCM server (records bearer + body) ----
        let fcm_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fcm_addr = fcm_listener.local_addr().unwrap();
        let fcm_hits = Arc::new(AtomicUsize::new(0));
        let last_bearer: Arc<tokio::sync::Mutex<Option<String>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let last_body: Arc<tokio::sync::Mutex<Option<serde_json::Value>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let fcm_hits_clone = fcm_hits.clone();
        let last_bearer_clone = last_bearer.clone();
        let last_body_clone = last_body.clone();
        tokio::spawn(async move {
            let app = Router::new().route(
                "/messages:send",
                axum::routing::post(
                    move |headers: axum::http::HeaderMap, body: Json<serde_json::Value>| {
                        let counter = fcm_hits_clone.clone();
                        let bearer = last_bearer_clone.clone();
                        let last_body = last_body_clone.clone();
                        async move {
                            if let Some(auth) =
                                headers.get("authorization").and_then(|v| v.to_str().ok())
                            {
                                *bearer.lock().await = Some(auth.to_string());
                            }
                            *last_body.lock().await = Some(body.0);
                            counter.fetch_add(1, Ordering::SeqCst);
                            Json(serde_json::json!({ "name": "projects/p/messages/test" }))
                        }
                    },
                ),
            );
            axum::serve(fcm_listener, app).await.unwrap();
        });

        let repo = repo_with("conn-A", "device-token-A", DevicePlatform::Android).await;
        let n = FcmPushNotifier::with_endpoints(
            repo,
            FcmServiceAccount {
                key_type: "service_account".to_string(),
                project_id: "fake-project".to_string(),
                private_key: TEST_RSA_PEM.to_string(),
                client_email: "fake@fake.iam.gserviceaccount.com".to_string(),
                token_uri: None,
            },
            PushNotificationContent {
                title: "msg".to_string(),
                body: "you have a message".to_string(),
            },
            format!("http://{}/token", oauth_addr),
            format!("http://{}/messages:send", fcm_addr),
        );

        n.notify("conn-A").await.unwrap();
        assert_eq!(oauth_hits.load(Ordering::SeqCst), 1);
        assert_eq!(fcm_hits.load(Ordering::SeqCst), 1);
        let bearer = last_bearer.lock().await.clone().unwrap();
        assert_eq!(bearer, "Bearer fake-bearer-token");
        let body = last_body.lock().await.clone().unwrap();
        assert_eq!(body["message"]["token"], "device-token-A");
        assert!(body["message"]["android"].is_object());

        // Second call reuses the cached token — OAuth count stays 1.
        n.notify("conn-A").await.unwrap();
        assert_eq!(oauth_hits.load(Ordering::SeqCst), 1);
        assert_eq!(fcm_hits.load(Ordering::SeqCst), 2);
    }
}
