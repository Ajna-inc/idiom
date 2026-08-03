//! OID4VCI HTTP transport layer.
//!
//! Handles all HTTP communication with OID4VCI issuer endpoints:
//! metadata discovery, token exchange, nonce retrieval, credential request.

use super::error::{Oid4vciError, Result};
use super::types::*;

/// HTTP transport for OID4VCI protocol.
pub struct Oid4vciTransport {
    client: reqwest::Client,
}

impl Oid4vciTransport {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Oid4vciError::Http(format!("Failed to create HTTP client: {}", e)))?;
        Ok(Self { client })
    }

    /// GET /.well-known/openid-credential-issuer
    pub async fn fetch_issuer_metadata(&self, issuer_url: &str) -> Result<IssuerMetadata> {
        let url = format!(
            "{}/.well-known/openid-credential-issuer",
            issuer_url.trim_end_matches('/')
        );
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(Oid4vciError::InvalidMetadata(format!(
                "Metadata request failed: {}",
                resp.status()
            )));
        }
        let metadata: IssuerMetadata = resp.json().await?;
        Ok(metadata)
    }

    /// GET /.well-known/oauth-authorization-server (fallback for token endpoint)
    pub async fn fetch_auth_server_metadata(&self, issuer_url: &str) -> Result<AuthServerMetadata> {
        let url = format!(
            "{}/.well-known/oauth-authorization-server",
            issuer_url.trim_end_matches('/')
        );
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(Oid4vciError::TokenError(format!(
                "Auth server metadata request failed: {}",
                resp.status()
            )));
        }
        let metadata: AuthServerMetadata = resp.json().await?;
        Ok(metadata)
    }

    /// POST /token — exchange pre-authorized code for access token
    pub async fn request_token(
        &self,
        token_endpoint: &str,
        pre_auth_code: &str,
    ) -> Result<TokenResponse> {
        let resp = self
            .client
            .post(token_endpoint)
            .form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                ),
                ("pre-authorized_code", pre_auth_code),
            ])
            .send()
            .await?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Oid4vciError::TokenError(format!(
                "Token request failed: {}",
                body
            )));
        }
        let token: TokenResponse = resp.json().await?;
        Ok(token)
    }

    /// POST /nonce — get a fresh c_nonce
    pub async fn request_nonce(&self, nonce_endpoint: &str, access_token: &str) -> Result<String> {
        let resp = self
            .client
            .post(nonce_endpoint)
            .bearer_auth(access_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Oid4vciError::NonceError(format!(
                "Nonce request failed: {}",
                resp.status()
            )));
        }
        let body: serde_json::Value = resp.json().await?;
        body.get("c_nonce")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| Oid4vciError::NonceError("No c_nonce in response".to_string()))
    }

    /// POST /credential — send credential request, receive credential
    pub async fn request_credential(
        &self,
        credential_endpoint: &str,
        access_token: &str,
        request: &CredentialRequest,
    ) -> Result<CredentialResponse> {
        let resp = self
            .client
            .post(credential_endpoint)
            .bearer_auth(access_token)
            .json(request)
            .send()
            .await?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Oid4vciError::CredentialError(format!(
                "Credential request failed: {}",
                body
            )));
        }
        let credential: CredentialResponse = resp.json().await?;
        Ok(credential)
    }
}
