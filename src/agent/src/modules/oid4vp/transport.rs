//! HTTP transport for OpenID4VP

use super::error::{Oid4vpError, Result};
use super::types::{AuthorizationResponse, DirectPostResponse};
use reqwest::Client;
use std::time::Duration;

/// HTTP transport for OID4VP operations
pub struct Oid4vpTransport {
    client: Client,
}

impl Oid4vpTransport {
    /// Create new transport with default settings
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| {
                Oid4vpError::TransportError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self { client })
    }

    /// Fetch authorization request from request_uri
    pub async fn fetch_request_uri(&self, request_uri: &str) -> Result<String> {
        tracing::debug!("Fetching request from: {}", request_uri);

        let response =
            self.client.get(request_uri).send().await.map_err(|e| {
                Oid4vpError::HttpError(format!("Failed to fetch request_uri: {}", e))
            })?;

        // Check status
        if !response.status().is_success() {
            return Err(Oid4vpError::HttpError(format!(
                "Request URI returned status: {}",
                response.status()
            )));
        }

        // Get content type
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        // Parse based on content type
        if content_type.contains("application/json") {
            // JSON object
            let text = response
                .text()
                .await
                .map_err(|e| Oid4vpError::HttpError(format!("Failed to read response: {}", e)))?;
            Ok(text)
        } else if content_type.contains("application/oauth-authz-req+jwt") {
            // JWT
            let text = response
                .text()
                .await
                .map_err(|e| Oid4vpError::HttpError(format!("Failed to read JWT: {}", e)))?;
            Ok(text)
        } else {
            // Default to text
            let text = response
                .text()
                .await
                .map_err(|e| Oid4vpError::HttpError(format!("Failed to read response: {}", e)))?;
            Ok(text)
        }
    }

    /// Send authorization response via direct_post
    pub async fn send_direct_post(
        &self,
        response_uri: &str,
        authorization_response: &AuthorizationResponse,
    ) -> Result<DirectPostResponse> {
        tracing::debug!("Posting response to: {}", response_uri);

        // Build form data
        let mut form_data = vec![("vp_token", authorization_response.vp_token.clone())];

        if let Some(submission) = &authorization_response.presentation_submission {
            let submission_json = serde_json::to_string(submission).map_err(|e| {
                Oid4vpError::EncodingError(format!(
                    "Failed to serialize presentation_submission: {}",
                    e
                ))
            })?;
            form_data.push(("presentation_submission", submission_json));
        }

        if let Some(state) = &authorization_response.state {
            form_data.push(("state", state.clone()));
        }

        // Send POST request
        let response = self
            .client
            .post(response_uri)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| Oid4vpError::HttpError(format!("Failed to post response: {}", e)))?;

        // Check status
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Oid4vpError::HttpError(format!(
                "Response URI returned status {}: {}",
                status, body
            )));
        }

        // Parse response (may contain redirect_uri)
        let direct_post_response = response
            .json::<DirectPostResponse>()
            .await
            .unwrap_or(DirectPostResponse { redirect_uri: None });

        tracing::debug!("Direct post successful");
        Ok(direct_post_response)
    }

    /// Build redirect URI with authorization response (fallback method)
    pub fn build_redirect_uri(
        &self,
        redirect_uri: &str,
        authorization_response: &AuthorizationResponse,
    ) -> Result<String> {
        let mut params = vec![("vp_token", authorization_response.vp_token.clone())];

        if let Some(submission) = &authorization_response.presentation_submission {
            let submission_json = serde_json::to_string(submission).map_err(|e| {
                Oid4vpError::EncodingError(format!(
                    "Failed to serialize presentation_submission: {}",
                    e
                ))
            })?;
            params.push(("presentation_submission", submission_json));
        }

        if let Some(state) = &authorization_response.state {
            params.push(("state", state.clone()));
        }

        // Build query string
        let query_string = serde_urlencoded::to_string(&params).map_err(|e| {
            Oid4vpError::EncodingError(format!("Failed to build query string: {}", e))
        })?;

        Ok(format!("{}?{}", redirect_uri, query_string))
    }
}

impl Default for Oid4vpTransport {
    fn default() -> Self {
        Self::new().expect("Failed to create default transport")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_transport() {
        let transport = Oid4vpTransport::new();
        assert!(transport.is_ok());
    }

    #[test]
    fn test_build_redirect_uri() {
        let transport = Oid4vpTransport::new().unwrap();

        let response = AuthorizationResponse {
            vp_token: "base64encodedtoken".to_string(),
            presentation_submission: None,
            state: Some("state123".to_string()),
        };

        let redirect = transport
            .build_redirect_uri("https://verifier.com/callback", &response)
            .unwrap();

        assert!(redirect.contains("vp_token=base64encodedtoken"));
        assert!(redirect.contains("state=state123"));
    }
}
