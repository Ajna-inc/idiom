//! URI parsing for OpenID4VP

use super::error::{Oid4vpError, Result};
use super::types::{AuthorizationRequest, AuthorizationRequestPayload};
use std::collections::HashMap;
use url::Url;

/// Parse authorization request from various formats
pub fn parse_authorization_request(input: &str) -> Result<AuthorizationRequest> {
    // Try to parse as URI first
    if input.starts_with("openid4vp://")
        || input.starts_with("openid://")
        || input.starts_with("https://")
    {
        return parse_uri(input);
    }

    // Check if it's a JWT (starts with eyJ)
    if input.starts_with("eyJ") {
        return Ok(AuthorizationRequest::Jwt(input.to_string()));
    }

    // Try to parse as JSON
    if let Ok(payload) = serde_json::from_str::<AuthorizationRequestPayload>(input) {
        return Ok(AuthorizationRequest::Object(payload));
    }

    Err(Oid4vpError::InvalidRequest(
        "Could not parse authorization request".to_string(),
    ))
}

/// Parse OpenID4VP URI
fn parse_uri(uri_str: &str) -> Result<AuthorizationRequest> {
    let url = Url::parse(uri_str)?;

    let params: HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Check if request_uri is present (must be fetched)
    if let Some(request_uri) = params.get("request_uri") {
        return Ok(AuthorizationRequest::RequestUri {
            request_uri: request_uri.clone(),
        });
    }

    // Check if request parameter is present (embedded JWT)
    if let Some(request_jwt) = params.get("request") {
        return Ok(AuthorizationRequest::Jwt(request_jwt.clone()));
    }

    // Otherwise, build from URI parameters
    let payload = build_payload_from_params(params)?;
    Ok(AuthorizationRequest::Object(payload))
}

/// Build authorization request payload from URI parameters
fn build_payload_from_params(
    params: HashMap<String, String>,
) -> Result<AuthorizationRequestPayload> {
    // Required parameters
    let client_id = params
        .get("client_id")
        .ok_or_else(|| Oid4vpError::MissingParameter("client_id".to_string()))?
        .clone();

    let response_uri = params
        .get("response_uri")
        .ok_or_else(|| Oid4vpError::MissingParameter("response_uri".to_string()))?
        .clone();

    let nonce = params
        .get("nonce")
        .ok_or_else(|| Oid4vpError::MissingParameter("nonce".to_string()))?
        .clone();

    // Optional parameters
    let response_mode = params.get("response_mode").cloned();
    let state = params.get("state").cloned();

    // Parse presentation_definition if present
    let presentation_definition = params
        .get("presentation_definition")
        .and_then(|pd| serde_json::from_str(pd).ok());

    // Parse dcql_query if present (URL-encoded JSON)
    let dcql_query = params.get("dcql_query").and_then(|dq| {
        // First try direct JSON parse
        serde_json::from_str(dq).ok().or_else(|| {
            // Try URL-decoding first
            urlencoding::decode(dq)
                .ok()
                .and_then(|decoded| serde_json::from_str(&decoded).ok())
        })
    });

    // Parse client_metadata if present
    let client_metadata = params
        .get("client_metadata")
        .and_then(|cm| serde_json::from_str(cm).ok());

    Ok(AuthorizationRequestPayload {
        client_id,
        response_uri,
        response_mode,
        nonce,
        state,
        presentation_definition,
        dcql_query,
        client_metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uri_with_request_uri() {
        let uri = "openid4vp://?client_id=verifier&request_uri=https://verifier.com/request/123";
        let result = parse_authorization_request(uri).unwrap();

        match result {
            AuthorizationRequest::RequestUri { request_uri } => {
                assert_eq!(request_uri, "https://verifier.com/request/123");
            }
            _ => panic!("Expected RequestUri variant"),
        }
    }

    #[test]
    fn test_parse_uri_with_embedded_params() {
        let uri = "openid4vp://?client_id=verifier&response_uri=https://verifier.com/response&nonce=abc123";
        let result = parse_authorization_request(uri).unwrap();

        match result {
            AuthorizationRequest::Object(payload) => {
                assert_eq!(payload.client_id, "verifier");
                assert_eq!(payload.response_uri, "https://verifier.com/response");
                assert_eq!(payload.nonce, "abc123");
            }
            _ => panic!("Expected Object variant"),
        }
    }

    #[test]
    fn test_parse_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let result = parse_authorization_request(jwt).unwrap();

        match result {
            AuthorizationRequest::Jwt(token) => {
                assert_eq!(token, jwt);
            }
            _ => panic!("Expected Jwt variant"),
        }
    }

    #[test]
    fn test_parse_uri_missing_required_param() {
        let uri = "openid4vp://?client_id=verifier&response_uri=https://verifier.com/response";
        let result = parse_authorization_request(uri);
        assert!(result.is_err()); // Missing nonce
    }
}
