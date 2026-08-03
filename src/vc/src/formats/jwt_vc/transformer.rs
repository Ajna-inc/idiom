use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::core::{
    CredentialSubject, Issuer, VerifiableCredential, W3cCredential, W3cPresentation,
};

/// JWT payload for Verifiable Credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtVcPayload {
    /// Issuer (standard JWT claim)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Subject (standard JWT claim)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// JWT ID - maps to credential.id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Not before - maps to issuanceDate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Expiration - maps to expirationDate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Issued at
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<OneOrMany<String>>,

    /// Nonce for replay protection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// The W3C Verifiable Credential
    pub vc: VcClaim,

    /// Additional claims
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

/// JWT payload for Verifiable Presentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtVpPayload {
    /// Issuer (holder in presentation case)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// JWT ID - maps to presentation.id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Audience (verifier)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<OneOrMany<String>>,

    /// Not before
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Expiration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Issued at
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// Nonce for replay protection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// The W3C Verifiable Presentation
    pub vp: VpClaim,

    /// Additional claims
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

/// VC claim structure in JWT
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VcClaim {
    #[serde(rename = "@context")]
    pub context: Value,

    #[serde(rename = "type")]
    pub type_: Vec<String>,

    pub credential_subject: Value,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<Value>,
}

/// VP claim structure in JWT
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpClaim {
    #[serde(rename = "@context")]
    pub context: Value,

    #[serde(rename = "type")]
    pub type_: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifiable_credential: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_submission: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

pub struct JwtVcTransformer;

impl JwtVcTransformer {
    /// Transform W3C credential to JWT payload
    pub fn credential_to_jwt_payload(
        credential: &W3cCredential,
    ) -> Result<JwtVcPayload, Box<dyn std::error::Error + Send + Sync>> {
        // Extract issuer string
        let issuer = match &credential.issuer {
            Issuer::String(s) => s.clone(),
            Issuer::Object(obj) => obj.id.clone(),
        };

        // Extract subject ID if single subject
        let subject_id = match &credential.credential_subject {
            CredentialSubject::Single(subj) => subj.id.clone(),
            CredentialSubject::Multiple(subjects) => subjects.first().and_then(|s| s.id.clone()),
        };

        // Convert context to JSON value
        let context_value = serde_json::to_value(&credential.context)?;

        // Convert credential subject to JSON value
        let subject_value = serde_json::to_value(&credential.credential_subject)?;

        // Build VC claim
        let vc_claim = VcClaim {
            context: context_value,
            type_: credential.type_.clone(),
            credential_subject: subject_value,
            credential_status: credential
                .credential_status
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?,
            credential_schema: credential
                .credential_schema
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?,
        };

        let payload = JwtVcPayload {
            iss: Some(issuer),
            sub: subject_id,
            jti: credential.id.clone(),
            nbf: Some(credential.issuance_date.timestamp()),
            exp: credential.expiration_date.map(|d| d.timestamp()),
            iat: Some(Utc::now().timestamp()),
            aud: None,
            nonce: None,
            vc: vc_claim,
            additional: HashMap::new(),
        };

        Ok(payload)
    }

    /// Transform JWT payload to W3C credential
    pub fn jwt_payload_to_credential(
        payload: &JwtVcPayload,
    ) -> Result<W3cCredential, Box<dyn std::error::Error + Send + Sync>> {
        // Extract issuer
        let issuer = payload.iss.as_ref().ok_or("Missing issuer in JWT")?.clone();

        // Parse context
        let context = serde_json::from_value(payload.vc.context.clone())?;

        // Parse credential subject
        let credential_subject = serde_json::from_value(payload.vc.credential_subject.clone())?;

        // Convert timestamps
        let issuance_date = payload
            .nbf
            .and_then(|nbf| DateTime::from_timestamp(nbf, 0))
            .unwrap_or_else(Utc::now);

        let expiration_date = payload.exp.and_then(|exp| DateTime::from_timestamp(exp, 0));

        // Parse optional fields
        let credential_status = payload
            .vc
            .credential_status
            .as_ref()
            .map(|s| serde_json::from_value(s.clone()))
            .transpose()?;

        let credential_schema = payload
            .vc
            .credential_schema
            .as_ref()
            .map(|s| serde_json::from_value(s.clone()))
            .transpose()?;

        let credential = W3cCredential {
            context,
            id: payload.jti.clone(),
            type_: payload.vc.type_.clone(),
            issuer: Issuer::String(issuer),
            issuance_date,
            expiration_date,
            credential_subject,
            credential_status,
            credential_schema,
            refresh_service: None,
            proof: None, // JWT signature serves as proof
        };

        Ok(credential)
    }

    /// Transform W3C presentation to JWT payload
    pub fn presentation_to_jwt_payload(
        presentation: &W3cPresentation,
    ) -> Result<JwtVpPayload, Box<dyn std::error::Error + Send + Sync>> {
        Self::presentation_to_jwt_payload_with_options(presentation, None, None)
    }

    /// Transform W3C presentation to JWT payload with audience and nonce
    pub fn presentation_to_jwt_payload_with_options(
        presentation: &W3cPresentation,
        audience: Option<String>,
        nonce: Option<String>,
    ) -> Result<JwtVpPayload, Box<dyn std::error::Error + Send + Sync>> {
        // Convert context to JSON value
        let context_value = serde_json::to_value(&presentation.context)?;

        // Extract JWT credentials from presentation
        let jwt_credentials = presentation.verifiable_credential.as_ref().map(|creds| {
            creds
                .iter()
                .filter_map(|c| {
                    if let VerifiableCredential::Jwt(jwt) = c {
                        Some(jwt.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<String>>()
        });

        let vp_claim = VpClaim {
            context: context_value,
            type_: presentation.type_.clone(),
            verifiable_credential: jwt_credentials,
            presentation_submission: None,
        };

        let payload = JwtVpPayload {
            iss: presentation.holder.clone(),
            jti: presentation.id.clone(),
            aud: audience.map(OneOrMany::One),
            nbf: Some(Utc::now().timestamp()),
            exp: None,
            iat: Some(Utc::now().timestamp()),
            nonce,
            vp: vp_claim,
            additional: HashMap::new(),
        };

        Ok(payload)
    }

    /// Transform JWT payload to W3C presentation
    pub fn jwt_payload_to_presentation(
        payload: &JwtVpPayload,
    ) -> Result<W3cPresentation, Box<dyn std::error::Error + Send + Sync>> {
        // Parse context
        let context = serde_json::from_value(payload.vp.context.clone())?;

        // Convert JWT strings to VerifiableCredential enum
        let verifiable_credential = payload.vp.verifiable_credential.as_ref().map(|creds| {
            creds
                .iter()
                .map(|jwt| VerifiableCredential::Jwt(jwt.clone()))
                .collect()
        });

        let presentation = W3cPresentation {
            context,
            id: payload.jti.clone(),
            type_: payload.vp.type_.clone(),
            verifiable_credential,
            holder: payload.iss.clone(),
            proof: None, // JWT signature serves as proof
        };

        Ok(presentation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::CredentialSubjectObject;
    use serde_json::json;

    #[test]
    fn test_credential_to_jwt_payload() {
        let subject = CredentialSubjectObject {
            id: Some("did:example:subject".to_string()),
            claims: {
                let mut claims = HashMap::new();
                claims.insert("name".to_string(), json!("Alice"));
                claims.insert("age".to_string(), json!(25));
                claims
            },
        };

        let credential = W3cCredential::new("did:example:issuer", subject)
            .with_id("http://example.com/credentials/123");

        let payload = JwtVcTransformer::credential_to_jwt_payload(&credential).unwrap();

        assert_eq!(payload.iss, Some("did:example:issuer".to_string()));
        assert_eq!(payload.sub, Some("did:example:subject".to_string()));
        assert_eq!(
            payload.jti,
            Some("http://example.com/credentials/123".to_string())
        );
        assert!(payload.nbf.is_some());
    }

    #[test]
    fn test_jwt_payload_roundtrip() {
        let subject = CredentialSubjectObject {
            id: Some("did:example:subject".to_string()),
            claims: HashMap::new(),
        };

        let original = W3cCredential::new("did:example:issuer", subject)
            .with_id("http://example.com/credentials/123");

        let payload = JwtVcTransformer::credential_to_jwt_payload(&original).unwrap();
        let recovered = JwtVcTransformer::jwt_payload_to_credential(&payload).unwrap();

        assert_eq!(recovered.id, original.id);
        match (&recovered.issuer, &original.issuer) {
            (Issuer::String(a), Issuer::String(b)) => assert_eq!(a, b),
            _ => panic!("Issuer mismatch"),
        }
    }
}
