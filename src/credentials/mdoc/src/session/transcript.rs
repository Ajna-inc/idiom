//! Session transcript calculation for different OpenID4VP protocol versions
//!
//! Implements 5 different session transcript calculation methods to support
//! various OpenID4VP protocol versions and use cases.

use crate::context::MdocContext;
use crate::error::Result;
use crate::proximity::DeviceEngagement;
use crate::types::SessionTranscript;
use ciborium::value::Value;

/// Session transcript calculator for different OpenID4VP variants
pub struct SessionTranscriptCalculator;

impl SessionTranscriptCalculator {
    /// Calculate session transcript for OpenID4VP DC API Draft 24 (latest)
    ///
    /// Used by: Google CM Wallet and other implementations using the latest DC API
    ///
    /// Structure: [null, null, ["OpenID4VPDCAPIHandover", SHA-256(origin, clientId, nonce)]]
    ///
    /// # Example
    /// ```rust,ignore
    /// let transcript = SessionTranscriptCalculator::for_oid4vp_dc_api_draft24(
    ///     "https://wallet.google.com",
    ///     "client_id_123",
    ///     "verifier_nonce_abc",
    ///     &context
    /// ).await?;
    /// ```
    pub async fn for_oid4vp_dc_api_draft24(
        origin: &str,
        client_id: &str,
        verifier_generated_nonce: &str,
        context: &dyn MdocContext,
    ) -> Result<SessionTranscript> {
        // Encode the digest input: [origin, clientId, verifierGeneratedNonce]
        let digest_input = Value::Array(vec![
            Value::Text(origin.to_string()),
            Value::Text(client_id.to_string()),
            Value::Text(verifier_generated_nonce.to_string()),
        ]);

        let mut digest_input_bytes = Vec::new();
        ciborium::ser::into_writer(&digest_input, &mut digest_input_bytes)?;

        // Compute SHA-256 digest
        let digest = context
            .digest(crate::context::DigestAlgorithm::Sha256, &digest_input_bytes)
            .await?;

        // Create handover: ["OpenID4VPDCAPIHandover", digest]
        let handover = Value::Array(vec![
            Value::Text("OpenID4VPDCAPIHandover".to_string()),
            Value::Bytes(digest),
        ]);

        let mut handover_bytes = Vec::new();
        ciborium::ser::into_writer(&handover, &mut handover_bytes)?;

        Ok(SessionTranscript {
            device_engagement: None,
            e_reader_key: None,
            handover: handover_bytes,
        })
    }

    /// Calculate session transcript for OpenID4VP DC API (standard)
    ///
    /// Structure: [null, null, ["OpenID4VPDCAPIHandover", SHA-256(origin, nonce, jwkThumbprint?)]]
    ///
    /// # Example
    /// ```rust,ignore
    /// let transcript = SessionTranscriptCalculator::for_oid4vp_dc_api(
    ///     "https://example.com",
    ///     "verifier_nonce",
    ///     Some(&jwk_thumbprint),
    ///     &context
    /// ).await?;
    /// ```
    pub async fn for_oid4vp_dc_api(
        origin: &str,
        verifier_generated_nonce: &str,
        jwk_thumbprint: Option<&[u8]>,
        context: &dyn MdocContext,
    ) -> Result<SessionTranscript> {
        // Encode the digest input: [origin, verifierGeneratedNonce, jwkThumbprint or null]
        let digest_input = Value::Array(vec![
            Value::Text(origin.to_string()),
            Value::Text(verifier_generated_nonce.to_string()),
            match jwk_thumbprint {
                Some(bytes) => Value::Bytes(bytes.to_vec()),
                None => Value::Null,
            },
        ]);

        let mut digest_input_bytes = Vec::new();
        ciborium::ser::into_writer(&digest_input, &mut digest_input_bytes)?;

        // Compute SHA-256 digest
        let digest = context
            .digest(crate::context::DigestAlgorithm::Sha256, &digest_input_bytes)
            .await?;

        // Create handover: ["OpenID4VPDCAPIHandover", digest]
        let handover = Value::Array(vec![
            Value::Text("OpenID4VPDCAPIHandover".to_string()),
            Value::Bytes(digest),
        ]);

        let mut handover_bytes = Vec::new();
        ciborium::ser::into_writer(&handover, &mut handover_bytes)?;

        Ok(SessionTranscript {
            device_engagement: None,
            e_reader_key: None,
            handover: handover_bytes,
        })
    }

    /// Calculate session transcript for OpenID4VP (standard with response URI)
    ///
    /// Structure: [null, null, ["OpenID4VPHandover", SHA-256(clientId, nonce, jwkThumbprint?, responseUri)]]
    ///
    /// # Example
    /// ```rust,ignore
    /// let transcript = SessionTranscriptCalculator::for_oid4vp(
    ///     "client_id",
    ///     "verifier_nonce",
    ///     None,
    ///     "https://example.com/response",
    ///     &context
    /// ).await?;
    /// ```
    pub async fn for_oid4vp(
        client_id: &str,
        verifier_generated_nonce: &str,
        jwk_thumbprint: Option<&[u8]>,
        response_uri: &str,
        context: &dyn MdocContext,
    ) -> Result<SessionTranscript> {
        // Encode the digest input: [clientId, verifierGeneratedNonce, jwkThumbprint or null, responseUri]
        let digest_input = Value::Array(vec![
            Value::Text(client_id.to_string()),
            Value::Text(verifier_generated_nonce.to_string()),
            match jwk_thumbprint {
                Some(bytes) => Value::Bytes(bytes.to_vec()),
                None => Value::Null,
            },
            Value::Text(response_uri.to_string()),
        ]);

        let mut digest_input_bytes = Vec::new();
        ciborium::ser::into_writer(&digest_input, &mut digest_input_bytes)?;

        // Compute SHA-256 digest
        let digest = context
            .digest(crate::context::DigestAlgorithm::Sha256, &digest_input_bytes)
            .await?;

        // Create handover: ["OpenID4VPHandover", digest]
        let handover = Value::Array(vec![
            Value::Text("OpenID4VPHandover".to_string()),
            Value::Bytes(digest),
        ]);

        let mut handover_bytes = Vec::new();
        ciborium::ser::into_writer(&handover, &mut handover_bytes)?;

        Ok(SessionTranscript {
            device_engagement: None,
            e_reader_key: None,
            handover: handover_bytes,
        })
    }

    /// Calculate session transcript for OpenID4VP Draft 18 (legacy)
    ///
    /// Used by: French playground, Ubique implementation
    ///
    /// Structure: [null, null, [SHA-256(clientId, mdocNonce), SHA-256(responseUri, mdocNonce), verifierNonce]]
    ///
    /// # Example
    /// ```rust,ignore
    /// let transcript = SessionTranscriptCalculator::for_oid4vp_draft18(
    ///     "client_id",
    ///     "https://example.com/response",
    ///     "verifier_nonce",
    ///     "mdoc_nonce",
    ///     &context
    /// ).await?;
    /// ```
    pub async fn for_oid4vp_draft18(
        client_id: &str,
        response_uri: &str,
        verifier_generated_nonce: &str,
        mdoc_generated_nonce: &str,
        context: &dyn MdocContext,
    ) -> Result<SessionTranscript> {
        // First digest: SHA-256([clientId, mdocGeneratedNonce])
        let client_digest_input = Value::Array(vec![
            Value::Text(client_id.to_string()),
            Value::Text(mdoc_generated_nonce.to_string()),
        ]);

        let mut client_digest_input_bytes = Vec::new();
        ciborium::ser::into_writer(&client_digest_input, &mut client_digest_input_bytes)?;

        let client_digest = context
            .digest(
                crate::context::DigestAlgorithm::Sha256,
                &client_digest_input_bytes,
            )
            .await?;

        // Second digest: SHA-256([responseUri, mdocGeneratedNonce])
        let response_digest_input = Value::Array(vec![
            Value::Text(response_uri.to_string()),
            Value::Text(mdoc_generated_nonce.to_string()),
        ]);

        let mut response_digest_input_bytes = Vec::new();
        ciborium::ser::into_writer(&response_digest_input, &mut response_digest_input_bytes)?;

        let response_digest = context
            .digest(
                crate::context::DigestAlgorithm::Sha256,
                &response_digest_input_bytes,
            )
            .await?;

        // Create handover: [clientDigest, responseDigest, verifierGeneratedNonce]
        let handover = Value::Array(vec![
            Value::Bytes(client_digest),
            Value::Bytes(response_digest),
            Value::Text(verifier_generated_nonce.to_string()),
        ]);

        let mut handover_bytes = Vec::new();
        ciborium::ser::into_writer(&handover, &mut handover_bytes)?;

        Ok(SessionTranscript {
            device_engagement: None,
            e_reader_key: None,
            handover: handover_bytes,
        })
    }

    /// Calculate session transcript for Web API (proximity presentation)
    ///
    /// Used for: BLE, NFC, WiFi-Aware presentations
    ///
    /// Structure: [DeviceEngagement, EReaderKey, SHA-256(ReaderEngagement)]
    ///
    /// # Example
    /// ```rust,ignore
    /// let transcript = SessionTranscriptCalculator::for_web_api(
    ///     &device_engagement,
    ///     &e_reader_key_bytes,
    ///     &reader_engagement_bytes,
    ///     &context
    /// ).await?;
    /// ```
    pub async fn for_web_api(
        device_engagement: &DeviceEngagement,
        e_reader_key_bytes: &[u8],
        reader_engagement_bytes: &[u8],
        context: &dyn MdocContext,
    ) -> Result<SessionTranscript> {
        // Compute SHA-256 of reader engagement
        let reader_engagement_hash = context
            .digest(
                crate::context::DigestAlgorithm::Sha256,
                reader_engagement_bytes,
            )
            .await?;

        Ok(SessionTranscript {
            device_engagement: Some(device_engagement.to_cbor()?),
            e_reader_key: Some(e_reader_key_bytes.to_vec()),
            handover: reader_engagement_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{DigestAlgorithm, MdocContext};
    use async_trait::async_trait;

    struct MockContext;

    #[async_trait]
    impl MdocContext for MockContext {
        async fn random(&self, length: usize) -> crate::error::Result<Vec<u8>> {
            Ok(vec![0u8; length])
        }

        async fn digest(
            &self,
            _algorithm: DigestAlgorithm,
            data: &[u8],
        ) -> crate::error::Result<Vec<u8>> {
            // Return fake SHA-256 hash
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }

        async fn cose_sign1_sign(
            &self,
            _key_id: &str,
            _payload: &[u8],
            _protected_headers: &[u8],
            _algorithm: crate::context::SignatureAlgorithm,
        ) -> crate::error::Result<Vec<u8>> {
            Ok(vec![0u8; 64])
        }

        async fn cose_sign1_verify(
            &self,
            _public_key: &crate::cose::CoseKey,
            _signature: &[u8],
            _payload: &[u8],
            _protected_headers: &[u8],
            _algorithm: crate::context::SignatureAlgorithm,
        ) -> crate::error::Result<bool> {
            Ok(true)
        }

        async fn cose_mac0_sign(
            &self,
            _key: &[u8],
            _payload: &[u8],
            _protected_headers: &[u8],
        ) -> crate::error::Result<Vec<u8>> {
            Ok(vec![0u8; 32])
        }

        async fn cose_mac0_verify(
            &self,
            _key: &[u8],
            _mac: &[u8],
            _payload: &[u8],
            _protected_headers: &[u8],
        ) -> crate::error::Result<bool> {
            Ok(true)
        }

        async fn get_public_key_from_certificate(
            &self,
            _certificate: &[u8],
            _algorithm: crate::context::SignatureAlgorithm,
        ) -> crate::error::Result<crate::cose::CoseKey> {
            Ok(crate::cose::CoseKey::new(2))
        }

        async fn validate_certificate_chain(
            &self,
            _certificate_chain: &[Vec<u8>],
            _trusted_certificates: &[Vec<u8>],
        ) -> crate::error::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_dc_api_draft24() {
        let context = MockContext;

        let transcript = SessionTranscriptCalculator::for_oid4vp_dc_api_draft24(
            "https://wallet.google.com",
            "client_id_123",
            "nonce_abc",
            &context,
        )
        .await
        .unwrap();

        assert!(transcript.device_engagement.is_none());
        assert!(transcript.e_reader_key.is_none());
        assert!(!transcript.handover.is_empty());
    }

    #[tokio::test]
    async fn test_dc_api() {
        let context = MockContext;
        let jwk_thumbprint = vec![1, 2, 3, 4];

        let transcript = SessionTranscriptCalculator::for_oid4vp_dc_api(
            "https://example.com",
            "nonce",
            Some(&jwk_thumbprint),
            &context,
        )
        .await
        .unwrap();

        assert!(transcript.device_engagement.is_none());
        assert!(!transcript.handover.is_empty());
    }

    #[tokio::test]
    async fn test_oid4vp() {
        let context = MockContext;

        let transcript = SessionTranscriptCalculator::for_oid4vp(
            "client_id",
            "nonce",
            None,
            "https://example.com/response",
            &context,
        )
        .await
        .unwrap();

        assert!(transcript.device_engagement.is_none());
        assert!(!transcript.handover.is_empty());
    }

    #[tokio::test]
    async fn test_oid4vp_draft18() {
        let context = MockContext;

        let transcript = SessionTranscriptCalculator::for_oid4vp_draft18(
            "client_id",
            "https://example.com/response",
            "verifier_nonce",
            "mdoc_nonce",
            &context,
        )
        .await
        .unwrap();

        assert!(transcript.device_engagement.is_none());
        assert!(!transcript.handover.is_empty());
    }

    #[tokio::test]
    async fn test_web_api() {
        let context = MockContext;

        let device_key = crate::cose::CoseKey::new(2);
        let edevice_key = crate::proximity::EDeviceKey::new(device_key);
        let security = crate::proximity::Security::new(1, edevice_key);
        let engagement = DeviceEngagement::new(security);

        let e_reader_key_bytes = vec![5, 6, 7, 8];
        let reader_engagement_bytes = vec![9, 10, 11, 12];

        let transcript = SessionTranscriptCalculator::for_web_api(
            &engagement,
            &e_reader_key_bytes,
            &reader_engagement_bytes,
            &context,
        )
        .await
        .unwrap();

        assert!(transcript.device_engagement.is_some());
        assert!(transcript.e_reader_key.is_some());
        assert!(!transcript.handover.is_empty());
    }
}
