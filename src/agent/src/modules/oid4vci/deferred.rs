//! Deferred credential issuance support for OID4VCI.
//!
//! When the issuer can't immediately mint a credential (manual review,
//! eligibility checks, …), it responds to `/credential` with an
//! `acceptance_token` + a suggested polling `interval`. The wallet then
//! polls `/deferred_credential` until the credential is ready.

use serde::{Deserialize, Serialize};

/// Body returned by `/credential` when issuance is pending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredCredentialAcknowledgement {
    /// Token to present at the deferred endpoint. Treat as opaque.
    pub acceptance_token: String,
    /// Suggested polling interval, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// Optional natural-language reason exposed to the wallet UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Body sent by the wallet to `/deferred_credential`. Carries the acceptance
/// token previously returned and (optionally) a fresh dPoP proof so the
/// issuer can rebind to the wallet's key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredCredentialRequest {
    pub acceptance_token: String,
}

/// Status discriminator on the deferred endpoint response — either the
/// credential is ready, or polling should continue.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeferredCredentialOutcome {
    /// The credential is ready — body shape matches the immediate
    /// `/credential` success response.
    Ready(super::types::CredentialResponse),
    /// Continue polling — body returns a fresh acceptance token + interval.
    StillPending(DeferredCredentialAcknowledgement),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ready_outcome() {
        let j = r#"{
            "format": "vc+sd-jwt",
            "credential": "eyJ.fake.jwt",
            "c_nonce_expires_in": 300
        }"#;
        let outcome: DeferredCredentialOutcome = serde_json::from_str(j).unwrap();
        match outcome {
            DeferredCredentialOutcome::Ready(r) => assert_eq!(r.format, "vc+sd-jwt"),
            _ => panic!("expected Ready"),
        }
    }

    #[test]
    fn parses_pending_outcome() {
        let j = r#"{"acceptance_token":"abc","interval":5}"#;
        let outcome: DeferredCredentialOutcome = serde_json::from_str(j).unwrap();
        match outcome {
            DeferredCredentialOutcome::StillPending(p) => {
                assert_eq!(p.acceptance_token, "abc");
                assert_eq!(p.interval, Some(5));
            }
            _ => panic!("expected StillPending"),
        }
    }
}
