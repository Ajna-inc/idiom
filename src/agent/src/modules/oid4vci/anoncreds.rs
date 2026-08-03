//! AnonCreds bridge for OID4VCI.
//!
//! Bridges the AnonCreds blinded link secret protocol with the OID4VCI
//! credential request/response flow, implementing the AnonCreds Credential
//! Format Profile from `anoncreds-oid4vci.md`.

use super::error::{Oid4vciError, Result};
use super::types::*;

/// Build an AnonCreds proof for an OID4VCI credential request.
///
/// This creates the blinded link secret commitment using the `c_nonce`
/// from the OID4VCI nonce endpoint as the AnonCreds credential nonce.
///
/// Returns the `CredentialProof::AnonCreds` variant ready to include
/// in the credential request, plus the request metadata needed to
/// unblind the credential later.
pub fn build_anoncreds_proof(
    _cred_offer_json: &serde_json::Value,
    cred_request_json: &serde_json::Value,
    cred_def_id: &str,
    holder_nonce: &str,
) -> Result<CredentialProof> {
    // The cred_request_json comes from anoncreds_core::holder::create_credential_request()
    // which already contains blinded_ms and blinded_ms_correctness_proof.
    let blinded_ms = cred_request_json
        .get("blinded_ms")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let blinded_ms_correctness_proof = cred_request_json
        .get("blinded_ms_correctness_proof")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let prover_did = cred_request_json
        .get("prover_did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(CredentialProof::AnonCreds {
        prover_did,
        cred_def_id: cred_def_id.to_string(),
        blinded_ms,
        blinded_ms_correctness_proof,
        nonce: holder_nonce.to_string(),
    })
}

/// Convert a `c_nonce` from OID4VCI into an AnonCreds-compatible nonce.
///
/// AnonCreds nonces are large decimal integers. If the c_nonce is already
/// decimal, use it directly. Otherwise, hash it to produce a numeric nonce.
pub fn c_nonce_to_anoncreds_nonce(c_nonce: &str) -> String {
    // If it's already a decimal number, use directly
    if c_nonce.chars().all(|c| c.is_ascii_digit()) && !c_nonce.is_empty() {
        return c_nonce.to_string();
    }

    // Otherwise, hash to produce a numeric nonce
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(c_nonce.as_bytes());
    // Take first 10 bytes (80 bits) as big integer
    let mut nonce_val: u128 = 0;
    for &byte in &hash[..10] {
        nonce_val = (nonce_val << 8) | (byte as u128);
    }
    nonce_val.to_string()
}

/// Extract an AnonCreds credential from an OID4VCI credential response.
///
/// The credential response contains the blind CL signature that the
/// holder needs to unblind using the request metadata.
pub fn extract_anoncreds_credential(response: &CredentialResponse) -> Result<serde_json::Value> {
    if response.format != "anoncreds" {
        return Err(Oid4vciError::UnsupportedFormat(format!(
            "Expected 'anoncreds' format, got '{}'",
            response.format
        )));
    }
    Ok(response.credential.clone())
}
