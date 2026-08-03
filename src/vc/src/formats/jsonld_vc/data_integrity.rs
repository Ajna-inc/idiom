//! W3C Data Integrity Proof verification for `eddsa-jcs-2022` and
//! `eddsa-rdfc-2022` cryptosuites — the modern default for ldp_vc
//! issuance (OpenBadges v3, EBSI v2, etc.).
//!
//! ## Pipeline (both cryptosuites)
//!
//! 1. **Canonicalize the document** (without the `proof` block)
//!    - `eddsa-jcs-2022`  → RFC 8785 JSON Canonicalization Scheme
//!    - `eddsa-rdfc-2022` → JSON-LD canonicalization (URDNA2015 on the
//!      RDF dataset)
//! 2. **Canonicalize the proof config** — the proof block minus
//!    `proofValue` — using the same scheme.
//! 3. **`hashData = SHA-256(canonicalProofConfig) || SHA-256(canonicalDocument)`**
//! 4. **Verify Ed25519** over `hashData` using the issuer's public key
//!    (resolved from the proof's `verificationMethod` DID URL).
//! 5. `proofValue` is a base58-btc multibase string (leading `z`).
//!
//! ## Status
//!
//! - `eddsa-jcs-2022` is fully implemented and verified.
//! - `eddsa-rdfc-2022` is **structurally** implemented but currently
//!   delegates to the in-house simplified canonicalization in
//!   `super::canonicalization` (which does NOT match URDNA2015 bit-for-
//!   bit), so byte-equivalent verification against externally-issued
//!   credentials only works when the document has no blank nodes that
//!   trigger the URDNA labelling algorithm. The hook is in place; a
//!   future change can swap in `rdf-canon::canonicalize` once we wire
//!   in real JSON-LD → RDF expansion.

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::context_loader::ContextLoader;
use super::rdfc_canonicalize::canonicalize_jsonld_to_nquads;

/// URL of the Data Integrity v2 context (matches the standard Data
/// Integrity v2 context). The
/// proof config canonicalization MUST happen with the DI context in
/// the doc's @context list — append it if the issuer didn't include
/// it.
pub const DATA_INTEGRITY_V2_CONTEXT_URL: &str = "https://w3id.org/security/data-integrity/v2";

/// Result of verifying a Data Integrity proof.
#[derive(Debug, Clone)]
pub struct DiVerificationOutcome {
    pub is_valid: bool,
    pub cryptosuite: String,
    pub verification_method: String,
    /// If verification failed, a one-line reason — surface this to the
    /// UI so users can tell "cryptosuite not implemented" from
    /// "signature invalid" from "issuer key didn't resolve".
    pub error: Option<String>,
}

/// Verify a `DataIntegrityProof`. `document_without_proof` must be the
/// credential JSON with the `proof` field removed; `proof` is the
/// (single, already-array-collapsed) proof object.
///
/// `issuer_public_key` is the 32-byte Ed25519 public key obtained by
/// resolving the proof's `verificationMethod` DID URL — callers are
/// responsible for that resolution because it crosses the network and
/// is reused across other verifications.
///
/// `context_loader` provides the JSON-LD contexts needed for
/// `eddsa-rdfc-2022` canonicalization (offline; the cache is pre-
/// populated in `ContextLoader::new`). For `eddsa-jcs-2022` the
/// loader is unused and may be a fresh offline instance.
pub async fn verify_data_integrity_proof(
    document_without_proof: &Value,
    proof: &Value,
    issuer_public_key: &[u8; 32],
    context_loader: Arc<ContextLoader>,
) -> DiVerificationOutcome {
    let cryptosuite = proof
        .get("cryptosuite")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let verification_method = proof
        .get("verificationMethod")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let proof_value_b58 = match proof.get("proofValue").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => {
            return DiVerificationOutcome {
                is_valid: false,
                cryptosuite,
                verification_method,
                error: Some("proof.proofValue missing".to_string()),
            };
        }
    };
    let sig_bytes = match decode_multibase_base58_btc(proof_value_b58) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        Ok(other) => {
            return DiVerificationOutcome {
                is_valid: false,
                cryptosuite,
                verification_method,
                error: Some(format!(
                    "proofValue: expected 64-byte Ed25519 signature, got {} bytes",
                    other.len()
                )),
            };
        }
        Err(e) => {
            return DiVerificationOutcome {
                is_valid: false,
                cryptosuite,
                verification_method,
                error: Some(format!("proofValue multibase decode: {}", e)),
            };
        }
    };

    // Build the hashData (proof config first, then doc).
    let hash_data =
        match build_hash_data(document_without_proof, proof, &cryptosuite, context_loader).await {
            Ok(b) => b,
            Err(e) => {
                return DiVerificationOutcome {
                    is_valid: false,
                    cryptosuite,
                    verification_method,
                    error: Some(format!("canonicalization: {}", e)),
                };
            }
        };

    // Ed25519 verify
    let verifying = match VerifyingKey::from_bytes(issuer_public_key) {
        Ok(k) => k,
        Err(e) => {
            return DiVerificationOutcome {
                is_valid: false,
                cryptosuite,
                verification_method,
                error: Some(format!(
                    "issuer public key is not a valid Ed25519 point: {}",
                    e
                )),
            };
        }
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            return DiVerificationOutcome {
                is_valid: false,
                cryptosuite,
                verification_method,
                error: Some(format!("signature decode: {}", e)),
            };
        }
    };
    match verifying.verify(&hash_data, &sig) {
        Ok(()) => DiVerificationOutcome {
            is_valid: true,
            cryptosuite,
            verification_method,
            error: None,
        },
        Err(e) => DiVerificationOutcome {
            is_valid: false,
            cryptosuite,
            verification_method,
            error: Some(format!("Ed25519 verify rejected the proof: {}", e)),
        },
    }
}

/// Signing-side helper: the exact hashData a signer must sign so that
/// `verify_data_integrity_proof` accepts the proof. `proof` is the proof
/// under construction (with or without `proofValue` — it's stripped either
/// way). A thin wrapper over the shared builder so signing and verification
/// can never drift.
pub async fn data_integrity_hash_data(
    document_without_proof: &Value,
    proof: &Value,
    cryptosuite: &str,
    context_loader: Arc<ContextLoader>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    build_hash_data(document_without_proof, proof, cryptosuite, context_loader).await
}

/// Build the SHA-256 hashData for either cryptosuite:
/// `SHA-256(canonicalProofConfig) || SHA-256(canonicalDocument)`
async fn build_hash_data(
    document_without_proof: &Value,
    proof: &Value,
    cryptosuite: &str,
    context_loader: Arc<ContextLoader>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // Build the proof config — every field of the proof minus
    // `proofValue`. The reference
    // implementation at `eddsa-rdfc-2022-cryptosuite/EddsaRdfc2022.ts`
    // line 305-309 match every present field, not just a fixed
    // subset, so we copy everything else through.
    let mut proof_config = proof.clone();
    if let Some(obj) = proof_config.as_object_mut() {
        obj.remove("proofValue");
        // The proof config's
        // @context MUST be the document's @context with the DI v2
        // context guaranteed to be present (appended if missing).
        // The previous JCS-only path inherited @context naively
        // which works for JCS but produces different RDF for RDFC.
        let doc_ctx = document_without_proof.get("@context").cloned();
        let proof_ctx = ensure_di_context(doc_ctx);
        obj.insert("@context".to_string(), proof_ctx);
    }

    let canon_doc =
        canonicalize_for_cryptosuite(document_without_proof, cryptosuite, context_loader.clone())
            .await?;
    let canon_proof =
        canonicalize_for_cryptosuite(&proof_config, cryptosuite, context_loader).await?;

    let proof_hash = Sha256::digest(canon_proof.as_bytes());
    let doc_hash = Sha256::digest(canon_doc.as_bytes());

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&proof_hash);
    out.extend_from_slice(&doc_hash);
    Ok(out)
}

/// Compute the `proofContext`:
/// take the document's @context (a string or array) and append the
/// Data Integrity v2 context if it's not already in there. Returns a
/// Value suitable to drop into the proof config under `@context`.
fn ensure_di_context(doc_ctx: Option<Value>) -> Value {
    match doc_ctx {
        None => Value::String(DATA_INTEGRITY_V2_CONTEXT_URL.to_string()),
        Some(Value::String(s)) => {
            if s == DATA_INTEGRITY_V2_CONTEXT_URL {
                Value::String(s)
            } else {
                json!([s, DATA_INTEGRITY_V2_CONTEXT_URL])
            }
        }
        Some(Value::Array(mut arr)) => {
            if !arr
                .iter()
                .any(|v| v.as_str() == Some(DATA_INTEGRITY_V2_CONTEXT_URL))
            {
                arr.push(Value::String(DATA_INTEGRITY_V2_CONTEXT_URL.to_string()));
            }
            Value::Array(arr)
        }
        Some(other) => json!([other, DATA_INTEGRITY_V2_CONTEXT_URL]),
    }
}

async fn canonicalize_for_cryptosuite(
    value: &Value,
    cryptosuite: &str,
    context_loader: Arc<ContextLoader>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    match cryptosuite {
        "eddsa-jcs-2022" => {
            // RFC 8785 JSON Canonicalization Scheme. `serde_jcs`
            // produces the exact byte sequence required.
            Ok(serde_jcs::to_string(value)?)
        }
        "eddsa-rdfc-2022" => {
            // Full pipeline: JSON-LD expansion + JSON-LD-to-RDF via
            // `json-ld 0.21`, then URDNA2015 via `rdf-canon 0.15`. The
            // EmbeddedContextLoader serves every required @context from
            // our pre-cached set; no network calls.
            canonicalize_jsonld_to_nquads(value, context_loader).await
        }
        other => Err(format!("unsupported Data Integrity cryptosuite: {}", other).into()),
    }
}

/// Decode a `z…` multibase base58-btc string to raw bytes. Used for
/// `proofValue` and `publicKeyMultibase`.
pub fn decode_multibase_base58_btc(
    s: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let trimmed = s.trim();
    let body = trimmed
        .strip_prefix('z')
        .ok_or("multibase value must start with 'z' (base58-btc)")?;
    Ok(bs58::decode(body).into_vec()?)
}

/// Decode a `Multikey` `publicKeyMultibase` value (`z6Mk…` for
/// Ed25519) to its raw 32-byte public key. The multikey format is
/// `0xed 0x01` (multicodec for Ed25519-pub) followed by the 32-byte
/// key. Returns Err if the prefix doesn't match Ed25519.
pub fn ed25519_pubkey_from_multikey(
    multikey: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let raw = decode_multibase_base58_btc(multikey)?;
    let stripped = raw
        .strip_prefix(&[0xed, 0x01])
        .ok_or("publicKeyMultibase is not an Ed25519 multikey (missing 0xed 0x01 prefix)")?;
    if stripped.len() != 32 {
        return Err(format!(
            "expected 32-byte Ed25519 key after multicodec prefix, got {}",
            stripped.len()
        )
        .into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(stripped);
    Ok(arr)
}

/// Convert a `did:web:foo:bar:baz` DID URL to the document URL
/// `https://foo/bar/baz/did.json` for did:web.
pub fn did_web_to_document_url(did: &str) -> Result<String, String> {
    let did_no_frag = did.split('#').next().unwrap_or(did);
    let body = did_no_frag
        .strip_prefix("did:web:")
        .ok_or_else(|| format!("not a did:web URL: {}", did))?;
    // Path segments separated by `:`; URL-decode each segment.
    // The first segment is the host; the rest are path
    // components. If there's only the host, the document path is
    // `/.well-known/did.json`.
    let parts: Vec<&str> = body.split(':').collect();
    let host = percent_decode(parts[0]);
    if parts.len() == 1 {
        return Ok(format!("https://{}/.well-known/did.json", host));
    }
    let path = parts[1..]
        .iter()
        .map(|s| percent_decode(s))
        .collect::<Vec<_>>()
        .join("/");
    Ok(format!("https://{}/{}/did.json", host, path))
}

/// Minimal percent-decoder for did:web segments. did:web only uses
/// `%3A` for `:` (port separator) so this just handles that case.
fn percent_decode(s: &str) -> String {
    s.replace("%3A", ":").replace("%3a", ":")
}

/// Resolve a did:web verification method to its Ed25519 public key.
///
/// `verification_method` is the full URL with fragment (e.g.
/// `did:web:api.essi.studio:issuers:essi-main-wallet#key-0`).
///
/// HTTP-aware so a verifier can be called from the agent without
/// shipping its own networking. Caller controls the reqwest client
/// — tests can pass a short-timeout one to keep them snappy.
pub async fn resolve_did_web_key(
    verification_method: &str,
    client: &reqwest::Client,
) -> Result<[u8; 32], String> {
    let (did, fragment) = match verification_method.split_once('#') {
        Some((d, f)) => (d, Some(f)),
        None => (verification_method, None),
    };
    let doc_url = did_web_to_document_url(did)?;
    let resp = client
        .get(&doc_url)
        .send()
        .await
        .map_err(|e| format!("fetch DID document {}: {}", doc_url, e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "DID document {} returned status {}",
            doc_url,
            resp.status()
        ));
    }
    let doc: Value = resp
        .json()
        .await
        .map_err(|e| format!("parse DID document JSON from {}: {}", doc_url, e))?;
    let methods = doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("DID document {} has no verificationMethod array", doc_url))?;

    // Build the set of candidate ids: either the explicit full URL,
    // or any vm whose `id` ends with the requested `#<fragment>`.
    let target_ids: BTreeSet<String> = std::iter::once(verification_method.to_string())
        .chain(fragment.map(|f| format!("#{}", f)))
        .collect();

    for vm in methods {
        let id = match vm.get("id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => continue,
        };
        let matches =
            target_ids.contains(id) || fragment.is_some_and(|f| id.ends_with(&format!("#{}", f)));
        if !matches {
            continue;
        }
        let vm_type = vm.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let multikey = vm.get("publicKeyMultibase").and_then(|v| v.as_str());
        let pub_jwk = vm.get("publicKeyJwk");

        if vm_type == "Multikey" || vm_type == "Ed25519VerificationKey2020" {
            if let Some(mk) = multikey {
                return ed25519_pubkey_from_multikey(mk).map_err(|e| e.to_string());
            }
        }
        if let Some(jwk) = pub_jwk {
            // OKP / Ed25519 JWK
            let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            if kty == "OKP" && crv == "Ed25519" {
                if let Some(x) = jwk.get("x").and_then(|v| v.as_str()) {
                    let bytes = base64::Engine::decode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        x,
                    )
                    .map_err(|e| format!("decode JWK x: {}", e))?;
                    if bytes.len() != 32 {
                        return Err(format!("JWK x is {} bytes, expected 32", bytes.len()));
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    return Ok(arr);
                }
            }
        }
        return Err(format!(
            "verificationMethod {} has neither a Multikey nor an OKP/Ed25519 publicKeyJwk",
            id
        ));
    }
    Err(format!(
        "no verificationMethod in {} matched {}",
        doc_url, verification_method
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_web_to_document_url_host_only() {
        assert_eq!(
            did_web_to_document_url("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
    }

    #[test]
    fn did_web_to_document_url_with_path() {
        assert_eq!(
            did_web_to_document_url("did:web:api.essi.studio:issuers:essi-main-wallet#key-0")
                .unwrap(),
            "https://api.essi.studio/issuers/essi-main-wallet/did.json"
        );
    }

    #[test]
    fn ed25519_pubkey_from_multikey_decodes_known_value() {
        // The exact key the essi.studio demo issuer publishes.
        let mk = "z6MkiETzgSzaUA7fWuka95njmvMZcfRJQBvKFzvZENRGXn9s";
        let key = ed25519_pubkey_from_multikey(mk).expect("decode");
        assert_eq!(key.len(), 32);
        // Smoke-check: should be a valid Ed25519 point.
        VerifyingKey::from_bytes(&key).expect("valid point");
    }
}
