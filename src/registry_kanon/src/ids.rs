//! did:kanon identifier + AnonCreds resource-id derivation, keccak256, and
//! canonical JSON — the byte-level rules the on-chain contracts key on.
//!
//! Mirrors `did_kanon/v1_0/identifiers.py`:
//!   - DID (org):   `did:kanon:org:0x<64 hex>`
//!   - DID (user):  `did:kanon:user:0x<64 hex>`
//!   - Schema id:   `{issuer_did}/anoncreds/v0/SCHEMA/{name}/{version}`
//!   - CredDef id:  `{issuer_did}/anoncreds/v0/CLAIM_DEF/{schema_tag}/{tag}`
//!   - RevReg id:   `{cred_def_id}/revoc/{tag}` (synthesized; never on-chain)
//!
//! On-chain object keys are `keccak256(utf8(resource_id))`; integrity anchors
//! are `keccak256(utf8(canonical_json))`.

use sha3::{Digest, Keccak256};

use crate::error::{KanonError, Result};

pub type Bytes32 = [u8; 32];

/// Ethereum keccak256 (pre-NIST Keccak, as used by the contracts).
pub fn keccak256(data: &[u8]) -> Bytes32 {
    let mut h = Keccak256::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

pub fn bytes32_hex(b: &Bytes32) -> String {
    format!("0x{}", hex::encode(b))
}

/// Parse a `0x`-prefixed 32-byte hex string into `Bytes32`.
pub fn parse_bytes32(s: &str) -> Result<Bytes32> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let raw =
        hex::decode(stripped).map_err(|e| KanonError::Invalid(format!("bad hex {s}: {e}")))?;
    if raw.len() != 32 {
        return Err(KanonError::Invalid(format!(
            "expected 32 bytes, got {} for {s}",
            raw.len()
        )));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&raw);
    Ok(b)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidScope {
    Org,
    User,
}

#[derive(Debug, Clone)]
pub struct ParsedKanonDid {
    /// Bare DID (no path), e.g. `did:kanon:org:0x…`.
    pub did: String,
    pub scope: DidScope,
    /// The `0x<64 hex>` identifier component.
    pub id_hex: String,
}

/// Parse a `did:kanon:` DID or DID-URL (path is ignored). Returns `None` for
/// non-kanon or malformed DIDs.
pub fn parse_kanon_did(did_url: &str) -> Option<ParsedKanonDid> {
    let bare = did_url.split(['/', '?', '#']).next().unwrap_or(did_url);
    let rest = bare.strip_prefix("did:kanon:")?;
    let (scope, id_hex) = if let Some(h) = rest.strip_prefix("org:") {
        (DidScope::Org, h)
    } else {
        let h = rest.strip_prefix("user:")?;
        (DidScope::User, h)
    };
    if !is_bytes32_hex(id_hex) {
        return None;
    }
    Some(ParsedKanonDid {
        did: bare.to_string(),
        scope,
        id_hex: id_hex.to_string(),
    })
}

fn is_bytes32_hex(s: &str) -> bool {
    match s.strip_prefix("0x") {
        Some(h) => h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()),
        None => false,
    }
}

/// Extract the org id (bytes32) from an org-scoped issuer DID. Errors if the
/// issuer is not `did:kanon:org:0x…` — schema/cred-def writes are org-scoped.
pub fn issuer_org_id(issuer_id: &str) -> Result<Bytes32> {
    let parsed = parse_kanon_did(issuer_id)
        .ok_or_else(|| KanonError::Invalid(format!("not a did:kanon DID: {issuer_id}")))?;
    if parsed.scope != DidScope::Org {
        return Err(KanonError::Invalid(format!(
            "issuer must be org-scoped (did:kanon:org:…), got {issuer_id}"
        )));
    }
    parse_bytes32(&parsed.id_hex)
}

pub fn schema_resource_id(issuer_did: &str, name: &str, version: &str) -> String {
    format!("{issuer_did}/anoncreds/v0/SCHEMA/{name}/{version}")
}

pub fn cred_def_resource_id(issuer_did: &str, schema_tag: &str, tag: &str) -> String {
    format!("{issuer_did}/anoncreds/v0/CLAIM_DEF/{schema_tag}/{tag}")
}

pub fn rev_reg_id(cred_def_id: &str, tag: &str) -> String {
    format!("{cred_def_id}/revoc/{tag}")
}

/// `keccak256(utf8(resource_id))` — the on-chain bytes32 key.
pub fn resource_id_to_bytes32(resource_id: &str) -> Bytes32 {
    keccak256(resource_id.as_bytes())
}

/// `keccak256(utf8(cred_id))` — the AnonCredsStatusRegistry lookup key.
pub fn cred_id_hash(cred_id: &str) -> Bytes32 {
    keccak256(cred_id.as_bytes())
}

/// Recursive canonical JSON: object keys sorted at every level, compact
/// separators, matching Python's `json.dumps(sort_keys=True,
/// separators=(",", ":"))`. Independent of serde_json's `preserve_order`.
pub fn canonical_json(value: &serde_json::Value) -> String {
    let mut s = String::new();
    write_canonical(value, &mut s);
    s
}

fn write_canonical(v: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // Key as a JSON string.
                out.push_str(&serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into()));
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(e, out);
            }
            out.push(']');
        }
        // Scalars serialize identically to serde_json compact form.
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_org_did() {
        let did =
            "did:kanon:org:0xa479b0a8c0152ccb4f56efcdbca2d9790dc53f4e5475e5c205f769775c7c3a16";
        let p = parse_kanon_did(did).unwrap();
        assert_eq!(p.scope, DidScope::Org);
        assert!(issuer_org_id(did).is_ok());
    }

    #[test]
    fn rejects_non_kanon() {
        assert!(parse_kanon_did("did:web:example.com").is_none());
        assert!(issuer_org_id("did:kanon:user:0xab").is_err());
    }

    #[test]
    fn schema_id_shape() {
        let did = "did:kanon:org:0x00";
        assert_eq!(
            schema_resource_id(did, "Passport", "1.0"),
            "did:kanon:org:0x00/anoncreds/v0/SCHEMA/Passport/1.0"
        );
    }

    #[test]
    fn canonical_sorts_keys() {
        let v = serde_json::json!({"b": 1, "a": [3, 2], "c": {"z": 1, "y": 2}});
        assert_eq!(canonical_json(&v), r#"{"a":[3,2],"b":1,"c":{"y":2,"z":1}}"#);
    }
}
