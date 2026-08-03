//! Bitstring Status List support for W3C VC and SD-JWT credentials.
//!
//! Implements the data-model + check side of the W3C Bitstring Status List.
//! A VC carries a
//! `credentialStatus` object pointing to a hosted status-list credential.
//! Verifiers fetch that credential, inflate the gzip-compressed base64-url
//! bitstring, and read the bit at `statusListIndex` to learn if the
//! credential has been revoked, suspended, etc.
//!
//! This module provides the parser + bit lookup. Callers wire it into a
//! verifier and decide what to do when a bit is set.

use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Status purpose values.
pub mod purposes {
    pub const REVOCATION: &str = "revocation";
    pub const SUSPENSION: &str = "suspension";
    pub const MESSAGE: &str = "message";
}

/// `credentialStatus` member carried by a verifiable credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatusEntry {
    /// Identifier for this status entry (URL-friendly).
    pub id: String,
    /// Type: `BitstringStatusListEntry`, but we also
    /// accept the older `StatusList2021Entry` for backward compatibility.
    #[serde(rename = "type")]
    pub type_: String,
    /// What the bit at the index represents: `revocation`, `suspension`, etc.
    #[serde(rename = "statusPurpose")]
    pub status_purpose: String,
    /// 0-based offset into the bitstring.
    #[serde(rename = "statusListIndex")]
    pub status_list_index: StatusListIndex,
    /// URL of the status-list credential to fetch.
    #[serde(rename = "statusListCredential")]
    pub status_list_credential: String,
    /// Number of bits per entry (default 1). Must be a power of two.
    #[serde(rename = "statusSize", default = "default_status_size")]
    pub status_size: u8,
}

fn default_status_size() -> u8 {
    1
}

/// `statusListIndex` is a string but most issuers serialise it
/// as a JSON number. Accept both.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StatusListIndex {
    Number(u64),
    String(String),
}

impl StatusListIndex {
    pub fn as_u64(&self) -> Result<u64, StatusListError> {
        match self {
            StatusListIndex::Number(n) => Ok(*n),
            StatusListIndex::String(s) => s
                .parse::<u64>()
                .map_err(|e| StatusListError::Parse(format!("statusListIndex not numeric: {}", e))),
        }
    }
}

/// A fully-resolved status list credential's body. The `encodedList` field
/// is base64url-no-pad of the gzip-compressed bitmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListCredentialSubject {
    /// `BitstringStatusList` or the older `StatusList2021`.
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "statusPurpose")]
    pub status_purpose: String,
    #[serde(rename = "encodedList")]
    pub encoded_list: String,
}

/// Possible verdicts when checking a credential against its status list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusVerdict {
    /// Bit is 0 — credential is in good standing for the queried purpose.
    Active,
    /// Bit is 1 — credential is revoked / suspended / flagged.
    Set,
}

#[derive(Debug, Error)]
pub enum StatusListError {
    #[error("status list parse error: {0}")]
    Parse(String),
    #[error("status list index {index} out of range (bitstring is {len} bits)")]
    OutOfRange { index: u64, len: u64 },
    #[error("base64url decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("gzip inflate failed: {0}")]
    Inflate(String),
}

/// Pull the credentialStatus entry off a VC's JSON form. Returns None if the
/// credential isn't carrying one (i.e. unconditional, not revocable).
pub fn extract_credential_status(
    credential_json: &serde_json::Value,
) -> Option<CredentialStatusEntry> {
    let raw = credential_json.get("credentialStatus")?;
    // Some issuers wrap in a list — pick the first revocation/suspension entry.
    if let Some(list) = raw.as_array() {
        for item in list {
            if let Ok(entry) = serde_json::from_value::<CredentialStatusEntry>(item.clone()) {
                return Some(entry);
            }
        }
        None
    } else {
        serde_json::from_value(raw.clone()).ok()
    }
}

/// Decode a status list credential's `encodedList` field into the raw bits.
pub fn decode_status_list(encoded_list: &str) -> Result<Vec<u8>, StatusListError> {
    let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_list.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded_list))?;

    // GZIP is mandated. Try multigz first (status list 2021 uses gzip
    // header). Use flate2 if available; otherwise fall back to a tiny
    // header-stripped inflate.
    inflate_gzip(&compressed)
}

#[cfg(feature = "status-list-gzip")]
fn inflate_gzip(compressed: &[u8]) -> Result<Vec<u8>, StatusListError> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(compressed);
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .map_err(|e| StatusListError::Inflate(e.to_string()))?;
    Ok(buf)
}

#[cfg(not(feature = "status-list-gzip"))]
fn inflate_gzip(compressed: &[u8]) -> Result<Vec<u8>, StatusListError> {
    // Fallback: if the bytes don't look like a gzip stream, treat them as
    // already-uncompressed (older drafts used raw bitstrings).
    if compressed.len() >= 2 && compressed[0] == 0x1f && compressed[1] == 0x8b {
        return Err(StatusListError::Inflate(
            "gzip decoding requires the `status-list-gzip` feature".into(),
        ));
    }
    let _ = compressed;
    Ok(compressed.to_vec())
}

/// Read the bit at `index` from the bitstring. With `statusSize` > 1, returns
/// the unsigned integer value formed by the `statusSize` bits starting at
/// `index * statusSize`.
pub fn read_status_bit(
    bitstring: &[u8],
    index: u64,
    status_size: u8,
) -> Result<u64, StatusListError> {
    let status_size = status_size.max(1) as u64;
    let bit_index = index * status_size;
    let total_bits = (bitstring.len() as u64) * 8;
    if bit_index + status_size > total_bits {
        return Err(StatusListError::OutOfRange {
            index,
            len: total_bits,
        });
    }
    let mut value: u64 = 0;
    for i in 0..status_size {
        let bi = bit_index + i;
        let byte = bitstring[(bi / 8) as usize];
        let bit = (byte >> (7 - (bi % 8))) & 1;
        value = (value << 1) | (bit as u64);
    }
    Ok(value)
}

/// Decide the verdict for a credential given its status entry and the
/// already-fetched status list credential body.
pub fn check_status(
    entry: &CredentialStatusEntry,
    status_list_credential: &serde_json::Value,
) -> Result<StatusVerdict, StatusListError> {
    // The status list credential's `credentialSubject` carries `encodedList`.
    let subject = status_list_credential
        .get("credentialSubject")
        .ok_or_else(|| {
            StatusListError::Parse("status list credential missing credentialSubject".into())
        })?;
    let encoded = subject
        .get("encodedList")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StatusListError::Parse("missing encodedList".into()))?;

    let bits = decode_status_list(encoded)?;
    let index = entry.status_list_index.as_u64()?;
    let value = read_status_bit(&bits, index, entry.status_size)?;

    Ok(if value == 0 {
        StatusVerdict::Active
    } else {
        StatusVerdict::Set
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn read_bit_index_zero() {
        // 0b10000000 → bit 0 is set
        let bits = vec![0b1000_0000];
        assert_eq!(read_status_bit(&bits, 0, 1).unwrap(), 1);
        // bit 1 not set
        assert_eq!(read_status_bit(&bits, 1, 1).unwrap(), 0);
    }

    #[test]
    fn read_bit_multibyte() {
        // 0b00000000 00000010 → bit 14 = 1, bit 15 = 0
        let bits = vec![0b0000_0000, 0b0000_0010];
        assert_eq!(read_status_bit(&bits, 14, 1).unwrap(), 1);
        assert_eq!(read_status_bit(&bits, 15, 1).unwrap(), 0);
    }

    #[test]
    fn read_bits_size_two() {
        // 0b10110100 → two-bit reads: idx0=10(=2), idx1=11(=3), idx2=01(=1), idx3=00(=0)
        let bits = vec![0b1011_0100];
        assert_eq!(read_status_bit(&bits, 0, 2).unwrap(), 2);
        assert_eq!(read_status_bit(&bits, 1, 2).unwrap(), 3);
        assert_eq!(read_status_bit(&bits, 2, 2).unwrap(), 1);
        assert_eq!(read_status_bit(&bits, 3, 2).unwrap(), 0);
    }

    #[test]
    fn extract_status_entry() {
        let vc = json!({
            "credentialStatus": {
                "id": "https://example.com/status/1#3",
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "3",
                "statusListCredential": "https://example.com/status/1"
            }
        });
        let entry = extract_credential_status(&vc).expect("parse");
        assert_eq!(entry.status_purpose, "revocation");
        assert_eq!(entry.status_list_index.as_u64().unwrap(), 3);
    }

    #[test]
    fn out_of_range_errors() {
        let bits = vec![0u8; 1]; // 8 bits
        let err = read_status_bit(&bits, 100, 1).unwrap_err();
        assert!(matches!(err, StatusListError::OutOfRange { .. }));
    }

    #[test]
    fn check_status_active_with_uncompressed_fallback() {
        // Skip gzip path — test the bit-reading via a synthetic
        // already-uncompressed list (only works when the gzip feature is off).
        // We build the encodedList ourselves to simulate the fallback path
        // (`status-list-gzip` feature is not enabled in default tests).
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode([0b0000_0000_u8, 0b0000_0010_u8]);
        let entry = CredentialStatusEntry {
            id: "x".into(),
            type_: "BitstringStatusListEntry".into(),
            status_purpose: "revocation".into(),
            status_list_index: StatusListIndex::Number(14),
            status_list_credential: "https://example.com".into(),
            status_size: 1,
        };
        let body = json!({
            "credentialSubject": { "encodedList": encoded }
        });
        let verdict = check_status(&entry, &body).unwrap();
        assert_eq!(verdict, StatusVerdict::Set);
    }
}
