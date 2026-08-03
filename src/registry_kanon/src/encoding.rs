//! Encode/decode AnonCreds object bodies as `data:` URIs, the form stored
//! on-chain in the Schema/CredDef registries.
//!
//! `uri = "data:application/json;base64," + base64(canonical_json)`.
//! On resolution we decode the URI's exact bytes (whatever the original
//! issuer wrote) so verification is agnostic to *our* canonicalization —
//! critical for resolving credentials the Python plugin already published.

use base64::Engine;

use crate::error::{KanonError, Result};

const PREFIX: &str = "data:application/json;base64,";

pub fn to_data_uri(canonical_json: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(canonical_json.as_bytes());
    format!("{PREFIX}{b64}")
}

/// Decode a `data:application/json;base64,…` URI back to raw JSON bytes.
pub fn from_data_uri(uri: &str) -> Result<Vec<u8>> {
    let b64 = uri
        .strip_prefix(PREFIX)
        .ok_or_else(|| KanonError::Encoding(format!("unexpected data uri: {uri}")))?;
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| KanonError::Encoding(format!("base64 decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let json = r#"{"a":1}"#;
        let uri = to_data_uri(json);
        assert!(uri.starts_with(PREFIX));
        assert_eq!(from_data_uri(&uri).unwrap(), json.as_bytes());
    }
}
