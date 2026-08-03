//! Parser + matcher for Aries / DIDComm message type URIs.
//!
//! Used by dispatchers / handlers to answer "do I support this incoming
//! message?" — version compatibility follows Aries RFC 0017 (matching
//! major version, drift on minor allowed in either direction).
//!
//! A message type URI follows the shape
//!   `<document-uri>/<protocol-name>/<major>.<minor>/<message-name>`
//! e.g. `https://didcomm.org/connections/1.0/request`.

use serde::{Deserialize, Serialize};

/// Indy/Sovrin legacy prefix that many older protocols emit instead of
/// `https://didcomm.org`. We translate it into the canonical form on
/// receipt so handler dispatch only needs to know one URI shape.
pub const LEGACY_DID_SOV_PREFIX: &str = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec";
const NEW_DIDCOMM_PREFIX: &str = "https://didcomm.org";

/// A fully parsed message type URI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedMessageType {
    pub document_uri: String,
    pub protocol_name: String,
    pub protocol_version: String,
    pub protocol_major_version: u32,
    pub protocol_minor_version: u32,
    pub message_name: String,
    pub protocol_uri: String,
    pub message_type_uri: String,
}

/// A fully parsed protocol URI (no message segment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedProtocolUri {
    pub document_uri: String,
    pub protocol_name: String,
    pub protocol_version: String,
    pub protocol_major_version: u32,
    pub protocol_minor_version: u32,
    pub protocol_uri: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageTypeError {
    #[error("message type URI must have 4 segments after the document URI, got: {0}")]
    InvalidShape(String),
    #[error("protocol URI must have 3 segments after the document URI, got: {0}")]
    InvalidProtocolShape(String),
    #[error("protocol version must be `major.minor` with numeric components, got: {0}")]
    InvalidVersion(String),
}

/// Translate a legacy `did:sov:...spec/...` prefix on a message-type string
/// into the modern `https://didcomm.org/...` form. No-op on non-legacy URIs.
pub fn replace_legacy_did_sov_prefix(message_type: &str) -> String {
    if let Some(rest) = message_type.strip_prefix(LEGACY_DID_SOV_PREFIX) {
        format!("{}{}", NEW_DIDCOMM_PREFIX, rest)
    } else {
        message_type.to_string()
    }
}

/// Reverse direction: rewrite a modern `https://didcomm.org/...` URI back
/// to the legacy did:sov prefix. Used by senders talking to legacy peers.
pub fn replace_new_didcomm_prefix_with_legacy_did_sov(message_type: &str) -> String {
    if let Some(rest) = message_type.strip_prefix(NEW_DIDCOMM_PREFIX) {
        format!("{}{}", LEGACY_DID_SOV_PREFIX, rest)
    } else {
        message_type.to_string()
    }
}

/// Translate the `@type` field of a parsed DIDComm message JSON value
/// from legacy → modern form. Mutates in place; safe no-op on non-legacy.
pub fn replace_legacy_did_sov_prefix_on_message(message: &mut serde_json::Value) {
    if let Some(t) = message.get("@type").and_then(|v| v.as_str()) {
        let replaced = replace_legacy_did_sov_prefix(t);
        if replaced != t {
            message["@type"] = serde_json::Value::String(replaced);
        }
    }
}

/// Inverse of the above — for senders that need to talk legacy.
pub fn replace_new_didcomm_prefix_with_legacy_did_sov_on_message(message: &mut serde_json::Value) {
    if let Some(t) = message.get("@type").and_then(|v| v.as_str()) {
        let replaced = replace_new_didcomm_prefix_with_legacy_did_sov(t);
        if replaced != t {
            message["@type"] = serde_json::Value::String(replaced);
        }
    }
}

/// Parse a message-type URI into its components.
pub fn parse_message_type(uri: &str) -> Result<ParsedMessageType, MessageTypeError> {
    let segments = split_into_segments(uri);
    // Need exactly 4 trailing segments: protocol-name / version / message-name.
    // Everything before the protocol-name is the document URI.
    if segments.len() < 4 {
        return Err(MessageTypeError::InvalidShape(uri.to_string()));
    }
    let message_name = segments[segments.len() - 1].clone();
    let protocol_version = segments[segments.len() - 2].clone();
    let protocol_name = segments[segments.len() - 3].clone();
    let document_uri = segments[..segments.len() - 3].join("/");

    // Reject extra trailing path components.
    let expected_suffix = format!(
        "{}/{}/{}/{}",
        document_uri, protocol_name, protocol_version, message_name
    );
    if uri != expected_suffix {
        return Err(MessageTypeError::InvalidShape(uri.to_string()));
    }

    let (major, minor) = parse_version(&protocol_version)?;
    let protocol_uri = format!("{}/{}/{}", document_uri, protocol_name, protocol_version);

    Ok(ParsedMessageType {
        document_uri,
        protocol_name,
        protocol_version,
        protocol_major_version: major,
        protocol_minor_version: minor,
        message_name,
        protocol_uri,
        message_type_uri: uri.to_string(),
    })
}

/// Parse a protocol URI (no trailing message-name) into its components.
pub fn parse_didcomm_protocol_uri(uri: &str) -> Result<ParsedProtocolUri, MessageTypeError> {
    let segments = split_into_segments(uri);
    if segments.len() < 3 {
        return Err(MessageTypeError::InvalidProtocolShape(uri.to_string()));
    }
    let protocol_version = segments[segments.len() - 1].clone();
    let protocol_name = segments[segments.len() - 2].clone();
    let document_uri = segments[..segments.len() - 2].join("/");

    // Reject inputs with extra trailing segments that would belong to a
    // message-type URI (e.g. `…/connections/1.0/message-type`).
    let expected_suffix = format!("{}/{}/{}", document_uri, protocol_name, protocol_version);
    if uri != expected_suffix {
        return Err(MessageTypeError::InvalidProtocolShape(uri.to_string()));
    }

    let (major, minor) = parse_version(&protocol_version)?;
    let protocol_uri = expected_suffix.clone();

    Ok(ParsedProtocolUri {
        document_uri,
        protocol_name,
        protocol_version,
        protocol_major_version: major,
        protocol_minor_version: minor,
        protocol_uri,
    })
}

/// Compatibility check: does an incoming message type satisfy a handler
/// that expects `expected`? Same major version + same protocol/document.
/// Minor version drift is allowed in either direction (per Aries
/// RFC 0017 protocol versioning).
///
/// Pass `allow_legacy_did_sov_mismatch = true` to match RFC-compliant
/// agents that still emit the legacy `did:sov:…;spec/…` prefix.
pub fn supports_incoming_message_type(
    incoming: &ParsedMessageType,
    expected: &ParsedMessageType,
    allow_legacy_did_sov_mismatch: bool,
) -> bool {
    if incoming.message_name != expected.message_name {
        return false;
    }
    supports_incoming_didcomm_protocol_uri_internal(
        &incoming.document_uri,
        incoming.protocol_major_version,
        &incoming.protocol_name,
        &expected.document_uri,
        expected.protocol_major_version,
        &expected.protocol_name,
        allow_legacy_did_sov_mismatch,
    )
}

/// Same check at the protocol-URI level (no message-name comparison).
pub fn supports_incoming_didcomm_protocol_uri(
    incoming: &ParsedProtocolUri,
    expected: &ParsedProtocolUri,
    allow_legacy_did_sov_mismatch: bool,
) -> bool {
    supports_incoming_didcomm_protocol_uri_internal(
        &incoming.document_uri,
        incoming.protocol_major_version,
        &incoming.protocol_name,
        &expected.document_uri,
        expected.protocol_major_version,
        &expected.protocol_name,
        allow_legacy_did_sov_mismatch,
    )
}

fn supports_incoming_didcomm_protocol_uri_internal(
    incoming_doc: &str,
    incoming_major: u32,
    incoming_name: &str,
    expected_doc: &str,
    expected_major: u32,
    expected_name: &str,
    allow_legacy: bool,
) -> bool {
    if incoming_name != expected_name {
        return false;
    }
    if incoming_major != expected_major {
        return false;
    }
    if incoming_doc != expected_doc {
        if !allow_legacy {
            return false;
        }
        // Permit the legacy did:sov ↔ https://didcomm.org swap.
        let normalised_incoming = if incoming_doc == LEGACY_DID_SOV_PREFIX {
            NEW_DIDCOMM_PREFIX
        } else {
            incoming_doc
        };
        let normalised_expected = if expected_doc == LEGACY_DID_SOV_PREFIX {
            NEW_DIDCOMM_PREFIX
        } else {
            expected_doc
        };
        if normalised_incoming != normalised_expected {
            return false;
        }
    }
    true
}

fn split_into_segments(uri: &str) -> Vec<String> {
    uri.split('/').map(|s| s.to_string()).collect()
}

fn parse_version(version: &str) -> Result<(u32, u32), MessageTypeError> {
    let mut parts = version.split('.');
    let major = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| MessageTypeError::InvalidVersion(version.to_string()))?;
    let minor = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| MessageTypeError::InvalidVersion(version.to_string()))?;
    if parts.next().is_some() {
        return Err(MessageTypeError::InvalidVersion(version.to_string()));
    }
    Ok((major, minor))
}
