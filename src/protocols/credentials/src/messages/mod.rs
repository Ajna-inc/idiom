// Issue Credential v3 protocol messages

mod ack;
mod issue;
mod offer;
mod preview;
mod problem_report;
mod propose;
mod request;

pub use ack::{AckMessage, AckStatus};
pub use issue::IssueCredentialMessage;
pub use offer::OfferCredentialMessage;
pub use preview::{are_preview_attributes_equal, CredentialPreviewAttribute};
pub use problem_report::{
    codes as problem_codes, FixHint, Impact, ProblemDescription, ProblemReportMessage, Where,
    WhoRetries,
};
pub use propose::ProposeCredentialMessage;
pub use request::RequestCredentialMessage;

/// Shared helper to pull JSON payload out of the first attachment of an
/// inbound credential-protocol message.
pub(crate) fn extract_attachment_json_pub(
    message: &didcomm::core::Message,
) -> Result<String, crate::CredentialError> {
    offer::extract_attachment_json(message)
}

/// AnonCreds format identifiers for Issue Credential v3
pub mod formats {
    pub const ANONCREDS_CREDENTIAL_OFFER: &str = "anoncreds/credential-offer@v1.0";
    pub const ANONCREDS_CREDENTIAL_REQUEST: &str = "anoncreds/credential-request@v1.0";
    pub const ANONCREDS_CREDENTIAL: &str = "anoncreds/credential@v1.0";
}

/// Attachment format descriptor used in credential messages
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AttachmentFormatDescriptor {
    /// ID of the corresponding attachment
    pub attach_id: String,
    /// Format identifier (e.g., "anoncreds/credential-offer@v1.0")
    pub format: String,
}

// ── Aries Issue-Credential 2.0 (RFC 0453) wire helpers ───────────────────────
//
// Interoperable wallets speak issue-credential 2.0 (Aries v1): `@type` at
// the top level, payloads in `offers~attach` / `requests~attach` /
// `credentials~attach` decorators (base64), and an optional `credential_preview`.
// idiom's envelope service flattens v1 messages, so putting these decorators in a
// message `body` (issue) or a plain `@type` value (offer) yields the exact 2.0
// wire shape. These helpers build/parse that shape; the AnonCreds payloads +
// format ids are identical to v3.

use serde_json::{json, Value};

/// One `~attach` decorator entry carrying `json_str` base64-encoded.
pub fn v2_attachment(attach_id: &str, format: &str, json_str: &str) -> Value {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(json_str.as_bytes());
    json!({
        "@id": attach_id,
        "mime-type": "application/json",
        "format": format,
        "data": { "base64": b64 },
    })
}

/// Pull the first `~attach` payload (a JSON string) out of a 2.0 message's
/// decorator (`offers~attach` etc.). idiom's v1 parser flattens the inbound
/// message into `body`, so the decorator lives there.
pub fn extract_v2_attach(body: &Value, decorator: &str) -> Option<String> {
    let att = body.get(decorator)?.as_array()?.first()?;
    let data = att.get("data")?;
    if let Some(b64) = data.get("base64").and_then(|v| v.as_str()) {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        return String::from_utf8(bytes).ok();
    }
    if let Some(j) = data.get("json") {
        return Some(j.to_string());
    }
    None
}
