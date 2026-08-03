// Present Proof v3 protocol messages

pub(crate) mod ack;
mod presentation;
mod problem_report;
pub(crate) mod request_presentation;

pub use ack::{AckMessage, AckStatus};
pub use presentation::PresentationMessage;
pub use problem_report::{
    codes as problem_codes, FixHint, Impact, ProblemDescription, ProblemReportMessage, Where,
    WhoRetries,
};
pub use request_presentation::RequestPresentationMessage;

/// AnonCreds proof request attachment format identifier
pub const ANONCREDS_PROOF_REQUEST: &str = "anoncreds/proof-request@v1.0";

/// AnonCreds proof attachment format identifier
pub const ANONCREDS_PROOF: &str = "anoncreds/proof@v1.0";

use serde_json::{json, Value};

/// Build an Aries 2.0 base64 attachment entry (`{@id, mime-type, format,
/// data:{base64}}`) — the wire shape an interoperable anoncreds format service
/// reads from `request_presentations~attach` / `presentations~attach`. Mirrors
/// `protocol_credentials::messages::v2_attachment`.
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

/// Extract the first attachment's JSON from a v1-flattened body decorator
/// (`request_presentations~attach` / `presentations~attach`), decoding base64
/// or reading inline `json`.
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
