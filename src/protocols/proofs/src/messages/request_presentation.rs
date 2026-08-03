use didcomm::core::{Attachment, AttachmentData, Message as DidcommMessage};
use serde::{Deserialize, Serialize};

use super::ANONCREDS_PROOF_REQUEST;

/// Present Proof 3.0 Request Presentation Message
///
/// Sent by the Verifier to request a proof from the Prover.
/// Contains a proof request as an attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPresentationMessage {
    /// Message ID
    pub id: String,

    /// Optional comment from the verifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Whether the prover will also send a proposal (not typically used)
    #[serde(default)]
    pub will_confirm: bool,

    /// Serialized proof request JSON (AnonCreds PresentationRequest)
    pub proof_request_json: String,
}

impl RequestPresentationMessage {
    /// Message type constant (Aries Present-Proof 2.0, for interoperable peers)
    pub const TYPE: &'static str = "https://didcomm.org/present-proof/2.0/request-presentation";

    /// Create a new request-presentation message
    pub fn new(proof_request_json: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            comment: None,
            will_confirm: true,
            proof_request_json,
        }
    }

    /// Set a comment on the request
    pub fn with_comment(mut self, comment: String) -> Self {
        self.comment = Some(comment);
        self
    }

    /// Set custom message ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Build the Aries 2.0 request-presentation value sent on the wire. Places
    /// `@type`/`@id` and the `request_presentations~attach` decorator in the
    /// message body so the peer reads the Aries message (including
    /// `@type`) from the decrypted body — mirrors the credential offer's
    /// `to_aries_v2_value`. Sent directly via `send_via_connection`.
    pub fn to_aries_v2_value(&self) -> serde_json::Value {
        let attach_id = uuid::Uuid::new_v4().to_string();
        serde_json::json!({
            "@type": Self::TYPE,
            "@id": self.id,
            "comment": self.comment,
            "will_confirm": self.will_confirm,
            "formats": [ { "attach_id": attach_id, "format": ANONCREDS_PROOF_REQUEST } ],
            "request_presentations~attach": [
                crate::messages::v2_attachment(&attach_id, ANONCREDS_PROOF_REQUEST, &self.proof_request_json)
            ],
        })
    }

    /// Convert to a DIDComm Message
    pub fn to_didcomm_message(&self) -> DidcommMessage {
        let body = serde_json::json!({
            "comment": self.comment,
            "will_confirm": self.will_confirm,
        });

        let attachment = Attachment {
            id: Some(uuid::Uuid::new_v4().to_string()),
            description: None,
            filename: None,
            media_type: Some("application/json".to_string()),
            format: Some(ANONCREDS_PROOF_REQUEST.to_string()),
            lastmod_time: None,
            byte_count: None,
            data: AttachmentData::Json {
                json: serde_json::from_str(&self.proof_request_json)
                    .unwrap_or_else(|_| serde_json::Value::String(self.proof_request_json.clone())),
            },
        };

        let mut msg = DidcommMessage::new(self.id.clone(), Self::TYPE.to_string(), body);
        msg.attachments = Some(vec![attachment]);

        msg
    }

    /// Parse from a DIDComm Message
    pub fn from_didcomm_message(msg: &DidcommMessage) -> Result<Self, String> {
        let comment = msg
            .body
            .get("comment")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let will_confirm = msg
            .body
            .get("will_confirm")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Aries 2.0: the proof request lives in the v1-flattened body
        // decorator `request_presentations~attach`. Prefer that; fall back to the
        // v3 `attachments` field.
        if let Some(proof_request_json) =
            super::extract_v2_attach(&msg.body, "request_presentations~attach")
        {
            return Ok(Self {
                id: msg.id.clone(),
                comment,
                will_confirm,
                proof_request_json,
            });
        }

        // Extract proof request from attachment
        let attachments = msg
            .attachments
            .as_ref()
            .ok_or_else(|| "Missing attachments in request-presentation message".to_string())?;

        let proof_request_attachment = attachments
            .iter()
            .find(|a| a.format.as_deref() == Some(ANONCREDS_PROOF_REQUEST))
            .or_else(|| attachments.first())
            .ok_or_else(|| "No proof request attachment found".to_string())?;

        let proof_request_json = match &proof_request_attachment.data {
            AttachmentData::Json { json } => serde_json::to_string(json)
                .map_err(|e| format!("Failed to serialize proof request: {}", e))?,
            AttachmentData::Base64 { base64 } => {
                let decoded = base64_decode(base64)
                    .map_err(|e| format!("Failed to decode base64 attachment: {}", e))?;
                String::from_utf8(decoded)
                    .map_err(|e| format!("Invalid UTF-8 in proof request: {}", e))?
            }
            AttachmentData::Links { .. } => {
                return Err("Links attachments are not supported for proof requests".to_string());
            }
        };

        Ok(Self {
            id: msg.id.clone(),
            comment,
            will_confirm,
            proof_request_json,
        })
    }
}

/// Decode a base64 string (standard encoding)
pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    // Simple base64 decode without pulling in the base64 crate
    // We use serde_json's roundtrip since it handles base64 natively in attachments
    // For robustness, we do a manual decode
    let mut output = Vec::new();
    let chars: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'\n' && b != b'\r' && b != b' ')
        .collect();

    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn decode_char(c: u8, table: &[u8]) -> Result<u8, String> {
        table
            .iter()
            .position(|&t| t == c)
            .map(|p| p as u8)
            .ok_or_else(|| format!("Invalid base64 character: {}", c as char))
    }

    let mut i = 0;
    while i < chars.len() {
        let remaining = chars.len() - i;
        if remaining < 2 {
            return Err("Invalid base64 input length".to_string());
        }

        let b0 = decode_char(chars[i], table)?;
        let b1 = decode_char(chars[i + 1], table)?;
        output.push((b0 << 2) | (b1 >> 4));

        if i + 2 < chars.len() && chars[i + 2] != b'=' {
            let b2 = decode_char(chars[i + 2], table)?;
            output.push((b1 << 4) | (b2 >> 2));

            if i + 3 < chars.len() && chars[i + 3] != b'=' {
                let b3 = decode_char(chars[i + 3], table)?;
                output.push((b2 << 6) | b3);
            }
        }

        i += 4;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_creation() {
        let proof_request = r#"{"name":"test","version":"1.0","nonce":"12345","requested_attributes":{},"requested_predicates":{}}"#;
        let request = RequestPresentationMessage::new(proof_request.to_string());

        assert!(!request.id.is_empty());
        assert!(request.comment.is_none());
        assert!(request.will_confirm);
        assert_eq!(request.proof_request_json, proof_request);
    }

    #[test]
    fn test_request_with_comment() {
        let request = RequestPresentationMessage::new("{}".to_string())
            .with_comment("Please prove your age".to_string());

        assert_eq!(request.comment, Some("Please prove your age".to_string()));
    }

    #[test]
    fn test_to_didcomm_message() {
        let proof_request = r#"{"name":"test","version":"1.0"}"#;
        let request = RequestPresentationMessage::new(proof_request.to_string());
        let msg = request.to_didcomm_message();

        assert_eq!(msg.msg_type, RequestPresentationMessage::TYPE);
        assert_eq!(msg.id, request.id);
        assert!(msg.attachments.is_some());
        assert_eq!(msg.attachments.as_ref().unwrap().len(), 1);

        let attachment = &msg.attachments.as_ref().unwrap()[0];
        assert_eq!(attachment.format.as_deref(), Some(ANONCREDS_PROOF_REQUEST));
    }

    #[test]
    fn test_roundtrip() {
        let proof_request = r#"{"name":"test","version":"1.0"}"#;
        let original = RequestPresentationMessage::new(proof_request.to_string())
            .with_comment("Verify identity".to_string());

        let msg = original.to_didcomm_message();
        let parsed = RequestPresentationMessage::from_didcomm_message(&msg).unwrap();

        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.comment, original.comment);
        assert_eq!(parsed.will_confirm, original.will_confirm);

        // The proof request JSON should be equivalent
        let original_val: serde_json::Value =
            serde_json::from_str(&original.proof_request_json).unwrap();
        let parsed_val: serde_json::Value =
            serde_json::from_str(&parsed.proof_request_json).unwrap();
        assert_eq!(original_val, parsed_val);
    }

    #[test]
    fn test_base64_decode() {
        let encoded = "SGVsbG8gV29ybGQ=";
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(decoded, b"Hello World");
    }
}
