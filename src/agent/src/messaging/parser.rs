use crate::error::{AgentError, Result};
use didcomm::core::Message as DidcommMessage;
use serde_json::{Map, Value};

/// Parse a JSON message into a DIDComm Message struct
///
/// This function handles the conversion from Aries-style messages
/// (@id, @type, ~thread) to the DIDComm core format.
pub fn parse_message_to_didcomm(message: &Value) -> Result<DidcommMessage> {
    tracing::debug!("🔍 [parse_message_to_didcomm] Parsing message...");
    tracing::debug!(
        "  Input message: {}",
        serde_json::to_string_pretty(message).unwrap_or_default()
    );

    let mut didcomm_value = Map::new();

    if let Some(obj) = message.as_object() {
        tracing::debug!("  Has body field: {}", obj.contains_key("body"));
        // Map @id to id (also check for "id" field directly for DIDComm v1 compat)
        if let Some(id) = obj.get("@id").or_else(|| obj.get("id")) {
            didcomm_value.insert("id".to_string(), id.clone());
        }

        // Map @type to type (also check for "type" field directly for DIDComm v1 compat)
        if let Some(msg_type) = obj.get("@type").or_else(|| obj.get("type")) {
            didcomm_value.insert("type".to_string(), msg_type.clone());
        }

        // Map ~thread to thread (also check for "thread" field directly for DIDComm v1 compat)
        if let Some(thread) = obj.get("~thread").or_else(|| obj.get("thread")) {
            didcomm_value.insert("thread".to_string(), thread.clone());
        }

        // Extract "from" field from message envelope (critical for sender identification)
        if let Some(from) = obj.get("from") {
            didcomm_value.insert("from".to_string(), from.clone());
        }

        // Extract "to" field from message envelope
        if let Some(to) = obj.get("to") {
            didcomm_value.insert("to".to_string(), to.clone());
        }

        // Reconstruct v2 attachments from an Aries `<role>~attach` decorator
        // (offers~attach / requests~attach / credentials~attach /
        // presentations~attach / …) — the counterpart to `message_to_v1`, so
        // credential/proof payloads survive the v1 bridge.
        if let Some(attachments) = obj
            .get("attachments")
            .filter(|v| v.is_array())
            .cloned()
            .or_else(|| {
                obj.iter()
                    .find(|(k, v)| k.ends_with("~attach") && v.is_array())
                    .map(|(_, v)| v.clone())
            })
        {
            didcomm_value.insert("attachments".to_string(), attachments);
        }

        // Extract body from message:
        // - DIDComm v2 style: use message["body"] if present
        // - Legacy Aries style: use entire message for backwards compatibility
        let body = if let Some(body_field) = obj.get("body") {
            // DIDComm v2 style - body is a separate field
            tracing::debug!(
                "  Using DIDComm v2 body field: {}",
                serde_json::to_string_pretty(body_field).unwrap_or_default()
            );
            body_field.clone()
        } else {
            tracing::debug!("  Using Aries style (entire message as body)");
            // Legacy Aries style - entire message is the body
            // But ensure @type, @id, and ~thread fields are present for compatibility
            let mut body = message.clone();
            if let Some(body_obj) = body.as_object_mut() {
                // If we have "type" but not "@type", copy it over
                if body_obj.contains_key("type") && !body_obj.contains_key("@type") {
                    if let Some(type_val) = body_obj.get("type").cloned() {
                        body_obj.insert("@type".to_string(), type_val);
                    }
                }
                // If we have "id" but not "@id", copy it over
                if body_obj.contains_key("id") && !body_obj.contains_key("@id") {
                    if let Some(id_val) = body_obj.get("id").cloned() {
                        body_obj.insert("@id".to_string(), id_val);
                    }
                }
                // If we have "thread" but not "~thread", copy it over
                if body_obj.contains_key("~thread") {
                    // Already has ~thread, good
                } else if body_obj.contains_key("thread") && !body_obj.contains_key("~thread") {
                    if let Some(thread_val) = body_obj.get("thread").cloned() {
                        body_obj.insert("~thread".to_string(), thread_val);
                    }
                }
            }
            body
        };
        didcomm_value.insert("body".to_string(), body);
    }

    serde_json::from_value(Value::Object(didcomm_value))
        .map_err(|e| AgentError::Transport(format!("Failed to parse DIDComm message: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_aries_style_message() {
        // Legacy Aries-style message with @id, @type, ~thread decorators
        let message = json!({
            "@id": "test-123",
            "@type": "https://didcomm.org/test/1.0/test",
            "~thread": {
                "thid": "thread-123"
            },
            "data": "test-data"
        });

        let result = parse_message_to_didcomm(&message);
        assert!(result.is_ok());

        let didcomm_msg = result.unwrap();
        assert_eq!(didcomm_msg.id, "test-123");
        assert_eq!(didcomm_msg.msg_type, "https://didcomm.org/test/1.0/test");

        // For Aries style, entire message becomes body (with compatibility fields added)
        let body = didcomm_msg.body.as_object().unwrap();
        assert_eq!(body.get("data").unwrap(), "test-data");
        assert_eq!(body.get("@id").unwrap(), "test-123");
    }

    #[test]
    fn test_parse_didcomm_v2_with_body_field() {
        // DIDComm v2 style message with separate body field
        let message = json!({
            "id": "msg-456",
            "type": "https://ajna.network/blockchain/1.0/faucet/status",
            "body": {
                "address": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            },
            "from": "did:ajna:testuser",
            "to": ["did:ajna:validator"]
        });

        let result = parse_message_to_didcomm(&message);
        assert!(result.is_ok());

        let didcomm_msg = result.unwrap();
        assert_eq!(didcomm_msg.id, "msg-456");
        assert_eq!(
            didcomm_msg.msg_type,
            "https://ajna.network/blockchain/1.0/faucet/status"
        );

        // Body should be JUST the body field, not the entire message envelope
        let body = didcomm_msg.body.as_object().unwrap();
        assert_eq!(
            body.get("address").unwrap(),
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
        // Should NOT contain envelope fields
        assert!(body.get("from").is_none());
        assert!(body.get("to").is_none());
        assert!(body.get("id").is_none());
        assert!(body.get("type").is_none());
    }

    #[test]
    fn test_parse_faucet_request_roundtrip() {
        // Simulate what the client sends for faucet request
        let message = json!({
            "id": "faucet-req-001",
            "type": "https://ajna.network/blockchain/1.0/faucet/request",
            "body": {
                "recipient": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            },
            "from": "did:ajna:user123"
        });

        let result = parse_message_to_didcomm(&message);
        assert!(result.is_ok());

        let didcomm_msg = result.unwrap();

        // Verify body contains only the inner body content
        let body = didcomm_msg.body.as_object().unwrap();
        assert_eq!(
            body.get("recipient").unwrap(),
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
        assert!(
            body.get("from").is_none(),
            "Body should not contain 'from' from envelope"
        );
    }

    #[test]
    fn test_parse_mixed_format_with_id_and_body() {
        // Message with both DIDComm v1 style "id" and v2 style "body"
        let message = json!({
            "id": "test-mixed",
            "type": "https://example.com/test",
            "body": {
                "key": "value"
            }
        });

        let result = parse_message_to_didcomm(&message);
        assert!(result.is_ok());

        let didcomm_msg = result.unwrap();
        assert_eq!(didcomm_msg.id, "test-mixed");

        // Body should be extracted correctly
        let body = didcomm_msg.body.as_object().unwrap();
        assert_eq!(body.get("key").unwrap(), "value");
        assert!(body.get("id").is_none());
    }
}
