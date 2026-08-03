//! Decode bytes from the WS into a [`FrameHeader`] + [`FrameBody`].
//!
//! Decoding is split into two halves so the mediator can route
//! unmolested frame bytes after only parsing the header:
//!
//! - [`decode_header`] reads the 38-byte plaintext header. Cheap.
//!   Used by the mediator to look up `routing_prefix`.
//! - [`decode_and_verify`] performs the AEAD-verify + body deserialize.
//!   Only the recipient (or a mediator playing recipient for
//!   DATA_FORWARD) needs this.

use crate::dcx::crypto::{aead_open, nonce_for_msg_id};
use crate::dcx::errors::FrameError;
use crate::dcx::frame::types::*;
use crate::dcx::frame::{FrameBody, FrameHeader, FrameType};

/// Parse the 38-byte plaintext header from the start of `bytes`.
///
/// Returns the parsed header plus a slice of the remaining wire bytes
/// (the nonce + ciphertext+tag) so callers can hand them to
/// [`decode_and_verify`] without re-slicing.
pub fn decode_header(bytes: &[u8]) -> Result<(FrameHeader, &[u8]), FrameError> {
    if bytes.len() > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge { got: bytes.len() });
    }
    if bytes.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
        return Err(FrameError::TooShort {
            got: bytes.len(),
            need: HEADER_LEN + NONCE_LEN + TAG_LEN,
        });
    }

    let frame_type = bytes[0];
    let version = bytes[1];
    if FrameType::from_u8(frame_type).is_none() {
        return Err(FrameError::UnknownType(frame_type));
    }
    if version != FRAME_VERSION {
        return Err(FrameError::UnsupportedVersion(version));
    }

    let mut channel_id = [0u8; 16];
    channel_id.copy_from_slice(&bytes[2..18]);
    let mut routing_prefix = [0u8; 16];
    routing_prefix.copy_from_slice(&bytes[18..34]);
    let mut msg_id_bytes = [0u8; 8];
    msg_id_bytes.copy_from_slice(&bytes[34..42]);
    let msg_id = u64::from_be_bytes(msg_id_bytes);

    let header = FrameHeader {
        frame_type,
        version,
        channel_id,
        routing_prefix,
        msg_id,
    };
    Ok((header, &bytes[HEADER_LEN..]))
}

/// Decrypt and deserialize the body of a frame, given the parsed
/// header and the (nonce + ciphertext+tag) tail returned by
/// [`decode_header`].
pub fn decode_and_verify(
    header: &FrameHeader,
    tail: &[u8],
    k_recv: &[u8; 32],
) -> Result<FrameBody, FrameError> {
    if tail.len() < NONCE_LEN + TAG_LEN {
        return Err(FrameError::TooShort {
            got: tail.len(),
            need: NONCE_LEN + TAG_LEN,
        });
    }

    let wire_nonce: [u8; 12] = tail[0..NONCE_LEN]
        .try_into()
        .expect("tail[0..12] has exactly 12 bytes");
    let expected_nonce = nonce_for_msg_id(header.msg_id);
    // Defense in depth: senders MUST use the deterministic nonce; reject
    // any frame whose wire nonce diverges.
    if wire_nonce != expected_nonce {
        return Err(FrameError::NonceMismatch);
    }

    let aad = header.encode_aad();
    let ciphertext_with_tag = &tail[NONCE_LEN..];
    let plaintext = aead_open(k_recv, &wire_nonce, &aad, ciphertext_with_tag)
        .map_err(|_| FrameError::AeadFailed)?;

    decode_body(header.frame_type, &plaintext)
}

/// One-shot: decode header AND verify body. Convenience wrapper for
/// callers that just want the final FrameBody.
pub fn decode_full(
    bytes: &[u8],
    k_recv: &[u8; 32],
) -> Result<(FrameHeader, FrameBody), FrameError> {
    let (header, tail) = decode_header(bytes)?;
    let body = decode_and_verify(&header, tail, k_recv)?;
    Ok((header, body))
}

/// Parse the plaintext body bytes (after AEAD has already verified them)
/// into the type-specific [`FrameBody`] variant.
pub fn decode_body(frame_type: u8, plaintext: &[u8]) -> Result<FrameBody, FrameError> {
    match FrameType::from_u8(frame_type) {
        Some(FrameType::Data) => decode_data_body(plaintext),
        Some(FrameType::DataForward) => decode_data_forward_body(plaintext),
        Some(FrameType::Ack) => decode_ack_body(plaintext),
        Some(FrameType::Ping) => decode_ping_body(plaintext),
        Some(FrameType::Pong) => decode_pong_body(plaintext),
        Some(FrameType::RotateNotify) => decode_rotate_notify_body(plaintext),
        Some(FrameType::ChannelClose) => decode_channel_close_body(plaintext),
        Some(FrameType::FlowWindow) => decode_flow_window_body(plaintext),
        Some(FrameType::Error) => decode_error_body(plaintext),
        Some(FrameType::ChannelConfirm) => decode_channel_confirm_body(plaintext),
        None => Err(FrameError::UnknownType(frame_type)),
    }
}

fn decode_data_body(pt: &[u8]) -> Result<FrameBody, FrameError> {
    if pt.len() < 4 {
        return Err(FrameError::MalformedPayload("data: too short".into()));
    }
    let payload_len = u16::from_be_bytes([pt[0], pt[1]]) as usize;
    if pt.len() < 2 + payload_len + 2 {
        return Err(FrameError::MalformedPayload(
            "data: declared payload_length exceeds plaintext".into(),
        ));
    }
    let payload_end = 2 + payload_len;
    let padding_len_bytes = [pt[payload_end], pt[payload_end + 1]];
    let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;
    let padding_start = payload_end + 2;
    if pt.len() < padding_start + padding_len {
        return Err(FrameError::MalformedPayload(
            "data: declared padding_length exceeds plaintext".into(),
        ));
    }
    Ok(FrameBody::Data {
        application_payload: pt[2..payload_end].to_vec(),
        padding: pt[padding_start..padding_start + padding_len].to_vec(),
    })
}

fn decode_data_forward_body(pt: &[u8]) -> Result<FrameBody, FrameError> {
    if pt.len() < 4 {
        return Err(FrameError::MalformedPayload(
            "data_forward: too short".into(),
        ));
    }
    let jwe_len = u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]) as usize;
    if pt.len() < 4 + jwe_len + 2 {
        return Err(FrameError::MalformedPayload(
            "data_forward: declared jwe length exceeds plaintext".into(),
        ));
    }
    let jwe_end = 4 + jwe_len;
    let endpoint_len = u16::from_be_bytes([pt[jwe_end], pt[jwe_end + 1]]) as usize;
    let endpoint_start = jwe_end + 2;
    if pt.len() < endpoint_start + endpoint_len + 2 {
        return Err(FrameError::MalformedPayload(
            "data_forward: declared endpoint length exceeds plaintext".into(),
        ));
    }
    let endpoint_end = endpoint_start + endpoint_len;
    let next_endpoint = std::str::from_utf8(&pt[endpoint_start..endpoint_end])
        .map_err(|e| FrameError::MalformedPayload(format!("next_endpoint not UTF-8: {e}")))?
        .to_string();
    let pad_len_bytes = [pt[endpoint_end], pt[endpoint_end + 1]];
    let padding_len = u16::from_be_bytes(pad_len_bytes) as usize;
    let padding_start = endpoint_end + 2;
    if pt.len() < padding_start + padding_len {
        return Err(FrameError::MalformedPayload(
            "data_forward: declared padding length exceeds plaintext".into(),
        ));
    }
    Ok(FrameBody::DataForward {
        inner_jwe: pt[4..jwe_end].to_vec(),
        next_endpoint,
        padding: pt[padding_start..padding_start + padding_len].to_vec(),
    })
}

fn decode_ack_body(pt: &[u8]) -> Result<FrameBody, FrameError> {
    if pt.len() != 9 {
        return Err(FrameError::MalformedPayload(format!(
            "ack: expected 9 bytes, got {}",
            pt.len()
        )));
    }
    let mut msg_id_bytes = [0u8; 8];
    msg_id_bytes.copy_from_slice(&pt[0..8]);
    Ok(FrameBody::Ack {
        acked_msg_id: u64::from_be_bytes(msg_id_bytes),
        status: pt[8],
    })
}

fn decode_ping_body(pt: &[u8]) -> Result<FrameBody, FrameError> {
    if pt.len() != 8 {
        return Err(FrameError::MalformedPayload(format!(
            "ping: expected 8 bytes, got {}",
            pt.len()
        )));
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(pt);
    Ok(FrameBody::Ping { nonce_data: n })
}

fn decode_pong_body(pt: &[u8]) -> Result<FrameBody, FrameError> {
    if pt.len() != 8 {
        return Err(FrameError::MalformedPayload(format!(
            "pong: expected 8 bytes, got {}",
            pt.len()
        )));
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(pt);
    Ok(FrameBody::Pong { nonce_data: n })
}

fn decode_rotate_notify_body(pt: &[u8]) -> Result<FrameBody, FrameError> {
    if pt.len() != 4 + 4 + 16 {
        return Err(FrameError::MalformedPayload(format!(
            "rotate_notify: expected 24 bytes, got {}",
            pt.len()
        )));
    }
    let old_gen = u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]);
    let new_gen = u32::from_be_bytes([pt[4], pt[5], pt[6], pt[7]]);
    let mut chan = [0u8; 16];
    chan.copy_from_slice(&pt[8..24]);
    Ok(FrameBody::RotateNotify {
        old_generation: old_gen,
        new_generation: new_gen,
        new_channel_id: chan,
    })
}

fn decode_channel_close_body(pt: &[u8]) -> Result<FrameBody, FrameError> {
    if pt.len() < 4 {
        return Err(FrameError::MalformedPayload(
            "channel_close: too short".into(),
        ));
    }
    let reason_code = u16::from_be_bytes([pt[0], pt[1]]);
    let msg_len = u16::from_be_bytes([pt[2], pt[3]]) as usize;
    if pt.len() < 4 + msg_len {
        return Err(FrameError::MalformedPayload(
            "channel_close: declared message length exceeds plaintext".into(),
        ));
    }
    let message = std::str::from_utf8(&pt[4..4 + msg_len])
        .map_err(|e| FrameError::MalformedPayload(format!("close message not UTF-8: {e}")))?
        .to_string();
    Ok(FrameBody::ChannelClose {
        reason_code,
        message,
    })
}

fn decode_flow_window_body(pt: &[u8]) -> Result<FrameBody, FrameError> {
    if pt.len() != 4 {
        return Err(FrameError::MalformedPayload(format!(
            "flow_window: expected 4 bytes, got {}",
            pt.len()
        )));
    }
    Ok(FrameBody::FlowWindow {
        window_credit: u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]),
    })
}

fn decode_error_body(pt: &[u8]) -> Result<FrameBody, FrameError> {
    if pt.len() < 4 {
        return Err(FrameError::MalformedPayload("error: too short".into()));
    }
    let error_code = u16::from_be_bytes([pt[0], pt[1]]);
    let msg_len = u16::from_be_bytes([pt[2], pt[3]]) as usize;
    if pt.len() < 4 + msg_len {
        return Err(FrameError::MalformedPayload(
            "error: declared message length exceeds plaintext".into(),
        ));
    }
    let message = std::str::from_utf8(&pt[4..4 + msg_len])
        .map_err(|e| FrameError::MalformedPayload(format!("error message not UTF-8: {e}")))?
        .to_string();
    Ok(FrameBody::Error {
        error_code,
        message,
    })
}

fn decode_channel_confirm_body(pt: &[u8]) -> Result<FrameBody, FrameError> {
    if pt.len() != 32 {
        return Err(FrameError::MalformedPayload(format!(
            "channel_confirm: expected 32 bytes, got {}",
            pt.len()
        )));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(pt);
    Ok(FrameBody::ChannelConfirm { confirm_hash: h })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcx::frame::encode::pack;

    fn test_header(frame_type: u8, msg_id: u64) -> FrameHeader {
        FrameHeader {
            frame_type,
            version: FRAME_VERSION,
            channel_id: [9u8; 16],
            routing_prefix: [3u8; 16],
            msg_id,
        }
    }

    #[test]
    fn data_roundtrip() {
        let key = [11u8; 32];
        let header = test_header(FRAME_TYPE_DATA, 100);
        let body = FrameBody::Data {
            application_payload: b"hello dcx".to_vec(),
            padding: vec![0xff; 7],
        };
        let bytes = pack(&header, &body, &key).unwrap();
        let (parsed_header, parsed_body) = decode_full(&bytes, &key).unwrap();
        assert_eq!(parsed_header, header);
        assert_eq!(parsed_body, body);
    }

    #[test]
    fn ack_roundtrip() {
        let key = [11u8; 32];
        let header = test_header(FRAME_TYPE_ACK, 42);
        let body = FrameBody::Ack {
            acked_msg_id: 41,
            status: 0,
        };
        let bytes = pack(&header, &body, &key).unwrap();
        let (h, b) = decode_full(&bytes, &key).unwrap();
        assert_eq!(h, header);
        assert_eq!(b, body);
    }

    #[test]
    fn channel_confirm_roundtrip() {
        let key = [11u8; 32];
        let header = test_header(FRAME_TYPE_CHANNEL_CONFIRM, 1);
        let body = FrameBody::ChannelConfirm {
            confirm_hash: [0x7Au8; 32],
        };
        let bytes = pack(&header, &body, &key).unwrap();
        let (h, b) = decode_full(&bytes, &key).unwrap();
        assert_eq!(h, header);
        assert_eq!(b, body);
    }

    #[test]
    fn rotate_notify_roundtrip() {
        let key = [11u8; 32];
        let header = test_header(FRAME_TYPE_ROTATE_NOTIFY, 7);
        let body = FrameBody::RotateNotify {
            old_generation: 0,
            new_generation: 1,
            new_channel_id: [0xABu8; 16],
        };
        let bytes = pack(&header, &body, &key).unwrap();
        let (h, b) = decode_full(&bytes, &key).unwrap();
        assert_eq!(h, header);
        assert_eq!(b, body);
    }

    #[test]
    fn rejects_unknown_type() {
        let mut bytes = vec![0xFFu8; HEADER_LEN + NONCE_LEN + TAG_LEN];
        bytes[1] = FRAME_VERSION;
        let err = decode_header(&bytes);
        assert!(matches!(err, Err(FrameError::UnknownType(0xFF))));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = vec![0u8; HEADER_LEN + NONCE_LEN + TAG_LEN];
        bytes[0] = FRAME_TYPE_DATA;
        bytes[1] = 0xFE;
        let err = decode_header(&bytes);
        assert!(matches!(err, Err(FrameError::UnsupportedVersion(0xFE))));
    }

    #[test]
    fn rejects_too_short() {
        let bytes = vec![FRAME_TYPE_DATA, FRAME_VERSION];
        let err = decode_header(&bytes);
        assert!(matches!(err, Err(FrameError::TooShort { .. })));
    }

    #[test]
    fn rejects_too_large() {
        let bytes = vec![0u8; MAX_FRAME_SIZE + 1];
        let err = decode_header(&bytes);
        assert!(matches!(err, Err(FrameError::TooLarge { .. })));
    }

    #[test]
    fn tampered_ciphertext_fails_aead() {
        let key = [11u8; 32];
        let header = test_header(FRAME_TYPE_DATA, 5);
        let body = FrameBody::Data {
            application_payload: b"x".to_vec(),
            padding: vec![],
        };
        let mut bytes = pack(&header, &body, &key).unwrap();
        // Flip a bit deep in the ciphertext.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let err = decode_full(&bytes, &key);
        assert!(matches!(err, Err(FrameError::AeadFailed)));
    }

    #[test]
    fn wrong_key_fails_aead() {
        let header = test_header(FRAME_TYPE_PING, 9);
        let body = FrameBody::Ping {
            nonce_data: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let bytes = pack(&header, &body, &[1u8; 32]).unwrap();
        let err = decode_full(&bytes, &[2u8; 32]);
        assert!(matches!(err, Err(FrameError::AeadFailed)));
    }

    #[test]
    fn nonce_mismatch_detected() {
        let key = [11u8; 32];
        let header = test_header(FRAME_TYPE_DATA, 5);
        let body = FrameBody::Data {
            application_payload: b"x".to_vec(),
            padding: vec![],
        };
        let mut bytes = pack(&header, &body, &key).unwrap();
        // Corrupt the on-wire nonce so it no longer matches msg_id.
        bytes[HEADER_LEN] ^= 0xFF;
        let err = decode_full(&bytes, &key);
        assert!(matches!(err, Err(FrameError::NonceMismatch)));
    }
}
