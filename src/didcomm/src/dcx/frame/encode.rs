//! Encode a [`Frame`] body into the on-wire binary form.

use crate::dcx::crypto::{aead_seal, nonce_for_msg_id};
use crate::dcx::errors::FrameError;
use crate::dcx::frame::types::*;
use crate::dcx::frame::{FrameBody, FrameHeader};

/// Pack a frame body into bytes ready to send over the WS.
///
/// Steps:
///   1. Serialize the body type-specific plaintext (length-prefixed).
///   2. Derive the nonce from `header.msg_id`.
///   3. AEAD-encrypt the plaintext using the header as AAD.
///   4. Concatenate `header || nonce || ciphertext-with-tag`.
pub fn pack(
    header: &FrameHeader,
    body: &FrameBody,
    k_send: &[u8; 32],
) -> Result<Vec<u8>, FrameError> {
    let aad = header.encode_aad();
    let nonce = nonce_for_msg_id(header.msg_id);
    let plaintext = encode_body(body)?;

    let ct = aead_seal(k_send, &nonce, &aad, &plaintext).map_err(|_| FrameError::AeadFailed)?;

    let total_len = HEADER_LEN + NONCE_LEN + ct.len();
    if total_len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge { got: total_len });
    }

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&aad);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Serialize a [`FrameBody`] to the plaintext bytes that go inside the
/// AEAD ciphertext. All multi-byte fields are big-endian.
pub fn encode_body(body: &FrameBody) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::new();
    match body {
        FrameBody::Data {
            application_payload,
            padding,
        } => {
            if application_payload.len() > u16::MAX as usize {
                return Err(FrameError::MalformedPayload(
                    "application_payload exceeds u16::MAX".into(),
                ));
            }
            if padding.len() > u16::MAX as usize {
                return Err(FrameError::MalformedPayload(
                    "padding exceeds u16::MAX".into(),
                ));
            }
            out.extend_from_slice(&(application_payload.len() as u16).to_be_bytes());
            out.extend_from_slice(application_payload);
            out.extend_from_slice(&(padding.len() as u16).to_be_bytes());
            out.extend_from_slice(padding);
        }
        FrameBody::DataForward {
            inner_jwe,
            next_endpoint,
            padding,
        } => {
            if inner_jwe.len() > u32::MAX as usize {
                return Err(FrameError::MalformedPayload(
                    "inner_jwe exceeds u32::MAX".into(),
                ));
            }
            if next_endpoint.len() > u16::MAX as usize {
                return Err(FrameError::MalformedPayload(
                    "next_endpoint exceeds u16::MAX".into(),
                ));
            }
            out.extend_from_slice(&(inner_jwe.len() as u32).to_be_bytes());
            out.extend_from_slice(inner_jwe);
            out.extend_from_slice(&(next_endpoint.len() as u16).to_be_bytes());
            out.extend_from_slice(next_endpoint.as_bytes());
            out.extend_from_slice(&(padding.len() as u16).to_be_bytes());
            out.extend_from_slice(padding);
        }
        FrameBody::Ack {
            acked_msg_id,
            status,
        } => {
            out.extend_from_slice(&acked_msg_id.to_be_bytes());
            out.push(*status);
        }
        FrameBody::Ping { nonce_data } => out.extend_from_slice(nonce_data),
        FrameBody::Pong { nonce_data } => out.extend_from_slice(nonce_data),
        FrameBody::RotateNotify {
            old_generation,
            new_generation,
            new_channel_id,
        } => {
            out.extend_from_slice(&old_generation.to_be_bytes());
            out.extend_from_slice(&new_generation.to_be_bytes());
            out.extend_from_slice(new_channel_id);
        }
        FrameBody::ChannelClose {
            reason_code,
            message,
        } => {
            out.extend_from_slice(&reason_code.to_be_bytes());
            let msg = message.as_bytes();
            if msg.len() > u16::MAX as usize {
                return Err(FrameError::MalformedPayload(
                    "close message exceeds u16::MAX".into(),
                ));
            }
            out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
            out.extend_from_slice(msg);
        }
        FrameBody::FlowWindow { window_credit } => {
            out.extend_from_slice(&window_credit.to_be_bytes());
        }
        FrameBody::Error {
            error_code,
            message,
        } => {
            out.extend_from_slice(&error_code.to_be_bytes());
            let msg = message.as_bytes();
            if msg.len() > u16::MAX as usize {
                return Err(FrameError::MalformedPayload(
                    "error message exceeds u16::MAX".into(),
                ));
            }
            out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
            out.extend_from_slice(msg);
        }
        FrameBody::ChannelConfirm { confirm_hash } => {
            out.extend_from_slice(confirm_hash);
        }
    }
    Ok(out)
}
