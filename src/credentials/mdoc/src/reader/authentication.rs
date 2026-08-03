//! Reader Authentication - Proves reader is authorized to request data

use crate::cbor;
use crate::context::{MdocContext, SignatureAlgorithm};
use crate::cose::{CoseKey, Sign1};
use crate::error::{MdocError, Result};
use crate::reader::ItemsRequest;
use crate::types::SessionTranscript;
use ciborium::value::Value;

/// ReaderAuthentication structure per ISO 18013-5
///
/// Structure that gets signed by the reader to prove authorization:
/// ["ReaderAuthentication", SessionTranscript, ItemsRequest]
#[derive(Debug, Clone)]
pub struct ReaderAuthentication {
    pub session_transcript: SessionTranscript,
    pub items_request: ItemsRequest,
}

impl ReaderAuthentication {
    /// Create a new ReaderAuthentication
    pub fn new(session_transcript: SessionTranscript, items_request: ItemsRequest) -> Self {
        Self {
            session_transcript,
            items_request,
        }
    }

    /// Encode to CBOR as per ISO 18013-5
    ///
    /// Creates: ["ReaderAuthentication", session_transcript_bytes, items_request_bytes]
    pub fn encode(&self) -> Result<Vec<u8>> {
        // Encode session transcript
        let session_transcript_bytes = cbor::encode(&self.session_transcript)?;

        // Encode items request
        let items_request_bytes = self.items_request.encode()?;

        // Create the structure array
        let structure = Value::Array(vec![
            Value::Text("ReaderAuthentication".to_string()),
            Value::Bytes(session_transcript_bytes),
            Value::Bytes(items_request_bytes),
        ]);

        // Encode to CBOR
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&structure, &mut buf)?;
        Ok(buf)
    }

    /// Decode from CBOR
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        use std::io::Cursor;

        let value: Value = ciborium::de::from_reader(Cursor::new(bytes))?;

        if let Value::Array(arr) = value {
            if arr.len() != 3 {
                return Err(MdocError::Other(
                    "ReaderAuthentication must have 3 elements".to_string(),
                ));
            }

            // Check context string
            if let Value::Text(context) = &arr[0] {
                if context != "ReaderAuthentication" {
                    return Err(MdocError::Other(format!(
                        "Expected 'ReaderAuthentication', got '{}'",
                        context
                    )));
                }
            } else {
                return Err(MdocError::Other(
                    "First element must be 'ReaderAuthentication'".to_string(),
                ));
            }

            // Decode session transcript
            let session_transcript_bytes = if let Value::Bytes(bytes) = &arr[1] {
                bytes
            } else {
                return Err(MdocError::Other("Second element must be bytes".to_string()));
            };
            let session_transcript: SessionTranscript = cbor::decode(session_transcript_bytes)?;

            // Decode items request
            let items_request_bytes = if let Value::Bytes(bytes) = &arr[2] {
                bytes
            } else {
                return Err(MdocError::Other("Third element must be bytes".to_string()));
            };
            let items_request = ItemsRequest::decode(items_request_bytes)?;

            Ok(Self {
                session_transcript,
                items_request,
            })
        } else {
            Err(MdocError::Other(
                "ReaderAuthentication must be an array".to_string(),
            ))
        }
    }
}

/// ReaderAuth - COSE_Sign1 containing signed ReaderAuthentication
///
/// This is what gets included in the DocRequest to prove the reader
/// is authorized to request the data.
#[derive(Debug, Clone)]
pub struct ReaderAuth {
    pub sign1: Sign1,
}

impl ReaderAuth {
    /// Create a new ReaderAuth by signing the ReaderAuthentication structure
    pub async fn create(
        context: &dyn MdocContext,
        session_transcript: SessionTranscript,
        items_request: ItemsRequest,
        reader_key_id: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self> {
        // Create ReaderAuthentication structure
        let reader_auth = ReaderAuthentication::new(session_transcript, items_request);

        // Encode it
        let reader_auth_bytes = reader_auth.encode()?;

        // Sign with COSE_Sign1
        let sign1 = Sign1::builder()
            .payload(reader_auth_bytes)
            .algorithm(algorithm)
            .build()?;

        let signed = sign1.sign(context, reader_key_id).await?;

        Ok(Self { sign1: signed })
    }

    /// Validate the ReaderAuth signature
    pub async fn validate(
        &self,
        context: &dyn MdocContext,
        reader_public_key: &CoseKey,
        expected_session_transcript: &SessionTranscript,
        expected_items_request: &ItemsRequest,
    ) -> Result<()> {
        // Verify signature first
        let is_valid = self.sign1.verify(context, reader_public_key).await?;
        if !is_valid {
            return Err(MdocError::InvalidSignature);
        }

        // Decode the payload
        let payload = self
            .sign1
            .payload()
            .ok_or_else(|| MdocError::IssuerAuthFailed {
                reason: "Missing ReaderAuthentication payload".to_string(),
            })?;

        let reader_auth = ReaderAuthentication::decode(payload)?;

        // Verify session transcript matches
        let expected_st_bytes = cbor::encode(expected_session_transcript)?;
        let actual_st_bytes = cbor::encode(&reader_auth.session_transcript)?;
        if expected_st_bytes != actual_st_bytes {
            return Err(MdocError::SessionTranscriptError(
                "Session transcript mismatch".to_string(),
            ));
        }

        // Verify items request matches
        let expected_ir_bytes = expected_items_request.encode()?;
        let actual_ir_bytes = reader_auth.items_request.encode()?;
        if expected_ir_bytes != actual_ir_bytes {
            return Err(MdocError::Other(
                "ItemsRequest mismatch in ReaderAuth".to_string(),
            ));
        }

        Ok(())
    }

    /// Encode to CBOR
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.sign1.encode()
    }

    /// Decode from CBOR
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let sign1 = Sign1::decode(bytes)?;
        Ok(Self { sign1 })
    }

    /// Get the embedded ReaderAuthentication
    pub fn get_reader_authentication(&self) -> Result<ReaderAuthentication> {
        let payload = self
            .sign1
            .payload()
            .ok_or_else(|| MdocError::IssuerAuthFailed {
                reason: "Missing payload".to_string(),
            })?;
        ReaderAuthentication::decode(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reader_authentication_encode_decode() {
        let session_transcript = SessionTranscript {
            device_engagement: None,
            e_reader_key: None,
            handover: vec![1, 2, 3],
        };

        let items_request = ItemsRequest::new("org.iso.18013.5.1.mDL").request_elements(
            "org.iso.18013.5.1",
            vec![("family_name".to_string(), false)],
        );

        let reader_auth = ReaderAuthentication::new(session_transcript, items_request);

        let bytes = reader_auth.encode().unwrap();
        let decoded = ReaderAuthentication::decode(&bytes).unwrap();

        assert_eq!(
            decoded.session_transcript.handover,
            reader_auth.session_transcript.handover
        );
        assert_eq!(
            decoded.items_request.doc_type,
            reader_auth.items_request.doc_type
        );
    }
}
