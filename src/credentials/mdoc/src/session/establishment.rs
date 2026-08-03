//! Session establishment for proximity presentations

use crate::error::Result;
use crate::proximity::DeviceEngagement;
use serde::{Deserialize, Serialize};

/// SessionEstablishment contains the ephemeral keys and session parameters
///
/// Created during proximity presentation setup (after DeviceEngagement)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEstablishment {
    /// E-Reader key (verifier's ephemeral public key)
    #[serde(rename = "eReaderKey")]
    pub e_reader_key: crate::cose::CoseKey,

    /// Optional session data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
}

impl SessionEstablishment {
    /// Create new SessionEstablishment with reader's ephemeral key
    pub fn new(e_reader_key: crate::cose::CoseKey) -> Self {
        Self {
            e_reader_key,
            data: None,
        }
    }

    /// Builder pattern: add session data
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    /// Encode to CBOR bytes
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(self, &mut buffer)?;
        Ok(buffer)
    }

    /// Decode from CBOR bytes
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes).map_err(Into::into)
    }

    /// Create enhanced session transcript from device engagement and session establishment
    ///
    /// Enhanced session transcript includes:
    /// - DeviceEngagement bytes
    /// - EReaderKey bytes
    /// - Handover
    pub fn create_session_transcript(
        device_engagement: &DeviceEngagement,
        handover_bytes: Vec<u8>,
    ) -> Result<crate::types::SessionTranscript> {
        let device_engagement_bytes = device_engagement.to_cbor()?;

        Ok(crate::types::SessionTranscript {
            device_engagement: Some(device_engagement_bytes),
            e_reader_key: None,
            handover: handover_bytes,
        })
    }

    /// Create session transcript with this establishment
    pub fn to_session_transcript(
        &self,
        device_engagement: &DeviceEngagement,
        handover_bytes: Vec<u8>,
    ) -> Result<crate::types::SessionTranscript> {
        let device_engagement_bytes = device_engagement.to_cbor()?;
        let e_reader_key_bytes = {
            let mut buffer = Vec::new();
            ciborium::ser::into_writer(&self.e_reader_key, &mut buffer)?;
            buffer
        };

        Ok(crate::types::SessionTranscript {
            device_engagement: Some(device_engagement_bytes),
            e_reader_key: Some(e_reader_key_bytes),
            handover: handover_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_establishment_creation() {
        let reader_key = crate::cose::CoseKey::new(2); // EC2 key
        let establishment = SessionEstablishment::new(reader_key);

        assert!(establishment.data.is_none());
    }

    #[test]
    fn test_session_establishment_with_data() {
        let reader_key = crate::cose::CoseKey::new(2);
        let data = vec![1, 2, 3, 4];
        let establishment = SessionEstablishment::new(reader_key).with_data(data.clone());

        assert_eq!(establishment.data, Some(data));
    }

    #[test]
    fn test_session_establishment_cbor() {
        let reader_key = crate::cose::CoseKey::new(2);
        let establishment = SessionEstablishment::new(reader_key);

        let cbor = establishment.to_cbor().unwrap();
        let decoded = SessionEstablishment::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.e_reader_key.kty, 2);
    }
}
