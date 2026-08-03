/// Disclosure handling for SD-JWT
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

use super::hasher::SdJwtHasher;
use super::types::SdJwtError;

/// A single disclosure
#[derive(Debug, Clone)]
pub struct Disclosure {
    /// Salt for this disclosure
    pub salt: String,
    /// Claim name (for object properties) or None for array elements
    pub claim_name: Option<String>,
    /// Claim value
    pub claim_value: Value,
}

impl Disclosure {
    /// Create a new disclosure
    pub fn new(salt: String, claim_name: Option<String>, claim_value: Value) -> Self {
        Self {
            salt,
            claim_name,
            claim_value,
        }
    }

    /// Create disclosure for object property
    pub fn for_object_property(claim_name: &str, claim_value: Value) -> Self {
        Self {
            salt: SdJwtHasher::create_salt(),
            claim_name: Some(claim_name.to_string()),
            claim_value,
        }
    }

    /// Create disclosure for array element
    pub fn for_array_element(claim_value: Value) -> Self {
        Self {
            salt: SdJwtHasher::create_salt(),
            claim_name: None,
            claim_value,
        }
    }

    /// Encode disclosure to base64url string
    pub fn encode(&self) -> String {
        let disclosure_array = if let Some(name) = &self.claim_name {
            json!([self.salt, name, self.claim_value])
        } else {
            json!([self.salt, self.claim_value])
        };

        let json_str =
            serde_json::to_string(&disclosure_array).expect("Failed to serialize disclosure");

        URL_SAFE_NO_PAD.encode(json_str.as_bytes())
    }

    /// Decode disclosure from base64url string
    pub fn decode(encoded: &str) -> Result<Self, SdJwtError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| SdJwtError::InvalidDisclosure(format!("Base64 decode error: {}", e)))?;

        let disclosure_array: Value = serde_json::from_slice(&decoded)
            .map_err(|e| SdJwtError::InvalidDisclosure(format!("JSON parse error: {}", e)))?;

        let arr = disclosure_array
            .as_array()
            .ok_or_else(|| SdJwtError::InvalidDisclosure("Not an array".to_string()))?;

        if arr.len() < 2 || arr.len() > 3 {
            return Err(SdJwtError::InvalidDisclosure(format!(
                "Invalid disclosure array length: {}",
                arr.len()
            )));
        }

        let salt = arr[0]
            .as_str()
            .ok_or_else(|| SdJwtError::InvalidDisclosure("Salt must be string".to_string()))?
            .to_string();

        let (claim_name, claim_value) = if arr.len() == 3 {
            // Object property disclosure
            let name = arr[1]
                .as_str()
                .ok_or_else(|| {
                    SdJwtError::InvalidDisclosure("Claim name must be string".to_string())
                })?
                .to_string();
            (Some(name), arr[2].clone())
        } else {
            // Array element disclosure
            (None, arr[1].clone())
        };

        Ok(Self {
            salt,
            claim_name,
            claim_value,
        })
    }

    /// Get the hash of this disclosure
    pub fn hash(&self, hasher: &SdJwtHasher) -> String {
        hasher.hash_disclosure(&self.encode())
    }
}

/// Disclosure frame for specifying which claims to disclose
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DisclosureFrame {
    /// Boolean indicating whether to disclose
    Boolean(bool),
    /// Object with nested disclosure frames
    Object(HashMap<String, DisclosureFrame>),
    /// Array of disclosure frames
    Array(Vec<DisclosureFrame>),
}

impl DisclosureFrame {
    /// Create a frame that discloses everything
    pub fn disclose_all() -> Self {
        DisclosureFrame::Boolean(true)
    }

    /// Create a frame that discloses nothing
    pub fn disclose_none() -> Self {
        DisclosureFrame::Boolean(false)
    }

    /// Create a frame from a list of JSON paths
    pub fn from_paths(paths: &[Vec<String>]) -> Self {
        let mut root = HashMap::new();

        for path in paths {
            if path.is_empty() {
                continue;
            }

            Self::insert_path(&mut root, path);
        }

        DisclosureFrame::Object(root)
    }

    fn insert_path(map: &mut HashMap<String, DisclosureFrame>, path: &[String]) {
        if path.is_empty() {
            return;
        }

        let key = &path[0];
        if path.len() == 1 {
            map.insert(key.clone(), DisclosureFrame::Boolean(true));
        } else {
            let entry = map
                .entry(key.clone())
                .or_insert_with(|| DisclosureFrame::Object(HashMap::new()));

            if let DisclosureFrame::Object(nested) = entry {
                Self::insert_path(nested, &path[1..]);
            }
        }
    }

    /// Check if a path should be disclosed
    pub fn should_disclose(&self, path: &[String]) -> bool {
        match self {
            DisclosureFrame::Boolean(b) => *b,
            DisclosureFrame::Object(map) => {
                if path.is_empty() {
                    false
                } else {
                    map.get(&path[0])
                        .map(|frame| frame.should_disclose(&path[1..]))
                        .unwrap_or(false)
                }
            }
            DisclosureFrame::Array(_) => false, // Arrays handled differently
        }
    }
}

/// Processor for creating and applying disclosures
pub struct DisclosureProcessor {
    hasher: SdJwtHasher,
}

impl DisclosureProcessor {
    pub fn new(hasher: SdJwtHasher) -> Self {
        Self { hasher }
    }

    /// Process claims and create disclosures based on disclosure frame
    pub fn process_claims(
        &self,
        claims: &Value,
        frame: &DisclosureFrame,
    ) -> Result<(Value, Vec<Disclosure>), SdJwtError> {
        let mut disclosures = Vec::new();
        let processed = self.process_value(claims, frame, &mut disclosures)?;
        Ok((processed, disclosures))
    }

    fn process_value(
        &self,
        value: &Value,
        frame: &DisclosureFrame,
        disclosures: &mut Vec<Disclosure>,
    ) -> Result<Value, SdJwtError> {
        match (value, frame) {
            (_, DisclosureFrame::Boolean(false)) => {
                // Don't disclose - return placeholder
                Ok(Value::Null)
            }
            (_, DisclosureFrame::Boolean(true)) => {
                // Disclose everything - return as is
                Ok(value.clone())
            }
            (Value::Object(map), DisclosureFrame::Object(frame_map)) => {
                let mut result = serde_json::Map::new();
                let mut sd_digests = Vec::new();

                for (key, val) in map {
                    if let Some(subframe) = frame_map.get(key) {
                        match subframe {
                            DisclosureFrame::Boolean(true) => {
                                // Create disclosure for this property
                                let disclosure = Disclosure::for_object_property(key, val.clone());
                                let digest = disclosure.hash(&self.hasher);
                                sd_digests.push(digest);
                                disclosures.push(disclosure);
                            }
                            DisclosureFrame::Boolean(false) => {
                                // Skip this property
                            }
                            _ => {
                                // Process nested structure
                                let processed = self.process_value(val, subframe, disclosures)?;
                                result.insert(key.clone(), processed);
                            }
                        }
                    } else {
                        // No frame specified - include as is
                        result.insert(key.clone(), val.clone());
                    }
                }

                // Add _sd claim if we have disclosures
                if !sd_digests.is_empty() {
                    result.insert("_sd".to_string(), json!(sd_digests));
                    result.insert(
                        "_sd_alg".to_string(),
                        json!(self.hasher.algorithm_identifier()),
                    );
                }

                Ok(Value::Object(result))
            }
            (Value::Array(arr), DisclosureFrame::Array(frame_arr)) => {
                let mut result = Vec::new();

                for (i, val) in arr.iter().enumerate() {
                    if let Some(subframe) = frame_arr.get(i) {
                        match subframe {
                            DisclosureFrame::Boolean(true) => {
                                // Create disclosure for array element
                                let disclosure = Disclosure::for_array_element(val.clone());
                                let digest = json!({ "...": disclosure.hash(&self.hasher) });
                                result.push(digest);
                                disclosures.push(disclosure);
                            }
                            DisclosureFrame::Boolean(false) => {
                                // Skip this element
                            }
                            _ => {
                                // Process nested structure
                                let processed = self.process_value(val, subframe, disclosures)?;
                                result.push(processed);
                            }
                        }
                    } else {
                        // No frame specified - include as is
                        result.push(val.clone());
                    }
                }

                Ok(Value::Array(result))
            }
            _ => Ok(value.clone()),
        }
    }

    /// Apply disclosures to reveal selected claims
    pub fn apply_disclosures(
        &self,
        sd_jwt_claims: &Value,
        disclosures: &[String],
    ) -> Result<Value, SdJwtError> {
        let mut result = sd_jwt_claims.clone();

        // Decode all disclosures
        let decoded_disclosures: Vec<Disclosure> = disclosures
            .iter()
            .map(|d| Disclosure::decode(d))
            .collect::<Result<Vec<_>, _>>()?;

        // Apply each disclosure
        for disclosure in decoded_disclosures {
            self.apply_disclosure(&mut result, &disclosure)?;
        }

        // Remove _sd and _sd_alg claims
        if let Value::Object(ref mut map) = result {
            map.remove("_sd");
            map.remove("_sd_alg");
        }

        Ok(result)
    }

    fn apply_disclosure(
        &self,
        claims: &mut Value,
        disclosure: &Disclosure,
    ) -> Result<(), SdJwtError> {
        let digest = disclosure.hash(&self.hasher);

        if let Some(claim_name) = &disclosure.claim_name {
            // Object property disclosure
            if let Value::Object(ref mut map) = claims {
                // Check if digest is in _sd array
                if let Some(Value::Array(sd_array)) = map.get("_sd") {
                    if sd_array.iter().any(|v| v.as_str() == Some(&digest)) {
                        // Add the disclosed claim
                        map.insert(claim_name.clone(), disclosure.claim_value.clone());
                    }
                }
            }
        } else {
            // Array element disclosure - would need to find and replace
            // This is more complex and depends on the specific array structure
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disclosure_encode_decode() {
        let disclosure = Disclosure::for_object_property("name", json!("Alice"));
        let encoded = disclosure.encode();
        let decoded = Disclosure::decode(&encoded).unwrap();

        assert_eq!(decoded.claim_name, Some("name".to_string()));
        assert_eq!(decoded.claim_value, json!("Alice"));
    }

    #[test]
    fn test_disclosure_frame_from_paths() {
        let paths = vec![
            vec!["address".to_string(), "street".to_string()],
            vec!["name".to_string()],
        ];

        let frame = DisclosureFrame::from_paths(&paths);

        assert!(frame.should_disclose(&["address".to_string(), "street".to_string()]));
        assert!(frame.should_disclose(&["name".to_string()]));
        assert!(!frame.should_disclose(&["age".to_string()]));
    }
}
