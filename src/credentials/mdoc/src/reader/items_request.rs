//! ItemsRequest - Specifies which data elements the reader wants to receive

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Request for specific data elements from an mDoc
///
/// Maps namespaces to element identifiers with "intent to retain" flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemsRequest {
    /// Document type being requested
    #[serde(rename = "docType")]
    pub doc_type: String,

    /// Requested elements per namespace
    /// Map: namespace -> (element_identifier -> intent_to_retain)
    #[serde(rename = "nameSpaces")]
    pub namespaces: HashMap<String, HashMap<String, bool>>,
}

impl ItemsRequest {
    /// Create a new ItemsRequest for a document type
    pub fn new(doc_type: impl Into<String>) -> Self {
        Self {
            doc_type: doc_type.into(),
            namespaces: HashMap::new(),
        }
    }

    /// Request specific elements from a namespace
    pub fn request_elements(
        mut self,
        namespace: impl Into<String>,
        elements: Vec<(String, bool)>, // (element_id, intent_to_retain)
    ) -> Self {
        let element_map: HashMap<String, bool> = elements.into_iter().collect();
        self.namespaces.insert(namespace.into(), element_map);
        self
    }

    /// Request all elements in a namespace (with no intent to retain)
    pub fn request_all_in_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespaces.insert(namespace.into(), HashMap::new());
        self
    }

    /// Add a single element request
    pub fn add_element(
        &mut self,
        namespace: impl Into<String>,
        element_id: impl Into<String>,
        intent_to_retain: bool,
    ) {
        let namespace = namespace.into();
        let element_id = element_id.into();

        self.namespaces
            .entry(namespace)
            .or_default()
            .insert(element_id, intent_to_retain);
    }

    /// Encode to CBOR
    pub fn encode(&self) -> Result<Vec<u8>> {
        crate::cbor::encode(self)
    }

    /// Decode from CBOR
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        crate::cbor::decode(bytes)
    }

    /// Get all requested element identifiers for a namespace
    pub fn get_requested_elements(&self, namespace: &str) -> Option<Vec<&String>> {
        self.namespaces
            .get(namespace)
            .map(|elements| elements.keys().collect())
    }

    /// Check if an element is requested with intent to retain
    pub fn has_intent_to_retain(&self, namespace: &str, element_id: &str) -> bool {
        self.namespaces
            .get(namespace)
            .and_then(|elements| elements.get(element_id))
            .copied()
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_items_request_builder() {
        let request = ItemsRequest::new("org.iso.18013.5.1.mDL").request_elements(
            "org.iso.18013.5.1",
            vec![
                ("family_name".to_string(), false),
                ("given_name".to_string(), false),
                ("birth_date".to_string(), true),
            ],
        );

        assert_eq!(request.doc_type, "org.iso.18013.5.1.mDL");
        assert_eq!(request.namespaces.len(), 1);

        let elements = request.get_requested_elements("org.iso.18013.5.1").unwrap();
        assert_eq!(elements.len(), 3);

        assert!(!request.has_intent_to_retain("org.iso.18013.5.1", "family_name"));
        assert!(request.has_intent_to_retain("org.iso.18013.5.1", "birth_date"));
    }

    #[test]
    fn test_items_request_encode_decode() {
        let request = ItemsRequest::new("org.iso.18013.5.1.mDL").request_elements(
            "org.iso.18013.5.1",
            vec![("family_name".to_string(), false)],
        );

        let bytes = request.encode().unwrap();
        let decoded = ItemsRequest::decode(&bytes).unwrap();

        assert_eq!(decoded.doc_type, request.doc_type);
        assert_eq!(decoded.namespaces.len(), request.namespaces.len());
    }
}
