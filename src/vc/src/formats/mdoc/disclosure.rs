//! Selective disclosure structures for mDoc
//!
//! Handles device requests and responses for selective disclosure

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::types::{IssuerSignedItem, MDoc};

/// Device request for selective disclosure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRequest {
    /// Version of the request format
    pub version: String,

    /// Document requests (one per doc type)
    pub doc_requests: Vec<DocRequest>,
}

/// Request for a specific document type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocRequest {
    /// Document type being requested
    pub doc_type: String,

    /// Namespaces with requested data elements
    pub namespaces: HashMap<String, NamespaceRequest>,

    /// Request info (optional metadata)
    pub request_info: Option<serde_json::Value>,
}

/// Request for elements within a namespace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceRequest {
    /// Specific data elements requested
    pub data_elements: Vec<String>,

    /// Whether all elements are requested
    #[serde(default)]
    pub request_all: bool,
}

/// Device response containing disclosed credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceResponse {
    /// Version of the response format
    pub version: String,

    /// Documents (one per doc type)
    pub documents: Vec<MDoc>,

    /// Document errors (if any)
    pub document_errors: Option<Vec<DocumentError>>,

    /// Status (0 = OK)
    pub status: u8,
}

/// Error for a specific document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentError {
    /// Document type
    pub doc_type: String,

    /// Error code
    pub error_code: u32,

    /// Error message
    pub error_message: String,
}

/// Disclosure request builder
pub struct DisclosureRequest {
    doc_type: String,
    namespaces: HashMap<String, Vec<String>>,
}

impl DisclosureRequest {
    /// Create new disclosure request for a doc type
    pub fn new(doc_type: String) -> Self {
        Self {
            doc_type,
            namespaces: HashMap::new(),
        }
    }

    /// Request specific elements from a namespace
    pub fn request_elements(mut self, namespace: String, elements: Vec<String>) -> Self {
        self.namespaces.insert(namespace, elements);
        self
    }

    /// Request all elements from a namespace
    pub fn request_all_in_namespace(mut self, namespace: String) -> Self {
        self.namespaces.insert(namespace, vec![]);
        self
    }

    /// Build the DocRequest
    pub fn build(self) -> DocRequest {
        let mut namespaces = HashMap::new();

        for (ns, elements) in self.namespaces {
            let request_all = elements.is_empty();
            namespaces.insert(
                ns,
                NamespaceRequest {
                    data_elements: elements,
                    request_all,
                },
            );
        }

        DocRequest {
            doc_type: self.doc_type,
            namespaces,
            request_info: None,
        }
    }
}

/// Disclosure processor for filtering elements
pub struct DisclosureProcessor;

impl DisclosureProcessor {
    /// Filter an mDoc based on disclosure request
    pub fn filter_mdoc(mdoc: &MDoc, request: &DocRequest) -> Result<MDoc, DisclosureError> {
        // Verify doc type matches
        if mdoc.doc_type != request.doc_type {
            return Err(DisclosureError::DocTypeMismatch {
                expected: request.doc_type.clone(),
                actual: mdoc.doc_type.clone(),
            });
        }

        let mut filtered_mdoc = MDoc::new(mdoc.doc_type.clone());
        filtered_mdoc.version = mdoc.version.clone();
        filtered_mdoc.status = mdoc.status;

        // Filter each namespace
        for (namespace, ns_request) in &request.namespaces {
            if let Some(items) = mdoc.get_namespace_elements(namespace) {
                let filtered_items = Self::filter_namespace_items(items, ns_request)?;

                for item in filtered_items {
                    filtered_mdoc.add_issuer_signed_element(namespace.clone(), item);
                }
            }
        }

        // Copy issuer auth and device signed (if present)
        filtered_mdoc.issuer_signed.issuer_auth = mdoc.issuer_signed.issuer_auth.clone();
        filtered_mdoc.device_signed = mdoc.device_signed.clone();

        Ok(filtered_mdoc)
    }

    /// Filter items within a namespace
    fn filter_namespace_items(
        items: &[IssuerSignedItem],
        request: &NamespaceRequest,
    ) -> Result<Vec<IssuerSignedItem>, DisclosureError> {
        if request.request_all {
            // Return all items
            Ok(items.to_vec())
        } else {
            // Return only requested elements
            let mut filtered = Vec::new();

            for requested_element in &request.data_elements {
                if let Some(item) = items
                    .iter()
                    .find(|i| &i.element_identifier == requested_element)
                {
                    filtered.push(item.clone());
                }
            }

            Ok(filtered)
        }
    }

    /// Validate that all requested elements are available
    pub fn validate_request(mdoc: &MDoc, request: &DocRequest) -> Result<(), DisclosureError> {
        for (namespace, ns_request) in &request.namespaces {
            let items = mdoc
                .get_namespace_elements(namespace)
                .ok_or_else(|| DisclosureError::NamespaceNotFound(namespace.clone()))?;

            if !ns_request.request_all {
                for requested_element in &ns_request.data_elements {
                    let found = items
                        .iter()
                        .any(|i| &i.element_identifier == requested_element);
                    if !found {
                        return Err(DisclosureError::ElementNotFound {
                            namespace: namespace.clone(),
                            element: requested_element.clone(),
                        });
                    }
                }
            }
        }

        Ok(())
    }
}

/// Error types for disclosure processing
#[derive(Debug, thiserror::Error)]
pub enum DisclosureError {
    #[error("Doc type mismatch: expected {expected}, got {actual}")]
    DocTypeMismatch { expected: String, actual: String },

    #[error("Namespace not found: {0}")]
    NamespaceNotFound(String),

    #[error("Element not found: {element} in namespace {namespace}")]
    ElementNotFound { namespace: String, element: String },

    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

#[cfg(test)]
mod tests {
    use super::super::types::{mdl_elements, DOCTYPE_MDL, NAMESPACE_MDL};
    use super::*;

    #[test]
    fn test_disclosure_request_builder() {
        let request = DisclosureRequest::new(DOCTYPE_MDL.to_string())
            .request_elements(
                NAMESPACE_MDL.to_string(),
                vec![
                    mdl_elements::FAMILY_NAME.to_string(),
                    mdl_elements::GIVEN_NAME.to_string(),
                ],
            )
            .build();

        assert_eq!(request.doc_type, DOCTYPE_MDL);
        assert_eq!(request.namespaces.len(), 1);

        let ns_request = request.namespaces.get(NAMESPACE_MDL).unwrap();
        assert_eq!(ns_request.data_elements.len(), 2);
        assert!(!ns_request.request_all);
    }

    #[test]
    fn test_disclosure_request_all() {
        let request = DisclosureRequest::new(DOCTYPE_MDL.to_string())
            .request_all_in_namespace(NAMESPACE_MDL.to_string())
            .build();

        let ns_request = request.namespaces.get(NAMESPACE_MDL).unwrap();
        assert!(ns_request.request_all);
        assert_eq!(ns_request.data_elements.len(), 0);
    }

    #[test]
    fn test_filter_mdoc() {
        use super::super::types::IssuerSignedItem;

        let mut mdoc = MDoc::new(DOCTYPE_MDL.to_string());

        // Add some elements
        mdoc.add_issuer_signed_element(
            NAMESPACE_MDL.to_string(),
            IssuerSignedItem {
                digest_id: 0,
                random: vec![1, 2, 3],
                element_identifier: mdl_elements::FAMILY_NAME.to_string(),
                element_value: serde_json::json!("Doe"),
            },
        );

        mdoc.add_issuer_signed_element(
            NAMESPACE_MDL.to_string(),
            IssuerSignedItem {
                digest_id: 1,
                random: vec![4, 5, 6],
                element_identifier: mdl_elements::GIVEN_NAME.to_string(),
                element_value: serde_json::json!("Jane"),
            },
        );

        mdoc.add_issuer_signed_element(
            NAMESPACE_MDL.to_string(),
            IssuerSignedItem {
                digest_id: 2,
                random: vec![7, 8, 9],
                element_identifier: mdl_elements::BIRTH_DATE.to_string(),
                element_value: serde_json::json!("1990-01-15"),
            },
        );

        // Request only family_name and given_name
        let request = DisclosureRequest::new(DOCTYPE_MDL.to_string())
            .request_elements(
                NAMESPACE_MDL.to_string(),
                vec![
                    mdl_elements::FAMILY_NAME.to_string(),
                    mdl_elements::GIVEN_NAME.to_string(),
                ],
            )
            .build();

        // Filter
        let filtered = DisclosureProcessor::filter_mdoc(&mdoc, &request).unwrap();

        // Should only have 2 elements
        let filtered_items = filtered.get_namespace_elements(NAMESPACE_MDL).unwrap();
        assert_eq!(filtered_items.len(), 2);

        // Should not include birth_date
        assert!(!filtered_items
            .iter()
            .any(|i| i.element_identifier == mdl_elements::BIRTH_DATE));
    }

    #[test]
    fn test_validate_request_success() {
        use super::super::types::IssuerSignedItem;

        let mut mdoc = MDoc::new(DOCTYPE_MDL.to_string());

        mdoc.add_issuer_signed_element(
            NAMESPACE_MDL.to_string(),
            IssuerSignedItem {
                digest_id: 0,
                random: vec![1, 2, 3],
                element_identifier: mdl_elements::FAMILY_NAME.to_string(),
                element_value: serde_json::json!("Doe"),
            },
        );

        let request = DisclosureRequest::new(DOCTYPE_MDL.to_string())
            .request_elements(
                NAMESPACE_MDL.to_string(),
                vec![mdl_elements::FAMILY_NAME.to_string()],
            )
            .build();

        // Should succeed
        assert!(DisclosureProcessor::validate_request(&mdoc, &request).is_ok());
    }

    #[test]
    fn test_validate_request_element_not_found() {
        let mdoc = MDoc::new(DOCTYPE_MDL.to_string());

        let request = DisclosureRequest::new(DOCTYPE_MDL.to_string())
            .request_elements(
                NAMESPACE_MDL.to_string(),
                vec![mdl_elements::FAMILY_NAME.to_string()],
            )
            .build();

        // Should fail - element not in mdoc
        let result = DisclosureProcessor::validate_request(&mdoc, &request);
        assert!(result.is_err());
    }
}
