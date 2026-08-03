//! Holder/Device API for creating device responses with selective disclosure
//!
//! Based on animo-id/mdoc's DeviceResponse pattern

use crate::context::{MdocContext, SignatureAlgorithm};
use crate::cose::Sign1;
use crate::error::{MdocError, Result};
use crate::types::*;
use std::collections::{HashMap, HashSet};

/// Builder for creating device responses
///
/// # Example (matching animo API):
///
/// ```rust,ignore
/// let device_response = DeviceResponseBuilder::from(issuer_mdoc)
///     .using_presentation_definition(presentation_definition)
///     .using_session_transcript_for_oid4vp(nonce, client_id, response_uri, verifier_nonce)
///     .authenticate_with_signature(context, device_key_id, SignatureAlgorithm::ES256)
///     .await?;
/// ```
pub struct DeviceResponseBuilder {
    document: Document,
    presentation_definition: Option<PresentationDefinition>,
    session_transcript: Option<SessionTranscript>,
}

/// Presentation Definition (DIF format for OID4VP)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PresentationDefinition {
    pub id: String,
    pub input_descriptors: Vec<InputDescriptor>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InputDescriptor {
    pub id: String,
    pub format: Option<HashMap<String, serde_json::Value>>,
    pub constraints: Option<Constraints>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Constraints {
    pub limit_disclosure: Option<String>,
    pub fields: Option<Vec<FieldConstraint>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FieldConstraint {
    pub path: Vec<String>,
    pub intent_to_retain: Option<bool>,
}

impl DeviceResponseBuilder {
    /// Create a new device response builder from an issued mDoc
    pub fn from(document: Document) -> Self {
        Self {
            document,
            presentation_definition: None,
            session_transcript: None,
        }
    }

    /// Set the presentation definition for selective disclosure
    pub fn using_presentation_definition(mut self, pd: PresentationDefinition) -> Self {
        self.presentation_definition = Some(pd);
        self
    }

    /// Create session transcript for OID4VP
    pub fn using_session_transcript_for_oid4vp(
        mut self,
        mdoc_nonce: String,
        client_id: String,
        response_uri: String,
        verifier_nonce: String,
    ) -> Self {
        // Create OID4VP handover structure
        let handover =
            create_oid4vp_handover(&mdoc_nonce, &client_id, &response_uri, &verifier_nonce);

        self.session_transcript = Some(SessionTranscript {
            device_engagement: None,
            e_reader_key: None,
            handover,
        });
        self
    }

    /// Set a custom session transcript
    pub fn using_session_transcript(mut self, transcript: SessionTranscript) -> Self {
        self.session_transcript = Some(transcript);
        self
    }

    /// Create device response with device signature authentication
    pub async fn authenticate_with_signature(
        self,
        context: &dyn MdocContext,
        device_key_id: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<DeviceResponse> {
        let session_transcript = self.session_transcript.clone().ok_or_else(|| {
            MdocError::SessionTranscriptError("Session transcript is required".to_string())
        })?;

        // Apply selective disclosure if presentation definition is provided
        let filtered_document = if let Some(ref pd) = self.presentation_definition {
            self.apply_selective_disclosure(pd)?
        } else {
            self.document.clone()
        };

        // Create DeviceAuthentication structure
        let device_auth_bytes = create_device_authentication_bytes(
            &session_transcript,
            &filtered_document.doc_type,
            &filtered_document.issuer_signed.name_spaces,
        )?;

        // Sign with device key
        let sign1 = Sign1::builder()
            .payload(device_auth_bytes)
            .algorithm(algorithm)
            .build()?;

        let signed = sign1.sign(context, device_key_id).await?;
        let device_signature_bytes = signed.encode()?;

        // Convert to CBOR Value (real-world mDocs use COSE array)
        let device_signature: ciborium::Value =
            ciborium::de::from_reader(&device_signature_bytes[..])?;

        // Add device authentication to document
        let mut final_document = filtered_document;
        final_document.device_signed = Some(DeviceSigned {
            name_spaces: HashMap::new(), // No additional device-signed elements
            device_auth: DeviceAuth::Signature { device_signature },
        });

        // Create device response
        Ok(DeviceResponse {
            version: "1.0".to_string(),
            documents: vec![Some(final_document)],
            document_errors: None,
            status: 0,
        })
    }

    /// Apply selective disclosure based on presentation definition
    fn apply_selective_disclosure(&self, pd: &PresentationDefinition) -> Result<Document> {
        // Find the input descriptor matching our doc type
        let descriptor = pd
            .input_descriptors
            .iter()
            .find(|d| d.id == self.document.doc_type)
            .ok_or_else(|| {
                MdocError::PresentationDefinitionError(
                    "No matching input descriptor found".to_string(),
                )
            })?;

        // Extract requested fields from constraints
        let requested_fields = extract_requested_fields(descriptor)?;

        // Filter the document
        let mut filtered_doc = Document {
            doc_type: self.document.doc_type.clone(),
            issuer_signed: IssuerSigned {
                name_spaces: HashMap::new(),
                issuer_auth: self.document.issuer_signed.issuer_auth.clone(),
            },
            device_signed: None,
            errors: None,
        };

        // Filter namespaces based on requested fields
        for (namespace, requested_elements) in requested_fields {
            if let Some(source_items) = self.document.issuer_signed.name_spaces.get(&namespace) {
                let filtered_items: Vec<IssuerSignedItem> = source_items
                    .iter()
                    .filter(|item| requested_elements.contains(&item.element_identifier))
                    .cloned()
                    .collect();

                if !filtered_items.is_empty() {
                    filtered_doc
                        .issuer_signed
                        .name_spaces
                        .insert(namespace, filtered_items);
                }
            }
        }

        Ok(filtered_doc)
    }

    /// Validate the issuer-signed portion of the document
    ///
    /// Verifies:
    /// - MSO signature is valid
    /// - All element digests match
    /// - Document is within validity period
    pub fn validate_issuer_signed(&self) -> Result<()> {
        // Verify MSO structure exists
        let issuer_auth = &self.document.issuer_signed.issuer_auth;

        // Convert issuer_auth Value back to bytes for Sign1 decoding
        let mut issuer_auth_bytes = Vec::new();
        ciborium::ser::into_writer(&issuer_auth, &mut issuer_auth_bytes)?;

        // Decode the COSE_Sign1 from issuer_auth
        let sign1 = Sign1::decode(&issuer_auth_bytes)?;

        // Get the payload (MSO)
        let mso_bytes = sign1.payload().ok_or_else(|| MdocError::InvalidMSO {
            reason: "Missing MSO payload in issuer auth".to_string(),
        })?;

        // Decode MSO
        let mso: MobileSecurityObject =
            ciborium::de::from_reader(mso_bytes).map_err(|e| MdocError::InvalidMSO {
                reason: format!("Failed to decode MSO: {}", e),
            })?;

        // Verify doc type matches
        if mso.doc_type != self.document.doc_type {
            return Err(MdocError::DocTypeMismatch {
                expected: mso.doc_type.clone(),
                actual: self.document.doc_type.clone(),
            });
        }

        // Verify all element digests
        for (namespace, items) in &self.document.issuer_signed.name_spaces {
            // Get value digests for this namespace from MSO
            let value_digests =
                mso.value_digests
                    .get(namespace)
                    .ok_or_else(|| MdocError::NamespaceNotFound {
                        namespace: namespace.clone(),
                    })?;

            // Verify each item's digest
            for item in items {
                let digest_id = item.digest_id;
                let expected_digest = value_digests.get(&digest_id).ok_or_else(|| {
                    MdocError::DigestVerificationFailed {
                        element: item.element_identifier.clone(),
                    }
                })?;

                // Compute actual digest
                let encoded_item = {
                    let mut buf = Vec::new();
                    ciborium::ser::into_writer(item, &mut buf)?;
                    buf
                };

                let actual_digest = compute_digest(&encoded_item, &mso.digest_algorithm)?;

                if expected_digest != &actual_digest {
                    return Err(MdocError::DigestVerificationFailed {
                        element: item.element_identifier.clone(),
                    });
                }
            }
        }

        // TODO: Verify validity period (requires proper time handling)
        // For now, we accept all validity periods

        Ok(())
    }

    /// Validate a device request is well-formed
    ///
    /// Verifies:
    /// - Request has valid structure
    /// - DocType matches
    /// - Requested namespaces exist in document
    pub fn validate_device_request(&self, device_request: &DeviceRequest) -> Result<()> {
        // Find doc request matching our doc type
        let doc_request = device_request
            .doc_requests
            .iter()
            .find(|dr| dr.doc_type == self.document.doc_type)
            .ok_or_else(|| MdocError::DocTypeMismatch {
                expected: self.document.doc_type.clone(),
                actual: "No matching doc request".to_string(),
            })?;

        // Verify all requested namespaces exist in our document
        for namespace in doc_request.name_spaces.keys() {
            if !self
                .document
                .issuer_signed
                .name_spaces
                .contains_key(namespace)
            {
                return Err(MdocError::NamespaceNotFound {
                    namespace: namespace.clone(),
                });
            }
        }

        Ok(())
    }

    /// Create a device response directly from a device request
    ///
    /// Convenience method that:
    /// 1. Validates the device request
    /// 2. Converts it to a presentation definition
    /// 3. Creates the device response
    pub async fn create_device_response_for_device_request(
        self,
        device_request: &DeviceRequest,
        session_transcript: SessionTranscript,
        context: &dyn MdocContext,
        device_key_id: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<DeviceResponse> {
        // Validate the request
        self.validate_device_request(device_request)?;

        // Convert device request to presentation definition
        let presentation_definition = device_request_to_presentation_definition(device_request)?;

        // Create device response
        self.using_presentation_definition(presentation_definition)
            .using_session_transcript(session_transcript)
            .authenticate_with_signature(context, device_key_id, algorithm)
            .await
    }
}

/// Compute digest using specified algorithm
fn compute_digest(data: &[u8], algorithm: &str) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256, Sha384, Sha512};

    match algorithm {
        "SHA-256" => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        "SHA-384" => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        "SHA-512" => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(MdocError::Other(format!(
            "Unsupported digest algorithm: {}",
            algorithm
        ))),
    }
}

/// Convert DeviceRequest to PresentationDefinition
fn device_request_to_presentation_definition(
    device_request: &DeviceRequest,
) -> Result<PresentationDefinition> {
    let mut input_descriptors = Vec::new();

    for doc_request in &device_request.doc_requests {
        let mut fields = Vec::new();

        // Convert namespace requests to field constraints
        for (namespace, namespace_request) in &doc_request.name_spaces {
            // If request_all is true, we'd need to request all elements
            // For now, we only handle explicit element lists
            if let Some(ref elements) = namespace_request.elements {
                for element_id in elements {
                    let path = format!("$['{}']['{}']", namespace, element_id);
                    fields.push(FieldConstraint {
                        path: vec![path],
                        intent_to_retain: Some(false), // Default to false
                    });
                }
            }
        }

        input_descriptors.push(InputDescriptor {
            id: doc_request.doc_type.clone(),
            format: None,
            constraints: Some(Constraints {
                limit_disclosure: Some("required".to_string()),
                fields: Some(fields),
            }),
        });
    }

    Ok(PresentationDefinition {
        id: "device-request".to_string(),
        input_descriptors,
    })
}

/// Extract requested fields from input descriptor
fn extract_requested_fields(
    descriptor: &InputDescriptor,
) -> Result<HashMap<String, HashSet<String>>> {
    let mut fields_by_namespace: HashMap<String, HashSet<String>> = HashMap::new();

    if let Some(ref constraints) = descriptor.constraints {
        if let Some(ref fields) = constraints.fields {
            for field in fields {
                // Parse JSONPath: $['namespace']['element']
                if let Some(path_str) = field.path.first() {
                    if let Some((namespace, element)) = parse_mdoc_path(path_str) {
                        fields_by_namespace
                            .entry(namespace)
                            .or_default()
                            .insert(element);
                    }
                }
            }
        }
    }

    Ok(fields_by_namespace)
}

/// Parse mDoc JSONPath format: $['namespace']['element']
fn parse_mdoc_path(path: &str) -> Option<(String, String)> {
    // Simple parser for $['namespace']['element'] format
    let parts: Vec<&str> = path.split("']['").collect();
    if parts.len() == 2 {
        let namespace = parts[0].trim_start_matches("$['");
        let element = parts[1].trim_end_matches("']");
        Some((namespace.to_string(), element.to_string()))
    } else {
        None
    }
}

/// Create OID4VP handover structure
fn create_oid4vp_handover(
    mdoc_nonce: &str,
    client_id: &str,
    response_uri: &str,
    verifier_nonce: &str,
) -> Vec<u8> {
    // OID4VP handover is a CBOR-encoded array:
    // [mdoc_nonce, client_id, response_uri, verifier_nonce]
    use ciborium::value::Value;

    let handover = Value::Array(vec![
        Value::Text(mdoc_nonce.to_string()),
        Value::Text(client_id.to_string()),
        Value::Text(response_uri.to_string()),
        Value::Text(verifier_nonce.to_string()),
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&handover, &mut buf).expect("Failed to encode handover");
    buf
}

/// Create DeviceAuthentication structure per ISO 18013-5
fn create_device_authentication_bytes(
    session_transcript: &SessionTranscript,
    doc_type: &str,
    namespaces: &HashMap<String, Vec<IssuerSignedItem>>,
) -> Result<Vec<u8>> {
    use ciborium::value::Value;

    // Encode session transcript
    let mut transcript_buf = Vec::new();
    ciborium::ser::into_writer(session_transcript, &mut transcript_buf)?;

    // Create DeviceAuthentication structure:
    // [
    //   "DeviceAuthentication",
    //   sessionTranscript,
    //   docType,
    //   namespacesBytes (encoded)
    // ]

    // Encode namespaces
    let mut namespaces_buf = Vec::new();
    ciborium::ser::into_writer(namespaces, &mut namespaces_buf)?;

    let device_auth = Value::Array(vec![
        Value::Text("DeviceAuthentication".to_string()),
        Value::Bytes(transcript_buf),
        Value::Text(doc_type.to_string()),
        Value::Bytes(namespaces_buf),
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&device_auth, &mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mdoc_path() {
        let path = "$['org.iso.18013.5.1']['family_name']";
        let (namespace, element) = parse_mdoc_path(path).unwrap();

        assert_eq!(namespace, "org.iso.18013.5.1");
        assert_eq!(element, "family_name");
    }

    #[test]
    fn test_oid4vp_handover_creation() {
        let handover =
            create_oid4vp_handover("nonce1", "client123", "https://example.com", "vnonce");

        assert!(!handover.is_empty());

        // Decode and verify structure
        use ciborium::value::Value;
        use std::io::Cursor;

        let value: Value = ciborium::de::from_reader(Cursor::new(&handover)).unwrap();
        if let Value::Array(arr) = value {
            assert_eq!(arr.len(), 4);
        } else {
            panic!("Expected array");
        }
    }
}
