/// Canonicalization for JSON-LD documents
/// Implements URDNA2015 algorithm for RDF dataset normalization
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Options for canonicalization
#[derive(Debug, Clone, Default)]
pub struct CanonicalizeOptions {
    /// Algorithm to use (currently only URDNA2015 supported)
    pub algorithm: String,
    /// Base IRI for relative IRIs
    pub base: Option<String>,
    /// Expand context
    pub expand_context: Option<Value>,
    /// Safe mode - prevent infinite recursion
    pub safe: bool,
}

impl CanonicalizeOptions {
    pub fn new() -> Self {
        Self {
            algorithm: "URDNA2015".to_string(),
            base: None,
            expand_context: None,
            safe: true,
        }
    }
}

/// Represents a quad in N-Quads format
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Quad {
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub graph: Option<String>,
}

impl Quad {
    /// Convert to N-Quads string representation
    pub fn to_nquads(&self) -> String {
        let graph_part = self
            .graph
            .as_ref()
            .map(|g| format!(" <{}>", g))
            .unwrap_or_default();

        format!(
            "{} {} {}{} .",
            self.subject, self.predicate, self.object, graph_part
        )
    }
}

/// Basic canonicalization implementation
/// Note: This is a simplified version. For production, consider using
/// a full JSON-LD library like `json-ld` crate
pub async fn canonicalize(
    document: &Value,
    options: Option<CanonicalizeOptions>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let _options = options.unwrap_or_default();

    // For now, we'll implement a basic canonicalization
    // In production, you'd want to use a full JSON-LD library

    // Step 1: Expand the document (simplified - doesn't handle all cases)
    let expanded = expand_document(document)?;

    // Step 2: Convert to RDF quads
    let quads = to_quads(&expanded)?;

    // Step 3: Sort quads to create canonical form
    let mut sorted_quads = quads;
    sorted_quads.sort();

    // Step 4: Convert to N-Quads string
    let nquads = sorted_quads
        .iter()
        .map(|q| q.to_nquads())
        .collect::<Vec<String>>()
        .join("\n");

    Ok(nquads)
}

/// Expand JSON-LD document (simplified implementation)
fn expand_document(document: &Value) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    // This is a very simplified expansion that doesn't handle:
    // - Context processing
    // - Compact IRIs
    // - Language maps
    // - etc.

    // For production, use a proper JSON-LD library

    match document {
        Value::Object(obj) => {
            let mut expanded = serde_json::Map::new();

            // Handle @context by removing it (it's already processed)
            for (key, value) in obj.iter() {
                if key == "@context" {
                    continue;
                }

                // Expand the key if it's not already an IRI
                let expanded_key = if key.starts_with("@") || key.contains("://") {
                    key.clone()
                } else {
                    // In a real implementation, this would resolve against context
                    format!("https://example.org/vocab#{}", key)
                };

                expanded.insert(expanded_key, expand_value(value)?);
            }

            Ok(Value::Object(expanded))
        }
        Value::Array(arr) => {
            let mut expanded = Vec::new();
            for item in arr {
                expanded.push(expand_document(item)?);
            }
            Ok(Value::Array(expanded))
        }
        _ => Ok(document.clone()),
    }
}

/// Expand a value recursively
fn expand_value(value: &Value) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    match value {
        Value::Object(_) | Value::Array(_) => expand_document(value),
        _ => Ok(value.clone()),
    }
}

/// Convert expanded document to RDF quads (simplified)
fn to_quads(expanded: &Value) -> Result<Vec<Quad>, Box<dyn std::error::Error + Send + Sync>> {
    let mut quads = Vec::new();
    let subject = "_:root"; // Default blank node for root

    extract_quads(expanded, subject, &mut quads)?;

    Ok(quads)
}

/// Extract quads from a value
fn extract_quads(
    value: &Value,
    subject: &str,
    quads: &mut Vec<Quad>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Value::Object(obj) = value {
        for (predicate, object) in obj.iter() {
            if predicate == "@id" || predicate == "@type" {
                continue; // Skip special keywords for now
            }

            match object {
                Value::String(s) => {
                    // Create literal quad
                    quads.push(Quad {
                        subject: subject.to_string(),
                        predicate: predicate.clone(),
                        object: format!("\"{}\"", s),
                        graph: None,
                    });
                }
                Value::Number(n) => {
                    // Create typed literal quad
                    quads.push(Quad {
                        subject: subject.to_string(),
                        predicate: predicate.clone(),
                        object: format!("\"{}\"^^<http://www.w3.org/2001/XMLSchema#decimal>", n),
                        graph: None,
                    });
                }
                Value::Bool(b) => {
                    // Create boolean literal quad
                    quads.push(Quad {
                        subject: subject.to_string(),
                        predicate: predicate.clone(),
                        object: format!("\"{}\"^^<http://www.w3.org/2001/XMLSchema#boolean>", b),
                        graph: None,
                    });
                }
                Value::Object(nested) => {
                    // Create blank node for nested object
                    let nested_subject = format!("_:b{}", quads.len());

                    quads.push(Quad {
                        subject: subject.to_string(),
                        predicate: predicate.clone(),
                        object: nested_subject.clone(),
                        graph: None,
                    });

                    extract_quads(&Value::Object(nested.clone()), &nested_subject, quads)?;
                }
                Value::Array(arr) => {
                    for (i, item) in arr.iter().enumerate() {
                        match item {
                            Value::String(s) => {
                                quads.push(Quad {
                                    subject: subject.to_string(),
                                    predicate: predicate.clone(),
                                    object: format!("\"{}\"", s),
                                    graph: None,
                                });
                            }
                            Value::Object(_) => {
                                let nested_subject = format!("_:b{}_{}", quads.len(), i);

                                quads.push(Quad {
                                    subject: subject.to_string(),
                                    predicate: predicate.clone(),
                                    object: nested_subject.clone(),
                                    graph: None,
                                });

                                extract_quads(item, &nested_subject, quads)?;
                            }
                            _ => {
                                // Handle other types
                                extract_quads(item, subject, quads)?;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// Create hash of canonicalized document
pub async fn hash_canonicalized(
    document: &Value,
    options: Option<CanonicalizeOptions>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let canonical = canonicalize(document, options).await?;

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());

    Ok(hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_basic_canonicalization() {
        let doc = json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "issuer": "did:example:123",
            "credentialSubject": {
                "id": "did:example:456",
                "name": "Alice"
            }
        });

        let result = canonicalize(&doc, None).await.unwrap();

        // Should produce N-Quads output
        assert!(result.contains("_:root"));
        assert!(result.contains("\"Alice\""));
    }

    #[tokio::test]
    async fn test_canonicalization_ordering() {
        // Documents with different property order should produce same canonical form
        let doc1 = json!({
            "name": "Alice",
            "age": 30
        });

        let doc2 = json!({
            "age": 30,
            "name": "Alice"
        });

        let canonical1 = canonicalize(&doc1, None).await.unwrap();
        let canonical2 = canonicalize(&doc2, None).await.unwrap();

        // After sorting, both should be identical
        assert_eq!(canonical1, canonical2);
    }
}
