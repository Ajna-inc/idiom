/// Document Loader for JSON-LD processing
/// Handles loading remote documents and contexts
use serde_json::Value;
use std::sync::Arc;

use super::context_loader::ContextLoader;

/// Represents a remote document loaded for JSON-LD processing
#[derive(Debug, Clone)]
pub struct RemoteDocument {
    /// The context URL if this is a context document
    pub context_url: Option<String>,
    /// The actual document content
    pub document: Value,
    /// The document URL
    pub document_url: String,
}

/// Document loader for JSON-LD processing
pub struct DocumentLoader {
    /// Context loader for loading contexts
    context_loader: Arc<ContextLoader>,
}

impl DocumentLoader {
    /// Create a new document loader
    pub fn new(context_loader: Arc<ContextLoader>) -> Self {
        Self { context_loader }
    }

    /// Create a document loader with default context loader
    pub fn default() -> Self {
        Self {
            context_loader: Arc::new(ContextLoader::new()),
        }
    }

    /// Load a document by URL
    pub async fn load_document(
        &self,
        url: &str,
    ) -> Result<RemoteDocument, Box<dyn std::error::Error + Send + Sync>> {
        // Try to load as context first
        let document = self.context_loader.load_context(url).await?;

        Ok(RemoteDocument {
            context_url: Some(url.to_string()),
            document,
            document_url: url.to_string(),
        })
    }

    /// Load and expand contexts from a document
    pub async fn load_contexts(
        &self,
        document: &Value,
    ) -> Result<Vec<RemoteDocument>, Box<dyn std::error::Error + Send + Sync>> {
        let mut contexts = Vec::new();

        if let Some(context) = document.get("@context") {
            match context {
                Value::String(url) => {
                    let doc = self.load_document(url).await?;
                    contexts.push(doc);
                }
                Value::Array(arr) => {
                    // A `@context` array may mix remote URLs with inline context
                    // objects (both are valid per JSON-LD). The previous code only
                    // handled the string entries and silently dropped any inline
                    // objects, so a mixed array lost its inline contexts.
                    for item in arr {
                        match item {
                            Value::String(url) => {
                                let doc = self.load_document(url).await?;
                                contexts.push(doc);
                            }
                            Value::Object(_) => {
                                contexts.push(RemoteDocument {
                                    context_url: None,
                                    document: item.clone(),
                                    document_url: "inline".to_string(),
                                });
                            }
                            _ => {}
                        }
                    }
                }
                Value::Object(_) => {
                    // Inline context, create a document for it
                    contexts.push(RemoteDocument {
                        context_url: None,
                        document: context.clone(),
                        document_url: "inline".to_string(),
                    });
                }
                _ => {}
            }
        }

        Ok(contexts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_load_document() {
        let loader = DocumentLoader::default();

        // Give time for context loader to initialize
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let doc = loader
            .load_document("https://www.w3.org/2018/credentials/v1")
            .await
            .unwrap();

        assert_eq!(doc.document_url, "https://www.w3.org/2018/credentials/v1");
        assert!(doc.context_url.is_some());
        assert!(doc.document.is_object());
    }

    #[tokio::test]
    async fn test_load_contexts() {
        let loader = DocumentLoader::default();

        let document = json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                {
                    "custom": "https://example.com/custom#"
                }
            ],
            "type": "VerifiableCredential"
        });

        // Give time for context loader to initialize
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let contexts = loader.load_contexts(&document).await.unwrap();

        // Should have 2 contexts (one URL, one inline)
        assert_eq!(contexts.len(), 2);
        assert_eq!(
            contexts[0].document_url,
            "https://www.w3.org/2018/credentials/v1"
        );
        assert_eq!(contexts[1].document_url, "inline");
    }
}
