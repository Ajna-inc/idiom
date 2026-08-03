//! DID Resolution traits
//!
//! Defines the traits for DID resolution and registration.

use crate::core::{did::DID, document::DidDocument, record::DidRecord};
use async_trait::async_trait;

/// DID Resolution result
pub type ResolutionResult<T> = Result<T, ResolutionError>;

/// DID Resolution errors
#[derive(Debug, thiserror::Error)]
pub enum ResolutionError {
    #[error("DID not found: {0}")]
    NotFound(String),

    #[error("Unsupported DID method: {0}")]
    UnsupportedMethod(String),

    #[error("Invalid DID: {0}")]
    InvalidDid(String),

    #[error("Resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// DID Resolver trait
///
/// Implementations resolve DIDs to DID Documents.
#[async_trait]
pub trait DidResolver: Send + Sync {
    /// Get the DID method this resolver supports (e.g., "peer", "key", "web")
    fn method_name(&self) -> &str;

    /// Whether this resolver allows caching of resolved documents
    ///
    /// Deterministic methods (did:key, did:peer) return false.
    /// Remote-fetched methods (did:web) return true.
    fn allows_caching(&self) -> bool {
        false
    }

    /// Resolve a DID to a DID Document
    async fn resolve(&self, did: &DID) -> ResolutionResult<DidDocument>;
}

/// DID Creator/Registrar trait
///
/// Implementations can create new DIDs.
#[async_trait]
pub trait DidCreator: Send + Sync {
    /// Create a new DID with the given options
    async fn create(&self, options: CreateDidOptions) -> ResolutionResult<CreateDidResult>;
}

/// Options for creating a DID
#[derive(Debug, Clone, Default)]
pub struct CreateDidOptions {
    /// Key type to use (optional, method-specific default if not provided)
    pub key_type: Option<String>,

    /// Service endpoints to include
    pub service_endpoints: Vec<String>,

    /// Additional method-specific options
    pub options: std::collections::HashMap<String, serde_json::Value>,
}

/// Result of creating a DID
#[derive(Debug, Clone)]
pub struct CreateDidResult {
    /// The created DID
    pub did: DID,

    /// The DID Document
    pub did_document: DidDocument,

    /// The DID Record (for storage)
    pub did_record: DidRecord,

    /// Additional metadata
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

impl CreateDidOptions {
    /// Create new options
    pub fn new() -> Self {
        Self::default()
    }

    /// Set key type
    pub fn with_key_type(mut self, key_type: String) -> Self {
        self.key_type = Some(key_type);
        self
    }

    /// Add a service endpoint
    pub fn with_service_endpoint(mut self, endpoint: String) -> Self {
        self.service_endpoints.push(endpoint);
        self
    }

    /// Add a custom option
    pub fn with_option(mut self, key: String, value: serde_json::Value) -> Self {
        self.options.insert(key, value);
        self
    }
}

impl CreateDidResult {
    /// Create a new result
    pub fn new(did: DID, did_document: DidDocument, did_record: DidRecord) -> Self {
        Self {
            did,
            did_document,
            did_record,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }
}
