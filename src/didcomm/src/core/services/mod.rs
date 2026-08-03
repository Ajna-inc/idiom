mod did_document_service;
pub mod v1_compat;

pub use did_document_service::{DidCommDocumentService, DidResolver, ServiceEndpoint};
pub use v1_compat::{base58_to_multibase, multibase_to_base58};

// EnvelopeService requires native features (spawn_blocking, full tokio runtime)
#[cfg(feature = "native")]
mod envelope_service;
#[cfg(feature = "native")]
pub use envelope_service::{EnvelopeService, UnpackMetadata};
