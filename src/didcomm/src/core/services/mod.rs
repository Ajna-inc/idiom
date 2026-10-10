mod did_document_service;
pub mod v1_compat;

pub use did_document_service::{DidCommDocumentService, DidResolver, ServiceEndpoint};
pub use v1_compat::{base58_to_multibase, multibase_to_base58};

// EnvelopeService requires native features (spawn_blocking, full tokio runtime)
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod envelope_service;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use envelope_service::{EnvelopeService, UnpackMetadata};
