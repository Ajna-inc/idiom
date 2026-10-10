mod did_comm_document_service;

pub use did_comm_document_service::{DidCommDocumentError, DidCommDocumentService};

// MessageDispatcher requires EnvelopeService which is native-only
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod dispatcher;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use dispatcher::MessageDispatcher;
