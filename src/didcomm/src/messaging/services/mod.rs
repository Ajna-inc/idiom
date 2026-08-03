mod did_comm_document_service;

pub use did_comm_document_service::{DidCommDocumentError, DidCommDocumentService};

// MessageDispatcher requires EnvelopeService which is native-only
#[cfg(feature = "native")]
mod dispatcher;
#[cfg(feature = "native")]
pub use dispatcher::MessageDispatcher;
