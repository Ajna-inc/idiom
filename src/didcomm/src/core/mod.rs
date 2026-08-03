//! # DIDComm Core
//!
//! Core DIDComm messaging functionality including message types, envelope services,
//! and integration with DID resolution.
//!
//! ## Overview
//!
//! This crate provides the foundational types and services for DIDComm v2 messaging:
//!
//! - **Message types**: `Message`, `Thread`, `Attachment` for DIDComm messages
//! - **Envelope services**: Pack/unpack messages with encryption and signing
//! - **DID resolution**: Integration with DID documents for DIDComm
//!
//! ## Example
//!
//! ```rust,no_run
//! use didcomm::core::{Message, MessageBuilder};
//!
//! // Create a basic message
//! let msg = Message::builder("https://didcomm.org/basicmessage/2.0/message")
//!     .body(serde_json::json!({"content": "Hello!"}))
//!     .from("did:key:alice")
//!     .add_recipient("did:key:bob")
//!     .build();
//! ```

pub mod capability_detector;
pub mod error;
pub mod message_type;
pub mod models;
pub mod services;
pub mod version;

// Re-exports
pub use capability_detector::{CapabilityDetector, DIDCommCapabilities};
pub use error::{DidcommError, Result};
pub use message_type::{
    parse_didcomm_protocol_uri, parse_message_type, replace_legacy_did_sov_prefix,
    replace_legacy_did_sov_prefix_on_message, replace_new_didcomm_prefix_with_legacy_did_sov,
    replace_new_didcomm_prefix_with_legacy_did_sov_on_message,
    supports_incoming_didcomm_protocol_uri, supports_incoming_message_type, MessageTypeError,
    ParsedMessageType, ParsedProtocolUri, LEGACY_DID_SOV_PREFIX,
};
pub use models::{Attachment, AttachmentData, Message, MessageBuilder, Thread};
pub use services::{DidCommDocumentService, DidResolver, ServiceEndpoint};
pub use version::{DIDCommVersion, PackOptions};

// Native-only exports (require full tokio runtime)
#[cfg(feature = "native")]
pub use services::{EnvelopeService, UnpackMetadata};
