//! OpenID4VP (OpenID for Verifiable Presentations) implementation
//!
//! This module implements the holder (wallet) side of OpenID4VP, allowing
//! wallets to present mDocs to verifiers via QR codes or deep links.
//!
//! # Features
//! - Parse OpenID4VP authorization requests
//! - DCQL (DC API Query Language) support
//! - Session transcript calculation for OID4VP
//! - HTTP transport (direct_post)
//!
//! # Example
//! ```rust,ignore
//! use agent::modules::oid4vp::Oid4vpHolderService;
//!
//! let service = Oid4vpHolderService::new()?;
//!
//! // Resolve authorization request from QR code
//! let resolved = service.resolve_authorization_request(
//!     qr_code_content,
//!     available_documents,
//!     Some(origin),
//! ).await?;
//!
//! // Accept and respond
//! let redirect_uri = service.accept_authorization_request(
//!     &resolved,
//!     selected_credentials,
//!     &agent,
//! ).await?;
//! ```

pub mod anoncreds;
pub mod dcql;
pub mod error;
pub mod holder;
pub mod pex;
pub mod transport;
pub mod types;
pub mod uri;
pub mod verifier;
pub mod wallet_metadata;

pub use dcql::{DcqlQuery, DcqlService};
pub use error::Oid4vpError;
pub use holder::Oid4vpHolderService;
pub use pex::{PresentationDefinition, PresentationSubmission};
pub use types::*;
pub use verifier::{
    AuthorizationResponseParams, CreateRequestOptions, Oid4vpVerifierService,
    VerificationSessionRecord, VerificationSessionState,
};
pub use wallet_metadata::{VpFormat, WalletMetadata};
