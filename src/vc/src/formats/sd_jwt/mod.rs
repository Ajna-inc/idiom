pub mod compact;
/// SD-JWT (Selective Disclosure JWT) Implementation
///
/// This module implements SD-JWT according to the IETF draft specification.
/// SD-JWT allows issuers to create credentials where claims can be selectively
/// disclosed by the holder during presentation.
pub mod disclosure;
pub mod hasher;
pub mod holder;
pub mod issuer;
pub mod service;
pub mod types;
pub mod verifier;

// Re-export main types
pub use compact::CompactSdJwt;
pub use disclosure::{Disclosure, DisclosureFrame, DisclosureProcessor};
pub use hasher::SdJwtHasher;
pub use holder::SdJwtHolder;
pub use issuer::SdJwtIssuer;
pub use service::SdJwtService;
pub use types::{KeyBindingJwt, SdJwtClaims, SdJwtError, SdJwtVc};
pub use verifier::SdJwtVerifier;
