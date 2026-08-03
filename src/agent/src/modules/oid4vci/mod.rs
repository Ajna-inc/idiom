//! OID4VCI — OpenID for Verifiable Credential Issuance
//!
//! Holder-side implementation for receiving credentials from OID4VCI issuers.
//! Supports standard formats (JWT, SD-JWT) and AnonCreds (CL signatures
//! with blinded link secret binding).

pub mod anoncreds;
pub mod deferred;
pub mod dpop;
pub mod error;
pub mod holder;
pub mod issuer;
pub mod key_attestation;
pub mod minter;
pub mod transport;
pub mod types;

pub use deferred::{
    DeferredCredentialAcknowledgement, DeferredCredentialOutcome, DeferredCredentialRequest,
};
pub use dpop::{build_dpop_proof, parse_dpop_proof, DPopClaims, DPopHeader, DPopSigner};
pub use error::{Oid4vciError, Result};
pub use holder::{Oid4vciHolderService, ProofBuilder};
pub use issuer::{
    Oid4vciCredentialMinter, Oid4vciIssuerConfig, Oid4vciIssuerService, TokenIssuance,
};
pub use key_attestation::{
    parse_key_attestation, KeyAttestationClaims, KeyStorage, UserAuthentication,
};
pub use minter::{ed25519_jwk, VcCredentialMinter, WalletJwtProofBuilder};
pub use types::*;
