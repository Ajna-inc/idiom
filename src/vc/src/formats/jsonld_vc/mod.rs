pub mod bbs;
pub mod canonicalization;
/// JSON-LD Verifiable Credentials Implementation
/// Phase 2 of the credential implementation plan
pub mod context_loader;
pub mod data_integrity;
pub mod document_loader;
pub mod rdfc_canonicalize;
pub mod service;
pub mod signature_suites;

// Re-export main types
pub use bbs::{BbsBlsSignature2020Suite, BBS_BLS_SIGNATURE_2020, BBS_BLS_SIGNATURE_PROOF_2020};
pub use canonicalization::{canonicalize, CanonicalizeOptions};
pub use context_loader::ContextLoader;
pub use data_integrity::{
    data_integrity_hash_data, decode_multibase_base58_btc, did_web_to_document_url,
    ed25519_pubkey_from_multikey, resolve_did_web_key, verify_data_integrity_proof,
    DiVerificationOutcome,
};
pub use document_loader::{DocumentLoader, RemoteDocument};
pub use service::JsonLdVcService;
pub use signature_suites::{
    Ed25519Signature2018Suite, Ed25519Signature2020Suite, ProofOptions, ProofPurpose,
    SignatureSuite,
};
