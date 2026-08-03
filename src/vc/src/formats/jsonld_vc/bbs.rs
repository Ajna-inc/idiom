//! BBS+ signature suite scaffolding.
//!
//! `BbsBlsSignature2020` is a JSON-LD Data Integrity proof type that supports
//! selective disclosure via derived proofs. The cryptographic core requires
//! BLS12-381 pairings; we deliberately gate the implementation behind the
//! `bbs` feature so the default build doesn't pull in heavy pairing crates.
//!
//! What this module provides today:
//! - the suite type identifier (`BbsBlsSignature2020`)
//! - a `BbsSignatureSuite` struct implementing `SignatureSuite` whose
//!   methods return a clear "not enabled" error unless the `bbs` feature is on
//!
//! When the `bbs` feature is enabled, callers can swap in a real implementation
//! that wires `bbs-plus`/`pairing` crates without changing the public API.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

use crate::core::Proof;
use agent_core::traits::WalletProvider;

use super::signature_suites::{ProofOptions, SignatureSuite};

/// Suite identifier for JSON-LD BBS+ Data Integrity proofs.
pub const BBS_BLS_SIGNATURE_2020: &str = "BbsBlsSignature2020";

/// Suite identifier for the selectively-disclosed derived proof produced by
/// `derive_proof()` (specified by W3C VC-DI-BBS).
pub const BBS_BLS_SIGNATURE_PROOF_2020: &str = "BbsBlsSignatureProof2020";

/// BBS+ signature suite — stub. The wallet must hold a BLS12-381 G2 key
/// addressable by `key_id`; the actual signing path is gated behind the
/// `bbs` feature.
pub struct BbsBlsSignature2020Suite {
    #[allow(dead_code)]
    wallet: Arc<dyn WalletProvider>,
    #[allow(dead_code)]
    key_id: String,
}

impl BbsBlsSignature2020Suite {
    pub fn new(wallet: Arc<dyn WalletProvider>, key_id: String) -> Self {
        Self { wallet, key_id }
    }
}

#[async_trait]
impl SignatureSuite for BbsBlsSignature2020Suite {
    fn suite_type(&self) -> &str {
        BBS_BLS_SIGNATURE_2020
    }

    #[cfg(not(feature = "bbs"))]
    async fn create_proof(
        &self,
        _document: &Value,
        _options: &ProofOptions,
    ) -> Result<Proof, Box<dyn std::error::Error + Send + Sync>> {
        Err("BBS+ signing requires the `bbs` feature to be enabled".into())
    }

    #[cfg(not(feature = "bbs"))]
    async fn verify_proof(
        &self,
        _document: &Value,
        _proof: &Proof,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Err("BBS+ verification requires the `bbs` feature to be enabled".into())
    }

    #[cfg(not(feature = "bbs"))]
    async fn create_proof_value(
        &self,
        _verify_data: &[u8],
        _key_id: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Err("BBS+ signing requires the `bbs` feature to be enabled".into())
    }

    // When the `bbs` feature is enabled, a downstream crate should provide
    // the real implementation by re-implementing these three methods.
    #[cfg(feature = "bbs")]
    async fn create_proof(
        &self,
        _document: &Value,
        _options: &ProofOptions,
    ) -> Result<Proof, Box<dyn std::error::Error + Send + Sync>> {
        unimplemented!("plug in your BBS+ implementation here")
    }

    #[cfg(feature = "bbs")]
    async fn verify_proof(
        &self,
        _document: &Value,
        _proof: &Proof,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        unimplemented!("plug in your BBS+ implementation here")
    }

    #[cfg(feature = "bbs")]
    async fn create_proof_value(
        &self,
        _verify_data: &[u8],
        _key_id: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        unimplemented!("plug in your BBS+ implementation here")
    }
}
