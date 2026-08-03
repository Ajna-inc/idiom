//! Program abstraction — Rust port of `programs/PoeProgram.ts`.
//!
//! A program bundles its metadata plus an optional executor (prover side) and
//! verifier (requester side). Register one program object instead of wiring
//! metadata/executor/verifier separately.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::models::{BindingContext, ProgramExecution, ProofArtifact, VerificationResult};

/// Registry metadata for a program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramMetadata {
    pub program_id: String,
    pub version: String,
    pub name: String,
    /// Allowed verifying-key hashes. Requester MUST reject others.
    pub allowed_vk_hashes: Vec<String>,
    /// Allowed program parameter hashes (optional pinning).
    #[serde(default)]
    pub allowed_params_hashes: Vec<String>,
    pub public_schema: String,
    #[serde(default)]
    pub supports_interactive: bool,
    /// ZK scheme this program's proofs use (e.g. "halo2-kzg").
    pub scheme: String,
    #[serde(default)]
    pub circuit_id: String,
}

/// Prover side: run the program and produce a proof artifact.
#[async_trait]
pub trait ProgramExecutor: Send + Sync {
    fn program_id(&self) -> &str;
    async fn execute(
        &self,
        execution: &ProgramExecution,
        binding: &BindingContext,
    ) -> Result<ProofArtifact>;
}

/// Requester side: verify a proof artifact against the expected binding.
#[async_trait]
pub trait ProofVerifier: Send + Sync {
    fn program_id(&self) -> &str;
    async fn verify(
        &self,
        artifact: &ProofArtifact,
        expected: &BindingContext,
    ) -> Result<VerificationResult>;
}

/// A registrable PoE program. Return `None` from `executor`/`verifier` for
/// prover-only or verifier-only deployments (mobile wallet = executor-only).
pub trait PoeProgram: Send + Sync {
    fn program_id(&self) -> &str;
    fn version(&self) -> &str;
    fn metadata(&self) -> ProgramMetadata;
    fn executor(&self) -> Option<Arc<dyn ProgramExecutor>> {
        None
    }
    fn verifier(&self) -> Option<Arc<dyn ProofVerifier>> {
        None
    }
}
