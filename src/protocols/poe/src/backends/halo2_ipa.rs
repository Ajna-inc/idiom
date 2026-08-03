//! Native halo2 (IPA) backend — the cross-platform mobile engine.
//!
//! Wraps the `poe-prover` crate (crates.io halo2, cross-compiles to iOS/Android)
//! to provide both sides of the flash-liveness program:
//!   • prover  → [`build_flash_artifact`] proves `score ≥ tau` bound to the nonce
//!   • verifier → [`Halo2IpaProofSystem`] implements [`ProofSystem`] (`halo2-ipa`)
//!
//! Unlike the ezkl proof (which embeds instances), halo2 IPA needs the public
//! inputs at verify time — pulled from `artifact.public.binding.nonce` and
//! `artifact.public.extra["tau"]`.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{json, Map};

use crate::error::{PoeError, Result};
use crate::models::{BindingContext, ProofArtifact, ProofResult, PublicOutputs, ZkProof};
use crate::programs::{FLASH_CIRCUIT_ID, FLASH_PROGRAM_ID, FLASH_PUBLIC_SCHEMA};
use crate::registry::ProofSystem;

use poe_prover::LivenessProver;

/// Fixed vk identifier for the IPA flash circuit (the circuit is versioned by id).
pub const FLASH_IPA_VK: &str = "0x68616c6f32697061666c617368763100000000000000000000000000000000";

fn parse_nonce(s: &str) -> Result<[u8; 32]> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    let v = hex::decode(h).map_err(|e| PoeError::InvalidProof(format!("nonce hex: {e}")))?;
    v.try_into()
        .map_err(|_| PoeError::InvalidProof("nonce must be 32 bytes".into()))
}

/// Prover side: run the flash program and build a PoE `ProofArtifact`.
/// `score`/`tau` are fixed-point integers (score is the private liveness logit).
pub fn build_flash_artifact(
    prover: &LivenessProver,
    score: u64,
    tau: u64,
    binding: BindingContext,
) -> Result<ProofArtifact> {
    let nonce = parse_nonce(&binding.nonce)?;
    let proof = prover
        .prove(score, tau, &nonce)
        .ok_or_else(|| PoeError::PolicyViolation("score < tau: liveness failed".into()))?;
    let mut extra = Map::new();
    extra.insert("tau".to_string(), json!(tau));
    Ok(ProofArtifact {
        program_id: FLASH_PROGRAM_ID.to_string(),
        result: ProofResult::Pass,
        public: PublicOutputs {
            binding,
            schema: FLASH_PUBLIC_SCHEMA.to_string(),
            outputs_hash: None,
            vk_hash: FLASH_IPA_VK.to_string(),
            timestamp: None,
            extra,
        },
        zk: ZkProof {
            scheme: "halo2-ipa".to_string(),
            circuit_id: FLASH_CIRCUIT_ID.to_string(),
            vk_hash: FLASH_IPA_VK.to_string(),
            proof_b64: base64::engine::general_purpose::URL_SAFE.encode(&proof),
            metadata: None,
        },
        summary: None,
        evidence_refs: None,
    })
}

/// Verifier side: a `ProofSystem` that runs the halo2 IPA verifier.
pub struct Halo2IpaProofSystem {
    prover: Arc<LivenessProver>,
}

impl Halo2IpaProofSystem {
    pub fn new() -> Self {
        Self {
            prover: Arc::new(LivenessProver::new()),
        }
    }
    /// Shared prover (params/vk are deterministic, so prove/verify agree).
    pub fn prover(&self) -> Arc<LivenessProver> {
        self.prover.clone()
    }
}

impl Default for Halo2IpaProofSystem {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProofSystem for Halo2IpaProofSystem {
    fn scheme(&self) -> &str {
        "halo2-ipa"
    }

    async fn verify(&self, artifact: &ProofArtifact, proof: &[u8]) -> Result<bool> {
        let tau = artifact
            .public
            .extra
            .get("tau")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| PoeError::InvalidProof("missing public tau".into()))?;
        let nonce = parse_nonce(&artifact.public.binding.nonce)?;
        Ok(self.prover.verify(proof, tau, &nonce))
    }
}
