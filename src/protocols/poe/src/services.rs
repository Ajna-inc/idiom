//! PoE services — port of `services/`.
//!
//! `NonceService` (issue/track anti-replay nonces), `context_hash` binding
//! helper, and `ProofVerificationService` (the requester's 6-step pipeline:
//! expiry → registry → zk-verify → binding → policy → receipt).
//!
//! State here is in-memory; in the agent these back onto askar repositories
//! (see `protocol_workflow::repository`). That wiring is phase 2.

use std::collections::HashSet;
use std::sync::Mutex;

use base64::Engine as _;
use chrono::Utc;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{PoeError, Result};
use crate::models::{
    BindingContext, ExecutionReceipt, ProofArtifact, ProofResult, VerificationResult,
};
use crate::registry::{ProgramRegistry, ProofSystemRegistry};

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// SHA-256 context hash of an arbitrary serialized transaction context.
pub fn context_hash(context_bytes: &[u8]) -> String {
    hex0x(&Sha256::digest(context_bytes))
}

// --------------------------------------------------------------------------
#[derive(Default)]
pub struct NonceService {
    issued: Mutex<HashSet<String>>,
    used: Mutex<HashSet<String>>,
}

impl NonceService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generate_nonce(&self) -> String {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        let n = hex0x(&b);
        self.issued.lock().unwrap().insert(n.clone());
        n
    }

    pub fn generate_session_id(&self) -> String {
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        hex0x(&b)
    }

    /// Was this nonce issued by us and not yet consumed?
    pub fn is_valid(&self, nonce: &str) -> bool {
        let low = nonce.to_ascii_lowercase();
        self.issued
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.eq_ignore_ascii_case(nonce))
            && !self.used.lock().unwrap().contains(&low)
    }

    /// Consume a nonce after a successful verification (anti-replay).
    pub fn mark_used(&self, nonce: &str) {
        self.used.lock().unwrap().insert(nonce.to_ascii_lowercase());
    }
}

// --------------------------------------------------------------------------
/// Default cap on the decoded byte size of a single verification artifact.
const DEFAULT_MAX_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;

/// Requester-side verification pipeline.
pub struct ProofVerificationService {
    pub max_artifact_bytes: usize,
}

impl Default for ProofVerificationService {
    fn default() -> Self {
        Self {
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
        }
    }
}

impl ProofVerificationService {
    /// Full requester pipeline. Returns a `VerificationResult` on success or a
    /// `PoeError` whose `.code()` maps to the canonical problem-report code.
    pub async fn verify(
        &self,
        artifact: &ProofArtifact,
        expected: &BindingContext,
        registry: &ProgramRegistry,
        proof_systems: &ProofSystemRegistry,
        issuer_did: &str,
    ) -> Result<VerificationResult> {
        // 2. Registry: program known + vk_hash allowed.
        registry.check_vk(&artifact.program_id, &artifact.zk.vk_hash)?;

        // decode proof + size guard (`too_large`).
        let proof = base64::engine::general_purpose::URL_SAFE
            .decode(artifact.zk.proof_b64.as_bytes())
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(artifact.zk.proof_b64.as_bytes())
            })
            .map_err(|e| PoeError::InvalidProof(format!("bad base64: {e}")))?;
        if proof.len() > self.max_artifact_bytes {
            return Err(PoeError::TooLarge(proof.len()));
        }

        // 3. ZK verify via the registered proof system for this scheme.
        let system = proof_systems.get(&artifact.zk.scheme).ok_or_else(|| {
            PoeError::InvalidProof(format!("no backend for {}", artifact.zk.scheme))
        })?;
        let ok = system.verify(artifact, &proof).await?;
        if !ok {
            return Err(PoeError::InvalidProof("zk verification failed".into()));
        }

        // 4. Binding: the artifact's public binding MUST equal what we issued.
        if !artifact.public.binding.matches(expected) {
            return Err(PoeError::ContextMismatch);
        }

        // 5. Program policy (device attestation, geo-velocity, …) — phase 2 hook.

        // Only a passing result yields a positive verification.
        if artifact.result != ProofResult::Pass {
            return Err(PoeError::PolicyViolation("result != pass".into()));
        }

        // 6. Receipt.
        let now = Utc::now().to_rfc3339();
        let receipt = ExecutionReceipt {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            proof_hash: hex0x(&Sha256::digest(&proof)),
            issued_at: now.clone(),
            issuer_did: issuer_did.to_string(),
            session_id: artifact.public.binding.session_id.clone(),
            program_id: artifact.program_id.clone(),
            result: artifact.result,
            expires_at: None,
        };
        Ok(VerificationResult {
            verified: true,
            timestamp: now,
            verifier_did: Some(issuer_did.to_string()),
            errors: None,
            receipt: Some(receipt),
        })
    }
}
