//! Real halo2-kzg proof verification via the `ezkl` verifier.
//!
//! This backend performs an ACTUAL cryptographic verification (no mock): it
//! feeds the proof + verifying key + settings + SRS to `ezkl verify`. It is the
//! requester-side (verifier) engine and is intended for desktop/server relying
//! parties. On-device (mobile) proving/verifying via the `ezkl` *library* —
//! which cross-compiles halo2 for iOS/Android — is the follow-up; this backend
//! is gated behind the `ezkl-cli` feature so mobile builds can exclude it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use async_trait::async_trait;

use crate::error::{PoeError, Result};
use crate::models::ProofArtifact;
use crate::registry::ProofSystem;

/// Per-circuit artifacts the verifier pins.
#[derive(Debug, Clone)]
pub struct CircuitPaths {
    pub vk: PathBuf,
    pub settings: PathBuf,
}

/// `ProofSystem` backed by the `ezkl` binary.
pub struct EzklCliProofSystem {
    ezkl_bin: PathBuf,
    srs: PathBuf,
    circuits: HashMap<String, CircuitPaths>,
}

impl EzklCliProofSystem {
    pub fn new(ezkl_bin: impl Into<PathBuf>, srs: impl Into<PathBuf>) -> Self {
        Self {
            ezkl_bin: ezkl_bin.into(),
            srs: srs.into(),
            circuits: HashMap::new(),
        }
    }

    /// Register the vk + settings for a `circuit_id`.
    pub fn with_circuit(
        mut self,
        circuit_id: impl Into<String>,
        vk: impl Into<PathBuf>,
        settings: impl Into<PathBuf>,
    ) -> Self {
        self.circuits.insert(
            circuit_id.into(),
            CircuitPaths {
                vk: vk.into(),
                settings: settings.into(),
            },
        );
        self
    }
}

#[async_trait]
impl ProofSystem for EzklCliProofSystem {
    fn scheme(&self) -> &str {
        "halo2-kzg"
    }

    async fn verify(&self, artifact: &ProofArtifact, proof: &[u8]) -> Result<bool> {
        let circuit_id = &artifact.zk.circuit_id;
        let paths = self.circuits.get(circuit_id).ok_or_else(|| {
            PoeError::InvalidProof(format!("no artifacts for circuit {circuit_id}"))
        })?;

        // `ezkl verify` reads the proof from a JSON file; the decoded proof
        // bytes ARE that JSON (proof_b64 = base64(proof.json)).
        let tmp = std::env::temp_dir().join(format!("poe_proof_{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&tmp, proof).map_err(|e| PoeError::Internal(format!("write proof: {e}")))?;

        let out = Command::new(&self.ezkl_bin)
            .arg("verify")
            .args(["--proof-path".as_ref(), tmp.as_os_str()])
            .args(["--settings-path".as_ref(), paths.settings.as_os_str()])
            .args(["--vk-path".as_ref(), paths.vk.as_os_str()])
            .args(["--srs-path".as_ref(), self.srs.as_os_str()])
            .output();

        let _ = std::fs::remove_file(&tmp);
        match out {
            Ok(o) => Ok(o.status.success()),
            Err(e) => Err(PoeError::Internal(format!("ezkl exec failed: {e}"))),
        }
    }
}
