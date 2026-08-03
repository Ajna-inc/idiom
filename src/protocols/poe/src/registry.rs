//! Program + proof-system registries — port of `registry/`.
//!
//! The requester's registry maps `program_id`/`circuit_id` → allowed verifying
//! keys and program parameters. Requesters MUST reject any `vk_hash` or params
//! not in the registry.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{PoeError, Result};
use crate::models::ProofArtifact;
use crate::program::{PoeProgram, ProgramMetadata};

#[derive(Default)]
pub struct ProgramRegistry {
    programs: HashMap<String, Arc<dyn PoeProgram>>,
    metadata: HashMap<String, ProgramMetadata>,
}

impl ProgramRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, program: Arc<dyn PoeProgram>) {
        let meta = program.metadata();
        self.metadata.insert(program.program_id().to_string(), meta);
        self.programs
            .insert(program.program_id().to_string(), program);
    }

    pub fn get(&self, program_id: &str) -> Option<&Arc<dyn PoeProgram>> {
        self.programs.get(program_id)
    }

    pub fn metadata(&self, program_id: &str) -> Option<&ProgramMetadata> {
        self.metadata.get(program_id)
    }

    /// Registry enforcement: program known and this vk_hash allowed for it.
    pub fn check_vk(&self, program_id: &str, vk_hash: &str) -> Result<()> {
        let meta = self
            .metadata
            .get(program_id)
            .ok_or_else(|| PoeError::ProgramNotSupported(program_id.to_string()))?;
        if meta
            .allowed_vk_hashes
            .iter()
            .any(|h| h.eq_ignore_ascii_case(vk_hash))
        {
            Ok(())
        } else {
            Err(PoeError::VkUnknown(vk_hash.to_string()))
        }
    }

    /// Optional params pinning.
    pub fn check_params(&self, program_id: &str, params_hash: &str) -> Result<()> {
        let meta = self
            .metadata
            .get(program_id)
            .ok_or_else(|| PoeError::ProgramNotSupported(program_id.to_string()))?;
        if meta.allowed_params_hashes.is_empty()
            || meta
                .allowed_params_hashes
                .iter()
                .any(|h| h.eq_ignore_ascii_case(params_hash))
        {
            Ok(())
        } else {
            Err(PoeError::ParamsUnknown(params_hash.to_string()))
        }
    }
}

/// Pluggable cryptographic proof-system backend (halo2-kzg, groth16, …).
/// A concrete halo2-kzg backend calling the `ezkl` crate is added in phase 2.
#[async_trait::async_trait]
pub trait ProofSystem: Send + Sync {
    fn scheme(&self) -> &str;
    /// Verify decoded proof bytes. The `artifact` carries the circuit id, vk hash,
    /// and public inputs (binding + program-specific `public.extra`) that some
    /// schemes (e.g. halo2 IPA) need passed alongside the proof.
    async fn verify(&self, artifact: &ProofArtifact, proof: &[u8]) -> Result<bool>;
}

#[derive(Default)]
pub struct ProofSystemRegistry {
    systems: HashMap<String, Arc<dyn ProofSystem>>,
}

impl ProofSystemRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&mut self, system: Arc<dyn ProofSystem>) {
        self.systems.insert(system.scheme().to_string(), system);
    }
    pub fn get(&self, scheme: &str) -> Option<&Arc<dyn ProofSystem>> {
        self.systems.get(scheme)
    }
}
