//! Concrete PoE programs.
//!
//! `FlashLivenessProgram` = the AA-ZK active-flash liveness circuit
//! (`verid.liveness.flash.v1`, halo2-kzg). The requester's `nonce` becomes the
//! flash challenge seed; a live 3D face reflecting the random flash sequence is
//! proven without revealing the face. Metadata is filled from the compiled
//! circuit's `vk_hash`.
//!
//! The executor (native `ezkl` proving + the flash feature extractor) and the
//! halo2-kzg `ProofSystem` backend are wired in phase 2; this provides the
//! program identity + registry metadata the protocol needs today.

use crate::program::{PoeProgram, ProgramMetadata};

pub const FLASH_PROGRAM_ID: &str = "verid.liveness.flash.v1";
pub const FLASH_CIRCUIT_ID: &str = "flash-liveness-v1";
pub const FLASH_PUBLIC_SCHEMA: &str = "verid.liveness.flash.v1/public@1";

pub struct FlashLivenessProgram {
    /// sha256(vk_flash.bin), `0x`-hex — pins the compiled circuit's verifying key.
    pub vk_hash: String,
}

impl FlashLivenessProgram {
    pub fn new(vk_hash: impl Into<String>) -> Self {
        Self {
            vk_hash: vk_hash.into(),
        }
    }
}

impl PoeProgram for FlashLivenessProgram {
    fn program_id(&self) -> &str {
        FLASH_PROGRAM_ID
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn metadata(&self) -> ProgramMetadata {
        ProgramMetadata {
            program_id: FLASH_PROGRAM_ID.to_string(),
            version: "1.0.0".to_string(),
            name: "Active-Flash Liveness".to_string(),
            allowed_vk_hashes: vec![self.vk_hash.clone()],
            allowed_params_hashes: vec![],
            public_schema: FLASH_PUBLIC_SCHEMA.to_string(),
            supports_interactive: true, // the flash schedule is an interactive challenge
            scheme: "halo2-kzg".to_string(),
            circuit_id: FLASH_CIRCUIT_ID.to_string(),
        }
    }

    // executor()/verifier(): phase 2 — native ezkl proving + halo2-kzg backend.
}

// ---------------------------------------------------------------------------
// Biometric Face Membership — the privacy-preserving recognition standard.
// Profile: docs/identity/FACE_MEMBERSHIP_POE_PROGRAM.md (AA-ZK).
//
// Prove "a live, registered human authenticated for THIS context" — revealing
// neither the face, the key K, nor which registry entry the person is. The proof
// asserts: H=Poseidon(K), H ∈ registry (Merkle root), tag=Poseidon(K, challenge),
// with challenge = Poseidon(nonce, context_hash, session_id) (the PoE binding).
// Scheme `halo2-ipa-membership` (Pasta/IPA, mobile-verifiable).

pub const FACE_MEMBERSHIP_PROGRAM_ID: &str = "id.face.membership.v1";
pub const FACE_MEMBERSHIP_CIRCUIT_ID: &str = "face-membership-v1";
pub const FACE_MEMBERSHIP_PUBLIC_SCHEMA: &str = "id.face.membership.v1/public@1";
pub const FACE_MEMBERSHIP_SCHEME: &str = "halo2-ipa-membership";

pub struct FaceMembershipProgram {
    /// sha256 of the canonical MembershipCircuit verifying key, `0x`-hex.
    pub vk_hash: String,
}

impl FaceMembershipProgram {
    pub fn new(vk_hash: impl Into<String>) -> Self {
        Self {
            vk_hash: vk_hash.into(),
        }
    }
}

impl PoeProgram for FaceMembershipProgram {
    fn program_id(&self) -> &str {
        FACE_MEMBERSHIP_PROGRAM_ID
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn metadata(&self) -> ProgramMetadata {
        ProgramMetadata {
            program_id: FACE_MEMBERSHIP_PROGRAM_ID.to_string(),
            version: "1.0.0".to_string(),
            name: "Biometric Face Membership".to_string(),
            allowed_vk_hashes: vec![self.vk_hash.clone()],
            allowed_params_hashes: vec![],
            public_schema: FACE_MEMBERSHIP_PUBLIC_SCHEMA.to_string(),
            supports_interactive: false,
            scheme: FACE_MEMBERSHIP_SCHEME.to_string(),
            circuit_id: FACE_MEMBERSHIP_CIRCUIT_ID.to_string(),
        }
    }
}
