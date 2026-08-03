//! Native halo2 (IPA) backend for the Biometric Face Membership program.
//!
//! Wraps `poe-prover::membership::MembershipProver` (bytes-only PoE API) to
//! provide both sides:
//!   • prover   → [`build_membership_artifact`] proves `Poseidon(K) ∈ registry`
//!                bound to `{nonce, context_hash, session_id}`
//!   • verifier → [`FaceMembershipProofSystem`] implements [`ProofSystem`]
//!                (`halo2-ipa-membership`)
//!
//! Public block (`id.face.membership.v1/public@1`) carries `registry_root` and
//! `tag` in `public.extra`; the challenge binding is recomputed from
//! `public.binding` at verify time. `K` and `H` stay private.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{json, Map};

use crate::error::{PoeError, Result};
use crate::models::{BindingContext, ProofArtifact, ProofResult, PublicOutputs, ZkProof};
use crate::programs::{
    FACE_MEMBERSHIP_CIRCUIT_ID, FACE_MEMBERSHIP_PROGRAM_ID, FACE_MEMBERSHIP_PUBLIC_SCHEMA,
    FACE_MEMBERSHIP_SCHEME,
};
use crate::registry::ProofSystem;

use poe_prover::membership::MembershipProver;

/// Placeholder vk identifier until the canonical VK serialization is frozen.
/// Requesters pin this per `circuit_id`.
pub const FACE_MEMBERSHIP_VK: &str =
    "0x66616365006d656d6265727368697000000000000000000000000000000000";

fn hex_bytes(s: &str) -> Result<Vec<u8>> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(h).map_err(|e| PoeError::InvalidProof(format!("hex: {e}")))
}
fn hex32(s: &str) -> Result<[u8; 32]> {
    hex_bytes(s)?
        .try_into()
        .map_err(|_| PoeError::InvalidProof("expected 32 bytes".into()))
}
fn to_hex(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Prover side: build a PoE `ProofArtifact` for face membership.
/// `siblings`/`dirs` come from the local `Registry::path_bytes(leaf_index)`.
pub fn build_membership_artifact(
    prover: &MembershipProver,
    key: &[u8; 32],
    siblings: &[[u8; 32]],
    dirs: &[bool],
    binding: BindingContext,
) -> Result<ProofArtifact> {
    let nonce = hex_bytes(&binding.nonce)?;
    let ctx = hex_bytes(&binding.context_hash)?;
    let sid = hex_bytes(&binding.session_id)?;
    let (proof, root, tag) = prover.prove_poe(key, siblings, dirs, &nonce, &ctx, &sid);

    let mut extra = Map::new();
    extra.insert("registry_root".to_string(), json!(to_hex(&root)));
    extra.insert("tag".to_string(), json!(to_hex(&tag)));

    Ok(ProofArtifact {
        program_id: FACE_MEMBERSHIP_PROGRAM_ID.to_string(),
        result: ProofResult::Pass,
        public: PublicOutputs {
            binding,
            schema: FACE_MEMBERSHIP_PUBLIC_SCHEMA.to_string(),
            outputs_hash: None,
            vk_hash: FACE_MEMBERSHIP_VK.to_string(),
            timestamp: None,
            extra,
        },
        zk: ZkProof {
            scheme: FACE_MEMBERSHIP_SCHEME.to_string(),
            circuit_id: FACE_MEMBERSHIP_CIRCUIT_ID.to_string(),
            vk_hash: FACE_MEMBERSHIP_VK.to_string(),
            proof_b64: base64::engine::general_purpose::URL_SAFE.encode(&proof),
            metadata: None,
        },
        summary: None,
        evidence_refs: None,
    })
}

/// Verifier side: a `ProofSystem` that runs the halo2 IPA membership verifier.
/// NOTE: the Requester MUST separately confirm `registry_root` is a trusted root
/// (from a Registrar) — this checks the ZK proof + challenge binding only.
pub struct FaceMembershipProofSystem {
    prover: Arc<MembershipProver>,
}

impl FaceMembershipProofSystem {
    pub fn new() -> Self {
        Self {
            prover: Arc::new(MembershipProver::new()),
        }
    }
    pub fn prover(&self) -> Arc<MembershipProver> {
        self.prover.clone()
    }
}

impl Default for FaceMembershipProofSystem {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProofSystem for FaceMembershipProofSystem {
    fn scheme(&self) -> &str {
        FACE_MEMBERSHIP_SCHEME
    }

    async fn verify(&self, artifact: &ProofArtifact, proof: &[u8]) -> Result<bool> {
        let extra = &artifact.public.extra;
        let root = hex32(
            extra
                .get("registry_root")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PoeError::InvalidProof("missing registry_root".into()))?,
        )?;
        let tag = hex32(
            extra
                .get("tag")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PoeError::InvalidProof("missing tag".into()))?,
        )?;
        let b = &artifact.public.binding;
        let nonce = hex_bytes(&b.nonce)?;
        let ctx = hex_bytes(&b.context_hash)?;
        let sid = hex_bytes(&b.session_id)?;
        Ok(self
            .prover
            .verify_poe(proof, &root, &nonce, &ctx, &sid, &tag))
    }
}
