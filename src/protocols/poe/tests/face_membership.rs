//! End-to-end PoE face-membership over the protocol types: registry → prover
//! artifact → `ProofSystem` verify, incl. wrong-binding (replay) and non-member
//! rejection. Run: `cargo test --features halo2-prove --test face_membership`.
#![cfg(feature = "halo2-prove")]

use base64::Engine as _;
use protocol_poe::backends::face_membership::{
    build_membership_artifact, FaceMembershipProofSystem, FACE_MEMBERSHIP_VK,
};
use protocol_poe::models::BindingContext;
use protocol_poe::programs::{
    FaceMembershipProgram, FACE_MEMBERSHIP_PROGRAM_ID, FACE_MEMBERSHIP_SCHEME,
};
use protocol_poe::registry::{ProgramRegistry, ProofSystem};

use poe_prover::registry::Registry;

fn binding(nonce: &str) -> BindingContext {
    BindingContext {
        nonce: nonce.to_string(),
        context_hash: "0x".to_string() + &"cc".repeat(32),
        session_id: "0x".to_string() + &"55".repeat(16),
    }
}

async fn verify(
    sys: &FaceMembershipProofSystem,
    artifact: &protocol_poe::models::ProofArtifact,
) -> bool {
    let proof = base64::engine::general_purpose::URL_SAFE
        .decode(&artifact.zk.proof_b64)
        .unwrap();
    sys.verify(artifact, &proof).await.unwrap()
}

#[tokio::test]
async fn face_membership_poe_roundtrip() {
    let sys = FaceMembershipProofSystem::new();
    let prover = sys.prover();

    // --- registrar: two enrolled users publish Poseidon(K) to the registry ---
    let mut registry = Registry::new();
    let key_a = [11u8; 32];
    let key_b = [22u8; 32];
    let idx_a = registry.insert_key(&key_a);
    let _idx_b = registry.insert_key(&key_b);
    let root = registry.root_bytes();
    let (sib_a, dir_a) = registry.path_bytes(idx_a);

    let nonce = "0x".to_string() + &"ab".repeat(32);

    // --- prover: user A builds a PoE artifact bound to the challenge context ---
    let artifact =
        build_membership_artifact(&prover, &key_a, &sib_a, &dir_a, binding(&nonce)).unwrap();
    assert_eq!(artifact.program_id, FACE_MEMBERSHIP_PROGRAM_ID);
    assert_eq!(artifact.zk.scheme, FACE_MEMBERSHIP_SCHEME);
    assert_eq!(
        artifact.public.extra["registry_root"].as_str().unwrap(),
        format!("0x{}", hex::encode(root))
    );

    // --- verifier: valid proof against the trusted root verifies ---
    assert!(verify(&sys, &artifact).await, "genuine member must verify");

    // --- replay: same proof, different challenge nonce → binding fails ---
    let mut replay = artifact.clone();
    replay.public.binding = binding(&("0x".to_string() + &"ff".repeat(32)));
    assert!(!verify(&sys, &replay).await, "replayed challenge must fail");

    // --- non-member: a key not in the registry → root mismatch → reject ---
    let outsider = [99u8; 32];
    let bad =
        build_membership_artifact(&prover, &outsider, &sib_a, &dir_a, binding(&nonce)).unwrap();
    // verifier checks against the trusted registry root, not the prover's:
    let proof = base64::engine::general_purpose::URL_SAFE
        .decode(&bad.zk.proof_b64)
        .unwrap();
    let nonce_b = hex::decode(&nonce[2..]).unwrap();
    let ctx = vec![0xccu8; 32];
    let sid = vec![0x55u8; 16];
    let tag = hex::decode(&bad.public.extra["tag"].as_str().unwrap()[2..]).unwrap();
    let ok = prover.verify_poe(
        &proof,
        &root,
        &nonce_b,
        &ctx,
        &sid,
        &tag.try_into().unwrap(),
    );
    assert!(!ok, "non-member proof must fail against the trusted root");

    // --- registry metadata wires up ---
    let mut preg = ProgramRegistry::new();
    preg.register(std::sync::Arc::new(FaceMembershipProgram::new(
        FACE_MEMBERSHIP_VK,
    )));
    assert!(preg
        .check_vk(FACE_MEMBERSHIP_PROGRAM_ID, FACE_MEMBERSHIP_VK)
        .is_ok());
    assert!(preg.check_vk(FACE_MEMBERSHIP_PROGRAM_ID, "0xdead").is_err());
}
