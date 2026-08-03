//! End-to-end PoE with the REAL native halo2 prover (feature `halo2-prove`):
//! prove liveness on-device-style → submit-poe → full requester pipeline → complete.

#![cfg(feature = "halo2-prove")]

use std::sync::Arc;

use protocol_poe::backends::halo2_ipa::{build_flash_artifact, Halo2IpaProofSystem, FLASH_IPA_VK};
use protocol_poe::{
    BindingContext, FlashLivenessProgram, ProgramRegistry, ProofSystemRegistry,
    ProofVerificationService,
};

fn binding(nonce: &str) -> BindingContext {
    BindingContext {
        nonce: nonce.to_string(),
        context_hash: format!("0x{}", "22".repeat(32)),
        session_id: format!("0x{}", "33".repeat(16)),
    }
}

#[tokio::test]
async fn real_halo2_liveness_poe_roundtrip() {
    let ps = Halo2IpaProofSystem::new();
    let prover = ps.prover();

    let nonce = format!("0x{}", "11".repeat(32));
    let bind = binding(&nonce);

    // Prover (wallet): prove score >= tau bound to the nonce -> submit-poe artifact.
    let artifact = build_flash_artifact(&prover, 9500, 9000, bind.clone()).expect("prove");
    assert_eq!(artifact.zk.scheme, "halo2-ipa");

    // Requester: registry + halo2 proof system + full verification pipeline.
    let mut reg = ProgramRegistry::new();
    reg.register(Arc::new(FlashLivenessProgram::new(FLASH_IPA_VK)));
    let mut psr = ProofSystemRegistry::new();
    psr.register(Arc::new(ps));
    let svc = ProofVerificationService::default();

    // 1) valid liveness proof -> REAL halo2 verify -> complete
    let res = svc
        .verify(&artifact, &bind, &reg, &psr, "did:example:verifier")
        .await
        .expect("valid liveness proof must verify");
    assert!(res.verified);
    println!(
        "REAL halo2 liveness PoE: verified, receipt {}",
        res.receipt.unwrap().receipt_id
    );

    // 2) replay: same proof, different issued nonce -> context_mismatch
    let err = svc
        .verify(
            &artifact,
            &binding(&format!("0x{}", "ff".repeat(32))),
            &reg,
            &psr,
            "did:v",
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "context_mismatch");
    println!("replay: rejected ({})", err.code());
}

#[tokio::test]
async fn failing_liveness_cannot_prove() {
    let ps = Halo2IpaProofSystem::new();
    // score < tau: no proof can be produced (fail-safe)
    let out = build_flash_artifact(
        &ps.prover(),
        8000,
        9000,
        binding(&format!("0x{}", "11".repeat(32))),
    );
    assert!(out.is_err());
}
