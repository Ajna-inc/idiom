//! REAL ezkl verification through the PoE pipeline (feature `ezkl-cli`).
//!
//! Reads the actual flash-circuit artifacts via env vars (so no cross-repo paths
//! are hard-coded); skips cleanly if they aren't set:
//!   EZKL_BIN, EZKL_SRS, FLASH_VK, FLASH_SETTINGS, FLASH_PROOF
//!
//! Run:
//!   EZKL_BIN=~/.ezkl/ezkl EZKL_SRS=~/.ezkl/srs/kzg17.srs \
//!   FLASH_VK=.../vk_flash.bin FLASH_SETTINGS=.../settings_flash.json \
//!   FLASH_PROOF=/tmp/flash_proof.json \
//!   cargo test -p protocol_poe --features ezkl-cli --test ezkl_verify -- --nocapture

#![cfg(feature = "ezkl-cli")]

use std::sync::Arc;

use base64::Engine as _;
use serde_json::Map;
use sha2::{Digest, Sha256};

use protocol_poe::backends::EzklCliProofSystem;
use protocol_poe::{
    BindingContext, FlashLivenessProgram, ProgramRegistry, ProofArtifact, ProofResult,
    ProofSystemRegistry, ProofVerificationService, PublicOutputs, ZkProof, FLASH_CIRCUIT_ID,
    FLASH_PROGRAM_ID, FLASH_PUBLIC_SCHEMA,
};

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|s| !s.is_empty())
}

fn binding() -> BindingContext {
    BindingContext {
        nonce: format!("0x{}", "11".repeat(32)),
        context_hash: format!("0x{}", "22".repeat(32)),
        session_id: format!("0x{}", "33".repeat(16)),
    }
}

fn artifact(vk_hash: &str, proof_b64: String) -> ProofArtifact {
    ProofArtifact {
        program_id: FLASH_PROGRAM_ID.to_string(),
        result: ProofResult::Pass,
        public: PublicOutputs {
            binding: binding(),
            schema: FLASH_PUBLIC_SCHEMA.to_string(),
            outputs_hash: None,
            vk_hash: vk_hash.to_string(),
            timestamp: None,
            extra: Map::new(),
        },
        zk: ZkProof {
            scheme: "halo2-kzg".to_string(),
            circuit_id: FLASH_CIRCUIT_ID.to_string(),
            vk_hash: vk_hash.to_string(),
            proof_b64,
            metadata: None,
        },
        summary: None,
        evidence_refs: None,
    }
}

#[tokio::test]
async fn real_ezkl_verify_pass_and_tamper() {
    let (Some(bin), Some(srs), Some(vk), Some(settings), Some(proof_path)) = (
        env("EZKL_BIN"),
        env("EZKL_SRS"),
        env("FLASH_VK"),
        env("FLASH_SETTINGS"),
        env("FLASH_PROOF"),
    ) else {
        eprintln!("SKIP: set EZKL_BIN/EZKL_SRS/FLASH_VK/FLASH_SETTINGS/FLASH_PROOF to run");
        return;
    };

    let vk_bytes = std::fs::read(&vk).expect("read vk");
    let vk_hash = format!("0x{}", hex::encode(Sha256::digest(&vk_bytes)));
    let proof_bytes = std::fs::read(&proof_path).expect("read proof");
    let proof_b64 = base64::engine::general_purpose::URL_SAFE.encode(&proof_bytes);

    let mut reg = ProgramRegistry::new();
    reg.register(Arc::new(FlashLivenessProgram::new(vk_hash.clone())));
    let mut ps = ProofSystemRegistry::new();
    ps.register(Arc::new(EzklCliProofSystem::new(bin, srs).with_circuit(
        FLASH_CIRCUIT_ID,
        vk,
        settings,
    )));
    let svc = ProofVerificationService::default();

    // 1) real proof -> REAL ezkl verify -> PASS
    let art = artifact(&vk_hash, proof_b64);
    let res = svc
        .verify(&art, &binding(), &reg, &ps, "did:example:verifier")
        .await
        .expect("real proof should verify");
    assert!(res.verified);
    println!(
        "REAL ezkl verify: PASS, receipt {}",
        res.receipt.unwrap().receipt_id
    );

    // 2) tamper the proof bytes -> ezkl rejects -> invalid_proof
    let mut bad = proof_bytes.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x01;
    let art_bad = artifact(
        &vk_hash,
        base64::engine::general_purpose::URL_SAFE.encode(&bad),
    );
    let err = svc
        .verify(&art_bad, &binding(), &reg, &ps, "did:example:verifier")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_proof");
    println!("tampered proof: correctly rejected ({})", err.code());
}
