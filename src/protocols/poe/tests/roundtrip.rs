//! PoE conformance round-trip in Rust — mirrors ml/scripts/poe_flash.py:
//! nominal PASS, replay/context_mismatch, unknown-VK, and JSON wire round-trip.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Map;

use protocol_poe::messages::SubmitPoeMessage;
use protocol_poe::registry::{ProofSystem, ProofSystemRegistry};
use protocol_poe::{
    BindingContext, FlashLivenessProgram, PoeError, ProgramRegistry, ProofArtifact, ProofResult,
    ProofVerificationService, PublicOutputs, Result, ZkProof,
};

const VK: &str = "0xddb52056b9f56d3500000000000000000000000000000000000000000000abcd";

/// Mock halo2-kzg backend: accepts any non-empty proof (real ezkl in phase 2).
struct MockHalo2;
#[async_trait]
impl ProofSystem for MockHalo2 {
    fn scheme(&self) -> &str {
        "halo2-kzg"
    }
    async fn verify(&self, _artifact: &ProofArtifact, proof: &[u8]) -> Result<bool> {
        Ok(!proof.is_empty())
    }
}

fn make_binding(nonce: &str) -> BindingContext {
    BindingContext {
        nonce: nonce.to_string(),
        context_hash: format!("0x{}", "22".repeat(32)),
        session_id: format!("0x{}", "33".repeat(16)),
    }
}

fn make_artifact(vk: &str, binding: BindingContext) -> ProofArtifact {
    ProofArtifact {
        program_id: protocol_poe::FLASH_PROGRAM_ID.to_string(),
        result: ProofResult::Pass,
        public: PublicOutputs {
            binding,
            schema: protocol_poe::FLASH_PUBLIC_SCHEMA.to_string(),
            outputs_hash: Some(format!("0x{}", "ab".repeat(32))),
            vk_hash: vk.to_string(),
            timestamp: None,
            extra: Map::new(),
        },
        zk: ZkProof {
            scheme: "halo2-kzg".to_string(),
            circuit_id: protocol_poe::FLASH_CIRCUIT_ID.to_string(),
            vk_hash: vk.to_string(),
            // stand-in for the real EZKL proof bytes (base64 url-safe of "proof")
            proof_b64: "cHJvb2Y=".to_string(),
            metadata: None,
        },
        summary: None,
        evidence_refs: None,
    }
}

fn setup() -> (
    ProgramRegistry,
    ProofSystemRegistry,
    ProofVerificationService,
) {
    let mut reg = ProgramRegistry::new();
    reg.register(Arc::new(FlashLivenessProgram::new(VK)));
    let mut ps = ProofSystemRegistry::new();
    ps.register(Arc::new(MockHalo2));
    (reg, ps, ProofVerificationService::default())
}

#[tokio::test]
async fn nominal_pass() {
    let (reg, ps, svc) = setup();
    let nonce = format!("0x{}", "11".repeat(32));
    let issued = make_binding(&nonce);
    let artifact = make_artifact(VK, make_binding(&nonce));
    let res = svc
        .verify(&artifact, &issued, &reg, &ps, "did:example:verifier")
        .await
        .expect("should verify");
    assert!(res.verified);
    assert!(res.receipt.is_some());
}

#[tokio::test]
async fn replay_context_mismatch() {
    let (reg, ps, svc) = setup();
    let artifact = make_artifact(VK, make_binding(&format!("0x{}", "11".repeat(32))));
    // requester expected a DIFFERENT nonce than the one bound in the proof
    let expected = make_binding(&format!("0x{}", "ff".repeat(32)));
    let err = svc
        .verify(&artifact, &expected, &reg, &ps, "did:example:verifier")
        .await
        .unwrap_err();
    assert!(matches!(err, PoeError::ContextMismatch));
    assert_eq!(err.code(), "context_mismatch");
}

#[tokio::test]
async fn unknown_vk() {
    let (reg, ps, svc) = setup();
    let nonce = format!("0x{}", "11".repeat(32));
    let issued = make_binding(&nonce);
    let artifact = make_artifact("0xdeadbeef", make_binding(&nonce)); // vk not in registry
    let err = svc
        .verify(&artifact, &issued, &reg, &ps, "did:example:verifier")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "vk_unknown");
}

#[test]
fn submit_message_json_roundtrip() {
    let nonce = format!("0x{}", "11".repeat(32));
    let artifact = make_artifact(VK, make_binding(&nonce));
    let msg = SubmitPoeMessage {
        program_id: artifact.program_id.clone(),
        result: artifact.result,
        proof_artifact: artifact,
        attachments: None,
    };
    let json = serde_json::to_string(&msg).unwrap();
    // wire field is `proof`, and binding is flattened into `public`
    assert!(json.contains("\"proof\""));
    assert!(json.contains("\"nonce\""));
    let back: SubmitPoeMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(back.program_id, protocol_poe::FLASH_PROGRAM_ID);
    assert_eq!(
        SubmitPoeMessage::TYPE,
        "https://didcomm.org/poe/1.0/submit-poe"
    );
}
