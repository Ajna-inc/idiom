//! PoE data model.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{PoeError, Result};

// --------------------------------------------------------------------------
// Binding context (anti-replay): every PoE MUST bind to {nonce,context,session}
// --------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingContext {
    /// 32-byte nonce, hex with `0x` prefix.
    pub nonce: String,
    /// 32-byte hash of the transaction/execution context, hex `0x`.
    pub context_hash: String,
    /// 16-byte session identifier, hex `0x`.
    pub session_id: String,
}

/// Required byte length of a binding-context nonce.
const NONCE_BYTES: usize = 32;
/// Required byte length of a binding-context context hash.
const CONTEXT_HASH_BYTES: usize = 32;
/// Required byte length of a binding-context session id.
const SESSION_ID_BYTES: usize = 16;

fn is_hex_0x(s: &str, byte_len: usize) -> bool {
    s.len() == 2 + byte_len * 2
        && s.starts_with("0x")
        && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

impl BindingContext {
    pub fn validate(&self) -> Result<()> {
        if !is_hex_0x(&self.nonce, NONCE_BYTES) {
            return Err(PoeError::InputsInvalid(
                "nonce must be 32-byte 0x-hex".into(),
            ));
        }
        if !is_hex_0x(&self.context_hash, CONTEXT_HASH_BYTES) {
            return Err(PoeError::InputsInvalid(
                "context_hash must be 32-byte 0x-hex".into(),
            ));
        }
        if !is_hex_0x(&self.session_id, SESSION_ID_BYTES) {
            return Err(PoeError::InputsInvalid(
                "session_id must be 16-byte 0x-hex".into(),
            ));
        }
        Ok(())
    }

    /// Case-insensitive equality (hex is case-insensitive).
    pub fn matches(&self, other: &BindingContext) -> bool {
        self.nonce.eq_ignore_ascii_case(&other.nonce)
            && self.context_hash.eq_ignore_ascii_case(&other.context_hash)
            && self.session_id.eq_ignore_ascii_case(&other.session_id)
    }
}

// --------------------------------------------------------------------------
// Program execution request
// --------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum DisclosureLevel {
    #[default]
    ProofOnly,
    #[serde(rename = "proof+summary")]
    ProofSummary,
    #[serde(rename = "proof+evidence-ref")]
    ProofEvidenceRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub alg: String,
    pub keyref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputReference {
    pub uri: String,
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInputs {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_value: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_reference: Option<Vec<InputReference>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_runtime_s: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_artifact_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_attesters: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_trust_level: Option<u32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportHints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_response_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramExecution {
    pub program_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_constraints: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inputs: Option<ProgramInputs>,
    #[serde(default)]
    pub disclosure: DisclosureLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<ExecutionPolicy>,
}

// --------------------------------------------------------------------------
// Proof artifact
// --------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofResult {
    Pass,
    Fail,
    Partial,
}

/// Public outputs revealed alongside the proof. Embeds the binding context and
/// carries arbitrary program-specific fields in `extra`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicOutputs {
    #[serde(flatten)]
    pub binding: BindingContext,
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs_hash: Option<String>,
    pub vk_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    /// e.g. "halo2-kzg", "groth16", "plonk", "stark".
    pub scheme: String,
    pub circuit_id: String,
    pub vk_hash: String,
    /// Base64 (url-safe) proof bytes.
    pub proof_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_summary: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steps: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRefData {
    pub links: Vec<String>,
    pub alg: String,
    pub keyref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub id: String,
    pub format: String, // always "by-reference"
    pub media_type: String,
    pub data: EvidenceRefData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub program_id: String,
    pub result: ProofResult,
    pub public: PublicOutputs,
    pub zk: ZkProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<ExecutionSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<EvidenceReference>>,
}

// --------------------------------------------------------------------------
// Interactive challenges
// --------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeStep {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChallengeSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steps: Option<Vec<ChallengeStep>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_s: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// --------------------------------------------------------------------------
// Verification result + receipt (requester side)
// --------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verified: bool,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ExecutionReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub proof_hash: String,
    pub issued_at: String,
    pub issuer_did: String,
    pub session_id: String,
    pub program_id: String,
    pub result: ProofResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}
