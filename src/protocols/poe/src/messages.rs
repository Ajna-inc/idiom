//! PoE 1.0 DIDComm v2 message bodies. Each carries its `TYPE` URI; the DIDComm
//! envelope (id/thid/from/to/expires_time) is applied by `didcomm_core` when
//! packing, matching the idiom convention (see `protocol_workflow::messages`).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::models::{
    BindingContext, ChallengeSpec, ExecutionReceipt, ProgramExecution, ProofArtifact, ProofResult,
    TransportHints,
};

/// Protocol base URI.
pub const PROTOCOL_URI: &str = "https://didcomm.org/poe/1.0";

/// requester → prover: ask the prover to run one or more programs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPoeMessage {
    pub programs: Vec<ProgramExecution>,
    #[serde(rename = "bind_to_context")]
    pub binding_context: BindingContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_hints: Option<TransportHints>,
}
impl RequestPoeMessage {
    pub const TYPE: &'static str = "https://didcomm.org/poe/1.0/request-poe";
}

/// prover → requester: negotiate capabilities/params (optional).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposePoeMessage {
    pub program: ProgramExecution,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
}
impl ProposePoeMessage {
    pub const TYPE: &'static str = "https://didcomm.org/poe/1.0/propose-poe";
}

/// requester ↔ prover: confirm the chosen program/params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptPoeMessage {
    pub program_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_constraints: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inputs_digest: Option<String>,
}
impl AcceptPoeMessage {
    pub const TYPE: &'static str = "https://didcomm.org/poe/1.0/accept-poe";
}

/// requester ↔ prover: decline the chosen program/params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclinePoeMessage {
    pub program_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
impl DeclinePoeMessage {
    pub const TYPE: &'static str = "https://didcomm.org/poe/1.0/decline-poe";
}

/// requester → prover: carry an interactive step schedule (e.g. the flash spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeMessage {
    pub challenge_spec: ChallengeSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
}
impl ChallengeMessage {
    pub const TYPE: &'static str = "https://didcomm.org/poe/1.0/challenge";
}

/// prover → requester: deliver the ZK proof and optional summary/evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPoeMessage {
    pub program_id: String,
    pub result: ProofResult,
    #[serde(rename = "proof")]
    pub proof_artifact: ProofArtifact,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<Value>>,
}
impl SubmitPoeMessage {
    pub const TYPE: &'static str = "https://didcomm.org/poe/1.0/submit-poe";
}

/// requester ↔ prover: signal success, optionally with a receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ExecutionReceipt>,
}
impl CompleteMessage {
    pub const TYPE: &'static str = "https://didcomm.org/poe/1.0/complete";
}

/// requester ↔ prover: canonical error report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoeProblemReportMessage {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Map<String, Value>>,
}
impl PoeProblemReportMessage {
    pub const TYPE: &'static str = "https://didcomm.org/poe/1.0/problem-report";
}
