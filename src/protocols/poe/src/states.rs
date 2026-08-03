//! PoE state machine.
//!
//! Requester: Idle → RequestSent → (ChallengeSent) → SubmitReceived → Complete | Problem
//! Prover:    Idle → RequestReceived → (Proposed/Accepted) → (ChallengeReceived) →
//!            Executing → SubmitSent → Complete | Problem

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PoeState {
    Idle,
    RequestSent,
    RequestReceived,
    Proposed,
    ProposalReceived,
    Accepted,
    Declined,
    ChallengeSent,
    ChallengeReceived,
    Executing,
    SubmitSent,
    SubmitReceived,
    Complete,
    Problem,
    Abandoned,
}
