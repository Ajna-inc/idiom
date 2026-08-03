//! PoE protocol roles.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PoeRole {
    /// Verifier relying on the PoE result (login, payments, issuance).
    Requester,
    /// Holder/Agent that executes the program and returns the proof.
    Prover,
    /// Optional (TEE-backed) compute service proving on the Prover's behalf.
    Attester,
}
