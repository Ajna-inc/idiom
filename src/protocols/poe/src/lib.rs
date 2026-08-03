//! # Proof of Execution (PoE) Protocol — `https://didcomm.org/poe/1.0`
//!
//! DIDComm v2 protocol for requesting and receiving zero-knowledge proofs that a
//! named program executed correctly on inputs bound to a transaction context,
//! without revealing private inputs.
//!
//! Roles: [`PoeRole::Requester`] (verifier), [`PoeRole::Prover`] (holder/wallet),
//! optional [`PoeRole::Attester`]. Every instance binds to
//! `{nonce, context_hash, session_id}` ([`BindingContext`]) for anti-replay.
//!
//! Phase 1 (this crate): full data model, message bodies, program/registry/
//! proof-system traits, nonce + binding + verification services, and the
//! [`FlashLivenessProgram`] example.
//! Phase 2: DIDComm handlers + askar repositories + agent DI wiring (mirroring
//! `protocol_workflow`), and the native `ezkl` halo2-kzg executor/backend.

pub mod backends;
pub mod error;
pub mod messages;
pub mod models;
pub mod program;
pub mod programs;
pub mod registry;
pub mod roles;
pub mod services;
pub mod states;

pub use error::{PoeError, Result};
pub use messages::{
    AcceptPoeMessage, ChallengeMessage, CompleteMessage, DeclinePoeMessage,
    PoeProblemReportMessage, ProposePoeMessage, RequestPoeMessage, SubmitPoeMessage, PROTOCOL_URI,
};
pub use models::{
    BindingContext, ChallengeSpec, ChallengeStep, DisclosureLevel, EvidenceReference,
    ExecutionPolicy, ExecutionReceipt, ExecutionSummary, ProgramExecution, ProgramInputs,
    ProofArtifact, ProofResult, PublicOutputs, TransportHints, VerificationResult, ZkProof,
};
pub use program::{PoeProgram, ProgramExecutor, ProgramMetadata, ProofVerifier};
pub use programs::{FlashLivenessProgram, FLASH_CIRCUIT_ID, FLASH_PROGRAM_ID, FLASH_PUBLIC_SCHEMA};
pub use registry::{ProgramRegistry, ProofSystem, ProofSystemRegistry};
pub use roles::PoeRole;
pub use services::{context_hash, NonceService, ProofVerificationService};
pub use states::PoeState;
