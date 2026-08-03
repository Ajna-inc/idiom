//! Proof-system backends (concrete `ProofSystem` implementations).

#[cfg(feature = "ezkl-cli")]
pub mod ezkl_cli;

#[cfg(feature = "ezkl-cli")]
pub use ezkl_cli::{CircuitPaths, EzklCliProofSystem};

// Native halo2 (IPA) prover/verifier via the cross-platform `poe-prover` crate.
#[cfg(feature = "halo2-prove")]
pub mod halo2_ipa;

// Native halo2 (IPA) backend for the Biometric Face Membership program.
#[cfg(feature = "halo2-prove")]
pub mod face_membership;
