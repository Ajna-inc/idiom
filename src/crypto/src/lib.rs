//! Minimal `ajna-crypto` surface for the SSI wallet.
//!
//! Only the two post-quantum signature schemes the wallet actually uses are
//! vendored here, extracted verbatim from the full Ajna blockchain crypto
//! crate so the SSI stack stays self-contained (no blockchain dependency):
//!
//! * [`slhdsa`] — SLH-DSA-SHAKE-128s (NIST FIPS 205), user signatures
//! * [`mldsa`]  — ML-DSA-65 (NIST FIPS 204), validator signatures

pub mod mldsa; // ML-DSA-65 (FIPS 204) - Validator signatures
pub mod sid; // Sanskrit SID (Syllable IDentifier) library
pub mod slhdsa; // SLH-DSA (FIPS 205) - User signatures

pub use mldsa::{ValidatorPublicKey, ValidatorSecretKey, ValidatorSignature};
pub use slhdsa::{UserPublicKey, UserSecretKey, UserSignature};
