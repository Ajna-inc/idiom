//! # Wallet
//!
//! Key management crate implementing the `WalletProvider` trait.
//!
//! This crate provides wallet implementations for secure key management,
//! signing, and verification. It depends on the vendored `crypto` crate for
//! post-quantum (PQC) signature algorithms (SLH-DSA, ML-DSA).
//!
//! The [`askar`] module provides a production-ready wallet backed by Aries
//! Askar for encrypted key storage.

pub mod askar;

pub use askar::AskarWalletProvider;
