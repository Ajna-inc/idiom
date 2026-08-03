//! Kanon network configuration. Mirrors the `did_kanon` plugin config keys
//! (`KANON_RPC_URL`, `KANON_CHAIN_ID`, `KANON_ADDRESS_BOOK`, `KANON_ORG_ID`,
//! `KANON_OPERATOR_KEY`, `KANON_DEFAULT_POLICY_MASK`).

use crate::error::{KanonError, Result};

/// Policy-mask tiers (bitmask), matching `CredentialDefinitionRegistry`.
pub const TIER_ONE_TIME: u8 = 1 << 0; // 0b01 — AnonCredsStatusRegistry (Tier 1)
pub const TIER_ZK_SNARK: u8 = 1 << 1; // 0b10 — MerkleStateRegistry + Halo2 (Tier 2)
pub const TIER_ALL: u8 = TIER_ONE_TIME | TIER_ZK_SNARK;

/// KanonAddressBook proxy on Besu chain 1947 — the single entry point from
/// which all seven registry addresses are resolved via `registries()`.
pub const ADDRESS_BOOK_1947: &str = "0x325c9cC81A75ab45775D7BAf007cE3612d473A9f";
pub const CHAIN_ID_BESU: u64 = 1947;

#[derive(Debug, Clone)]
pub struct KanonConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    /// KanonAddressBook address; registry addresses are resolved from it.
    pub address_book: String,
    /// Issuer org DID, `did:kanon:org:0x…`. Required for writes.
    pub issuer_did: Option<String>,
    /// secp256k1 operator private key (hex) for signing txs. `None` = read-only.
    pub operator_key: Option<String>,
    /// Default policy mask for new cred-defs when unspecified.
    pub default_policy_mask: u8,
    /// Legacy gas price for write txs. Kanon's Besu is a free-gas chain
    /// (gasPrice=0), so this defaults to 0 — required, else alloy's fee
    /// filler sets a nonzero cost the (0-balance) operator can't cover.
    pub gas_price: u128,
}

impl KanonConfig {
    /// Read-only config against Besu chain 1947 (resolve/verify only).
    pub fn besu_readonly(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            chain_id: CHAIN_ID_BESU,
            address_book: ADDRESS_BOOK_1947.to_string(),
            issuer_did: None,
            operator_key: None,
            default_policy_mask: TIER_ONE_TIME,
            gas_price: 0,
        }
    }

    pub fn with_issuer(mut self, issuer_did: impl Into<String>) -> Self {
        self.issuer_did = Some(issuer_did.into());
        self
    }

    pub fn with_operator_key(mut self, key: impl Into<String>) -> Self {
        self.operator_key = Some(key.into());
        self
    }

    pub fn with_default_policy_mask(mut self, mask: u8) -> Self {
        self.default_policy_mask = mask;
        self
    }

    pub fn issuer_did(&self) -> Result<&str> {
        self.issuer_did
            .as_deref()
            .ok_or_else(|| KanonError::Config("issuer_did required for writes".into()))
    }
}

/// Parse a policy-mask token (int or string) as the plugin does.
pub fn parse_policy_mask(token: &str) -> Option<u8> {
    match token.trim().to_ascii_uppercase().as_str() {
        "1" | "TIER_ONE_TIME" | "ONE_TIME" => Some(TIER_ONE_TIME),
        "2" | "TIER_ZK_SNARK" | "ZK" => Some(TIER_ZK_SNARK),
        "3" | "TIER_ALL" | "ALL" => Some(TIER_ALL),
        _ => None,
    }
}
