//! Poseidon hash over the BN254 scalar field — circomlib-compatible.
//!
//! A byte-identical Rust port of the reference Python
//! `did_kanon/v1_0/zk/poseidon.py` (itself a port of
//! `circomlibjs/src/poseidon_reference.js`). It uses the SAME parameter set
//! (round constants + MDS matrix) that the `non_revocation.circom` circuit's
//! `Poseidon(t)` templates compile against, so a Merkle leaf or root computed
//! here matches what the circuit (and the credo-ts / kanon SDK) compute over
//! the same inputs.
//!
//! Parameters come from the vendored `assets/poseidon_constants.json`, copied
//! verbatim from circomlibjs. That file is ~870 KB and is parsed once, lazily,
//! into arkworks `Fr` field elements.
//!
//! Do NOT swap this for a generic Poseidon (e.g. the BLS12-381 Grain-LFSR
//! Poseidon in AJNA_BLOCKCHAIN): it is a different field with a different
//! constant/MDS set and its hashes do not match the circuit. See the module
//! docstring of the Python reference for the empirical mismatch demonstration.
//!
//! KAT (also asserted in `#[test]`s):
//!   poseidon_hash([1, 2]) ==
//!     7853200120776062878684798364095072458815029376092732009249414926327459813530

use std::str::FromStr;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use once_cell::sync::Lazy;

use crate::error::{KanonError, Result};
use crate::ids::Bytes32;

/// Full-round count (fixed across `t` in circomlib's parameter selection).
const N_ROUNDS_F: usize = 8;

/// Partial-round count by `t - 2`. From
/// `circomlibjs/src/poseidon_reference.js`.
const N_ROUNDS_P: [usize; 16] = [
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
];

/// Vendored circomlib constants (decimal/hex felts as JSON strings).
const CONSTANTS_JSON: &str = include_str!("../assets/poseidon_constants.json");

/// `(C, M)` parsed into field elements.
///   `C[t-2]`  flat round constants, length `(R_F + R_P) * t`.
///   `M[t-2]`  the `t x t` MDS matrix.
struct Params {
    c: Vec<Vec<Fr>>,
    m: Vec<Vec<Vec<Fr>>>,
}

static PARAMS: Lazy<Params> = Lazy::new(|| load_params().expect("poseidon_constants.json parse"));

/// Parse a circomlibjs JSON felt — decimal or `0x…` hex — into `Fr`.
fn parse_field(s: &str) -> Result<Fr> {
    let t = s.trim();
    if let Some(hex_body) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        // Left-pad to an even length, decode big-endian, reduce mod the field.
        let padded = if hex_body.len() % 2 == 1 {
            format!("0{hex_body}")
        } else {
            hex_body.to_string()
        };
        let bytes = hex::decode(&padded)
            .map_err(|e| KanonError::Encoding(format!("poseidon constant hex {t}: {e}")))?;
        Ok(Fr::from_be_bytes_mod_order(&bytes))
    } else {
        // Decimal. `from_str` is radix-10 and reduces mod p.
        Fr::from_str(t).map_err(|_| KanonError::Encoding(format!("poseidon constant decimal: {t}")))
    }
}

fn load_params() -> Result<Params> {
    let raw: serde_json::Value = serde_json::from_str(CONSTANTS_JSON)
        .map_err(|e| KanonError::Encoding(format!("poseidon_constants.json: {e}")))?;

    let c_raw = raw
        .get("C")
        .and_then(|v| v.as_array())
        .ok_or_else(|| KanonError::Encoding("poseidon_constants.json missing C".into()))?;
    let m_raw = raw
        .get("M")
        .and_then(|v| v.as_array())
        .ok_or_else(|| KanonError::Encoding("poseidon_constants.json missing M".into()))?;

    let mut c: Vec<Vec<Fr>> = Vec::with_capacity(c_raw.len());
    for row in c_raw {
        let arr = row
            .as_array()
            .ok_or_else(|| KanonError::Encoding("poseidon C row not array".into()))?;
        let mut felts = Vec::with_capacity(arr.len());
        for v in arr {
            felts.push(parse_field(v.as_str().ok_or_else(|| {
                KanonError::Encoding("poseidon C entry not string".into())
            })?)?);
        }
        c.push(felts);
    }

    let mut m: Vec<Vec<Vec<Fr>>> = Vec::with_capacity(m_raw.len());
    for matrix in m_raw {
        let rows = matrix
            .as_array()
            .ok_or_else(|| KanonError::Encoding("poseidon M matrix not array".into()))?;
        let mut mat = Vec::with_capacity(rows.len());
        for r in rows {
            let arr = r
                .as_array()
                .ok_or_else(|| KanonError::Encoding("poseidon M row not array".into()))?;
            let mut felts = Vec::with_capacity(arr.len());
            for v in arr {
                felts.push(parse_field(v.as_str().ok_or_else(|| {
                    KanonError::Encoding("poseidon M entry not string".into())
                })?)?);
            }
            mat.push(felts);
        }
        m.push(mat);
    }

    Ok(Params { c, m })
}

/// `x^5` — the Poseidon S-box.
#[inline]
fn pow5(x: Fr) -> Fr {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// Circomlib-compatible Poseidon hash of `inputs` (state width `t = n + 1`,
/// capacity element `init_state = 0`). `inputs` must be a non-empty slice of
/// at most 16 field elements — circomlibjs's constant-table arity range.
///
/// Returns a single field element.
pub fn poseidon_hash(inputs: &[Fr]) -> Result<Fr> {
    poseidon_hash_with_state(inputs, Fr::from(0u64))
}

/// Poseidon with an explicit capacity element (kept general to mirror the
/// Python `init_state` argument; the circuit always uses `0`).
pub fn poseidon_hash_with_state(inputs: &[Fr], init_state: Fr) -> Result<Fr> {
    let n = inputs.len();
    if n == 0 {
        return Err(KanonError::Invalid(
            "poseidon_hash requires at least one input".into(),
        ));
    }
    if n > N_ROUNDS_P.len() {
        return Err(KanonError::Invalid(format!(
            "poseidon_hash arity {n} exceeds supported range [1, {}]",
            N_ROUNDS_P.len()
        )));
    }

    let t = n + 1;
    let n_rf = N_ROUNDS_F;
    let n_rp = N_ROUNDS_P[t - 2];

    let ct = &PARAMS.c[t - 2];
    let mt = &PARAMS.m[t - 2];

    let mut state: Vec<Fr> = Vec::with_capacity(t);
    state.push(init_state);
    state.extend_from_slice(inputs);

    for r in 0..(n_rf + n_rp) {
        // Add round constants.
        let base = r * t;
        for i in 0..t {
            state[i] += ct[base + i];
        }

        // S-box: full rounds apply x^5 to all; partial rounds only to state[0].
        if r < n_rf / 2 || r >= n_rf / 2 + n_rp {
            for s in state.iter_mut() {
                *s = pow5(*s);
            }
        } else {
            state[0] = pow5(state[0]);
        }

        // MDS multiply: new_state[i] = Σ_j M[i][j] * state[j].
        let mut new_state = vec![Fr::from(0u64); t];
        for i in 0..t {
            let row = &mt[i];
            let mut acc = Fr::from(0u64);
            for j in 0..t {
                acc += row[j] * state[j];
            }
            new_state[i] = acc;
        }
        state = new_state;
    }

    Ok(state[0])
}

/// BN254 scalar field modulus (informational; matches the Python
/// `BN254_PRIME`).
pub const BN254_PRIME_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Encode a field element as 32 big-endian bytes — the on-chain
/// `MerkleStateRegistry` convention (`bytes32(uint256(felt))`). Mirrors the
/// Python `felt_to_bytes32`.
pub fn felt_to_bytes32(f: Fr) -> Bytes32 {
    let be = f.into_bigint().to_bytes_be(); // 32 bytes for BN254 Fr
    let mut out = [0u8; 32];
    // to_bytes_be for a 254-bit field returns 32 bytes; guard anyway.
    let n = be.len().min(32);
    out[32 - n..].copy_from_slice(&be[be.len() - n..]);
    out
}

/// Interpret 32 big-endian bytes as a BN254 felt (reducing mod p). Mirrors the
/// big-endian `int.from_bytes(...) % p` the Python side does for credId /
/// credDefId / on-chain leaves.
pub fn felt_from_be_bytes(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fr(dec: &str) -> Fr {
        Fr::from_str(dec).unwrap()
    }

    /// KAT — the canonical circomlib value, documented in the reference.
    #[test]
    fn poseidon_1_2_matches_circomlib() {
        let h = poseidon_hash(&[Fr::from(1u64), Fr::from(2u64)]).unwrap();
        assert_eq!(
            h,
            fr("7853200120776062878684798364095072458815029376092732009249414926327459813530")
        );
    }

    /// KATs generated from the Python reference (`poseidon.py`) over the
    /// vendored constants.
    #[test]
    fn poseidon_more_arities_match_python() {
        assert_eq!(
            poseidon_hash(&[Fr::from(3u64), Fr::from(4u64)]).unwrap(),
            fr("14763215145315200506921711489642608356394854266165572616578112107564877678998")
        );
        assert_eq!(
            poseidon_hash(&[Fr::from(1u64)]).unwrap(),
            fr("18586133768512220936620570745912940619677854269274689475585506675881198879027")
        );
        // 3-input, the tagged Merkle-node hash Poseidon(NODE_TAG=2, 1, 2).
        assert_eq!(
            poseidon_hash(&[Fr::from(2u64), Fr::from(1u64), Fr::from(2u64)]).unwrap(),
            fr("12448107141648110753339079111365879398049652284040593012870233782552794396784")
        );
    }

    #[test]
    fn felt_bytes_round_trips_mod_p() {
        let f = Fr::from(5u64);
        let b = felt_to_bytes32(f);
        assert_eq!(felt_from_be_bytes(&b), f);
        assert_eq!(b[31], 5);
        assert!(b[..31].iter().all(|&x| x == 0));
    }
}
