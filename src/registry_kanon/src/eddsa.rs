//! BabyJubjub EdDSA-Poseidon — Rust port of circomlibjs's `signPoseidon`.
//!
//! Byte-identical to the reference Python `did_kanon/v1_0/zk/eddsa.py`, which
//! mirrors circomlibjs (the Node reference the Mode B `non_revocation.circom`
//! circuit verifies against). Issuer and verifier MUST agree byte-for-byte.
//!
//! Scheme (circomlibjs convention):
//!
//!   prv2pub(prv):
//!     h = BLAKE-512(prv)                          # 64 bytes
//!     s_buf = prune(h[0:32])                      # clamp lo/hi bits
//!     s = uint(s_buf, little-endian)              # secret scalar
//!     A = (s >> 3) · BASE8                        # public point
//!
//!   signPoseidon(prv, msg):
//!     r_buf = BLAKE-512(h[32:64] || msg_LE_32)
//!     r = uint(r_buf, little-endian) mod SUB_ORDER
//!     R8 = r · BASE8
//!     c  = Poseidon(R8x, R8y, Ax, Ay, msg)
//!     S  = (r + c · s) mod SUB_ORDER
//!     return (R8, S)
//!
//!   verifyPoseidon(msg, sig, A):
//!     c  = Poseidon(R8x, R8y, Ax, Ay, msg)
//!     Pleft  = S · BASE8
//!     Pright = R8 + (c · 8) · A
//!     return Pleft == Pright
//!
//! Every layer here is KAT-gated against the SDK-derived vectors in
//! `did_kanon/tests/unit/test_mode_b.py` (priv = 0x01*32) plus additional
//! vectors generated from the Python reference.

use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use base64::Engine;
use num_bigint::BigUint;

use crate::babyjub::{self, Point};
use crate::blake512::blake512;
use crate::error::{KanonError, Result};
use crate::poseidon::poseidon_hash;

/// Domain-separation constant — matches the leaf tag in the circuit.
pub const KANON_ZK_LEAF_TAG: u64 = 1;

/// A BabyJubjub-EdDSA signature over a Poseidon-hashed leaf. Wire form is
/// `(R8x, R8y, S)` — three BN254 felts packed into 96 bytes big-endian.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KanonZkSignature {
    pub r8x: BigUint,
    pub r8y: BigUint,
    pub s: BigUint,
}

/// A persisted issuer keypair. Only `private_key_hex` is secret; `(ax, ay)` are
/// the on-chain `IssuerZkPubKey` coordinates.
#[derive(Debug, Clone)]
pub struct KanonZkIssuerKey {
    pub private_key_hex: String,
    pub ax: BigUint,
    pub ay: BigUint,
}

/// Ed25519-style buffer clamping. Mirrors `Eddsa.pruneBuffer` — clear the low 3
/// bits and the top bit, set bit 254.
fn prune(buf32: &[u8]) -> [u8; 32] {
    debug_assert_eq!(buf32.len(), 32);
    let mut b = [0u8; 32];
    b.copy_from_slice(buf32);
    b[0] &= 0xF8;
    b[31] &= 0x7F;
    b[31] |= 0x40;
    b
}

/// Little-endian bytes → `BigUint`.
fn le_to_biguint(buf: &[u8]) -> BigUint {
    BigUint::from_bytes_le(buf)
}

/// Serialise a felt (`value % p`) as 32 little-endian bytes for the message-hash
/// composition. Matches `F.toRprLE` in circomlibjs.
fn felt_to_le32(value: &Fr) -> [u8; 32] {
    value.into_bigint().to_bytes_le_32()
}

/// Helper: `Fr::into_bigint().to_bytes_le()` padded/truncated to 32 bytes.
trait ToBytesLe32 {
    fn to_bytes_le_32(&self) -> [u8; 32];
}
impl ToBytesLe32 for <Fr as PrimeField>::BigInt {
    fn to_bytes_le_32(&self) -> [u8; 32] {
        use ark_ff::BigInteger;
        let v = self.to_bytes_le();
        let mut out = [0u8; 32];
        let n = v.len().min(32);
        out[..n].copy_from_slice(&v[..n]);
        out
    }
}

/// Parse a `0x`-prefixed (or bare) 32-byte private-key hex string.
fn parse_priv(private_key_hex: &str) -> Result<[u8; 32]> {
    let s = private_key_hex
        .strip_prefix("0x")
        .or_else(|| private_key_hex.strip_prefix("0X"))
        .unwrap_or(private_key_hex);
    let raw = hex::decode(s).map_err(|e| KanonError::Invalid(format!("private key hex: {e}")))?;
    if raw.len() != 32 {
        return Err(KanonError::Invalid("private key must be 32 bytes".into()));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&raw);
    Ok(b)
}

/// Normalise a private-key hex to `0x<64 hex>`.
fn normalize_priv_hex(private_key_hex: &str) -> String {
    let lower = private_key_hex.to_ascii_lowercase();
    if lower.starts_with("0x") {
        lower
    } else {
        format!("0x{lower}")
    }
}

/// Recover the public coords `(ax, ay)` from a persisted private key. Mirrors
/// `restore_issuer_key` / `prv2pub`.
pub fn restore_issuer_key(private_key_hex: &str) -> Result<KanonZkIssuerKey> {
    let sk = parse_priv(private_key_hex)?;
    let h = blake512(&sk);
    let pruned = prune(&h[..32]);
    let s = le_to_biguint(&pruned);
    let a = babyjub::mul(&babyjub::base8(), &(&s >> 3u32));
    Ok(KanonZkIssuerKey {
        private_key_hex: normalize_priv_hex(private_key_hex),
        ax: babyjub::fr_to_biguint(&a.x),
        ay: babyjub::fr_to_biguint(&a.y),
    })
}

/// Sign a leaf with the issuer's BJJ key. Matches `eddsa.signPoseidon` /
/// circomlibjs byte-for-byte. `leaf` is the BN254 field element the circuit
/// recomputes; callers pass it as an `Fr`.
pub fn sign_poseidon(private_key_hex: &str, leaf: &Fr) -> Result<KanonZkSignature> {
    let sk = parse_priv(private_key_hex)?;
    let h = blake512(&sk);
    let pruned = prune(&h[..32]);
    let s = le_to_biguint(&pruned);
    let a_point = babyjub::mul(&babyjub::base8(), &(&s >> 3u32));

    // Nonce: r = BLAKE-512(h[32:64] || msg_LE_32) mod SUB_ORDER.
    let mut compose = Vec::with_capacity(64);
    compose.extend_from_slice(&h[32..64]);
    compose.extend_from_slice(&felt_to_le32(leaf));
    let r_buf = blake512(&compose);
    let sub_order = babyjub::sub_order();
    let r = le_to_biguint(&r_buf) % &sub_order;

    let r8 = babyjub::mul(&babyjub::base8(), &r);

    // Challenge c = Poseidon(R8x, R8y, Ax, Ay, leaf).
    let c = poseidon_hash(&[r8.x, r8.y, a_point.x, a_point.y, *leaf])?;
    let c_big = babyjub::fr_to_biguint(&c);

    let s_sig = (&r + &c_big * &s) % &sub_order;
    Ok(KanonZkSignature {
        r8x: babyjub::fr_to_biguint(&r8.x),
        r8y: babyjub::fr_to_biguint(&r8.y),
        s: s_sig,
    })
}

/// Verify a Mode B signature. Mirrors `eddsa.verify_poseidon`:
/// `S · BASE8 == R8 + (c · 8) · A` where `c = Poseidon(R8x, R8y, Ax, Ay, leaf)`.
pub fn verify_poseidon(
    public_key: (&BigUint, &BigUint),
    leaf: &Fr,
    sig: &KanonZkSignature,
) -> bool {
    let sub_order = babyjub::sub_order();
    if sig.s >= sub_order {
        return false;
    }
    if sig.s.is_zero() {
        return false;
    }
    let r8 = point_from_biguints(&sig.r8x, &sig.r8y);
    let a = point_from_biguints(public_key.0, public_key.1);
    let neutral = Point::neutral();
    if r8 == neutral {
        return false;
    }
    if a == neutral {
        return false;
    }
    if !babyjub::in_curve(&r8) {
        return false;
    }
    if !babyjub::in_curve(&a) {
        return false;
    }

    let c = match poseidon_hash(&[r8.x, r8.y, a.x, a.y, *leaf]) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let c_big = babyjub::fr_to_biguint(&c);

    let p_left = babyjub::mul(&babyjub::base8(), &sig.s);
    let coeff = (&c_big * 8u32) % babyjub::order();
    let p_right_term = babyjub::mul(&a, &coeff);
    let p_right = babyjub::add(&r8, &p_right_term);
    p_left == p_right
}

fn point_from_biguints(x: &BigUint, y: &BigUint) -> Point {
    Point {
        x: Fr::from_le_bytes_mod_order(&x.to_bytes_le()),
        y: Fr::from_le_bytes_mod_order(&y.to_bytes_le()),
    }
}

/// Pack `(R8x, R8y, S)` as 96 big-endian bytes, then base64. Matches the SDK.
pub fn encode_zk_signature(sig: &KanonZkSignature) -> String {
    let mut buf = Vec::with_capacity(96);
    for v in [&sig.r8x, &sig.r8y, &sig.s] {
        buf.extend_from_slice(&biguint_to_be32(v));
    }
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// Inverse of `encode_zk_signature`.
pub fn decode_zk_signature(value: &str) -> Result<KanonZkSignature> {
    let buf = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|e| KanonError::Invalid(format!("kanonZkSig base64: {e}")))?;
    if buf.len() != 96 {
        return Err(KanonError::Invalid(format!(
            "expected 96 bytes, got {}",
            buf.len()
        )));
    }
    Ok(KanonZkSignature {
        r8x: BigUint::from_bytes_be(&buf[0..32]),
        r8y: BigUint::from_bytes_be(&buf[32..64]),
        s: BigUint::from_bytes_be(&buf[64..96]),
    })
}

/// `BigUint` → 32 big-endian bytes (left-zero-padded).
fn biguint_to_be32(v: &BigUint) -> [u8; 32] {
    let be = v.to_bytes_be();
    let mut out = [0u8; 32];
    let n = be.len().min(32);
    out[32 - n..].copy_from_slice(&be[be.len() - n..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn bu(s: &str) -> BigUint {
        BigUint::from_str(s).unwrap()
    }
    fn fr_dec(s: &str) -> Fr {
        Fr::from_str(s).unwrap()
    }

    // SDK reference vectors from did_kanon/tests/unit/test_mode_b.py.
    const SDK_PRIV_HEX: &str = "0x0101010101010101010101010101010101010101010101010101010101010101";
    const SDK_LEAF: &str =
        "1393485080625247459900569500640157328168465545537288134804249149028564603699";
    const SDK_AX: &str =
        "15944627324083773346390189001500210680939402028015651549526524193195473201952";
    const SDK_AY: &str =
        "17251889856797524237981285661279357764562574766148660962999867467495459148286";
    const SDK_R8X: &str =
        "17996337951031749394524763022520499015847634575338891769488487632607376949813";
    const SDK_R8Y: &str =
        "10272400637717881040885751049351288246004421904083538689985102034897630425737";
    const SDK_S: &str =
        "2398317530176221948237054226068083457741186453462032123787867089593074951308";

    /// prv2pub — pin `(Ax, Ay)` to the SDK reference (priv = 0x01*32).
    #[test]
    fn prv2pub_matches_sdk() {
        let k = restore_issuer_key(SDK_PRIV_HEX).unwrap();
        assert_eq!(k.ax, bu(SDK_AX));
        assert_eq!(k.ay, bu(SDK_AY));
    }

    /// signPoseidon — pin `(R8x, R8y, S)` to the SDK reference.
    #[test]
    fn sign_poseidon_matches_sdk() {
        let sig = sign_poseidon(SDK_PRIV_HEX, &fr_dec(SDK_LEAF)).unwrap();
        assert_eq!(sig.r8x, bu(SDK_R8X));
        assert_eq!(sig.r8y, bu(SDK_R8Y));
        assert_eq!(sig.s, bu(SDK_S));
    }

    /// verifyPoseidon — accept the SDK reference signature.
    #[test]
    fn verify_poseidon_accepts_sdk() {
        let sig = KanonZkSignature {
            r8x: bu(SDK_R8X),
            r8y: bu(SDK_R8Y),
            s: bu(SDK_S),
        };
        assert!(verify_poseidon(
            (&bu(SDK_AX), &bu(SDK_AY)),
            &fr_dec(SDK_LEAF),
            &sig
        ));
    }

    /// verify rejects a tampered signature.
    #[test]
    fn verify_rejects_tampered() {
        let sig = KanonZkSignature {
            r8x: bu(SDK_R8X),
            r8y: bu(SDK_R8Y),
            s: bu(SDK_S) + 1u32,
        };
        assert!(!verify_poseidon(
            (&bu(SDK_AX), &bu(SDK_AY)),
            &fr_dec(SDK_LEAF),
            &sig
        ));
    }

    /// Full sign→verify round trips for independent keys/leaves, cross-checked
    /// against the Python reference outputs.
    #[test]
    fn sign_verify_round_trip_python_vectors() {
        // priv=0x02*32, leaf=42.
        let sig = sign_poseidon(&format!("0x{}", "02".repeat(32)), &Fr::from(42u64)).unwrap();
        assert_eq!(
            sig.r8x,
            bu("20007160819228079428159650074974508307342180667770467893407020334837290037908")
        );
        assert_eq!(
            sig.r8y,
            bu("19531261863057274334481877022573199366168246417328294949117076581253706032489")
        );
        assert_eq!(
            sig.s,
            bu("42533571164958542316616793721732441200207513655551173915147894437542926147")
        );
        let k = restore_issuer_key(&format!("0x{}", "02".repeat(32))).unwrap();
        assert_eq!(
            k.ax,
            bu("4044393282578688582896187440332443375392492214705434598936990660961068722040")
        );
        assert_eq!(
            k.ay,
            bu("4862644268749425810567793658630502670008545397818408317392674122665460786971")
        );
        assert!(verify_poseidon((&k.ax, &k.ay), &Fr::from(42u64), &sig));

        // priv=0xdeadbeef*8, leaf=123456789.
        let dp = format!("0x{}", "deadbeef".repeat(8));
        let sig2 = sign_poseidon(&dp, &Fr::from(123456789u64)).unwrap();
        assert_eq!(
            sig2.r8x,
            bu("11260763035030294397824127717558540262387155621979111824771423154456075190372")
        );
        assert_eq!(
            sig2.s,
            bu("159949861968585042326410270400264269791391081416266203845598805373848932879")
        );
        let k2 = restore_issuer_key(&dp).unwrap();
        assert!(verify_poseidon(
            (&k2.ax, &k2.ay),
            &Fr::from(123456789u64),
            &sig2
        ));
    }

    /// encode/decode round trip, and the 96-byte wire length from the SDK.
    #[test]
    fn encode_decode_round_trip() {
        let sig = KanonZkSignature {
            r8x: bu(SDK_R8X),
            r8y: bu(SDK_R8Y),
            s: bu(SDK_S),
        };
        let enc = encode_zk_signature(&sig);
        assert_eq!(
            enc,
            "J8mQ+i2cLShwbyQWQhrrMt7bJ2A4XLs+Prvb8hfZwjUWtfkERwlK4CGjeXMcs7AoLv9XbUtzTxr3X8AFslhyiQVNZk1XobLk0ZfZmVSRieixnflJ9Wzq+ul7Hfeu96SM"
        );
        let dec = decode_zk_signature(&enc).unwrap();
        assert_eq!(dec, sig);
    }
}
