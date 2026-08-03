//! BabyJubjub curve arithmetic — twisted Edwards over the BN254 scalar field.
//!
//! Byte-identical Rust port of the reference Python
//! `did_kanon/v1_0/zk/_babyjub.py`, which mirrors
//! `circomlibjs/src/babyjub.js`:
//!
//!   - Base field:  Fp where p = BN254 scalar prime (== `ark_bn254::Fr`).
//!   - Curve:       a·x² + y² = 1 + d·x²·y²   (twisted Edwards),
//!                  a = 168700, d = 168696.
//!   - Group order: 8 × subgroup order.
//!   - `BASE8`:     8 · Generator — the scalar-mul base circomlibjs uses.
//!
//! The point coordinates live in the BN254 **scalar** field (`Fr`), which is
//! the base field of BabyJubjub. Scalars for `mul` are `BigUint` (the hashed,
//! clamped EdDSA secret / nonce). Correctness is gated by the KATs at the
//! bottom, generated from the Python reference.

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};
use num_bigint::BigUint;

/// Twisted-Edwards `a`.
fn a_param() -> Fr {
    Fr::from(168700u64)
}
/// Twisted-Edwards `d`.
fn d_param() -> Fr {
    Fr::from(168696u64)
}

/// Full group order (8 × subgroup order) as a decimal string.
pub const ORDER_DEC: &str =
    "21888242871839275222246405745257275088614511777268538073601725287587578984328";

/// A BabyJubjub point in affine `(x, y)` coordinates over `Fr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub x: Fr,
    pub y: Fr,
}

impl Point {
    /// Neutral element on twisted-Edwards: `(0, 1)`.
    pub fn neutral() -> Self {
        Point {
            x: Fr::zero(),
            y: Fr::from(1u64),
        }
    }
}

/// The `BASE8 = 8 · Generator` point circomlibjs's prv2pub / signPoseidon
/// scalar-multiply from.
pub fn base8() -> Point {
    Point {
        x: fr_dec("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
        y: fr_dec("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    }
}

/// Subgroup order (`ORDER >> 3`) as a `BigUint` — EdDSA secret scalars live
/// mod this.
pub fn sub_order() -> BigUint {
    order() >> 3
}

/// Full group order as a `BigUint`.
pub fn order() -> BigUint {
    BigUint::parse_bytes(ORDER_DEC.as_bytes(), 10).expect("ORDER_DEC")
}

fn fr_dec(s: &str) -> Fr {
    use std::str::FromStr;
    Fr::from_str(s).expect("fr_dec")
}

/// Twisted-Edwards point addition. Mirrors `BabyJub.addPoint` /
/// the Python `add` — the same rearranged intermediate form circomlibjs uses.
pub fn add(p: &Point, q: &Point) -> Point {
    let (x1, y1) = (p.x, p.y);
    let (x2, y2) = (q.x, q.y);
    let a = a_param();
    let d = d_param();

    let beta = x1 * y2;
    let gamma = y1 * x2;
    let delta = (y1 - a * x1) * (x2 + y2);
    let tau = beta * gamma;
    let dtau = d * tau;

    let inv_pos = (Fr::from(1u64) + dtau)
        .inverse()
        .expect("1+dtau invertible");
    let inv_neg = (Fr::from(1u64) - dtau)
        .inverse()
        .expect("1-dtau invertible");

    let x3 = (beta + gamma) * inv_pos;
    let y3 = (delta + a * beta - gamma) * inv_neg;
    Point { x: x3, y: y3 }
}

/// Scalar multiplication via textbook double-and-add, LSB first. Matches
/// `BabyJub.mulPointEscalar` / the Python `mul`. Starts from the neutral
/// element `(0, 1)`.
pub fn mul(base: &Point, k: &BigUint) -> Point {
    let mut res = Point::neutral();
    let mut exp = *base;
    let mut k = k.clone();
    let zero = BigUint::zero();
    let one = BigUint::from(1u64);
    while k > zero {
        if (&k & &one) == one {
            res = add(&res, &exp);
        }
        exp = add(&exp, &exp);
        k >>= 1;
    }
    res
}

/// Curve membership test: `a·x² + y² ≡ 1 + d·x²·y² (mod p)`.
pub fn in_curve(p: &Point) -> bool {
    let x2 = p.x * p.x;
    let y2 = p.y * p.y;
    let lhs = a_param() * x2 + y2;
    let rhs = Fr::from(1u64) + d_param() * x2 * y2;
    lhs == rhs
}

/// Convert a point coordinate (`Fr`) to a `BigUint` in `[0, p)`.
pub fn fr_to_biguint(f: &Fr) -> BigUint {
    (*f).into_bigint().into()
}

/// Convert an `Fr` to its canonical decimal string (for on-chain / wire coords).
pub fn fr_to_dec(f: &Fr) -> String {
    fr_to_biguint(f).to_str_radix(10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn bu(s: &str) -> BigUint {
        BigUint::from_str(s).unwrap()
    }

    #[test]
    fn base8_on_curve() {
        assert!(in_curve(&base8()));
        assert!(in_curve(&Point::neutral()));
    }

    /// KATs for `BASE8 · k` generated from the Python `_babyjub.mul`.
    #[test]
    fn base8_scalar_mul_matches_python() {
        let cases: &[(&str, &str, &str)] = &[
            ("0", "0", "1"),
            (
                "1",
                "5299619240641551281634865583518297030282874472190772894086521144482721001553",
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            ),
            (
                "2",
                "10031262171927540148667355526369034398030886437092045105752248699557385197826",
                "633281375905621697187330766174974863687049529291089048651929454608812697683",
            ),
            (
                "3",
                "2763488322167937039616325905516046217694264098671987087929565332380420898366",
                "15305195750036305661220525648961313310481046260814497672243197092298550508693",
            ),
            (
                "7",
                "20092560661213339045022877747484245238324772779820628739268223482659246842641",
                "12112450042127193446189577552007703839818242727902437791835414514847797088033",
            ),
            (
                "12345",
                "19099552327547260981542886231210125691902505931204088720746463491300185142606",
                "13276557205153692030187527501273228448057533426731746626187331221465573305487",
            ),
        ];
        for (k, ex, ey) in cases {
            let p = mul(&base8(), &bu(k));
            assert_eq!(fr_to_dec(&p.x), *ex, "x mismatch at k={k}");
            assert_eq!(fr_to_dec(&p.y), *ey, "y mismatch at k={k}");
            assert!(in_curve(&p));
        }
    }
}
