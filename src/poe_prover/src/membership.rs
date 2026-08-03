//! Full "matching" proof: prove knowledge of a private key `K` such that
//!   1. `H = Poseidon(K)`                      (commitment)
//!   2. `H ∈ registry`  (Merkle path -> public root)   (anonymous 1:N membership)
//!   3. `tag = Poseidon(K, challenge)`          (one-time, unlinkable binding)
//!
//! Public inputs: `[root, challenge, tag]`. `H` stays PRIVATE (revealing it would
//! let an observer brute-force which registry leaf you are). The tag binds the
//! SECRET `K` (not public `H`) to the challenge, so it can't be de-anonymised.
//!
//! Reuses the `halo2_gadgets` Pow5 Poseidon chip for every hash (leaf, each
//! Merkle level, and the tag). A per-level conditional-swap gate orders
//! (cur, sibling) by a private direction bit.

use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as Primitive, P128Pow5T3};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error, Expression, Instance, ProvingKey, Selector, SingleVerifier, VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;

use crate::commitment::key_to_limbs;

const WIDTH: usize = 3;
const RATE: usize = 2;
/// Merkle tree depth (supports up to 2^DEPTH registered commitments).
pub const DEPTH: usize = 16;
/// Circuit degree: leaf + DEPTH level hashes + tag. Bump if keygen overflows.
pub const K_MEMBERSHIP: u32 = 12;

// ---- off-circuit reference (matches the in-circuit chip bit-for-bit) --------
fn hash2(a: Fp, b: Fp) -> Fp {
    Primitive::<Fp, P128Pow5T3, ConstantLength<2>, WIDTH, RATE>::init().hash([a, b])
}
fn hash3(a: Fp, b: Fp, c: Fp) -> Fp {
    Primitive::<Fp, P128Pow5T3, ConstantLength<3>, WIDTH, RATE>::init().hash([a, b, c])
}

/// `H = Poseidon(K)` — the registry leaf.
pub fn commitment(key: &[u8; 32]) -> Fp {
    let [lo, hi] = key_to_limbs(key);
    hash2(lo, hi)
}

/// The registry leaf as 32 LE bytes — matches `fe::kdf::commit_poseidon`.
pub fn commitment_bytes(key: &[u8; 32]) -> [u8; 32] {
    use ff::PrimeField;
    commitment(key).to_repr()
}

/// Fold arbitrary bytes into the Pasta field via 128-bit little-endian limbs
/// (Horner base 2^128) — deterministic and injective enough for domain binding.
fn field_from_bytes(b: &[u8]) -> Fp {
    use ff::PrimeField;
    let two128 = Fp::from_raw([0, 0, 1, 0]); // 2^128
    let mut acc = Fp::zero();
    for chunk in b.chunks(16) {
        let mut limb = [0u8; 32];
        limb[..chunk.len()].copy_from_slice(chunk);
        acc = acc * two128 + Fp::from_repr(limb).unwrap();
    }
    acc
}

/// PoE context binding: `challenge = Poseidon(nonce, context_hash, session_id)`.
/// The circuit's public `challenge` input MUST equal this — that's the anti-replay
/// / anti-cross-use binding required by `didcomm.org/poe/1.0`.
pub fn challenge_from_binding(nonce: &[u8], context_hash: &[u8], session_id: &[u8]) -> Fp {
    hash3(
        field_from_bytes(nonce),
        field_from_bytes(context_hash),
        field_from_bytes(session_id),
    )
}

/// `challenge_from_binding` as 32 LE bytes.
pub fn challenge_bytes(nonce: &[u8], context_hash: &[u8], session_id: &[u8]) -> [u8; 32] {
    use ff::PrimeField;
    challenge_from_binding(nonce, context_hash, session_id).to_repr()
}

fn fp_from_bytes(b: &[u8; 32]) -> Fp {
    use ff::PrimeField;
    Fp::from_repr(*b).unwrap()
}
fn fp_to_bytes(f: Fp) -> [u8; 32] {
    use ff::PrimeField;
    f.to_repr()
}
/// Fold a Merkle authentication path to its root. `dir[i]=false` => cur is the
/// left child at level i.
pub fn merkle_root(leaf: Fp, siblings: &[Fp], dirs: &[bool]) -> Fp {
    let mut cur = leaf;
    for (s, d) in siblings.iter().zip(dirs.iter()) {
        cur = if *d { hash2(*s, cur) } else { hash2(cur, *s) };
    }
    cur
}
/// One-time challenge tag binding the SECRET key.
pub fn tag(key: &[u8; 32], challenge: Fp) -> Fp {
    let [lo, hi] = key_to_limbs(key);
    hash3(lo, hi, challenge)
}

// ---- circuit ----------------------------------------------------------------
#[derive(Clone)]
pub struct MembershipConfig {
    // load column for private field inputs (k limbs, siblings)
    load: Column<Advice>,
    // conditional-swap gate columns
    cur: Column<Advice>,
    sib: Column<Advice>,
    dir: Column<Advice>,
    left: Column<Advice>,
    right: Column<Advice>,
    s_swap: Selector,
    poseidon: Pow5Config<Fp, WIDTH, RATE>,
    instance: Column<Instance>,
}

#[derive(Clone, Default)]
pub struct MembershipCircuit {
    pub k: Option<[Fp; 2]>,
    pub siblings: Option<[Fp; DEPTH]>,
    pub dirs: Option<[bool; DEPTH]>,
}

impl MembershipCircuit {
    fn hasher2(
        &self,
        config: &MembershipConfig,
        mut layouter: impl Layouter<Fp>,
        a: AssignedCell<Fp, Fp>,
        b: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let chip = Pow5Chip::construct(config.poseidon.clone());
        let h = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init2"),
        )?;
        h.hash(layouter.namespace(|| "hash2"), [a, b])
    }
}

impl Circuit<Fp> for MembershipCircuit {
    type Config = MembershipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> MembershipConfig {
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let partial_sbox = meta.advice_column();
        let rc_a = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_b = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        meta.enable_constant(rc_b[0]);

        let load = meta.advice_column();
        let cur = meta.advice_column();
        let sib = meta.advice_column();
        let dir = meta.advice_column();
        let left = meta.advice_column();
        let right = meta.advice_column();
        for c in [load, cur, left, right] {
            meta.enable_equality(c);
        }
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let s_swap = meta.selector();
        meta.create_gate("cond swap", |meta| {
            let s = meta.query_selector(s_swap);
            let cur = meta.query_advice(cur, Rotation::cur());
            let sib = meta.query_advice(sib, Rotation::cur());
            let d = meta.query_advice(dir, Rotation::cur());
            let left = meta.query_advice(left, Rotation::cur());
            let right = meta.query_advice(right, Rotation::cur());
            let one = Expression::Constant(Fp::one());
            let boolean = d.clone() * (one - d.clone());
            // left  = cur + d*(sib-cur) ; right = sib + d*(cur-sib)
            let lc = left - (cur.clone() + d.clone() * (sib.clone() - cur.clone()));
            let rc = right - (sib.clone() + d * (cur - sib));
            vec![s.clone() * boolean, s.clone() * lc, s * rc]
        });

        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);
        MembershipConfig {
            load,
            cur,
            sib,
            dir,
            left,
            right,
            s_swap,
            poseidon,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: MembershipConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let f = |o: Option<Fp>| o.map(Value::known).unwrap_or_else(Value::unknown);

        // load private k limbs
        let (k0, k1) = layouter.assign_region(
            || "load K",
            |mut region| {
                let k0 =
                    region.assign_advice(|| "k0", config.load, 0, || f(self.k.map(|k| k[0])))?;
                let k1 =
                    region.assign_advice(|| "k1", config.load, 1, || f(self.k.map(|k| k[1])))?;
                Ok((k0, k1))
            },
        )?;

        // 1) leaf commitment H = Poseidon(k0, k1)
        let mut cur = self.hasher2(
            &config,
            layouter.namespace(|| "leaf"),
            k0.clone(),
            k1.clone(),
        )?;

        // 2) Merkle path -> root
        for i in 0..DEPTH {
            let sib_v = f(self.siblings.map(|s| s[i]));
            let dir_v = self.dirs.map(|d| if d[i] { Fp::one() } else { Fp::zero() });
            let (left, right) = layouter.assign_region(
                || "swap",
                |mut region| {
                    config.s_swap.enable(&mut region, 0)?;
                    let cur_c = cur.copy_advice(|| "cur", &mut region, config.cur, 0)?;
                    region.assign_advice(|| "sib", config.sib, 0, || sib_v)?;
                    region.assign_advice(|| "dir", config.dir, 0, || f(dir_v))?;
                    let cur_val = cur_c.value().copied();
                    let d = f(dir_v);
                    let left_v = cur_val + d * (sib_v - cur_val);
                    let right_v = sib_v + d * (cur_val - sib_v);
                    let left = region.assign_advice(|| "left", config.left, 0, || left_v)?;
                    let right = region.assign_advice(|| "right", config.right, 0, || right_v)?;
                    Ok((left, right))
                },
            )?;
            cur = self.hasher2(&config, layouter.namespace(|| "level"), left, right)?;
        }
        // constrain recomputed root == public instance[0]
        layouter.constrain_instance(cur.cell(), config.instance, 0)?;

        // 3) tag = Poseidon(k0, k1, challenge), challenge = public instance[1]
        let chal = layouter.assign_region(
            || "load challenge",
            |mut region| {
                region.assign_advice_from_instance(|| "chal", config.instance, 1, config.load, 2)
            },
        )?;
        let chip = Pow5Chip::construct(config.poseidon.clone());
        let h3 = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<3>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init3"),
        )?;
        let tag_cell = h3.hash(layouter.namespace(|| "tag"), [k0, k1, chal])?;
        layouter.constrain_instance(tag_cell.cell(), config.instance, 2)
    }
}

// ---- prover -----------------------------------------------------------------
pub struct MembershipProver {
    params: Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
    vk: VerifyingKey<EqAffine>,
}

impl MembershipProver {
    pub fn new() -> Self {
        let params = Params::<EqAffine>::new(K_MEMBERSHIP);
        let empty = MembershipCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("vk");
        let pk = keygen_pk(&params, vk.clone(), &empty).expect("pk");
        Self { params, pk, vk }
    }

    /// Prove `K` is registered (leaf under `root`) for this `challenge`.
    /// Returns (proof, tag). Public inputs are `[root, challenge, tag]`.
    pub fn prove(
        &self,
        key: &[u8; 32],
        siblings: &[Fp; DEPTH],
        dirs: &[bool; DEPTH],
        challenge: Fp,
    ) -> (Vec<u8>, Fp) {
        let leaf = commitment(key);
        let root = merkle_root(leaf, siblings, dirs);
        let t = tag(key, challenge);
        let circuit = MembershipCircuit {
            k: Some(key_to_limbs(key)),
            siblings: Some(*siblings),
            dirs: Some(*dirs),
        };
        let pubs = [root, challenge, t];
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(
            &self.params,
            &self.pk,
            &[circuit],
            &[&[&pubs]],
            OsRng,
            &mut transcript,
        )
        .expect("proof");
        (transcript.finalize(), t)
    }

    pub fn verify(&self, proof: &[u8], root: Fp, challenge: Fp, tag: Fp) -> bool {
        let strategy = SingleVerifier::new(&self.params);
        let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
        verify_proof(
            &self.params,
            &self.vk,
            strategy,
            &[&[&[root, challenge, tag]]],
            &mut transcript,
        )
        .is_ok()
    }

    // ---- bytes-only PoE API (keeps callers free of the field type) ----

    /// Prove membership bound to a PoE `{nonce, context_hash, session_id}`.
    /// `siblings`/`dirs` are the registry path (length `DEPTH`).
    /// Returns `(proof, root_bytes, tag_bytes)` — all 32 LE bytes.
    pub fn prove_poe(
        &self,
        key: &[u8; 32],
        siblings: &[[u8; 32]],
        dirs: &[bool],
        nonce: &[u8],
        context_hash: &[u8],
        session_id: &[u8],
    ) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        assert_eq!(siblings.len(), DEPTH, "siblings must be DEPTH long");
        assert_eq!(dirs.len(), DEPTH, "dirs must be DEPTH long");
        let mut sib = [Fp::zero(); DEPTH];
        let mut dir = [false; DEPTH];
        for i in 0..DEPTH {
            sib[i] = fp_from_bytes(&siblings[i]);
            dir[i] = dirs[i];
        }
        let challenge = challenge_from_binding(nonce, context_hash, session_id);
        let root = merkle_root(commitment(key), &sib, &dir);
        let (proof, tag) = self.prove(key, &sib, &dir, challenge);
        (proof, fp_to_bytes(root), fp_to_bytes(tag))
    }

    /// Verify a PoE membership proof against a trusted `root` and the expected
    /// `{nonce, context_hash, session_id}` (recomputes the challenge binding).
    pub fn verify_poe(
        &self,
        proof: &[u8],
        root: &[u8; 32],
        nonce: &[u8],
        context_hash: &[u8],
        session_id: &[u8],
        tag: &[u8; 32],
    ) -> bool {
        let challenge = challenge_from_binding(nonce, context_hash, session_id);
        self.verify(proof, fp_from_bytes(root), challenge, fp_from_bytes(tag))
    }
}

impl Default for MembershipProver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use rand::Rng;

    fn sample_path() -> ([Fp; DEPTH], [bool; DEPTH]) {
        let mut rng = rand::thread_rng();
        let mut sib = [Fp::zero(); DEPTH];
        let mut dir = [false; DEPTH];
        for i in 0..DEPTH {
            sib[i] = Fp::from(rng.gen::<u64>());
            dir[i] = rng.gen::<bool>();
        }
        (sib, dir)
    }

    #[test]
    fn membership_mock_satisfied() {
        let key = [9u8; 32];
        let (sib, dir) = sample_path();
        let root = merkle_root(commitment(&key), &sib, &dir);
        let chal = Fp::from(12345u64);
        let t = tag(&key, chal);
        let circuit = MembershipCircuit {
            k: Some(key_to_limbs(&key)),
            siblings: Some(sib),
            dirs: Some(dir),
        };
        MockProver::run(K_MEMBERSHIP, &circuit, vec![vec![root, chal, t]])
            .unwrap()
            .assert_satisfied();
    }

    #[test]
    fn prove_verify_and_reject() {
        let prover = MembershipProver::new();
        let key = [42u8; 32];
        let (sib, dir) = sample_path();
        let root = merkle_root(commitment(&key), &sib, &dir);
        let chal = Fp::from(777u64);
        let (proof, t) = prover.prove(&key, &sib, &dir, chal);
        assert!(
            prover.verify(&proof, root, chal, t),
            "valid membership must verify"
        );
        // wrong root (non-member) must fail
        assert!(
            !prover.verify(&proof, Fp::from(1u64), chal, t),
            "non-member root must fail"
        );
        // replaying with a different challenge must fail (tag mismatch)
        assert!(
            !prover.verify(&proof, root, Fp::from(888u64), t),
            "replayed challenge must fail"
        );
    }

    #[test]
    fn tag_is_challenge_bound() {
        let key = [5u8; 32];
        assert_ne!(
            tag(&key, Fp::from(1u64)),
            tag(&key, Fp::from(2u64)),
            "tag must change with challenge"
        );
    }
}
