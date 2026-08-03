//! Cross-platform halo2 prover for PoE liveness.
//!
//! Circuit (`LivenessCircuit`): prove knowledge of a private `score` such that
//! `score >= tau`, bound to a public `{tau, nonce}` — i.e. "liveness passed for
//! THIS challenge" without revealing the score. `tau` and `nonce` are public
//! instances (the PoE binding); `score` and its bit-decomposition are private.
//!
//! `score >= tau` is enforced by decomposing `diff = score - tau` into 64 bits
//! (each boolean, reconstructing `diff`) — a negative diff cannot be
//! represented, so a failing liveness score simply cannot be proven.
//!
//! Full-MLP-in-circuit is the documented next layer: replace the `score` witness
//! with `score = Σ wᵢ·xᵢ` (the same mul-add + range-check pattern, more rows).
//!
//! Uses IPA/Pasta (crates.io `halo2_proofs`), which cross-compiles to mobile.
//! Swapping to KZG/BN256 (for EVM on-chain verify) is a backend change later.

pub mod commitment;
pub mod membership;
pub mod registry;

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error, Expression, Fixed, Instance, ProvingKey, Selector, SingleVerifier, VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;

const BITS: usize = 64;
/// Circuit rows: 1 (subtraction) + BITS (decomposition). k must give 2^k > that.
pub const K: u32 = 8;

// --------------------------------------------------------------------------
#[derive(Clone)]
pub struct LivenessConfig {
    score: Column<Advice>,
    tau: Column<Advice>,
    nonce: Column<Advice>,
    diff: Column<Advice>,
    bit: Column<Advice>,
    acc: Column<Advice>,
    coeff: Column<Fixed>,
    instance: Column<Instance>,
    s_sub: Selector,
    s_dec: Selector,
}

#[derive(Clone, Default)]
pub struct LivenessCircuit {
    /// Private witness; `None` for keygen (`without_witnesses`).
    pub score: Option<u64>,
    pub tau: Option<u64>,
}

impl Circuit<Fp> for LivenessCircuit {
    type Config = LivenessConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> LivenessConfig {
        let score = meta.advice_column();
        let tau = meta.advice_column();
        let nonce = meta.advice_column();
        let diff = meta.advice_column();
        let bit = meta.advice_column();
        let acc = meta.advice_column();
        let coeff = meta.fixed_column();
        let instance = meta.instance_column();
        for c in [score, tau, nonce, diff, acc] {
            meta.enable_equality(c);
        }
        meta.enable_equality(instance);
        let s_sub = meta.selector();
        let s_dec = meta.selector();

        // score - tau - diff = 0  (tau is the copied public instance)
        meta.create_gate("sub", |meta| {
            let s = meta.query_selector(s_sub);
            let score = meta.query_advice(score, Rotation::cur());
            let tau = meta.query_advice(tau, Rotation::cur());
            let diff = meta.query_advice(diff, Rotation::cur());
            vec![s * (score - tau - diff)]
        });

        // per bit row: bit boolean, and acc_cur = acc_prev + bit*coeff
        meta.create_gate("decompose", |meta| {
            let s = meta.query_selector(s_dec);
            let b = meta.query_advice(bit, Rotation::cur());
            let coeff = meta.query_fixed(coeff);
            let acc_prev = meta.query_advice(acc, Rotation::prev());
            let acc_cur = meta.query_advice(acc, Rotation::cur());
            let boolean = b.clone() * (Expression::Constant(Fp::one()) - b.clone());
            let running = acc_cur - acc_prev - b * coeff;
            vec![s.clone() * boolean, s * running]
        });

        LivenessConfig {
            score,
            tau,
            nonce,
            diff,
            bit,
            acc,
            coeff,
            instance,
            s_sub,
            s_dec,
        }
    }

    fn synthesize(
        &self,
        config: LivenessConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let diff_u64 = match (self.score, self.tau) {
            (Some(s), Some(t)) => Some(s.checked_sub(t).expect("score < tau: liveness fail")),
            _ => None,
        };
        let f = |o: Option<u64>| {
            o.map(Fp::from)
                .map(Value::known)
                .unwrap_or_else(Value::unknown)
        };

        layouter.assign_region(
            || "liveness",
            |mut region| {
                // row 0: bind tau + nonce from instance, witness score/diff, acc=0
                config.s_sub.enable(&mut region, 0)?;
                let tau_cell = region.assign_advice_from_instance(
                    || "tau",
                    config.instance,
                    0,
                    config.tau,
                    0,
                )?;
                region.assign_advice_from_instance(
                    || "nonce",
                    config.instance,
                    1,
                    config.nonce,
                    0,
                )?;
                let score_cell =
                    region.assign_advice(|| "score", config.score, 0, || f(self.score))?;
                let diff_cell = region.assign_advice(|| "diff", config.diff, 0, || f(diff_u64))?;
                let _ = (tau_cell, score_cell);
                let mut acc_cell =
                    region.assign_advice(|| "acc0", config.acc, 0, || Value::known(Fp::zero()))?;

                // rows 1..=BITS: bit decomposition of diff
                let mut acc_val = Fp::zero();
                for i in 0..BITS {
                    let row = i + 1;
                    config.s_dec.enable(&mut region, row)?;
                    let coeff = Fp::from(1u64 << i);
                    region.assign_fixed(|| "coeff", config.coeff, row, || Value::known(coeff))?;
                    let bit_u = diff_u64.map(|d| (d >> i) & 1);
                    region.assign_advice(|| "bit", config.bit, row, || f(bit_u))?;
                    acc_val += Fp::from(bit_u.unwrap_or(0)) * coeff;
                    acc_cell = region.assign_advice(
                        || "acc",
                        config.acc,
                        row,
                        || {
                            diff_u64
                                .map(|_| acc_val)
                                .map(Value::known)
                                .unwrap_or_else(Value::unknown)
                        },
                    )?;
                }
                // final acc == diff  → proves score - tau = Σ bitᵢ·2ⁱ ≥ 0
                region.constrain_equal(acc_cell.cell(), diff_cell.cell())?;
                Ok(())
            },
        )
    }
}

// --------------------------------------------------------------------------
/// Reusable prover: params + keys generated once, then prove/verify many times.
pub struct LivenessProver {
    params: Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
    vk: VerifyingKey<EqAffine>,
}

/// Map a 32-byte nonce into the field (the PoE binding), via base-256 Horner.
pub fn nonce_to_field(nonce: &[u8; 32]) -> Fp {
    let mut acc = Fp::zero();
    let base = Fp::from(256u64);
    for b in nonce.iter() {
        acc = acc * base + Fp::from(*b as u64);
    }
    acc
}

impl LivenessProver {
    pub fn new() -> Self {
        let params = Params::<EqAffine>::new(K);
        let empty = LivenessCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("vk");
        let pk = keygen_pk(&params, vk.clone(), &empty).expect("pk");
        Self { params, pk, vk }
    }

    /// Public inputs: [tau, nonce]. Returns None if score < tau (can't prove).
    pub fn prove(&self, score: u64, tau: u64, nonce: &[u8; 32]) -> Option<Vec<u8>> {
        if score < tau {
            return None;
        }
        let circuit = LivenessCircuit {
            score: Some(score),
            tau: Some(tau),
        };
        let pubs = [Fp::from(tau), nonce_to_field(nonce)];
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(
            &self.params,
            &self.pk,
            &[circuit],
            &[&[&pubs]],
            OsRng,
            &mut transcript,
        )
        .ok()?;
        Some(transcript.finalize())
    }

    pub fn verify(&self, proof: &[u8], tau: u64, nonce: &[u8; 32]) -> bool {
        let pubs = [Fp::from(tau), nonce_to_field(nonce)];
        let strategy = SingleVerifier::new(&self.params);
        let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
        verify_proof(
            &self.params,
            &self.vk,
            strategy,
            &[&[&pubs]],
            &mut transcript,
        )
        .is_ok()
    }
}

impl Default for LivenessProver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn mock_prover_pass() {
        let circuit = LivenessCircuit {
            score: Some(9500),
            tau: Some(9000),
        };
        let pubs = vec![Fp::from(9000), nonce_to_field(&[7u8; 32])];
        MockProver::run(K, &circuit, vec![pubs])
            .unwrap()
            .assert_satisfied();
    }

    #[test]
    fn prove_and_verify() {
        let prover = LivenessProver::new();
        let nonce = [42u8; 32];
        let proof = prover.prove(9500, 9000, &nonce).expect("should prove");
        assert!(
            prover.verify(&proof, 9000, &nonce),
            "valid proof must verify"
        );
    }

    #[test]
    fn wrong_nonce_rejected() {
        let prover = LivenessProver::new();
        let proof = prover.prove(9500, 9000, &[1u8; 32]).unwrap();
        assert!(
            !prover.verify(&proof, 9000, &[2u8; 32]),
            "different nonce must fail"
        );
    }

    #[test]
    fn failing_score_cannot_prove() {
        let prover = LivenessProver::new();
        assert!(
            prover.prove(8000, 9000, &[1u8; 32]).is_none(),
            "score < tau: no proof"
        );
    }
}
