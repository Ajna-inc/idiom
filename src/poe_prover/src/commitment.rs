//! Commitment circuit: prove `H = Poseidon(K)` for a private key `K`, bound to a
//! public challenge via a one-time `tag` — plus (next stage) Merkle membership
//! `H ∈ registry`. Turns the FE's plaintext `commit(K)==H` check into a proof a
//! third party verifies without seeing `K` or the face.
//!
//! Reuses `halo2_gadgets` Poseidon (Pow5 chip in-circuit + matching primitive
//! off-circuit over the Pasta field), so the published `H` and the proven `H`
//! are identical by construction. Pasta/IPA keeps it mobile-verifiable.
//!
//! STAGE 1 (this file): `Poseidon(K) == H` with `H` a public input.
//! K is 256 bits -> two 128-bit field limbs (each < the Pasta modulus).

use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error, Instance, ProvingKey, SingleVerifier, VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;

const WIDTH: usize = 3;
const RATE: usize = 2;
/// Circuit degree. One Poseidon permutation fits comfortably; bump when Merkle
/// membership (multiple hashes) is added.
pub const K_COMMIT: u32 = 7;

/// Split a 32-byte key into two 128-bit little-endian field limbs
/// (each < the Pasta modulus, so injective).
pub fn key_to_limbs(key: &[u8; 32]) -> [Fp; 2] {
    let limb = |b: &[u8]| {
        let w0 = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let w1 = u64::from_le_bytes(b[8..16].try_into().unwrap());
        Fp::from_raw([w0, w1, 0, 0])
    };
    [limb(&key[..16]), limb(&key[16..])]
}

/// Off-circuit commitment `H = Poseidon(K_lo, K_hi)` — the value published to the
/// registry. Matches the in-circuit chip bit-for-bit (same spec/params).
pub fn poseidon_commit(key: &[u8; 32]) -> Fp {
    use halo2_gadgets::poseidon::primitives::Hash;
    Hash::<Fp, P128Pow5T3, ConstantLength<2>, WIDTH, RATE>::init().hash(key_to_limbs(key))
}

#[derive(Clone)]
pub struct CommitConfig {
    /// Our own equality-enabled column to load the private K limbs.
    input: Column<Advice>,
    poseidon: Pow5Config<Fp, WIDTH, RATE>,
    instance: Column<Instance>,
}

#[derive(Clone, Default)]
pub struct CommitmentCircuit {
    /// Private key limbs; `None` for keygen.
    pub k: Option<[Fp; 2]>,
}

impl Circuit<Fp> for CommitmentCircuit {
    type Config = CommitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> CommitConfig {
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

        let input = meta.advice_column();
        meta.enable_equality(input);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);
        CommitConfig {
            input,
            poseidon,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: CommitConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon.clone());

        // Load the two private key limbs into our equality-enabled column; the
        // Poseidon gadget copy-constrains them into its own state.
        let f = |o: Option<Fp>| o.map(Value::known).unwrap_or_else(Value::unknown);
        let message: [AssignedCell<Fp, Fp>; 2] = layouter.assign_region(
            || "load K limbs",
            |mut region| {
                let k0 =
                    region.assign_advice(|| "k_lo", config.input, 0, || f(self.k.map(|k| k[0])))?;
                let k1 =
                    region.assign_advice(|| "k_hi", config.input, 1, || f(self.k.map(|k| k[1])))?;
                Ok([k0, k1])
            },
        )?;

        let hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let h = hasher.hash(layouter.namespace(|| "hash K"), message)?;

        // Prove the hash equals the public commitment.
        layouter.constrain_instance(h.cell(), config.instance, 0)
    }
}

/// Reusable prover/verifier: params + keys once, then prove/verify many times.
pub struct CommitmentProver {
    params: Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
    vk: VerifyingKey<EqAffine>,
}

impl CommitmentProver {
    pub fn new() -> Self {
        let params = Params::<EqAffine>::new(K_COMMIT);
        let empty = CommitmentCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("vk");
        let pk = keygen_pk(&params, vk.clone(), &empty).expect("pk");
        Self { params, pk, vk }
    }

    /// Prove knowledge of `K` with `Poseidon(K) == commitment`.
    pub fn prove(&self, key: &[u8; 32]) -> Vec<u8> {
        let circuit = CommitmentCircuit {
            k: Some(key_to_limbs(key)),
        };
        let h = poseidon_commit(key);
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(
            &self.params,
            &self.pk,
            &[circuit],
            &[&[&[h]]],
            OsRng,
            &mut transcript,
        )
        .expect("proof");
        transcript.finalize()
    }

    /// Verify a proof against a public commitment `H`.
    pub fn verify(&self, proof: &[u8], commitment: Fp) -> bool {
        let strategy = SingleVerifier::new(&self.params);
        let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
        verify_proof(
            &self.params,
            &self.vk,
            strategy,
            &[&[&[commitment]]],
            &mut transcript,
        )
        .is_ok()
    }
}

impl Default for CommitmentProver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn commit_matches_offcircuit() {
        let key = [3u8; 32];
        let h = poseidon_commit(&key);
        let circuit = CommitmentCircuit {
            k: Some(key_to_limbs(&key)),
        };
        MockProver::run(K_COMMIT, &circuit, vec![vec![h]])
            .unwrap()
            .assert_satisfied();
    }

    #[test]
    fn prove_and_verify() {
        let prover = CommitmentProver::new();
        let key = [42u8; 32];
        let proof = prover.prove(&key);
        assert!(
            prover.verify(&proof, poseidon_commit(&key)),
            "valid proof must verify"
        );
    }

    #[test]
    fn wrong_commitment_rejected() {
        let prover = CommitmentProver::new();
        let proof = prover.prove(&[42u8; 32]);
        assert!(
            !prover.verify(&proof, poseidon_commit(&[7u8; 32])),
            "wrong H must fail"
        );
    }
}
