//! Poseidon Merkle registry of commitments — the public list a third party
//! checks membership against. Sparse (empty subtrees collapse to precomputed
//! defaults), so a depth-`DEPTH` path is cheap even with few entries. Uses the
//! SAME `hash2` and direction convention as `membership::MembershipCircuit`, so
//! a path emitted here verifies in-circuit unchanged.

use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as Primitive, P128Pow5T3};
use halo2_proofs::pasta::Fp;

use crate::membership::DEPTH;

fn hash2(a: Fp, b: Fp) -> Fp {
    Primitive::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b])
}

/// Append-only sparse Merkle accumulator over Pasta `Fp` leaves.
pub struct Registry {
    leaves: Vec<Fp>,
    /// `defaults[l]` = root of an all-empty subtree of height `l`.
    defaults: [Fp; DEPTH + 1],
}

impl Registry {
    pub fn new() -> Self {
        let mut defaults = [Fp::zero(); DEPTH + 1];
        for l in 1..=DEPTH {
            defaults[l] = hash2(defaults[l - 1], defaults[l - 1]);
        }
        Self {
            leaves: Vec::new(),
            defaults,
        }
    }

    /// Register a commitment leaf; returns its index.
    pub fn insert(&mut self, leaf: Fp) -> usize {
        self.leaves.push(leaf);
        self.leaves.len() - 1
    }

    /// Register a key's commitment `H = Poseidon(K)`; returns its leaf index.
    pub fn insert_key(&mut self, key: &[u8; 32]) -> usize {
        self.insert(crate::membership::commitment(key))
    }

    /// The registry root as 32 LE bytes (matches the ZK public input).
    pub fn root_bytes(&self) -> [u8; 32] {
        use ff::PrimeField;
        self.root().to_repr()
    }

    /// Authentication path for `leaf_index` as bytes: `(siblings, dirs)`.
    pub fn path_bytes(&self, leaf_index: usize) -> (Vec<[u8; 32]>, Vec<bool>) {
        use ff::PrimeField;
        let (sib, dir) = self.path(leaf_index);
        (sib.iter().map(|f| f.to_repr()).collect(), dir.to_vec())
    }

    /// Node value at (`level`, `index`). Empty subtrees short-circuit to the
    /// default, so work is O(entries · DEPTH), not O(2^DEPTH).
    fn node(&self, level: usize, index: usize) -> Fp {
        let start = index << level;
        if start >= self.leaves.len() {
            return self.defaults[level]; // subtree holds no occupied leaf
        }
        if level == 0 {
            return self.leaves[index];
        }
        hash2(
            self.node(level - 1, index * 2),
            self.node(level - 1, index * 2 + 1),
        )
    }

    pub fn root(&self) -> Fp {
        self.node(DEPTH, 0)
    }

    /// Authentication path for `leaf_index`: (siblings, directions), where
    /// `dir[i]=true` means the current node is the RIGHT child at level `i`
    /// (matching the circuit's conditional-swap gate).
    pub fn path(&self, leaf_index: usize) -> ([Fp; DEPTH], [bool; DEPTH]) {
        let mut sib = [Fp::zero(); DEPTH];
        let mut dir = [false; DEPTH];
        let mut idx = leaf_index;
        for level in 0..DEPTH {
            sib[level] = self.node(level, idx ^ 1);
            dir[level] = idx & 1 == 1;
            idx >>= 1;
        }
        (sib, dir)
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::{commitment, merkle_root};

    #[test]
    fn path_folds_to_root() {
        let mut reg = Registry::new();
        let keys: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
        let idxs: Vec<usize> = keys.iter().map(|k| reg.insert(commitment(k))).collect();
        let root = reg.root();
        for (k, &idx) in keys.iter().zip(idxs.iter()) {
            let (sib, dir) = reg.path(idx);
            assert_eq!(
                merkle_root(commitment(k), &sib, &dir),
                root,
                "path must fold to the registry root"
            );
        }
    }
}
