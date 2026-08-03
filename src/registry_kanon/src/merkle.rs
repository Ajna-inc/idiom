//! The two Merkle roots Mode B publishes on `MerkleStateRegistry`:
//!
//!   - **Keccak root** — an OpenZeppelin StandardMerkleTree (keccak256 +
//!     sorted pairs), bit-for-bit compatible with `MerkleProof.verify`
//!     on-chain. Ports `did_kanon/v1_0/zk/merkle_keccak.py`.
//!   - **Poseidon root** — a fixed-depth (26) tagged-Poseidon tree matching
//!     the `non_revocation.circom` `MerkleInclusion` template
//!     (`Poseidon(NODE_TAG=2, left, right)`) and the kanon SDK's
//!     `PoseidonTree(26, …)`. Ports `did_kanon/v1_0/zk/merkle_poseidon.py`.
//!
//! Both are used only to recompute the root over the active leaf set during
//! revocation — proof generation lives on the (out-of-scope) presentation
//! side.

use std::collections::HashMap;

use ark_bn254::Fr;

use crate::error::{KanonError, Result};
use crate::ids::{keccak256, Bytes32};
use crate::poseidon::{felt_to_bytes32, poseidon_hash};

// ─── Keccak OZ StandardMerkleTree ────────────────────────────────────────

/// OZ sorted-pair hash — matches `MerkleProof._hashPair`.
fn hash_pair(a: &Bytes32, b: &Bytes32) -> Bytes32 {
    let mut buf = [0u8; 64];
    if a <= b {
        buf[..32].copy_from_slice(a);
        buf[32..].copy_from_slice(b);
    } else {
        buf[..32].copy_from_slice(b);
        buf[32..].copy_from_slice(a);
    }
    keccak256(&buf)
}

/// Root of an OZ StandardMerkleTree over 32-byte `leaves`.
///
/// Mirrors `OZStandardMerkleTree`: empty layers → all-zero root; a single
/// leaf → that leaf; odd leaves are promoted upward unchanged. Leaf order is
/// preserved (the caller supplies leaves in the order they were added on
/// chain).
pub fn oz_keccak_root(leaves: &[Bytes32]) -> Bytes32 {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<Bytes32> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next: Vec<Bytes32> = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            if i + 1 < layer.len() {
                next.push(hash_pair(&layer[i], &layer[i + 1]));
            } else {
                // OZ "odd leaf" handling — promote upward unchanged.
                next.push(layer[i]);
            }
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

// ─── Poseidon fixed-depth tagged tree ────────────────────────────────────

/// Domain-separation tag — MUST match `non_revocation.circom`'s
/// `var NODE_TAG = 2;`. Changing it silently breaks every existing proof.
pub const NODE_TAG: u64 = 2;

/// The compiled circuit's tree depth (`NonRevocation(26, …)`) and the SDK's
/// `PoseidonTree(26, …)`.
pub const POSEIDON_TREE_DEPTH: usize = 26;

/// Parent of two Merkle children: `Poseidon(NODE_TAG, left, right)`.
fn hash_node(left: Fr, right: Fr) -> Result<Fr> {
    poseidon_hash(&[Fr::from(NODE_TAG), left, right])
}

/// Root of a sparse fixed-depth tagged-Poseidon tree over BN254 `leaves`, at
/// `depth`. Ports `PoseidonMerkleTree.root`.
///
/// Empty subtrees use precomputed zero hashes per level
/// (`zeros[0] = 0`, `zeros[d] = H(zeros[d-1], zeros[d-1])`), so a depth-26
/// tree over a handful of leaves costs O(leaves × depth) hashes, never
/// `2^depth`.
pub fn poseidon_root(depth: usize, leaves: &[Fr]) -> Result<Fr> {
    if depth < 1 {
        return Err(KanonError::Invalid("depth must be >= 1".into()));
    }
    let max_leaves: u128 = 1u128 << depth;
    if (leaves.len() as u128) > max_leaves {
        return Err(KanonError::Invalid(format!(
            "too many leaves ({}) for depth {depth} (max {max_leaves})",
            leaves.len()
        )));
    }

    // zeros[level] — value of an entirely empty subtree rooted at `level`.
    let mut zeros: Vec<Fr> = vec![Fr::from(0u64); depth + 1];
    for d in 1..=depth {
        zeros[d] = hash_node(zeros[d - 1], zeros[d - 1])?;
    }

    // Per-level sparse maps {index → value}; missing indices fall back to
    // zeros[level].
    let mut nodes: Vec<HashMap<u64, Fr>> = (0..=depth).map(|_| HashMap::new()).collect();

    let node_at = |nodes: &Vec<HashMap<u64, Fr>>, level: usize, index: u64| -> Fr {
        *nodes[level].get(&index).unwrap_or(&zeros[level])
    };

    for (leaf_index, leaf) in leaves.iter().enumerate() {
        let li = leaf_index as u64;
        nodes[0].insert(li, *leaf);
        let mut idx = li;
        for level in 0..depth {
            let is_right = idx & 1;
            let (left, right) = if is_right == 1 {
                (node_at(&nodes, level, idx - 1), node_at(&nodes, level, idx))
            } else {
                (node_at(&nodes, level, idx), node_at(&nodes, level, idx + 1))
            };
            idx /= 2;
            let parent = hash_node(left, right)?;
            nodes[level + 1].insert(idx, parent);
        }
    }

    Ok(node_at(&nodes, depth, 0))
}

/// Depth-26 Poseidon root over the active leaves, returned as on-chain
/// `bytes32` (`felt_to_bytes32(root)`). This is exactly the value the Python
/// `KanonZkIssuer._compute_poseidon_root` publishes.
pub fn poseidon_root_bytes32(leaves: &[Fr]) -> Result<Bytes32> {
    Ok(felt_to_bytes32(poseidon_root(POSEIDON_TREE_DEPTH, leaves)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::felt_from_be_bytes;

    fn leaf(name: &str) -> Bytes32 {
        keccak256(name.as_bytes())
    }

    // ── Keccak OZ tree KATs (from test_merkle_keccak.py + Python reference) ──

    #[test]
    fn oz_single_leaf_root_is_the_leaf() {
        // test_single_leaf_root_is_the_leaf
        assert_eq!(oz_keccak_root(&[leaf("only")]), leaf("only"));
        assert_eq!(
            hex::encode(oz_keccak_root(&[leaf("only")])),
            "0b8af30d93fe6f6056cc4381f3fe4c92ab4c6fa34ec1edc8baa4edf881e0a95a"
        );
    }

    #[test]
    fn oz_eight_leaves_root_matches_reference() {
        let leaves: Vec<Bytes32> = (0..8).map(|i| leaf(&format!("cred-{i}"))).collect();
        assert_eq!(
            hex::encode(oz_keccak_root(&leaves)),
            "c0c08a53a8326e6e9c16e142d63d5a2c291fc0c1b565da1adee177d426f062cb"
        );
    }

    #[test]
    fn oz_odd_count_promotes_unchanged() {
        // test_odd_count_handled — 3 leaves p,q,r.
        let leaves = [leaf("p"), leaf("q"), leaf("r")];
        assert_eq!(
            hex::encode(oz_keccak_root(&leaves)),
            "7bec420b80ce1ca3f13e91c63fca73768da7cb931e96dc07c3ac2264a21c6ca2"
        );
    }

    #[test]
    fn oz_empty_single_zero_leaf_root() {
        // KanonZkIssuer empty-set convention: a single zero leaf → the zero
        // leaf itself.
        assert_eq!(oz_keccak_root(&[[0u8; 32]]), [0u8; 32]);
    }

    // ── Poseidon tree KATs (from Python reference over vendored constants) ──

    fn fr_dec(dec: &str) -> Fr {
        use std::str::FromStr;
        Fr::from_str(dec).unwrap()
    }

    #[test]
    fn poseidon_depth3_single_leaf_root() {
        let root = poseidon_root(3, &[Fr::from(42u64)]).unwrap();
        assert_eq!(
            root,
            fr_dec("1700324920755279478603300888573230232288220210580399326400408641703996185080")
        );
    }

    #[test]
    fn poseidon_depth3_full_tree_root() {
        let leaves: Vec<Fr> = (1u64..=8).map(Fr::from).collect();
        let root = poseidon_root(3, &leaves).unwrap();
        assert_eq!(
            root,
            fr_dec("14664817687664360159712822085312303716612528823190773569409131094480095690526")
        );
    }

    #[test]
    fn poseidon_depth26_single_leaf_root() {
        let root = poseidon_root(POSEIDON_TREE_DEPTH, &[Fr::from(42u64)]).unwrap();
        assert_eq!(
            root,
            fr_dec("12794850040145268117979718839916616651727494700061926706466956509647499825798")
        );
    }

    #[test]
    fn poseidon_depth26_three_leaves_root() {
        let leaves = [Fr::from(111u64), Fr::from(222u64), Fr::from(333u64)];
        let root = poseidon_root(POSEIDON_TREE_DEPTH, &leaves).unwrap();
        assert_eq!(
            root,
            fr_dec("11767775341457996759057411767165553922121981056584838025017289029464953496428")
        );
    }

    #[test]
    fn poseidon_root_bytes32_matches_python_felt_encoding() {
        // Revoke scenario from the Python reference: remaining leaves
        // [1000, 3000] → depth-26 poseidon root, felt_to_bytes32.
        let leaves = [Fr::from(1000u64), Fr::from(3000u64)];
        let b = poseidon_root_bytes32(&leaves).unwrap();
        assert_eq!(
            hex::encode(b),
            "03cc0962f295e7bc4a8ae216b353ecdb996cf0ce5065369684755ba3809a4439"
        );
        // And the felt round-trips.
        assert_eq!(
            felt_from_be_bytes(&b),
            poseidon_root(POSEIDON_TREE_DEPTH, &leaves).unwrap()
        );
    }

    #[test]
    fn poseidon_too_many_leaves_for_depth_errors() {
        // depth 2 → max 4 leaves.
        assert!(poseidon_root(2, &(0u64..5).map(Fr::from).collect::<Vec<_>>()).is_err());
    }
}
