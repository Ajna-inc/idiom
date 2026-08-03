//! Selective Disclosure & Merkle Proofs
//!
//! Implements field-level selective disclosure with Merkle proofs against did_root.
//! Allows presenting only needed fields with cryptographic proofs.

use crate::ajna::crypto::{hash_with_dst, Hash, DST_AJNA_FIELD};
use crate::ajna::{AjnaDocument, AjnaError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Field path in DID Document (normalized)
/// Example: "/verificationMethod/0/publicKeyMultibase"
pub type FieldPath = String;

/// Field value (serialized as canonical JSON)
pub type FieldValue = Vec<u8>;

/// Merkle proof for a field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldProof {
    /// Field path (e.g., "/service[id='didcomm']/serviceEndpoint")
    pub path: FieldPath,

    /// Field value (canonical JSON bytes)
    pub value: FieldValue,

    /// Merkle sibling hashes for proof
    pub proof: Vec<Hash>,

    /// Index in the tree
    pub index: usize,
}

/// Merkle tree index over DID Document fields
#[derive(Debug, Clone)]
pub struct FieldIndex {
    /// Map from field path to (hash, value, index)
    fields: HashMap<FieldPath, (Hash, FieldValue, usize)>,

    /// Merkle tree (bottom-up)
    tree: Vec<Vec<Hash>>,

    /// Root hash
    root: Hash,
}

impl FieldIndex {
    /// Build field index from a DID Document
    ///
    /// # Arguments
    /// * `doc` - The DID Document to index
    ///
    /// # Returns
    /// Field index with Merkle tree
    pub fn build(doc: &AjnaDocument) -> Result<Self> {
        let mut fields = HashMap::new();
        let mut leaves = Vec::new();

        // Extract all fields with paths
        Self::extract_fields(doc, &mut fields, &mut leaves)?;

        // Build Merkle tree
        let tree = Self::build_merkle_tree(&leaves);
        let root = tree
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or([0u8; 32]);

        Ok(Self { fields, tree, root })
    }

    /// Extract fields from document with normalized paths
    fn extract_fields(
        doc: &AjnaDocument,
        fields: &mut HashMap<FieldPath, (Hash, FieldValue, usize)>,
        leaves: &mut Vec<Hash>,
    ) -> Result<()> {
        let mut index = 0;

        // DID id
        Self::add_field("/id", &doc.id, fields, leaves, &mut index)?;

        // Controllers
        if let Some(ref controllers) = doc.controller {
            for (i, controller) in controllers.elements().into_iter().enumerate() {
                let path = format!("/controller/{}", i);
                Self::add_field(&path, &controller, fields, leaves, &mut index)?;
            }
        }

        // Verification methods
        for (i, vm) in doc.verification_methods.elements().into_iter().enumerate() {
            let base = format!("/verificationMethod/{}", i);
            Self::add_field(&format!("{}/id", base), &vm.id, fields, leaves, &mut index)?;
            Self::add_field(
                &format!("{}/type", base),
                &vm.type_,
                fields,
                leaves,
                &mut index,
            )?;
            Self::add_field(
                &format!("{}/controller", base),
                &vm.controller,
                fields,
                leaves,
                &mut index,
            )?;
            Self::add_field(
                &format!("{}/publicKeyMultibase", base),
                &vm.public_key_multibase,
                fields,
                leaves,
                &mut index,
            )?;

            if let Some(ref purpose) = vm.purpose {
                for (j, p) in purpose.iter().enumerate() {
                    Self::add_field(
                        &format!("{}/purpose/{}", base, j),
                        p,
                        fields,
                        leaves,
                        &mut index,
                    )?;
                }
            }
        }

        // Services
        if let Some(ref services) = doc.service {
            for (key, service) in services.entries() {
                let base = format!("/service/{}", key);
                Self::add_field(
                    &format!("{}/id", base),
                    &service.id,
                    fields,
                    leaves,
                    &mut index,
                )?;
                Self::add_field(
                    &format!("{}/type", base),
                    &service.type_,
                    fields,
                    leaves,
                    &mut index,
                )?;
                Self::add_field(
                    &format!("{}/serviceEndpoint", base),
                    &service.service_endpoint,
                    fields,
                    leaves,
                    &mut index,
                )?;
            }
        }

        // Policy (LWW-Map)
        if let Some(ref policy) = doc.policy {
            for (key, value) in policy.entries() {
                let path = format!("/policy/{}", key);
                Self::add_field(&path, &value, fields, leaves, &mut index)?;
            }
        }

        // Deactivated
        if let Some(deactivated) = doc.deactivated {
            Self::add_field("/deactivated", &deactivated, fields, leaves, &mut index)?;
        }

        Ok(())
    }

    /// Add a field to the index
    fn add_field<T: Serialize>(
        path: &str,
        value: &T,
        fields: &mut HashMap<FieldPath, (Hash, FieldValue, usize)>,
        leaves: &mut Vec<Hash>,
        index: &mut usize,
    ) -> Result<()> {
        // Serialize value to canonical JSON
        let value_bytes =
            serde_json::to_vec(value).map_err(|e| AjnaError::SerializationError(e.to_string()))?;

        // Hash: Blake3("AJNA/FIELD/V1" || path || value)
        let hash = hash_field(path, &value_bytes);

        // Store
        fields.insert(path.to_string(), (hash, value_bytes.clone(), *index));
        leaves.push(hash);
        *index += 1;

        Ok(())
    }

    /// Build Merkle tree from leaves (bottom-up)
    fn build_merkle_tree(leaves: &[Hash]) -> Vec<Vec<Hash>> {
        if leaves.is_empty() {
            return vec![vec![[0u8; 32]]];
        }

        let mut tree = vec![leaves.to_vec()];

        while tree.last().unwrap().len() > 1 {
            let current_level = tree.last().unwrap();
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    // Hash pair
                    next_level.push(hash_pair(&current_level[i], &current_level[i + 1]));
                } else {
                    // Odd node: hash with itself (standard Merkle tree behavior)
                    next_level.push(hash_pair(&current_level[i], &current_level[i]));
                }
            }

            tree.push(next_level);
        }

        tree
    }

    /// Get Merkle root
    pub fn root(&self) -> Hash {
        self.root
    }

    /// Generate proof for a field path
    ///
    /// # Arguments
    /// * `path` - Field path to prove
    ///
    /// # Returns
    /// Merkle proof or error if field not found
    pub fn prove(&self, path: &str) -> Result<FieldProof> {
        let (_field_hash, value, index) = self
            .fields
            .get(path)
            .ok_or_else(|| AjnaError::InvalidReference(format!("Field not found: {}", path)))?;

        let proof_hashes = self.compute_proof_path(*index);

        Ok(FieldProof {
            path: path.to_string(),
            value: value.clone(),
            proof: proof_hashes,
            index: *index,
        })
    }

    /// Compute Merkle proof path for a leaf index
    fn compute_proof_path(&self, mut index: usize) -> Vec<Hash> {
        let mut proof = Vec::new();

        for level in &self.tree[..self.tree.len() - 1] {
            // Get sibling index
            let sibling_index = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };

            // Add sibling (if odd node at end, use itself)
            if sibling_index < level.len() {
                proof.push(level[sibling_index]);
            } else {
                // Odd node at end - it hashes with itself
                proof.push(level[index]);
            }

            // Move to parent
            index /= 2;
        }

        proof
    }

    /// Get all field paths
    pub fn paths(&self) -> Vec<&str> {
        self.fields.keys().map(|s| s.as_str()).collect()
    }

    /// Get field value by path
    pub fn get_field(&self, path: &str) -> Option<&FieldValue> {
        self.fields.get(path).map(|(_, v, _)| v)
    }
}

/// Verify a field proof against a root
///
/// # Arguments
/// * `proof` - The field proof
/// * `root` - Expected Merkle root
///
/// # Returns
/// True if proof is valid
pub fn verify_field_proof(proof: &FieldProof, root: &Hash) -> bool {
    // Re-hash the field
    let leaf_hash = hash_field(&proof.path, &proof.value);

    // Verify Merkle path
    let mut computed_hash = leaf_hash;
    let mut index = proof.index;

    for sibling in &proof.proof {
        if index.is_multiple_of(2) {
            // Current is left, sibling is right
            computed_hash = hash_pair(&computed_hash, sibling);
        } else {
            // Current is right, sibling is left
            computed_hash = hash_pair(sibling, &computed_hash);
        }
        index /= 2;
    }

    computed_hash == *root
}

/// Hash a field: Blake3("AJNA/FIELD/V1" || path || value)
pub fn hash_field(path: &str, value: &[u8]) -> Hash {
    let mut data = Vec::new();
    data.extend_from_slice(path.as_bytes());
    data.extend_from_slice(value);
    hash_with_dst(DST_AJNA_FIELD, &data)
}

/// Hash a pair of nodes in Merkle tree
fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Minimal disclosure view (only proven fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimalDocument {
    /// Fields with proofs
    pub fields: Vec<FieldProof>,

    /// Merkle root for verification
    pub root: Hash,
}

impl MinimalDocument {
    /// Create minimal document with selected fields
    pub fn new(index: &FieldIndex, paths: &[&str]) -> Result<Self> {
        let mut fields = Vec::new();

        for path in paths {
            fields.push(index.prove(path)?);
        }

        Ok(Self {
            fields,
            root: index.root(),
        })
    }

    /// Verify all proofs in the minimal document
    pub fn verify_all(&self) -> bool {
        self.fields
            .iter()
            .all(|proof| verify_field_proof(proof, &self.root))
    }

    /// Get field value by path (if present and verified)
    pub fn get_field(&self, path: &str) -> Option<&FieldValue> {
        self.fields
            .iter()
            .find(|p| p.path == path)
            .filter(|p| verify_field_proof(p, &self.root))
            .map(|p| &p.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ajna::lww_map::LWWMap;
    use crate::ajna::or_set::ORSet;
    use crate::ajna::{AjnaDid, Service, VectorClock, VerificationMethod};
    use chrono::Utc;
    use std::collections::HashMap;

    fn create_test_doc() -> AjnaDocument {
        use crate::ajna::{DIDKind, Network};
        let did = AjnaDid::generate(Network::Mainnet, DIDKind::Person);
        let did_str = did.to_string();

        let mut vm_set = ORSet::new();
        let vm = VerificationMethod {
            id: format!("{}#key-1", did_str),
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: did_str.clone(),
            public_key_multibase: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            purpose: Some(vec!["authentication".to_string()]),
        };
        vm_set.add(vm);

        let mut services = LWWMap::new();
        let service = Service {
            id: format!("{}#didcomm", did_str),
            type_: "DIDCommMessaging".to_string(),
            service_endpoint: "https://example.com/didcomm".to_string(),
            properties: HashMap::new(),
        };
        services.set("didcomm".to_string(), service, "test".to_string());

        AjnaDocument {
            id: did_str,
            verification_methods: vm_set,
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            controller: None,
            service: Some(services),
            policy: None,
            deactivated: None,
            vector_clock: VectorClock::new(),
            created: Utc::now(),
            updated: Utc::now(),
            node_id: "test-node".to_string(),
            blockchain_anchor: None,
        }
    }

    #[test]
    fn test_build_field_index() {
        let doc = create_test_doc();
        let index = FieldIndex::build(&doc).unwrap();

        // Should have fields
        assert!(!index.fields.is_empty());

        // Should have root
        assert_ne!(index.root(), [0u8; 32]);

        // Should have paths
        let paths = index.paths();
        assert!(paths.contains(&"/id"));
        assert!(paths.iter().any(|p| p.starts_with("/verificationMethod")));
    }

    #[test]
    fn test_generate_and_verify_proof() {
        let doc = create_test_doc();
        let index = FieldIndex::build(&doc).unwrap();

        // Prove the id field
        let proof = index.prove("/id").unwrap();

        // Verify proof
        assert!(verify_field_proof(&proof, &index.root()));

        // Wrong root should fail
        let wrong_root = [0u8; 32];
        assert!(!verify_field_proof(&proof, &wrong_root));
    }

    #[test]
    fn test_minimal_document() {
        let doc = create_test_doc();
        let index = FieldIndex::build(&doc).unwrap();

        // Create minimal doc with only id and first VM
        let paths = vec!["/id", "/verificationMethod/0/publicKeyMultibase"];
        let minimal = MinimalDocument::new(&index, &paths).unwrap();

        // Should have 2 proofs
        assert_eq!(minimal.fields.len(), 2);

        // Should verify
        assert!(minimal.verify_all());

        // Should be able to get fields
        assert!(minimal.get_field("/id").is_some());
        assert!(minimal
            .get_field("/verificationMethod/0/publicKeyMultibase")
            .is_some());

        // Non-disclosed field should be None
        assert!(minimal.get_field("/service/0/id").is_none());
    }

    #[test]
    fn test_field_hash_deterministic() {
        let path = "/test/field";
        let value = b"test value";

        let hash1 = hash_field(path, value);
        let hash2 = hash_field(path, value);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_invalid_proof_fails() {
        let doc = create_test_doc();
        let index = FieldIndex::build(&doc).unwrap();

        let mut proof = index.prove("/id").unwrap();

        // Tamper with value
        proof.value = b"tampered".to_vec();

        // Should fail verification
        assert!(!verify_field_proof(&proof, &index.root()));
    }

    #[test]
    fn test_multiple_proofs() {
        let doc = create_test_doc();
        let index = FieldIndex::build(&doc).unwrap();

        // Prove multiple fields
        let paths = index.paths();
        for path in paths {
            let proof = index.prove(path).unwrap();
            assert!(verify_field_proof(&proof, &index.root()));
        }
    }
}
