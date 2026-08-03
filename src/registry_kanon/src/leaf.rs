//! Mode B leaf derivation — the credential leaf the circuit and the kanon SDK
//! compute, plus the canonical attribute felt-encoding it depends on.
//!
//! Ports:
//!   - `did_kanon/v1_0/zk/attributes.py` (`attr_value_to_felt`,
//!     `encode_attributes_canonical`, `pad_attrs_to_circuit`).
//!   - `did_kanon/v1_0/zk/zk_issuer.py` (`derive_leaf`, `cred_id_to_felt`,
//!     `cred_def_id_to_felt`, `compute_zk_leaf`, `KANON_ZK_LEAF_TAG`).
//!
//! Two leaf forms:
//!   - **Keccak leaf** (`derive_leaf`): `keccak256(keccak256(credIdBytes))` —
//!     matches `MerkleStateRegistry.deriveLeaf(bytes32)` on chain.
//!   - **Poseidon leaf** (`compute_zk_leaf`):
//!     `Poseidon(LEAF_TAG=1, credDefFelt, credIdFelt, Poseidon(attrFelts))` —
//!     matches `non_revocation.circom`'s `MerkleInclusion`.

use ark_bn254::Fr;

use crate::error::{KanonError, Result};
use crate::ids::{keccak256, Bytes32};
use crate::poseidon::{felt_from_be_bytes, poseidon_hash};

// ─── Reserved attribute names (mirror @ajna-inc/kanon-sdk/anoncreds) ──────

pub const KANON_CRED_ID_ATTRIBUTE: &str = "kanonCredId";
pub const KANON_ZK_SIG_ATTRIBUTE: &str = "kanonZkSig";
pub const KANON_ZK_PROOF_ATTRIBUTE: &str = "kanonZkProof";

pub const KANON_ZK_RESERVED_ATTRIBUTE_NAMES: [&str; 3] = [
    KANON_CRED_ID_ATTRIBUTE,
    KANON_ZK_SIG_ATTRIBUTE,
    KANON_ZK_PROOF_ATTRIBUTE,
];

/// The compiled `non_revocation.circom` consumes EXACTLY 16 attribute felts.
pub const KANON_ZK_CIRCUIT_ATTRS: usize = 16;

/// Domain-separation constant — matches `non_revocation.circom`'s
/// `var LEAF_TAG = 1;`.
pub const KANON_ZK_LEAF_TAG: u64 = 1;

// ─── Felt encoding ───────────────────────────────────────────────────────

/// Canonical felt encoding of an AnonCreds attribute value:
/// `uint256(keccak256(utf8(value))) mod BN254_SCALAR_FIELD`.
pub fn attr_value_to_felt(value: &str) -> Fr {
    felt_from_be_bytes(&keccak256(value.as_bytes()))
}

/// Felt-encode `values` in canonical (lexicographic-name) order, excluding the
/// SDK-reserved names. Byte/code-point ordering (Rust `str` `Ord` is
/// code-point order, same as Python `sorted()` / JS `<`).
pub fn encode_attributes_canonical(values: &[(String, String)]) -> Vec<Fr> {
    encode_attributes_canonical_excl(values, &KANON_ZK_RESERVED_ATTRIBUTE_NAMES)
}

/// As `encode_attributes_canonical` but with an explicit exclude list.
pub fn encode_attributes_canonical_excl(
    values: &[(String, String)],
    exclude_names: &[&str],
) -> Vec<Fr> {
    let mut kept: Vec<(&str, &str)> = values
        .iter()
        .filter(|(k, _)| !exclude_names.contains(&k.as_str()))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    kept.sort_by(|a, b| a.0.cmp(b.0));
    kept.iter().map(|(_, v)| attr_value_to_felt(v)).collect()
}

/// Pad (or reject) a felt list to the circuit's 16-felt attribute width.
pub fn pad_attrs_to_circuit(attrs: &[Fr]) -> Result<Vec<Fr>> {
    if attrs.len() > KANON_ZK_CIRCUIT_ATTRS {
        return Err(KanonError::Invalid(format!(
            "pad_attrs_to_circuit: {} attributes exceed the circuit's {}-felt limit",
            attrs.len(),
            KANON_ZK_CIRCUIT_ATTRS
        )));
    }
    let mut out = attrs.to_vec();
    out.resize(KANON_ZK_CIRCUIT_ATTRS, Fr::from(0u64));
    Ok(out)
}

// ─── credId / credDefId → felt ───────────────────────────────────────────

fn bytes32_from_hex_or_raw(input: &[u8]) -> Result<Bytes32> {
    if input.len() != 32 {
        return Err(KanonError::Invalid(format!(
            "expected 32 bytes, got {}",
            input.len()
        )));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(input);
    Ok(b)
}

/// `keccak256(keccak256(credIdBytes))` — the SDK's `deriveLeaf`. `cred_id_hex`
/// is a `0x<64 hex>` (or bare 64-hex) string, since the SDK's
/// `generateCredentialId()` returns 32-byte secrets in that form.
pub fn derive_leaf_hex(cred_id_hex: &str) -> Result<Bytes32> {
    let s = cred_id_hex
        .strip_prefix("0x")
        .or_else(|| cred_id_hex.strip_prefix("0X"))
        .unwrap_or(cred_id_hex);
    if s.len() != 64 {
        return Err(KanonError::Invalid(format!(
            "cred_id hex must be exactly 64 chars (32 bytes), got {}",
            s.len()
        )));
    }
    let raw = hex::decode(s).map_err(|e| KanonError::Encoding(format!("cred_id hex: {e}")))?;
    let cred = bytes32_from_hex_or_raw(&raw)?;
    Ok(derive_leaf_bytes(&cred))
}

/// `keccak256(keccak256(credIdBytes))` over raw 32 bytes.
pub fn derive_leaf_bytes(cred_id: &Bytes32) -> Bytes32 {
    keccak256(&keccak256(cred_id))
}

/// Big-endian read of 32 bytes, reduced mod p — the credId / credDefId felt.
pub fn cred_bytes_to_felt(cred_bytes: &Bytes32) -> Fr {
    felt_from_be_bytes(cred_bytes)
}

// ─── Mode B leaf ─────────────────────────────────────────────────────────

/// The Mode B credential leaf:
///
/// `Poseidon(LEAF_TAG=1, credDefFelt, credIdFelt, Poseidon(attributes))`
///
/// `cred_def_bytes` / `cred_id_bytes` are the 32-byte inputs the caller reads
/// big-endian into a felt (mod p). `attributes` MUST be exactly 16 felts (the
/// circuit's compiled arity — use `pad_attrs_to_circuit`).
///
/// NOTE on `cred_id_bytes`: the Python issuer feeds `keccak256(utf8(credId))`
/// here (NOT `derive_leaf`) so the felt matches what the holder computes at
/// presentation time. Callers must mirror that choice.
pub fn compute_zk_leaf(
    cred_def_bytes: &Bytes32,
    cred_id_bytes: &Bytes32,
    attributes: &[Fr],
) -> Result<Fr> {
    if attributes.len() != KANON_ZK_CIRCUIT_ATTRS {
        return Err(KanonError::Invalid(format!(
            "compute_zk_leaf expects exactly {} attributes, got {}",
            KANON_ZK_CIRCUIT_ATTRS,
            attributes.len()
        )));
    }
    let cd_felt = cred_bytes_to_felt(cred_def_bytes);
    let cr_felt = cred_bytes_to_felt(cred_id_bytes);
    let attr_hash = poseidon_hash(attributes)?;
    poseidon_hash(&[Fr::from(KANON_ZK_LEAF_TAG), cd_felt, cr_felt, attr_hash])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn fr_dec(dec: &str) -> Fr {
        Fr::from_str(dec).unwrap()
    }

    // ── attr_value_to_felt (SDK reference values from test_zk_attributes.py) ──

    #[test]
    fn attr_value_to_felt_matches_sdk() {
        assert_eq!(
            attr_value_to_felt("hello world"),
            fr_dec("10266955550833782072748819713354542574314714086562809780720369216604475498412")
        );
        assert_eq!(
            attr_value_to_felt("Alice"),
            fr_dec("14669790907922563722347299748784787010675406498940812979592950462632291847528")
        );
        assert_eq!(
            attr_value_to_felt("42"),
            fr_dec("5033286923473644888831355870224575013586282181086149170185898684274841956788")
        );
        assert_eq!(
            attr_value_to_felt("kanonZkSig"),
            fr_dec("11085885992072089489107443704621887564000797846145187538994068576560020876245")
        );
        assert_eq!(
            attr_value_to_felt(""),
            fr_dec("1924180730567573949438414972962865885128629851683618892617351438379423999084")
        );
        assert_eq!(
            attr_value_to_felt("unicode: 你好 🚀"),
            fr_dec("7078566545983836886893878875352342737898776233931788747625434295902264015824")
        );
    }

    #[test]
    fn encode_canonical_orders_and_excludes_reserved() {
        // test_matches_sdk_reference_dict: order age, email, name; reserved excluded.
        let values = vec![
            ("name".to_string(), "Alice".to_string()),
            ("age".to_string(), "30".to_string()),
            ("email".to_string(), "alice@example.com".to_string()),
            (KANON_CRED_ID_ATTRIBUTE.to_string(), "0x123".to_string()),
            (KANON_ZK_SIG_ATTRIBUTE.to_string(), "sigblob".to_string()),
            (
                KANON_ZK_PROOF_ATTRIBUTE.to_string(),
                "proofblob".to_string(),
            ),
        ];
        let out = encode_attributes_canonical(&values);
        assert_eq!(
            out,
            vec![
                fr_dec(
                    "19351771638000836805849703169581596917989145648311926612179016298101550227933"
                ),
                fr_dec(
                    "9442795690386943280767297128646743839004807684462467420232979141467548185592"
                ),
                fr_dec(
                    "14669790907922563722347299748784787010675406498940812979592950462632291847528"
                ),
            ]
        );
    }

    #[test]
    fn encode_canonical_code_point_order() {
        // test_order_is_byte_lex_not_locale: 'B'(66) < 'Z'(90) < 'a'(97).
        let values = vec![
            ("Z".to_string(), "z".to_string()),
            ("a".to_string(), "a".to_string()),
            ("B".to_string(), "b".to_string()),
        ];
        let out = encode_attributes_canonical(&values);
        assert_eq!(
            out,
            vec![
                attr_value_to_felt("b"),
                attr_value_to_felt("z"),
                attr_value_to_felt("a"),
            ]
        );
    }

    #[test]
    fn pad_pads_and_rejects() {
        let out = pad_attrs_to_circuit(&[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]).unwrap();
        assert_eq!(out.len(), KANON_ZK_CIRCUIT_ATTRS);
        assert_eq!(&out[..3], &[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        assert!(out[3..].iter().all(|&x| x == Fr::from(0u64)));
        assert!(pad_attrs_to_circuit(&vec![Fr::from(0u64); 17]).is_err());
    }

    // ── derive_leaf (SDK reference from test_zk_issuer.py) ──

    #[test]
    fn derive_leaf_matches_sdk() {
        assert_eq!(
            hex::encode(derive_leaf_hex(&("0x".to_string() + &"a".repeat(64))).unwrap()),
            "d33ede4575bbbacfe23bb609d0aad431d1488a6fae421b0d2c8c1216a61569b1"
        );
    }

    #[test]
    fn derive_leaf_hex_and_bytes_agree() {
        let hex_id = "0x".to_string() + &"a".repeat(64);
        let raw = hex::decode("a".repeat(64)).unwrap();
        let mut cred = [0u8; 32];
        cred.copy_from_slice(&raw);
        assert_eq!(derive_leaf_hex(&hex_id).unwrap(), derive_leaf_bytes(&cred));
    }

    #[test]
    fn derive_leaf_rejects_bad_length() {
        assert!(derive_leaf_hex("0xdeadbeef").is_err());
    }

    // ── compute_zk_leaf (SDK reference from test_mode_b.py) ──

    #[test]
    fn compute_zk_leaf_matches_sdk() {
        // credDefId = 0x cd*32, kanonCredId = 0x 7a*32,
        // domainAttrs = { studentId: 'S-12345', name: 'Alice', gpa: '3.9' }.
        let cd = {
            let raw = hex::decode("cd".repeat(32)).unwrap();
            let mut b = [0u8; 32];
            b.copy_from_slice(&raw);
            b
        };
        let kanon_cred_id = "0x".to_string() + &"7a".repeat(32);
        // The issuer feeds keccak256(utf8(kanonCredId)) as the cred_id bytes.
        let cred_id_keccak = keccak256(kanon_cred_id.as_bytes());

        let attrs = vec![
            ("studentId".to_string(), "S-12345".to_string()),
            ("name".to_string(), "Alice".to_string()),
            ("gpa".to_string(), "3.9".to_string()),
        ];
        let attr_felts = encode_attributes_canonical(&attrs);
        let padded = pad_attrs_to_circuit(&attr_felts).unwrap();

        let leaf = compute_zk_leaf(&cd, &cred_id_keccak, &padded).unwrap();
        assert_eq!(
            leaf,
            fr_dec("1393485080625247459900569500640157328168465545537288134804249149028564603699")
        );
    }
}
