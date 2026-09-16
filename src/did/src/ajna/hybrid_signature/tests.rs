use super::*;
use ed25519_dalek::{Signer, SigningKey};

const CTX_A: &[u8] = b"example/context-a/v1";
const CTX_B: &[u8] = b"example/context-b/v1";

fn fixture(context: &[u8]) -> (HybridPublicKey, Vec<u8>) {
    let classical = SigningKey::from_bytes(&[31; 32]);
    let (pq, secret) = mldsa::keypair();
    let key =
        HybridPublicKey::from_parts(classical.verifying_key().as_bytes(), pq.to_bytes()).unwrap();
    let message = b"authority-test";
    let ed = classical.sign(&[context, &[0], message].concat());
    let pq = mldsa::sign(message, &secret, context).unwrap();
    (key, [ed.to_bytes().as_slice(), pq.to_bytes()].concat())
}

#[test]
fn both_components_are_required() {
    for context in [CTX_A, CTX_B] {
        let (key, proof) = fixture(context);
        assert!(key.verify_with_context(b"authority-test", &proof, context));
        for position in [0, 63, 64, SIGNATURE_BYTES - 1] {
            let mut changed = proof.clone();
            changed[position] ^= 1;
            assert!(!key.verify_with_context(b"authority-test", &changed, context));
        }
        for length in [0, 64, SIGNATURE_BYTES - 1] {
            assert!(!key.verify_with_context(b"authority-test", &proof[..length], context));
        }
        assert!(!key.verify_with_context(b"changed", &proof, context));
        assert!(!key.verify_with_context(
            b"authority-test",
            &[proof.as_slice(), &[0]].concat(),
            context
        ));
    }
}

#[test]
fn contexts_and_key_pairs_cannot_be_substituted() {
    let (key, proof) = fixture(CTX_A);
    assert!(!key.verify_with_context(b"authority-test", &proof, CTX_B));
    assert!(!key.verify_with_context(b"authority-test", &proof, b""));
    let (other, _) = fixture(CTX_A);
    // Same classical key, different PQ key: classical verification alone passes.
    assert_eq!(key.classical(), other.classical());
    assert!(!other.verify_with_context(b"authority-test", &proof, CTX_A));
}

#[test]
fn public_encoding_is_bounded_and_rejects_weak_classical_keys() {
    let (key, _) = fixture(CTX_A);
    let encoded = key.to_multibase();
    assert_eq!(
        HybridPublicKey::from_multibase(&encoded)
            .unwrap()
            .to_multibase(),
        encoded
    );
    assert!(HybridPublicKey::from_multibase(&format!("z{encoded}")).is_none());
    assert!(HybridPublicKey::from_bytes(&[0; 32]).is_none());
    let mut identity = [0; 32];
    identity[0] = 1;
    assert!(HybridPublicKey::from_parts(&identity, key.pq_bytes()).is_none());
    assert!(HybridPublicKey::from_parts(key.classical().as_bytes(), &[0; 1]).is_none());
}
