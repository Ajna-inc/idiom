//! Conformance tests for the kanon Postgres wallet backend.
//!
//! Gated on the `kanon` feature + a live Postgres in `KANON_TEST_DATABASE_URL`;
//! no-ops otherwise. See `kanon_conformance.rs` for the run command.
#![cfg(feature = "kanon")]

use agent_core::traits::{KeyPurpose, KeyType, WalletProvider};
use sqlx::Row;
use storage::kanon::KanonWalletProvider;

async fn wallet() -> Option<KanonWalletProvider> {
    let url = std::env::var("KANON_TEST_DATABASE_URL").ok()?;
    let profile = format!("wtest-{}", uuid::Uuid::new_v4());
    Some(
        KanonWalletProvider::from_pool(
            sqlx::PgPool::connect(&url).await.unwrap(),
            &profile,
            "bench-passphrase",
        )
        .await
        .expect("connect + provision key schema"),
    )
}

#[tokio::test]
async fn ed25519_create_sign_verify_and_persist() {
    let Some(w) = wallet().await else {
        eprintln!("skipping: KANON_TEST_DATABASE_URL unset");
        return;
    };

    // create
    let key = w
        .create_key(KeyType::Ed25519, KeyPurpose::AgentMessaging)
        .await
        .unwrap();
    assert_eq!(key.key_type, KeyType::Ed25519);
    assert_eq!(key.public_key.len(), 32);

    // get_key round-trips metadata
    let fetched = w.get_key(&key.id).await.unwrap().unwrap();
    assert_eq!(fetched.public_key, key.public_key);
    assert_eq!(fetched.purpose, KeyPurpose::AgentMessaging);

    // sign + verify (this exercises the askar LocalKey crypto path)
    let msg = b"benchmark payload";
    let sig = w.sign(&key.id, msg).await.unwrap();
    assert_eq!(sig.bytes.len(), 64, "ed25519 signature is 64 bytes");
    assert!(w.verify(&key.id, msg, &sig.bytes).await.unwrap());

    // tampered signature / message must fail
    let mut bad = sig.bytes.clone();
    bad[0] ^= 0xff;
    assert!(!w.verify(&key.id, msg, &bad).await.unwrap());
    assert!(!w.verify(&key.id, b"other", &sig.bytes).await.unwrap());

    // list + delete
    assert!(w.list_keys().await.unwrap().iter().any(|k| k.id == key.id));
    w.delete_key(&key.id).await.unwrap();
    assert!(w.get_key(&key.id).await.unwrap().is_none());
}

/// The secret is genuinely encrypted at rest: the stored `secret_ciphertext`
/// must not equal the raw secret, yet `get_secret_bytes` recovers it.
#[tokio::test]
async fn secret_is_encrypted_at_rest() {
    let Some(w) = wallet().await else { return };
    let key = w
        .create_key(KeyType::Ed25519, KeyPurpose::AgentMessaging)
        .await
        .unwrap();

    let secret = w.get_secret_bytes(&key.id).await.unwrap();
    assert!(!secret.is_empty());

    // Read the raw ciphertext straight from Postgres — it must differ from the
    // recovered plaintext (i.e. AES-GCM actually ran).
    let row = sqlx::query("SELECT secret_ciphertext, key_alg FROM kanon_key WHERE id = $1")
        .bind(&key.id)
        .fetch_one(
            &sqlx::PgPool::connect(&std::env::var("KANON_TEST_DATABASE_URL").unwrap())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
    let ct: Vec<u8> = row.get("secret_ciphertext");
    let key_alg: String = row.get("key_alg");
    assert_eq!(key_alg, "ed25519");
    assert_ne!(ct, secret, "ciphertext must not equal plaintext secret");
    // GCM appends a 16-byte tag, so ciphertext is longer than the secret.
    assert!(ct.len() >= secret.len());
}

/// Quantum key path (SLH-DSA) via the `crypto` crate — proves the wallet is a
/// full drop-in, not classical-only.
#[tokio::test]
async fn slhdsa_create_sign_verify() {
    let Some(w) = wallet().await else { return };
    let key = w
        .create_key(KeyType::SLHDSA, KeyPurpose::General)
        .await
        .unwrap();
    assert_eq!(key.key_type, KeyType::SLHDSA);

    let msg = b"quantum-signed payload";
    let sig = w.sign(&key.id, msg).await.unwrap();
    assert!(w.verify(&key.id, msg, &sig.bytes).await.unwrap());
    assert!(!w.verify(&key.id, b"tampered", &sig.bytes).await.unwrap());
}
