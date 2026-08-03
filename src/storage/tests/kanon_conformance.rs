//! Conformance tests for the kanon Postgres storage backend.
//!
//! Gated behind the `kanon` feature AND a live Postgres pointed to by
//! `KANON_TEST_DATABASE_URL`; when either is absent the tests no-op so default
//! `cargo test` stays green with no DB.
//!
//! Run:
//! ```bash
//! docker run -d --name kanon-test-pg -e POSTGRES_PASSWORD=pg -p 5544:5432 postgres:16-alpine
//! KANON_TEST_DATABASE_URL=postgres://postgres:pg@localhost:5544/postgres \
//!   cargo test -p storage --features kanon --test kanon_conformance
//! ```
#![cfg(feature = "kanon")]

use agent_core::traits::{Query, Record, StorageProvider};
use sqlx::Row;
use storage::kanon::KanonStorageProvider;

/// Compare two record values by JSON semantics, not raw bytes: values are stored
/// as JSONB, which normalizes key order and whitespace. idiom deserializes
/// records via serde, so semantic equality is the contract (DESIGN §4.5).
fn same_json(a: &[u8], b: &[u8]) {
    let av: serde_json::Value = serde_json::from_slice(a).unwrap();
    let bv: serde_json::Value = serde_json::from_slice(b).unwrap();
    assert_eq!(av, bv);
}

/// A fresh provider on a per-test-unique profile so tests don't collide even
/// against a shared DB. Returns `None` (test no-ops) when no DB is configured.
async fn provider() -> Option<KanonStorageProvider> {
    let url = std::env::var("KANON_TEST_DATABASE_URL").ok()?;
    let profile = format!("test-{}", uuid::Uuid::new_v4());
    Some(
        KanonStorageProvider::connect_with_profile(&url, &profile)
            .await
            .expect("connect + provision schema"),
    )
}

#[tokio::test]
async fn save_find_update_delete_roundtrip() {
    let Some(store) = provider().await else {
        eprintln!("skipping: KANON_TEST_DATABASE_URL unset");
        return;
    };

    let rec = Record::new(
        "connection",
        "conn-1",
        br#"{"state":"active","n":1}"#.to_vec(),
    )
    .add_tag("state", "active")
    .add_tag("their_did", "did:peer:xyz");
    store.save(&rec).await.unwrap();

    // find
    let got = store.find("connection", "conn-1").await.unwrap().unwrap();
    assert_eq!(got.name, "conn-1");
    same_json(&got.value, &rec.value);
    assert_eq!(got.tags.get("state").unwrap(), "active");
    assert_eq!(got.tags.get("their_did").unwrap(), "did:peer:xyz");

    // duplicate save must fail (askar parity)
    assert!(
        store.save(&rec).await.is_err(),
        "duplicate save should error"
    );

    // update replaces value + tags
    let updated = Record::new(
        "connection",
        "conn-1",
        br#"{"state":"completed","n":2}"#.to_vec(),
    )
    .add_tag("state", "completed");
    store.update(&updated).await.unwrap();
    let got = store.find("connection", "conn-1").await.unwrap().unwrap();
    same_json(&got.value, &updated.value);
    assert_eq!(got.tags.get("state").unwrap(), "completed");
    assert!(!got.tags.contains_key("their_did"), "tags fully replaced");

    // update of a missing record errors
    let missing = Record::new("connection", "nope", b"{}".to_vec());
    assert!(store.update(&missing).await.is_err());

    // delete
    store.delete("connection", "conn-1").await.unwrap();
    assert!(store.find("connection", "conn-1").await.unwrap().is_none());
}

#[tokio::test]
async fn find_all_tag_filter_limit_skip_and_count() {
    let Some(store) = provider().await else {
        return;
    };

    for i in 0..6 {
        let state = if i % 2 == 0 { "active" } else { "done" };
        let rec = Record::new(
            "cred",
            format!("c-{i}"),
            format!(r#"{{"i":{i}}}"#).into_bytes(),
        )
        .add_tag("state", state);
        store.save(&rec).await.unwrap();
    }

    // no filter → all 6 (including any NULL-tag rows would be included)
    let all = store.find_all("cred", &Query::new()).await.unwrap();
    assert_eq!(all.len(), 6);

    // tag-AND filter
    let active = store
        .find_all("cred", &Query::new().with_tag("state", "active"))
        .await
        .unwrap();
    assert_eq!(active.len(), 3);
    assert!(active
        .iter()
        .all(|r| r.tags.get("state").unwrap() == "active"));

    // count matches find_all length
    let n = store
        .count("cred", &Query::new().with_tag("state", "done"))
        .await
        .unwrap();
    assert_eq!(n, 3);

    // limit + skip
    let page = store
        .find_all("cred", &Query::new().with_limit(2).with_skip(2))
        .await
        .unwrap();
    assert_eq!(page.len(), 2);

    // delete_all clears the category
    store.delete_all("cred").await.unwrap();
    assert_eq!(
        store.find_all("cred", &Query::new()).await.unwrap().len(),
        0
    );
}

/// Proves JSONB parity: a JSON record value is stored as real queryable JSONB in
/// the `value` column (not an opaque blob), exactly like ACA-Py's plugin — so a
/// Postgres `->>` on the value works. This is the schema-compatibility signal.
#[tokio::test]
async fn value_is_stored_as_queryable_jsonb() {
    let Some(store) = provider().await else {
        return;
    };

    let rec = Record::new(
        "proof",
        "p-1",
        br#"{"verified":true,"role":"verifier"}"#.to_vec(),
    );
    store.save(&rec).await.unwrap();

    // Read the raw JSONB back through SQL, extracting a nested key.
    let row = sqlx::query(
        "SELECT value->>'role' AS role, (value->>'verified') AS verified \
         FROM kanon_generic_record WHERE record_type = 'proof' AND id = 'p-1'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let role: String = row.get("role");
    let verified: String = row.get("verified");
    assert_eq!(role, "verifier");
    assert_eq!(verified, "true");

    // And idiom round-trips the exact bytes back.
    let got = store.find("proof", "p-1").await.unwrap().unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&got.value).unwrap();
    assert_eq!(parsed["role"], "verifier");
    assert_eq!(parsed["verified"], true);

    store.delete_all("proof").await.unwrap();
}
