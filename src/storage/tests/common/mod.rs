//! Backend-agnostic `StorageProvider` conformance suite.
//!
//! One set of assertions, run against every backend (memory / askar / kanon) so
//! they are provably interchangeable. Included via `mod common;` by each
//! backend's test file.
#![allow(dead_code)]

use agent_core::traits::{Query, Record, StorageProvider};

/// Semantic JSON equality. kanon stores values as JSONB (which normalizes key
/// order); memory/askar are byte-exact. The provider contract is "the value
/// round-trips", which for JSON means semantic equality — so this holds for all
/// backends.
pub fn same_json(a: &[u8], b: &[u8]) {
    let av: serde_json::Value = serde_json::from_slice(a).expect("lhs json");
    let bv: serde_json::Value = serde_json::from_slice(b).expect("rhs json");
    assert_eq!(av, bv);
}

/// The portable `StorageProvider` contract. `ns` namespaces categories so the
/// same backing store can host many runs (and parallel tests) without collision.
pub async fn storage_contract(store: &dyn StorageProvider, ns: &str) {
    let cat = format!("{ns}-conn");

    // save + find round-trips value and tags
    let rec = Record::new(&cat, "c1", br#"{"state":"active","n":1}"#.to_vec())
        .add_tag("state", "active")
        .add_tag("their", "did:peer:z");
    store.save(&rec).await.unwrap();

    let got = store
        .find(&cat, "c1")
        .await
        .unwrap()
        .expect("record present");
    same_json(&got.value, &rec.value);
    assert_eq!(got.tags.get("state").unwrap(), "active");
    assert_eq!(got.tags.get("their").unwrap(), "did:peer:z");

    // duplicate save errors (consistent across backends)
    assert!(store.save(&rec).await.is_err(), "duplicate save must error");

    // update replaces value + tags of an existing record
    let upd =
        Record::new(&cat, "c1", br#"{"state":"done","n":2}"#.to_vec()).add_tag("state", "done");
    store.update(&upd).await.unwrap();
    let got = store.find(&cat, "c1").await.unwrap().unwrap();
    same_json(&got.value, &upd.value);
    assert_eq!(got.tags.get("state").unwrap(), "done");
    assert!(!got.tags.contains_key("their"), "tags fully replaced");

    // update of a MISSING record errors — consistent across all backends
    // (callers use update→save fallback for upsert).
    let missing = Record::new(&cat, "ghost", b"{}".to_vec());
    assert!(
        store.update(&missing).await.is_err(),
        "update of a missing record must error"
    );

    // find_all + tag-AND filter + count + limit
    let cat2 = format!("{ns}-cred");
    for i in 0..6 {
        let state = if i % 2 == 0 { "active" } else { "done" };
        let rec = Record::new(
            &cat2,
            format!("c{i}"),
            format!(r#"{{"i":{i}}}"#).into_bytes(),
        )
        .add_tag("state", state);
        store.save(&rec).await.unwrap();
    }
    assert_eq!(store.find_all(&cat2, &Query::new()).await.unwrap().len(), 6);
    let active = store
        .find_all(&cat2, &Query::new().with_tag("state", "active"))
        .await
        .unwrap();
    assert_eq!(active.len(), 3);
    assert!(active
        .iter()
        .all(|r| r.tags.get("state").unwrap() == "active"));
    assert_eq!(
        store
            .count(&cat2, &Query::new().with_tag("state", "done"))
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        store
            .find_all(&cat2, &Query::new().with_limit(2))
            .await
            .unwrap()
            .len(),
        2
    );

    // delete + delete_all
    store.delete(&cat, "c1").await.unwrap();
    assert!(store.find(&cat, "c1").await.unwrap().is_none());
    store.delete_all(&cat2).await.unwrap();
    assert_eq!(store.find_all(&cat2, &Query::new()).await.unwrap().len(), 0);
}
