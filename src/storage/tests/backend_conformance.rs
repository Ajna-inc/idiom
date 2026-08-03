//! Runs the shared `StorageProvider` conformance suite (see `common`) against
//! every backend via the `StorageBackend` factory, proving they're
//! interchangeable. memory + askar always run; kanon runs when the `kanon`
//! feature is on and `KANON_TEST_DATABASE_URL` is set.

mod common;

use storage::backend::StorageBackend;

fn ns(name: &str) -> String {
    format!("{name}-{}", uuid::Uuid::new_v4())
}

#[tokio::test]
async fn memory_backend_conforms() {
    let store = StorageBackend::from_spec("memory")
        .unwrap()
        .build()
        .await
        .unwrap();
    common::storage_contract(store.as_ref(), &ns("mem")).await;
}

#[tokio::test]
async fn askar_backend_conforms() {
    let store = StorageBackend::from_spec("askar")
        .unwrap()
        .build()
        .await
        .unwrap();
    common::storage_contract(store.as_ref(), &ns("askar")).await;
}

#[cfg(feature = "kanon")]
#[tokio::test]
async fn kanon_backend_conforms() {
    let Ok(url) = std::env::var("KANON_TEST_DATABASE_URL") else {
        eprintln!("skipping kanon: KANON_TEST_DATABASE_URL unset");
        return;
    };
    let store = StorageBackend::from_spec(&format!("kanon:{url}"))
        .unwrap()
        .build()
        .await
        .unwrap();
    common::storage_contract(store.as_ref(), &ns("kanon")).await;
}

/// Regression guard for the normalized behavior: `update` of a *missing* record
/// now errors on **every** backend (memory used to silently upsert). Keeps the
/// backends interchangeable for the update→save upsert fallback used across the
/// repos.
#[tokio::test]
async fn update_missing_errors_on_all_backends() {
    use agent_core::traits::Record;

    let rec = Record::new("x", "missing", b"{}".to_vec());
    for backend in [StorageBackend::memory(), StorageBackend::askar_memory()] {
        let store = backend.build().await.unwrap();
        assert!(
            store.update(&rec).await.is_err(),
            "{}: update of a missing record must error",
            backend.name()
        );
    }
}
