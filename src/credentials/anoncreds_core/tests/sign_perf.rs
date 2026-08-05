//! Profiles the AnonCreds CL issuance hot path (`create_credential`) in
//! isolation — in-memory registry, no DB, no DIDComm — to find the raw signing
//! cost and how well it parallelizes across cores. This is the ceiling the
//! end-to-end issuance path is measured against.
//!
//!   cargo test -p anoncreds_core --release --test sign_perf -- --nocapture

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anoncreds_core::{AnonCredsHolderService, AnonCredsIssuerService, InMemoryRegistry};

#[tokio::test(flavor = "multi_thread")]
async fn profile_cl_signing() {
    let registry = Arc::new(InMemoryRegistry::new());
    let issuer = Arc::new(AnonCredsIssuerService::new(registry.clone()));
    let holder = AnonCredsHolderService::new(registry.clone());

    let schema_reg = issuer
        .create_schema(
            "did:example:issuer",
            "Perf",
            "1.0",
            vec!["name".into(), "age".into()],
        )
        .await
        .unwrap();
    let cred_def_reg = issuer
        .create_credential_definition(
            "did:example:issuer",
            &schema_reg.schema_id,
            "default",
            false,
        )
        .await
        .unwrap();
    let cred_def_id = Arc::new(cred_def_reg.cred_def_id.clone());
    let offer = Arc::new(
        issuer
            .create_credential_offer(&schema_reg.schema_id, &cred_def_id)
            .await
            .unwrap(),
    );
    let request = Arc::new(
        holder
            .create_credential_request("t", &offer, &cred_def_id, "holder-entropy-12345")
            .await
            .unwrap(),
    );
    let attrs: HashMap<String, String> = [("name", "Alice"), ("age", "30")]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let cores = std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(0);

    // Warmup (also populates the cred-def cache).
    for _ in 0..20 {
        issuer
            .create_credential(&cred_def_id, &offer, &request, attrs.clone())
            .await
            .unwrap();
    }

    // Sequential — raw per-sign cost.
    let nseq = 500usize;
    let t = Instant::now();
    for _ in 0..nseq {
        issuer
            .create_credential(&cred_def_id, &offer, &request, attrs.clone())
            .await
            .unwrap();
    }
    let seq = nseq as f64 / t.elapsed().as_secs_f64();

    println!("\n──── AnonCreds CL create_credential (non-revocable, {cores} cores) ────");
    println!(
        "  sequential : {seq:>8.1} creds/s   ({:.2} ms/sign)",
        1000.0 / seq
    );

    // Concurrent — sweep to find the parallel-efficiency sweet spot.
    for conc in [cores, cores * 2, 64usize] {
        let per = (2500usize / conc).max(1);
        let t = Instant::now();
        let mut handles = Vec::with_capacity(conc);
        for _ in 0..conc {
            let (issuer, cred_def_id, offer, request, attrs) = (
                issuer.clone(),
                cred_def_id.clone(),
                offer.clone(),
                request.clone(),
                attrs.clone(),
            );
            handles.push(tokio::spawn(async move {
                for _ in 0..per {
                    issuer
                        .create_credential(&cred_def_id, &offer, &request, attrs.clone())
                        .await
                        .unwrap();
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let rate = (per * conc) as f64 / t.elapsed().as_secs_f64();
        println!(
            "  conc={conc:<3}    : {rate:>8.1} creds/s   → {:.1}x vs 1 thread ({:.0}% of {cores} cores)",
            rate / seq,
            rate / seq / cores as f64 * 100.0
        );
    }
    println!("──────────────────────────────────────────────────────────────────────\n");
}
