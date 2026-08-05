//! Micro-profile of the DIDComm v2 pack/unpack hot path, isolated from the async
//! plumbing (in-memory resolvers, no DID network, no spawn_blocking/block_on).
//! Tells us whether the per-message cost is the crypto itself or the surrounding
//! machinery — and quantifies the redundant JWS-over-authcrypt.
//!
//!   cargo test -p sicpa_didcomm --features testvectors --test hot_path -- --nocapture
#![cfg(feature = "testvectors")]

use std::time::Instant;

use sicpa_didcomm::did::resolvers::ExampleDIDResolver;
use sicpa_didcomm::secrets::resolvers::ExampleSecretsResolver;
use sicpa_didcomm::test_vectors::{
    ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID_DOC, BOB_SECRETS,
    BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2, MESSAGE_SIMPLE,
};
use sicpa_didcomm::{Message, PackEncryptedOptions, UnpackOptions};

fn per_op_us(total: std::time::Duration, n: usize) -> f64 {
    total.as_micros() as f64 / n as f64
}

#[tokio::test]
async fn profile_pack_unpack() {
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
    let alice_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());
    let bob_secrets = ExampleSecretsResolver::new(BOB_SECRETS.clone());

    let to = &BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id;
    let from = Some(ALICE_DID);
    let opts = PackEncryptedOptions {
        forward: false,
        ..PackEncryptedOptions::default()
    };

    let n = 3000usize;

    // Warmup.
    for _ in 0..50 {
        let _ = MESSAGE_SIMPLE
            .pack_encrypted(to, from, None, &did_resolver, &alice_secrets, &opts)
            .await
            .unwrap();
    }

    // 1) authcrypt only (from=Some, sign_by=None) — the sender is already
    //    authenticated by ECDH-1PU, no JWS.
    let t = Instant::now();
    let mut packed = String::new();
    for _ in 0..n {
        packed = MESSAGE_SIMPLE
            .pack_encrypted(to, from, None, &did_resolver, &alice_secrets, &opts)
            .await
            .unwrap()
            .0;
    }
    let pack_authcrypt = per_op_us(t.elapsed(), n);

    // 2) authcrypt + JWS (sign_by=Some) — the redundant non-repudiation path.
    let t = Instant::now();
    for _ in 0..n {
        let _ = MESSAGE_SIMPLE
            .pack_encrypted(
                to,
                from,
                Some(ALICE_DID),
                &did_resolver,
                &alice_secrets,
                &opts,
            )
            .await
            .unwrap();
    }
    let pack_signed = per_op_us(t.elapsed(), n);

    // 3) unpack (authcrypt-only envelope).
    let t = Instant::now();
    for _ in 0..n {
        let _ = Message::unpack(
            &packed,
            &did_resolver,
            &bob_secrets,
            &UnpackOptions::default(),
        )
        .await
        .unwrap();
    }
    let unpack_us = per_op_us(t.elapsed(), n);

    println!("\n──────── SICPA pack/unpack (in-memory resolvers, 1 recipient, N={n}) ────────");
    println!("  pack  authcrypt-only : {pack_authcrypt:>8.1} µs/op");
    println!(
        "  pack  authcrypt+JWS  : {pack_signed:>8.1} µs/op   (+{:.1} µs redundant sign)",
        pack_signed - pack_authcrypt
    );
    println!("  unpack               : {unpack_us:>8.1} µs/op");
    println!(
        "  → round trip (auth)  : {:>8.1} µs   = {:.0} msg/s single-thread",
        pack_authcrypt + unpack_us,
        1_000_000.0 / (pack_authcrypt + unpack_us)
    );
    println!("────────────────────────────────────────────────────────────────────────────\n");
}

// ── Concurrent throughput: raw async vs the `spawn_blocking(block_on(..))`
//    wrapper our envelope_service uses. Isolates the plumbing tax under load. ──
#[cfg(feature = "uniffi")]
use std::sync::Arc;

#[cfg(feature = "uniffi")]
async fn raw_roundtrip(
    to: Arc<String>,
    dr: Arc<ExampleDIDResolver>,
    asr: Arc<ExampleSecretsResolver>,
    bsr: Arc<ExampleSecretsResolver>,
    opts: Arc<PackEncryptedOptions>,
) {
    let packed = MESSAGE_SIMPLE
        .pack_encrypted(&to, Some(ALICE_DID), None, &*dr, &*asr, &opts)
        .await
        .unwrap()
        .0;
    let _ = Message::unpack(&packed, &*dr, &*bsr, &UnpackOptions::default())
        .await
        .unwrap();
}

// Mirror envelope_service: run the async op inside spawn_blocking + handle.block_on.
#[cfg(feature = "uniffi")]
async fn wrapped_roundtrip(
    to: Arc<String>,
    dr: Arc<ExampleDIDResolver>,
    asr: Arc<ExampleSecretsResolver>,
    bsr: Arc<ExampleSecretsResolver>,
    opts: Arc<PackEncryptedOptions>,
) {
    let h = tokio::runtime::Handle::current();
    let (to2, dr2, asr2, opts2) = (to.clone(), dr.clone(), asr.clone(), opts.clone());
    let packed = tokio::task::spawn_blocking(move || {
        h.block_on(async {
            MESSAGE_SIMPLE
                .pack_encrypted(&to2, Some(ALICE_DID), None, &*dr2, &*asr2, &opts2)
                .await
                .unwrap()
                .0
        })
    })
    .await
    .unwrap();
    let h = tokio::runtime::Handle::current();
    let (dr3, bsr3) = (dr.clone(), bsr.clone());
    let _ = tokio::task::spawn_blocking(move || {
        h.block_on(async {
            Message::unpack(&packed, &*dr3, &*bsr3, &UnpackOptions::default())
                .await
                .unwrap()
        })
    })
    .await
    .unwrap();
}

#[cfg(feature = "uniffi")]
#[tokio::test(flavor = "multi_thread")]
async fn profile_concurrent_plumbing() {
    let dr = Arc::new(ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
    ]));
    let asr = Arc::new(ExampleSecretsResolver::new(ALICE_SECRETS.clone()));
    let bsr = Arc::new(ExampleSecretsResolver::new(BOB_SECRETS.clone()));
    let to = Arc::new(BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2.id.clone());
    let opts = Arc::new(PackEncryptedOptions {
        forward: false,
        ..PackEncryptedOptions::default()
    });

    let cores = std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(0);
    let total = 24000usize;
    let conc = 64usize;

    for (label, wrapped) in [("raw async", false), ("spawn_blocking+block_on", true)] {
        // warmup
        for _ in 0..100 {
            raw_roundtrip(
                to.clone(),
                dr.clone(),
                asr.clone(),
                bsr.clone(),
                opts.clone(),
            )
            .await;
        }
        let per_worker = total / conc;
        let t = Instant::now();
        let mut handles = Vec::with_capacity(conc);
        for _ in 0..conc {
            let (to, dr, asr, bsr, opts) = (
                to.clone(),
                dr.clone(),
                asr.clone(),
                bsr.clone(),
                opts.clone(),
            );
            handles.push(tokio::spawn(async move {
                for _ in 0..per_worker {
                    if wrapped {
                        wrapped_roundtrip(
                            to.clone(),
                            dr.clone(),
                            asr.clone(),
                            bsr.clone(),
                            opts.clone(),
                        )
                        .await;
                    } else {
                        raw_roundtrip(
                            to.clone(),
                            dr.clone(),
                            asr.clone(),
                            bsr.clone(),
                            opts.clone(),
                        )
                        .await;
                    }
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "  {label:<26} {:>9.0} round-trips/s   ({conc}-way, {cores} cores)",
            total as f64 / secs
        );
    }
}
