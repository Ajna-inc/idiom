//! Unified Rust load tool for the perf benchmarks — replaces the Python driver
//! and the `perf/didcomm/*.mjs` replayers with one binary, following the same
//! capture→replay pattern as the DIDComm message bench:
//!
//!   * `capture` — do the expensive per-request work ONCE (OID4VCI: mint offer,
//!     token, nonce, sign the holder proof) and write ready-to-POST requests to
//!     a corpus (`{url, ctype, auth, b64}` per line — a superset of the DIDComm
//!     `{path, ctype, b64}` corpus).
//!   * `replay` — blast the corpus at the target at ramping concurrency with a
//!     cheap async loop (NO crypto in the hot path, reqwest keep-alive pool), so
//!     the AGENT is the bottleneck. Reports throughput + p50/p95/p99 per level.
//!
//! OID4VCI credential requests are single-use (the c_nonce is consumed), so each
//! concurrency level replays a disjoint slice of the corpus. DIDComm messages are
//! replayable, so `CYCLE=1` fires TOTAL requests per level cycling the corpus.
//!
//!   capture: TARGET=idiom ISSUER=http://localhost:3060 N=30000 CORPUS=c.ndjson idiom-perf capture
//!   replay : CORPUS=c.ndjson LEVELS=8,32,128,256 idiom-perf replay

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

const PRE_AUTH: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}
/// ACA-Py needs a one-time admin setup (issuer did:jwk + SD-JWT supported cred)
/// before offers can be minted; done once in `capture` and read here.
static ACAPY_SETUP: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

async fn acapy_setup(client: &reqwest::Client, admin: &str) -> (String, String) {
    let did = client
        .post(format!("{admin}/did/jwk/create"))
        .json(&json!({"key_type":"ed25519"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["did"]
        .as_str()
        .unwrap()
        .to_string();
    let cid = format!("UD{}", now());
    let sup: Value = client
        .post(format!("{admin}/oid4vci/credential-supported/create/sd-jwt"))
        .json(&json!({"format":"vc+sd-jwt","id":cid,"vct":"UniversityDegree",
            "cryptographic_binding_methods_supported":["jwk"],
            "credential_signing_alg_values_supported":["EdDSA"],
            "proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["EdDSA"]}},
            "sd_list":["/given_name","/family_name","/degree"],
            "credential_metadata":{"claims":[{"path":["given_name"]},{"path":["family_name"]},{"path":["degree"]}]}}))
        .send().await.unwrap().json().await.unwrap();
    let supid = sup["supported_cred_id"]
        .as_str()
        .or(sup["id"].as_str())
        .unwrap()
        .to_string();
    (did, supid)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "replay".into());
    match mode.as_str() {
        "capture" => capture().await,
        "replay" => replay().await,
        other => {
            eprintln!("usage: idiom-perf [capture|replay]  (got {other})");
            std::process::exit(2);
        }
    }
}

// ─────────────────────────── capture ───────────────────────────
// One offer → token → nonce → signed proof → a ready-to-POST credential request.
async fn capture() {
    let target = env("TARGET", "idiom");
    let n: usize = env("N", "10000").parse().unwrap();
    let issuer_base = env(
        "ISSUER",
        if target == "essi" {
            "http://localhost:8080"
        } else {
            "http://localhost:3060"
        },
    );
    let corpus = env("CORPUS", "corpus.ndjson");
    let client = reqwest::Client::builder()
        .tcp_nodelay(true)
        .build()
        .unwrap();
    if target == "acapy" {
        let admin = env("ACAPY_ADMIN", "http://localhost:3001");
        let _ = ACAPY_SETUP.set(acapy_setup(&client, &admin).await);
    }

    // One shared holder key (fixed binding, same as the other benches).
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let holder_jwk =
        json!({"kty":"OKP","crv":"Ed25519","x": B64.encode(sk.verifying_key().to_bytes())});

    let mut out = std::io::BufWriter::new(std::fs::File::create(&corpus).unwrap());
    let mut written = 0usize;
    for i in 0..n {
        if let Some(line) = capture_one(&client, &target, &issuer_base, &sk, &holder_jwk).await {
            writeln!(out, "{line}").unwrap();
            written += 1;
        }
        if (i + 1) % 2000 == 0 {
            eprintln!("  captured {}/{n}", i + 1);
        }
    }
    out.flush().unwrap();
    println!("captured {written}/{n} ready-to-POST credential requests → {corpus}");
}

async fn capture_one(
    client: &reqwest::Client,
    target: &str,
    issuer_base: &str,
    sk: &SigningKey,
    holder_jwk: &Value,
) -> Option<String> {
    let offer = mint_offer(client, target, issuer_base).await?;
    let issuer = offer["credential_issuer"].as_str()?;
    let meta: Value = client
        .get(format!("{issuer}/.well-known/openid-credential-issuer"))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    let code = offer["grants"][PRE_AUTH]["pre-authorized_code"].as_str()?;
    let tok: Value = client
        .post(meta["token_endpoint"].as_str()?)
        .form(&[("grant_type", PRE_AUTH), ("pre-authorized_code", code)])
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    let access = tok["access_token"].as_str()?.to_string();
    let mut nonce = tok["c_nonce"].as_str().map(String::from);
    if nonce.is_none() {
        if let Some(ne) = meta["nonce_endpoint"].as_str() {
            if let Ok(r) = client.post(ne).bearer_auth(&access).send().await {
                if let Ok(v) = r.json::<Value>().await {
                    nonce = v["c_nonce"].as_str().map(String::from);
                }
            }
        }
    }
    let header = json!({"typ":"openid4vci-proof+jwt","alg":"EdDSA","jwk": holder_jwk});
    let payload = json!({"aud": issuer, "iat": now(), "nonce": nonce.unwrap_or_default()});
    let si = format!(
        "{}.{}",
        B64.encode(header.to_string()),
        B64.encode(payload.to_string())
    );
    let proof_jwt = format!("{si}.{}", B64.encode(sk.sign(si.as_bytes()).to_bytes()));
    let cfg_id = offer["credential_configuration_ids"][0].as_str()?;
    let proof = json!({"proof_type":"jwt","jwt": proof_jwt});
    let body = match target {
        "credo" => json!({"credential_configuration_id": cfg_id, "proof": proof}),
        "idiom" | "essi" => json!({
            "credential_identifier": cfg_id, "proof": proof,
            "format": meta["credential_configurations_supported"][cfg_id]["format"]}),
        _ => json!({"credential_identifier": cfg_id, "proof": proof}),
    };
    let line = json!({
        "url": meta["credential_endpoint"].as_str()?,
        "ctype": "application/json",
        "auth": format!("Bearer {access}"),
        "b64": B64.encode(serde_json::to_vec(&body).ok()?),
    });
    Some(line.to_string())
}

// ─────────────────────────── replay ───────────────────────────
struct Req {
    url: String,
    ctype: String,
    auth: Option<String>,
    body: Vec<u8>,
}

async fn replay() {
    let corpus = env("CORPUS", "corpus.ndjson");
    let base = env("TARGET", "").trim_end_matches('/').to_string();
    let cycle = env("CYCLE", "0") == "1";
    let levels: Vec<usize> = env("LEVELS", "8,32,128,256")
        .split(',')
        .map(|s| s.trim().parse().unwrap())
        .collect();

    let reqs: Vec<Req> = std::fs::read_to_string(&corpus)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            let url = match v["url"].as_str() {
                Some(u) => u.to_string(),
                None => format!("{base}{}", v["path"].as_str().unwrap_or("/")),
            };
            Req {
                url,
                ctype: v["ctype"]
                    .as_str()
                    .unwrap_or("application/json")
                    .to_string(),
                auth: v["auth"].as_str().map(String::from),
                body: B64.decode(v["b64"].as_str().unwrap()).unwrap(),
            }
        })
        .collect();
    assert!(!reqs.is_empty(), "empty corpus {corpus}");
    let reqs = Arc::new(reqs);
    let per_level = env("SLICE", &(reqs.len() / levels.len().max(1)).to_string())
        .parse::<usize>()
        .unwrap()
        .max(1);
    let total: usize = env("TOTAL", "5000").parse().unwrap();

    println!(
        "replay: {} reqs → per-level {}  levels {:?}  mode={}",
        reqs.len(),
        if cycle { total } else { per_level },
        levels,
        if cycle { "cycle" } else { "single-use-slice" }
    );

    let client = Arc::new(
        reqwest::Client::builder()
            .pool_max_idle_per_host(*levels.iter().max().unwrap())
            .tcp_nodelay(true)
            .build()
            .unwrap(),
    );
    let mut best = 0f64;
    for (i, &c) in levels.iter().enumerate() {
        // pick this level's requests: disjoint slice (single-use) or cycle.
        let indices: Vec<usize> = if cycle {
            (0..total).map(|k| k % reqs.len()).collect()
        } else {
            let start = i * per_level;
            if start >= reqs.len() {
                eprintln!("  (corpus exhausted; capture a larger N to sweep further)");
                break;
            }
            (start..(start + per_level).min(reqs.len())).collect()
        };
        let count = indices.len();
        let lat = Arc::new(std::sync::Mutex::new(Vec::<f64>::with_capacity(count)));
        let ok = Arc::new(AtomicU64::new(0));
        let t0 = Instant::now();
        stream::iter(indices)
            .for_each_concurrent(c, |idx| {
                let (client, reqs, lat, ok) =
                    (client.clone(), reqs.clone(), lat.clone(), ok.clone());
                async move {
                    let r = &reqs[idx];
                    let s = Instant::now();
                    let mut rb = client.post(&r.url).header("content-type", &r.ctype);
                    if let Some(a) = &r.auth {
                        rb = rb.header("authorization", a);
                    }
                    if let Ok(resp) = rb.body(r.body.clone()).send().await {
                        if resp.status().is_success() {
                            ok.fetch_add(1, Ordering::Relaxed);
                        }
                        let _ = resp.bytes().await;
                    }
                    lat.lock().unwrap().push(s.elapsed().as_secs_f64() * 1000.0);
                }
            })
            .await;
        let secs = t0.elapsed().as_secs_f64();
        let ok = ok.load(Ordering::Relaxed);
        let mut l = lat.lock().unwrap().clone();
        l.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let tput = ok as f64 / secs;
        best = best.max(tput);
        println!(
            "  C={:>4}  {:>7.0} /s  ok={}/{}  p50/p95/p99={:.0}/{:.0}/{:.0}ms",
            c,
            tput,
            ok,
            count,
            pctl(&l, 50),
            pctl(&l, 95),
            pctl(&l, 99)
        );
    }
    println!("── peak: {best:.0} /s ──");
}

fn pctl(sorted: &[f64], p: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[((p as f64 / 100.0) * sorted.len() as f64) as usize % sorted.len()]
}

// ─── offer minting (per target), capture phase only ───
async fn mint_offer(client: &reqwest::Client, target: &str, base: &str) -> Option<Value> {
    match target {
        "idiom" => client
            .post(format!("{base}/oid4vci/offer"))
            .json(&json!({"configId": env("CONFIG_ID", "sdjwt")}))
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok(),
        "essi" => {
            let tok = std::env::var("TENANT_TOKEN").expect("TENANT_TOKEN");
            let supid = std::env::var("SUPPORTED_CRED_ID").expect("SUPPORTED_CRED_ID");
            let ex: Value = client
                .post(format!("{base}/oid4vci/exchange/create"))
                .bearer_auth(&tok)
                .json(&json!({"supported_cred_id": supid,
                    "credential_subject":{"given_name":"Alice","family_name":"Holder","degree":"BSc"}}))
                .send()
                .await
                .ok()?
                .json()
                .await
                .ok()?;
            let env_: Value = client
                .get(format!(
                    "{base}/oid4vci/credential-offer?exchange_id={}",
                    ex["exchange_id"].as_str()?
                ))
                .bearer_auth(&tok)
                .send()
                .await
                .ok()?
                .json()
                .await
                .ok()?;
            let uri = env_["credential_offer"].as_str()?;
            let q = uri.split("credential_offer=").nth(1)?;
            serde_json::from_str(&percent_decode(q)).ok()
        }
        "credo" => {
            let r: Value = client
                .post(format!("{base}/bench/offer"))
                .json(&json!({}))
                .send()
                .await
                .ok()?
                .json()
                .await
                .ok()?;
            Some(r["offer"].clone())
        }
        "acapy" => {
            let admin = env("ACAPY_ADMIN", "http://localhost:3001");
            let (did, supid) = ACAPY_SETUP.get()?;
            let ex: Value = client
                .post(format!("{admin}/oid4vci/exchange/create"))
                .json(&json!({"supported_cred_id": supid, "did": did,
                    "credential_subject":{"given_name":"Alice","family_name":"Holder","degree":"BSc"}}))
                .send().await.ok()?.json().await.ok()?;
            let off: Value = client
                .get(format!(
                    "{admin}/oid4vci/credential-offer?exchange_id={}&user_pin_required=false",
                    ex["exchange_id"].as_str()?
                ))
                .send()
                .await
                .ok()?
                .json()
                .await
                .ok()?;
            Some(off["offer"].clone())
        }
        other => panic!("unsupported TARGET {other}"),
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
