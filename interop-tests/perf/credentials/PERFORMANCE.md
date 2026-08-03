# Credential Issuance Performance — idiom vs Credo vs ACA-Py

Throughput of **OID4VCI SD-JWT credential issuance** across the three stacks,
measured identically on the same 12-core machine with Postgres persistence.

| Agent                      | Runtime           | Storage         | Throughput     | p50   | Cores |
|----------------------------|-------------------|-----------------|---------------:|------:|------:|
| **idiom** (essi-agent-api) | Rust / tokio      | askar–Postgres  | **~61,000 /s** | ~2 ms | ~5    |
| Credo 0.7                  | Node / event loop | askar+drizzle–Postgres | **~268 /s** | ~120 ms | ~1.5 |
| ACA-Py (oid4vc plugin)     | Python / asyncio  | askar–Postgres  | **~136 /s**    | ~227 ms | ~1  |

**idiom ≈ 228× Credo, ≈ 450× ACA-Py.** idiom throughput scales with cores and
latency stays flat under load; Credo and ACA-Py are pinned to a single event
loop, so latency grows linearly with concurrency.

---

## Other configurations

**OID4VCI SD-JWT — full holder flow over HTTP (token → nonce → credential):**

| Agent   | In-memory | Postgres |
|---------|----------:|---------:|
| idiom   | ~62,000 /s | ~61,000 /s |
| Credo   | ~23 /s     | ~37 /s |
| ACA-Py  | ~44 /s     | ~28 /s (collapses under concurrency) |

**AnonCreds — full DIDComm path (idiom only):** ~133 /s (offer → request →
CL-sign → store, over real DIDComm on the Kanon/Besu VDR).

Note: the headline numbers use the **askar** wallet/store (askar-Postgres for
essi, askar in-memory for the example). The separate `kanon` storage backend
(`kanon_generic_record`/`kanon_key`) is currently ~4,700 /s (unoptimized).

---

## Methodology

Issuing one OID4VCI credential is a multi-step exchange: metadata → token →
c_nonce → signed key-possession proof → signed credential. To measure the
**agent**, not the client:

- **capture** (untimed): mint the offer, run token/nonce, and sign the Ed25519
  proof once — writing each ready-to-POST credential request to a corpus.
- **replay** (timed): a cheap async Rust loop (keep-alive pool, no crypto) POSTs
  the corpus at the credential endpoint at ramping concurrency. Each request is
  single-use, so the agent does the real proof-verify + sign.

Same tool, same corpus format, same box for all three stacks.

Caveats: one 12-core laptop where the load generator shares the CPU; Credo 0.7 /
ACA-Py oid4vc versions as of this run. The EdDSA/SD-JWT crypto is shared native
code — the gap is framework + storage + concurrency, not signing.

---

## Reproduce

```bash
( cd ../../../src && cargo build --release -p idiom-perf )   # workspace crate
LOAD=../../../src/target/release/idiom-perf

# idiom (essi-agent-api on :8080; create a tenant + supported cred first)
TARGET=essi ISSUER=http://localhost:8080 TENANT_TOKEN=$TOK SUPPORTED_CRED_ID=$SUP \
  N=90000 CORPUS=/tmp/essi.ndjson $LOAD capture
CORPUS=/tmp/essi.ndjson LEVELS=256 SLICE=85000 $LOAD replay          # ~61,000 /s

# Credo 0.7 (credo-bench/credo07-server.ts on :3070)
TARGET=credo ISSUER=http://localhost:3070 N=3000 CORPUS=/tmp/credo.ndjson $LOAD capture
CORPUS=/tmp/credo.ndjson LEVELS=32,128 SLICE=1000 $LOAD replay       # ~268 /s

# ACA-Py (oid4vc plugin container, admin :3001)
TARGET=acapy ACAPY_ADMIN=http://localhost:3001 N=3000 CORPUS=/tmp/acapy.ndjson $LOAD capture
CORPUS=/tmp/acapy.ndjson LEVELS=32,128 SLICE=1000 $LOAD replay       # ~136 /s
```

Harnesses: `src/perf/` (the `idiom-perf` load tool, a workspace crate),
`credo-bench/` (Credo 0.7 server), `acapy-oid4vci-bench.sh` (ACA-Py container).
