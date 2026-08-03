# Performance harness — DIDComm, Credentials (OID4VCI), AnonCreds

One reusable tool benchmarks all three protocol areas with the **same
capture → replay** method, so the numbers are comparable and the setup isn't
duplicated per protocol.

The tool is **`idiom-perf`**, a first-class crate in the Cargo workspace
(`src/perf`) — so it's built, linted (`-D warnings`), and tested by CI like the
rest of the system, not a side script.

```bash
cd src && cargo build --release -p idiom-perf     # → src/target/release/idiom-perf
```

## The method (one pattern for all three)

Issuing/processing one message is a multi-step, crypto-heavy exchange. To
measure the **agent** and not the client:

1. **capture** (untimed) — do the expensive per-item work once (mint offer,
   token/nonce, sign the proof; or record real packed DIDComm messages) and
   write each ready-to-send request to a **corpus** (`corpus.ndjson`), one JSON
   line per item: `{ "url"|"path", "ctype", "auth"?, "b64" }`.
2. **replay** (timed) — a cheap async loop (reqwest keep-alive pool, no crypto
   in the hot path) POSTs the corpus at the target at ramping concurrency, so
   the agent is the bottleneck. Reports throughput + p50/p95/p99 per level.

The corpus format is a superset across protocols — the same `replay` drives all
three.

## Running each area

```bash
LOAD=src/target/release/idiom-perf

# ── Credentials — OID4VCI SD-JWT issuance ──────────────────────────────
# capture is protocol-aware (mints offers + signs proofs) per target:
TARGET=idiom ISSUER=http://localhost:3060 N=90000 CORPUS=/tmp/cred.ndjson $LOAD capture
CORPUS=/tmp/cred.ndjson LEVELS=8,32,128,256 SLICE=20000 $LOAD replay
#   TARGET in { idiom, essi, credo, acapy } — see credentials/PERFORMANCE.md

# ── DIDComm — raw message throughput ───────────────────────────────────
# corpus is captured with the didcomm proxy (records real packed messages):
#   node didcomm/capture-proxy.mjs   -> didcomm/corpus.ndjson
CORPUS=didcomm/corpus.ndjson TARGET=http://localhost:3060 CYCLE=1 \
  LEVELS=8,16,32,64,128 TOTAL=5000 $LOAD replay
#   CYCLE=1 = messages are replayable (cycle the corpus); a path-based corpus
#   uses TARGET as the base URL.

# ── AnonCreds — DIDComm issue-credential/2.0 ───────────────────────────
# capture credential-request messages, then replay at the issuer inbound:
#   see credentials/issuance-bench.sh (captures requests.ndjson)
CORPUS=credentials/requests.ndjson TARGET=http://localhost:3030 \
  LEVELS=8,16,32 TOTAL=5000 $LOAD replay
```

## Results

See [`credentials/PERFORMANCE.md`](./credentials/PERFORMANCE.md) for the
cross-agent comparison (idiom vs Credo vs ACA-Py) and
[`credentials/DESIGN.md`](./credentials/DESIGN.md) for methodology detail.

## Layout

| Path | What |
|------|------|
| `src/perf/` (`idiom-perf`) | the unified capture→replay tool (workspace crate) |
| `credentials/` | OID4VCI + AnonCreds harnesses, `PERFORMANCE.md`, comparison servers |
| `credentials/credo-bench/` | Credo 0.7 OID4VCI server (drizzle+askar/Postgres) |
| `credentials/acapy-oid4vci-bench.sh` | builds + runs a vanilla ACA-Py oid4vc container |
| `didcomm/` | DIDComm capture proxy + corpus (replayed by `idiom-perf`) |

## CI

`idiom-perf` is a workspace member, so `.github/workflows/ci.yml`
(`cargo fmt/clippy/build/test --workspace`) already builds, lint-gates, and
tests it. A `perf-smoke` job additionally spins up the agent and runs a small
capture → replay end-to-end to keep the harness working.
