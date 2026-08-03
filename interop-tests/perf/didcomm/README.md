# DIDComm raw-message-rate stress test

Finds the ceiling of how many **DIDComm messages the Traction / ACA-Py agent can
process per second** on the local docker stack.

Raw DIDComm is **agent-to-agent** (holder ↔ Traction) — it does **not** flow
through crms-ui, so this measures the single ACA-Py asyncio event loop
(unpack/dispatch + the `basicmessage_storage` Postgres write). crms-ui's rate
throttler is irrelevant here.

## What it does

A Credo **wallet-agent** (holder) floods `basicmessage` DIDComm messages at
Traction over one or more connections, ramping concurrency. Traction unpacks +
stores each; we poll Traction's persisted `GET /basicmessages` count as the
**processed** sink (the honest signal — ACA-Py returns HTTP 200 on *receipt*,
i.e. queued, not processed).

Per concurrency level it reports:

| column | meaning |
|--------|---------|
| `sent/s` | rate the holder pushed messages (accept rate) |
| `proc/s` | rate Traction actually **processed** them (drain rate) |
| `backlog` | messages still unprocessed when sending finished — **the saturation signal** |
| `send p50/p95/p99` | holder-side send latency |
| `cpu[...]` | peak CPU per container during the level (`docker stats`) |

The summary prints **max sustained** (backlog stayed low — the usable rate),
**saturated ceiling** (max proc/s flat-out under backlog), and the **saturation
onset** concurrency.

## Prerequisites

1. **Stack up** locally: `cd tests/e2e && npx tsx scripts/stack.ts` (or however
   you bring up `deploy/`). Wallet-agent on `:4501`, Traction admin on `:8031`.
2. **At least one holder↔operator connection.** The e2e onboarding creates one
   (`tests/e2e/data/preIssue.ts::onboardUhsChannel`). Grab the holder-side
   connection id(s):
   ```bash
   curl -s http://localhost:4501/wallet/connections | jq -r '.connections[]?.id // .[].id'
   ```
3. **Traction tenant bearer token** (for `GET /basicmessages`):
   ```bash
   # mint from the tenant's traction id + admin key, or copy one the app is using
   curl -s -X POST http://localhost:8031/multitenancy/tenant/<TRACTION_TENANT_ID>/token \
     -H "X-API-KEY: $ACAPY_ADMIN_API_KEY" -H 'content-type: application/json' \
     -d '{"api_key":"<TENANT_API_KEY>"}' | jq -r .token
   ```
   (`tests/e2e/fixtures/tractionToken.ts` does exactly this if you'd rather script it.)
4. **Container names** for CPU attribution:
   ```bash
   docker ps --format '{{.Names}}' | grep -E 'traction|wallet'   # e.g. traction-agent-1, wallet-agent
   ```

## Run

```bash
CONN_IDS="<holder-conn-id>[,<conn-id-2>...]" \
TRACTION_TENANT_TOKEN="<bearer>" \
STATS_CONTAINERS="traction-agent-1,wallet-agent" \
LEVELS="1,2,4,8,16,32,64,128" COUNT=2000 \
node tests/perf/didcomm/run.mjs
```

All config is env (defaults in `run.mjs`): `WALLET_AGENT_URL` (`:4501`),
`ACAPY_ADMIN_URL` (`:8031`), `LEVELS`, `COUNT` (msgs/level), `POLL_MS`,
`DRAIN_TIMEOUT_MS`.

## Reading the result

- **Ceiling = where `proc/s` plateaus while `backlog` explodes and one core pins.**
- **Attribute it with `cpu[...]`:**
  - hottest is **traction-agent ~100%/core** → that's the genuine DIDComm ceiling
    (ACA-Py is single-process; it won't use more than one core for the event loop).
  - hottest is **wallet-agent** → the *load generator* is the limit, not Traction.
    Add more holders (below) and re-run.
- Cross-check Postgres if neither CPU saturates: it may be the `basicmessage_storage`
  write (`SELECT * FROM pg_stat_activity`, lock waits).

## Variants

- **Isolate pure routing from storage:** set `basicmessage_storage.wallet_enabled=false`
  in `deploy/plugin-config.yml` (or drop the plugin) and re-run — the delta is the
  per-message Postgres write cost. NOTE: with storage off, `GET /basicmessages`
  won't grow, so use the *outbound* direction or count at the holder instead.
- **More holders (avoid generator bottleneck):** run several wallet-agent
  instances (different `WALLET_ID`/ports) and pass all their connection ids via
  `CONN_IDS` across multiple `WALLET_AGENT_URL`s (run one driver per holder host,
  or extend `run.mjs` to round-robin holder URLs).
- **One hot connection vs many:** pass a single `CONN_IDS` vs several to expose any
  per-connection/session serialization inside ACA-Py.

## Self-test (no real stack)

`run.mjs` was validated against a mock that models a bounded-rate agent:

```bash
ACCEPT_LAT_MS=5 PROCESS_RATE=800 MOCK_PORT=4599 node tests/perf/didcomm/mock-stack.mjs &
MOCK=1 WALLET_AGENT_URL=http://localhost:4599 ACAPY_ADMIN_URL=http://localhost:4599 \
  COUNT=1000 LEVELS=1,2,4,8,16 node tests/perf/didcomm/run.mjs
kill %1
```

Expected: `proc/s` rises then plateaus near `PROCESS_RATE`, `backlog` blows up once
`sent/s` exceeds it, and the summary reports sustained ≈ ceiling ≈ `PROCESS_RATE`.
```
  max SUSTAINED throughput  : ~576 msg/s  (at concurrency 4)
  saturated ceiling         : ~721 msg/s  (at concurrency 16)
  saturation onset          : concurrency 8
```
