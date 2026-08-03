# idiom

**Interoperable Decentralized Identity Orchestration Middleware**

idiom is a Rust implementation of a self-sovereign identity (SSI) agent stack:
DIDComm v1/v2 messaging, AnonCreds issuance & verification, a pluggable ledger
(VDR) layer including the on-chain **did:kanon** registry, a workflow
orchestration protocol, and a standalone DIDComm mediator. It is built to
interoperate with existing Aries agents (e.g. Credo/ACA-Py) on the wire.

---

## Highlights

- **DIDComm v1 + v2** — OOB invitations, DID Exchange, return-route inline
  responses, and Forward/mediated routing. Interoperable with credo-ts.
- **DID methods** — `key`, `peer` (peer:1 and self-resolving peer:2), `web`,
  `jwk`, `x25519`, `indy`, `cheqd`, plus `did:kanon` via the VDR.
- **AnonCreds** — schema / credential-definition / credential issuance and
  proof presentation (`issue-credential/2.0`, `present-proof/2.0`), link
  secrets, and revocation.
- **did:kanon VDR** — on-chain schema, cred-def, and revocation registries over
  a Besu chain (via `alloy`). Two revocation tiers: **Mode A** (one-time /
  AnonCredsStatusRegistry) and **Mode B** (ZK-SNARK / MerkleStateRegistry with
  Groth16 + BabyJubjub EdDSA + Poseidon Merkle).
- **Workflow protocol** — a template-driven state machine that orchestrates
  connection / issuance / proof steps, with pluggable actions
  (`state:set`, offer-credential, request-presentation, …) and an attribute
  planner. Byte-compatible with the reference `workflow_protocol` plugin.
- **Mediator server** — a standalone DIDComm mediator (coordinate-mediation +
  pickup + push notifications), deployable as a container.
- **Multi-tenant** — provider wrappers (`agent_tenants`) that back the
  `idiom-agent-api` service with per-tenant agents over a shared chain/storage.
- **Pluggable storage** — in-memory, Askar (SQLite), or Kanon (Postgres).

---

## Repository layout

```
rs_ssi_agent/
├── src/                    # Rust cargo workspace (all crates)
├── interop-tests/          # credo-ts interop suite + performance/e2e harness
├── Dockerfile              # builds the mediator server image
└── fly.toml                # mediator deploy config (app: mediator-ssi-rs)
```

### Crate map (`src/`)

| Area | Crates |
|------|--------|
| **Foundation** | `core/agent_core`, `core/agent_di`, `core/agent_events`, `agent_module` |
| **Crypto / storage / wallet** | `crypto`, `storage`, `wallet` |
| **Identity primitives** | `did`, `didcomm`, `vc` |
| **DIDComm protocols** | `oob`, `connections`, `basic_messages`, `user_profile`, `coordinate_mediation`, `pickup`, `push_notifications`, `signing`, `credentials`, `proofs`, `workflow`, `poe` (+ `poe_prover`) |
| **Credentials / documents** | `credentials/anoncreds_core`, `credentials/mdoc` |
| **Ledger (VDR)** | `registry_kanon` (did:kanon on Besu) |
| **Multi-tenant** | `agent_tenants` |
| **Top-level** | `agent` (orchestration layer), `mediator_server`, `perf` |

The `agent` crate composes the protocol modules into a runnable agent; ledger
and storage backends are selected at runtime, not hardcoded.

---

## Quickstart

### Prerequisites

- Rust (stable, 2021 edition) with `cargo`
- For interop / e2e: Node.js (for the credo-ts harness)

### Build

```bash
cd src
cargo build                       # all crates
cargo test                        # workspace tests
```

### Run an agent over HTTP

The `http_server` example runs a full agent with an HTTP + DIDComm surface:

```bash
cd src
cargo run --example http_server --features http-server -- --port 3030
```

Runtime backends are chosen by environment variables:

| Var | Values | Meaning |
|-----|--------|---------|
| `AGENT_PORT` | port | HTTP + DIDComm listen port |
| `STORE` | `memory` \| `askar` \| `kanon` | wallet/record storage backend |
| `LEDGER` | `memory` \| `storage` \| `kanon` | AnonCreds registry (VDR) backend |
| `PUBLIC_DIDCOMM_URL` | URL | endpoint advertised in invitations |

Key HTTP endpoints: `/health`, `/oob/create-invitation`,
`/oob/receive-invitation`, `/connections`, `/basic-messages/send`,
`/setup/schema`, `/setup/cred-def`, `/issue/offer`, `/credentials/count`, and
the `/workflow/*` orchestration API.

To use the on-chain did:kanon ledger, build with the extra feature and provide
`KANON_*` config:

```bash
cargo run --example http_server --features http-server,kanon-registry
# reads KANON_RPC_URL, KANON_ORG_ID, KANON_CHAIN_ID,
#       KANON_ADDRESS_BOOK, KANON_OPERATOR_KEY
```

### Cargo features (`agent` crate)

| Feature | Enables |
|---------|---------|
| `http-server` | the axum HTTP/DIDComm server + example |
| `anoncreds` | AnonCreds issuance/proof modules |
| `kanon-storage` | Kanon Postgres storage backend (`STORE=kanon`) |
| `kanon-registry` | did:kanon on-chain VDR (`LEDGER=kanon`); implies `anoncreds` |
| `discovery` | mDNS / BLE peer discovery (native only) |

---

## did:kanon VDR

`registry_kanon` implements the AnonCreds registry over on-chain Besu
contracts (resolved from a `KanonAddressBook`):

- **Schema / CredentialDefinition registries** — resource ids are
  `did:kanon:org:<orgId>/anoncreds/v0/SCHEMA|CLAIM_DEF/…`; on-chain keys are
  `keccak256(utf8(resource_id))`, integrity anchored by
  `keccak256(canonical_json)`. These derivations are byte-identical to the
  reference `did_kanon` plugin, so idiom and the Python agents resolve each
  other's objects on the shared chain.
- **Revocation**
  - **Mode A** (`TIER_ONE_TIME`) — `AnonCredsStatusRegistry`.
  - **Mode B** (`TIER_ZK_SNARK`) — `MerkleStateRegistry` with a depth-26
    Poseidon Merkle tree, BabyJubjub EdDSA issuer signatures, and Groth16
    proofs. Cryptographic primitives are validated against the reference
    plugin's known-answer vectors.

---

## Workflow orchestration

The `workflow` protocol drives multi-step SSI flows from a JSON template
(states, transitions, actions, and a credential/proof catalog). Actions include
`state:set` (merges the advance input into instance context) and the
issue-credential / request-presentation protocol actions; an **attribute
planner** materializes credential attributes from context/static/compute
sources. Semantics mirror the reference `workflow_protocol` plugin (e.g.
lenient attribute resolution and whole-input context merge) so templates
authored for either implementation behave identically.

---

## Mediator

`mediator_server` is a standalone DIDComm mediator (coordinate-mediation,
message pickup, push notifications) with SQLite persistence.

```bash
cd src
cargo run -p mediator_server --release
# MEDIATOR_HOST, MEDIATOR_PORT, DATABASE_URL
```

The provided `Dockerfile` builds and runs it (`EXPOSE 3000`, health at
`/health`); `fly.toml` deploys it as `mediator-ssi-rs`.

---

## Testing & interoperability

### Interop suite (`interop-tests/`)

Cross-agent tests against credo-ts (connection establishment, basic messages):

```bash
cd interop-tests
npm install
./scripts/run-interop.sh
```

### Performance & end-to-end harness

- `interop-tests/perf/didcomm` — DIDComm throughput/latency.
- `interop-tests/perf/credentials/e2e-issue.sh` — full AnonCreds issuance
  between two idiom agents over a real OOB DIDComm handshake, anchored on the
  shared Kanon chain. Chain config is sourced from `kanon.env`:

  ```bash
  cd interop-tests/perf/credentials
  ./e2e-issue.sh
  # → holder credentials.count=1
  # → ✅ FULL PATH OK — credential issued + stored over DIDComm on the shared chain
  ```

---

## Deployment

- **Mediator** — `Dockerfile` + `fly.toml` (`mediator-ssi-rs`).
- **Agent API** — the multi-tenant `idiom-agent-api` service (in the CrMS
  consumer repo) path-depends on these crates via `agent`, `agent_tenants`,
  and `registry_kanon`.
