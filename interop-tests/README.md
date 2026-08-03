# idiom ↔ Credo-TS live interop tests

Real DIDComm interoperability tests between the **idiom** Rust agent and a
**Credo-TS** agent. This is a live harness (not JSON fixtures): it starts both
agents, connects them over real DIDComm, and asserts on the events each agent
emits.

## Topology

Both agents are **mediated** through the live mediator at
`https://mediator.ajna.surf`. Each agent fetches its **own** fresh invite from
`https://mediator.ajna.surf/invite` (the JSON `.invitationUrl` field) and passes
it via `MEDIATOR_INVITATION_URL`. Neither agent runs a local inbound transport —
all inbound DIDComm arrives via mediator pickup.

```
  Credo-TS agent  ──┐                          ┌──  Rust agent (idiom)
  HTTP API :3000    │                          │    HTTP API + SSE :3002
  WS events :9000   ├──►  mediator.ajna.surf  ◄─┤
                    │     (pickup + routing)   │
                    └──────────────────────────┘
```

The vitest suites observe events over:
- Credo: WebSocket at `ws://localhost:9000`
- Rust: Server-Sent Events at `http://localhost:3002/events`

...and drive both agents over their HTTP APIs.

## Ports

| Agent | HTTP API | Events |
|-------|----------|--------|
| Credo | 3000     | WS 9000 |
| Rust  | 3002     | SSE on 3002 `/events` |

## Running

```bash
npm install
./scripts/run-interop.sh
```

`scripts/run-interop.sh` is the primary, CI-friendly entry point. It:
1. Frees ports 3000 / 3002 / 9000.
2. Fetches a fresh mediator invite for the Rust agent and a separate one for Credo.
3. Starts the Rust agent (`cargo run --example http_server --features http-server`)
   and the Credo agent (`tsx agents/start-credo.ts`), each mediated.
4. Waits for both `/health` endpoints, then waits ~25s per agent for the
   mediator handshake + pickup to come up.
5. Runs `npx vitest run tests/connection.test.ts tests/basic-messages.test.ts`.
6. Always cleans up both agents on exit (via a trap).

The Rust example is built on first run; to prebuild:

```bash
cargo build --example http_server --features http-server \
  --manifest-path ../src/agent/Cargo.toml
```

### Manual agent management

```bash
npm run agents:start    # start both agents (fresh invite each)
npm run agents:status
npm run test            # run all vitest suites against running agents
npm run agents:stop
```

## Notes

- **WebRTC was dropped.** The `webrtc` feature was removed from the Rust agent,
  so there is no `webrtc.test.ts`, no webrtc client methods, and the Rust agent
  is built with `--features http-server` only (no `webrtc`).
- Logs for each run land in `logs/` (git-ignored).
