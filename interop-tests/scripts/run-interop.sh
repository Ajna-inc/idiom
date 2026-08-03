#!/bin/bash
#
# One-command live interop runner (CI-friendly).
#
# Topology: both the Credo-TS agent and the idiom Rust agent are mediated
# via the live mediator at mediator.ajna.surf. Each agent receives its OWN
# freshly-fetched invite URL. All inbound DIDComm arrives via mediator pickup.
#
# Steps:
#   1. Free ports 3000 / 3002 / 9000.
#   2. Fetch a fresh invite for the Rust agent and a separate one for Credo.
#   3. Start the Rust agent (:3002) and the Credo agent (:3000 / :9000).
#   4. Wait for both /health endpoints, then wait ~25s each for the mediator
#      handshake + pickup to come up.
#   5. Run the connection + basic-messages vitest suites.
#   6. Always clean up both agents on exit.
#
# Ports:
#   Credo HTTP API 3000, Credo WS events 9000, Rust HTTP+SSE 3002.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$PROJECT_DIR/../src/agent"

CREDO_PID_FILE="$PROJECT_DIR/.credo-agent.pid"
RUST_PID_FILE="$PROJECT_DIR/.rust-agent.pid"

# Override to point at a different mediator, e.g. the idiom mediator:
#   MEDIATOR_INVITE_ENDPOINT=https://mediator-ssi-rs.fly.dev/invite bash scripts/run-interop.sh
MEDIATOR_INVITE_ENDPOINT="${MEDIATOR_INVITE_ENDPOINT:-https://mediator.ajna.surf/invite}"

CREDO_PORT=3000
CREDO_WS_PORT=9000
RUST_PORT=3002

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${YELLOW}$*${NC}"; }
ok()   { echo -e "${GREEN}$*${NC}"; }
err()  { echo -e "${RED}$*${NC}"; }

kill_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        log "  Freeing port $port"
        lsof -ti :$port | xargs kill -9 2>/dev/null || true
        sleep 1
    fi
}

cleanup() {
    echo ""
    log "🧹 Cleaning up agents..."
    for pf in "$CREDO_PID_FILE" "$RUST_PID_FILE"; do
        if [ -f "$pf" ]; then
            local pid
            pid=$(cat "$pf")
            if ps -p "$pid" >/dev/null 2>&1; then
                kill "$pid" 2>/dev/null || true
            fi
            rm -f "$pf"
        fi
    done
    kill_port $CREDO_PORT
    kill_port $CREDO_WS_PORT
    kill_port $RUST_PORT
    ok "✓ Cleanup complete"
}
trap cleanup EXIT INT TERM

fetch_invite() {
    curl -s "$MEDIATOR_INVITE_ENDPOINT" \
        | python3 -c 'import sys,json;print(json.load(sys.stdin)["invitationUrl"])'
}

wait_for_health() {
    local url=$1 name=$2 retries=${3:-60}
    log "  Waiting for $name health at $url ..."
    while [ $retries -gt 0 ]; do
        if curl -sf "$url" >/dev/null 2>&1; then
            ok "  ✓ $name is healthy"
            return 0
        fi
        sleep 1
        retries=$((retries - 1))
    done
    err "  ✗ $name did not become healthy"
    return 1
}

# ---------------------------------------------------------------------------

log "🔧 Step 1: Freeing ports $CREDO_PORT / $RUST_PORT / $CREDO_WS_PORT"
kill_port $CREDO_PORT
kill_port $RUST_PORT
kill_port $CREDO_WS_PORT

log "🔧 Step 2: Fetching fresh mediator invites (one per agent)"
RUST_INVITE=$(fetch_invite)
CREDO_INVITE=$(fetch_invite)
if [ -z "$RUST_INVITE" ] || [ -z "$CREDO_INVITE" ]; then
    err "✗ Failed to fetch mediator invites from $MEDIATOR_INVITE_ENDPOINT"
    exit 1
fi
ok "  ✓ Rust  invite:  ${RUST_INVITE:0:55}..."
ok "  ✓ Credo invite:  ${CREDO_INVITE:0:55}..."

mkdir -p "$PROJECT_DIR/logs"
STAMP=$(date +%Y%m%d-%H%M%S)
RUST_LOG_FILE="$PROJECT_DIR/logs/rust-$STAMP.log"
CREDO_LOG_FILE="$PROJECT_DIR/logs/credo-$STAMP.log"

log "🚀 Step 3a: Starting Rust agent (:$RUST_PORT), mediated"
(
    cd "$RUST_DIR"
    AGENT_PORT=$RUST_PORT AGENT_HOST=127.0.0.1 AGENT_LABEL="Rust Interop Agent" \
        MEDIATOR_INVITATION_URL="$RUST_INVITE" \
        RUST_LOG="${RUST_LOG:-agent=debug,protocol_connections=debug,protocol_oob=debug,protocol_coordinate_mediation=debug,protocol_pickup=debug,didcomm_transports=debug,didcomm_messaging=debug}" \
        cargo run --example http_server --features http-server
) > "$RUST_LOG_FILE" 2>&1 &
echo $! > "$RUST_PID_FILE"
log "  Rust logging to: $RUST_LOG_FILE"

log "🚀 Step 3b: Starting Credo agent (:$CREDO_PORT / ws :$CREDO_WS_PORT), mediated"
(
    cd "$PROJECT_DIR"
    MEDIATOR_INVITATION_URL="$CREDO_INVITE" npm run start:credo
) > "$CREDO_LOG_FILE" 2>&1 &
echo $! > "$CREDO_PID_FILE"
log "  Credo logging to: $CREDO_LOG_FILE"

log "⏳ Step 4: Waiting for health endpoints"
wait_for_health "http://localhost:$RUST_PORT/health"  "Rust"  90 || { err "Rust agent never came up"; exit 1; }
wait_for_health "http://localhost:$CREDO_PORT/health" "Credo" 90 || { err "Credo agent never came up"; exit 1; }

log "⏳ Step 4b: Waiting ~25s per agent for mediator handshake + pickup startup"
sleep 25
ok "  ✓ Grace period for Rust mediation elapsed"
sleep 25
ok "  ✓ Grace period for Credo mediation elapsed"

log "🧪 Step 5: Running vitest interop suites"
cd "$PROJECT_DIR"
set +e
# Optional: INTEROP_FILES overrides which spec files run; INTEROP_GREP passes a
# -t name filter (e.g. INTEROP_GREP="Credo inviter" to isolate one test).
_files="${INTEROP_FILES:-tests/connection.test.ts tests/basic-messages.test.ts}"
if [ -n "${INTEROP_GREP:-}" ]; then
    npx vitest run $_files -t "$INTEROP_GREP"
else
    npx vitest run $_files
fi
TEST_EXIT=$?
set -e 2>/dev/null || true

echo ""
if [ $TEST_EXIT -eq 0 ]; then
    ok "✅ Interop tests PASSED"
else
    err "❌ Interop tests FAILED (exit $TEST_EXIT)"
    err "   Rust log:  $RUST_LOG_FILE"
    err "   Credo log: $CREDO_LOG_FILE"
fi

exit $TEST_EXIT
