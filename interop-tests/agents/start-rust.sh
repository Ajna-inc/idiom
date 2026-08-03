#!/bin/bash
#
# Start the idiom Rust HTTP server for interop testing (mediated).
#
# The Rust agent connects to the live mediator via MEDIATOR_INVITATION_URL and
# receives all its inbound DIDComm through mediator pickup (no local inbound
# transport). Fetch a fresh invite before calling this, e.g.:
#
#   export MEDIATOR_INVITATION_URL=$(curl -s https://mediator.ajna.surf/invite \
#     | python3 -c 'import sys,json;print(json.load(sys.stdin)["invitationUrl"])')
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$SCRIPT_DIR/../../src/agent"

cd "$RUST_DIR"

echo "🚀 Starting Rust agent HTTP server (mediated)..."
echo ""

if [ -z "$MEDIATOR_INVITATION_URL" ]; then
  echo "⚠️  MEDIATOR_INVITATION_URL not set — fetching a fresh invite from mediator.ajna.surf"
  export MEDIATOR_INVITATION_URL=$(curl -s https://mediator.ajna.surf/invite \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["invitationUrl"])')
fi

export AGENT_PORT="${AGENT_PORT:-3002}"
export AGENT_HOST="${AGENT_HOST:-127.0.0.1}"
export AGENT_LABEL="${AGENT_LABEL:-Rust Interop Agent}"

echo "📡 Mediator URL: ${MEDIATOR_INVITATION_URL:0:60}..."
echo "🔌 Port:  $AGENT_PORT"
echo "🏷️  Label: $AGENT_LABEL"

export RUST_LOG="${RUST_LOG:-agent=debug,protocol_connections=debug,protocol_oob=debug,protocol_didexchange=debug,protocol_coordinate_mediation=debug,protocol_pickup=debug,didcomm_transports=debug,didcomm_messaging=debug}"

# http-server only — the webrtc feature was removed from the agent.
exec cargo run --example http_server --features http-server
