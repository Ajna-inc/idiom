#!/bin/bash
#
# Manage the Credo and Rust agents for interop testing.
#
# Both agents are mediated via the live mediator at mediator.ajna.surf. Each
# agent is given its OWN freshly-fetched invite URL via MEDIATOR_INVITATION_URL.
#
# Ports:
#   Credo HTTP API:      3000
#   Credo WS events:     9000
#   Rust  HTTP API+SSE:  3002

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$PROJECT_DIR/../src/agent"

CREDO_PID_FILE="$PROJECT_DIR/.credo-agent.pid"
RUST_PID_FILE="$PROJECT_DIR/.rust-agent.pid"

MEDIATOR_INVITE_ENDPOINT="https://mediator.ajna.surf/invite"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

fetch_invite() {
    curl -s "$MEDIATOR_INVITE_ENDPOINT" \
        | python3 -c 'import sys,json;print(json.load(sys.stdin)["invitationUrl"])'
}

check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

kill_process_on_port() {
    local port=$1
    if check_port $port; then
        echo -e "${YELLOW}Killing process on port $port${NC}"
        lsof -ti :$port | xargs kill -9 2>/dev/null
        sleep 1
    fi
}

stop_agents() {
    echo -e "${YELLOW}Stopping agents...${NC}"

    if [ -f "$CREDO_PID_FILE" ]; then
        local credo_pid=$(cat "$CREDO_PID_FILE")
        if ps -p $credo_pid > /dev/null 2>&1; then
            kill $credo_pid 2>/dev/null
        fi
        rm -f "$CREDO_PID_FILE"
    fi

    if [ -f "$RUST_PID_FILE" ]; then
        local rust_pid=$(cat "$RUST_PID_FILE")
        if ps -p $rust_pid > /dev/null 2>&1; then
            kill $rust_pid 2>/dev/null
        fi
        rm -f "$RUST_PID_FILE"
    fi

    kill_process_on_port 3000  # Credo HTTP API
    kill_process_on_port 3002  # Rust HTTP API + SSE
    kill_process_on_port 9000  # Credo WebSocket Events

    echo -e "${GREEN}✓ Agents stopped${NC}"
}

start_credo() {
    echo -e "${YELLOW}Starting Credo agent...${NC}"
    cd "$PROJECT_DIR"

    mkdir -p "$PROJECT_DIR/logs"
    local log_file="$PROJECT_DIR/logs/credo-$(date +%Y%m%d-%H%M%S).log"

    echo -e "  Fetching fresh mediator invite for Credo..."
    local credo_invite=$(fetch_invite)

    MEDIATOR_INVITATION_URL="$credo_invite" npm run start:credo > "$log_file" 2>&1 &
    echo $! > "$CREDO_PID_FILE"

    echo -e "  Logging to: $log_file"

    local retries=30
    while [ $retries -gt 0 ]; do
        if check_port 3000; then
            echo -e "${GREEN}✓ Credo agent ready on ports 3000 (HTTP API), 9000 (Events)${NC}"
            return 0
        fi
        sleep 1
        retries=$((retries - 1))
    done

    echo -e "${RED}✗ Credo agent failed to start${NC}"
    echo -e "${YELLOW}  Check logs: $log_file${NC}"
    return 1
}

start_rust() {
    echo -e "${YELLOW}Starting Rust agent...${NC}"
    cd "$RUST_DIR"

    local rust_port="${AGENT_PORT:-3002}"
    local rust_host="${AGENT_HOST:-127.0.0.1}"

    mkdir -p "$PROJECT_DIR/logs"
    local log_file="$PROJECT_DIR/logs/rust-$(date +%Y%m%d-%H%M%S).log"

    echo -e "  Fetching fresh mediator invite for Rust..."
    local rust_invite=$(fetch_invite)

    AGENT_PORT=$rust_port AGENT_HOST=$rust_host AGENT_LABEL="Rust Interop Agent" \
        MEDIATOR_INVITATION_URL="$rust_invite" \
        cargo run --example http_server --features http-server > "$log_file" 2>&1 &
    echo $! > "$RUST_PID_FILE"

    echo -e "  Logging to: $log_file"
    echo -e "  Port: $rust_port"

    local retries=60
    while [ $retries -gt 0 ]; do
        if check_port $rust_port; then
            echo -e "${GREEN}✓ Rust agent ready on port $rust_port (HTTP API + SSE Events)${NC}"
            return 0
        fi
        sleep 1
        retries=$((retries - 1))
    done

    echo -e "${RED}✗ Rust agent failed to start${NC}"
    echo -e "${YELLOW}  Check logs: $log_file${NC}"
    return 1
}

start_agents() {
    echo -e "${YELLOW}Starting agents for interop testing...${NC}\n"
    stop_agents
    sleep 2
    start_rust || exit 1
    start_credo || exit 1
    echo -e "\n${GREEN}✅ All agents running and ready for testing!${NC}"
}

status() {
    echo -e "${YELLOW}Agent Status:${NC}"
    if check_port 3000; then
        echo -e "  Credo HTTP API (3000): ${GREEN}✓ Running${NC}"
    else
        echo -e "  Credo HTTP API (3000): ${RED}✗ Stopped${NC}"
    fi
    if check_port 9000; then
        echo -e "  Credo Events WS (9000): ${GREEN}✓ Running${NC}"
    else
        echo -e "  Credo Events WS (9000): ${RED}✗ Stopped${NC}"
    fi
    if check_port 3002; then
        echo -e "  Rust HTTP API (3002): ${GREEN}✓ Running${NC}"
    else
        echo -e "  Rust HTTP API (3002): ${RED}✗ Stopped${NC}"
    fi
}

case "$1" in
    start)   start_agents ;;
    stop)    stop_agents ;;
    restart) stop_agents; sleep 2; start_agents ;;
    status)  status ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
