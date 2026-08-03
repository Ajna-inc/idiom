#!/usr/bin/env bash
# Credential-message benchmark, DIDComm-bench style:
#  1. Capture real packed credential messages from an idiom issuer→holder
#     exchange on the shared Kanon chain (STORE=kanon → keys persist in Postgres).
#  2. Restart the holder (reloads its keys+connection from Postgres — the "seed").
#  3. Replay the corpus ×1000s at the holder's inbound → processing throughput.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../../../src"
BIN="$SRC/target/debug/examples/http_server"
PROXY="$HERE/../didcomm/capture-proxy.mjs"
REPLAY="$HERE/../didcomm/replay.mjs"
CORPUS="$HERE/corpus.ndjson"
set -a; . "$HERE/kanon.env"; set +a

PG=postgres://postgres:pg@localhost:5555
ISTORE="kanon:$PG/issuer_db"
HSTORE="kanon:$PG/holder_db"
IPORT=3030; HPORT=3031; PPORT=4600
N=${N:-8}; TOTAL=${TOTAL:-3000}; LEVELS=${LEVELS:-8,16,32,64}
jq() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
wait_up() { for i in $(seq 1 40); do curl -sf "http://localhost:$1/health" >/dev/null 2>&1 && return; sleep 1; done; }

: > "$CORPUS"
echo "════ 1. CAPTURE (issuer→holder over the shared chain, STORE=kanon) ════"
PORT=$PPORT TARGET="http://localhost:$HPORT" CORPUS="$CORPUS" node "$PROXY" >/tmp/proxy.log 2>&1 &
PXPID=$!
AGENT_PORT=$IPORT AGENT_LABEL=issuer STORE="$ISTORE" LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/issuer.log 2>&1 &
IPID=$!
AGENT_PORT=$HPORT AGENT_LABEL=holder AGENT_ENDPOINT="http://localhost:$PPORT" STORE="$HSTORE" LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/holder.log 2>&1 &
HPID=$!
trap "kill $IPID $HPID $PXPID 2>/dev/null || true" EXIT
wait_up $IPORT; wait_up $HPORT; wait_up $PPORT

INV=$(curl -s -X POST "http://localhost:$IPORT/oob/create-invitation" -H 'content-type: application/json' -d '{}')
curl -s -X POST "http://localhost:$HPORT/oob/receive-invitation" -H 'content-type: application/json' \
  -d "{\"invitation\":$(echo "$INV" | jq 'json.dumps(d["invitation"])')}" >/dev/null
ICONN=""; for i in $(seq 1 25); do
  ICONN=$(curl -s "http://localhost:$IPORT/connections" | jq 'd[0]["id"] if d else ""')
  [ -n "$ICONN" ] && curl -s "http://localhost:$IPORT/connections" | jq 'd[0]["state"]' | grep -qiE "complet|response" && break; sleep 1
done
DID="did:kanon:org:${KANON_ORG_ID}"
SID=$(curl -s -X POST "http://localhost:$IPORT/setup/schema" -H 'content-type: application/json' \
  -d "{\"name\":\"cap\",\"version\":\"1.$(date +%s)\",\"attributes\":[\"name\",\"age\"],\"issuerId\":\"$DID\"}" | jq 'd["schemaId"]')
CDID=$(curl -s -X POST "http://localhost:$IPORT/setup/cred-def" -H 'content-type: application/json' \
  -d "{\"schemaId\":\"$SID\",\"issuerId\":\"$DID\",\"tag\":\"cap$(date +%s)\"}" | jq 'd["credDefId"]')
curl -s -X POST "http://localhost:$PPORT/__truncate" >/dev/null || true
for i in $(seq 1 $N); do
  curl -s -X POST "http://localhost:$IPORT/issue/offer" -H 'content-type: application/json' \
    -d "{\"connectionId\":\"$ICONN\",\"schemaId\":\"$SID\",\"credDefId\":\"$CDID\",\"attributes\":{\"name\":\"H$i\",\"age\":\"30\"}}" >/dev/null
  sleep 1
done
for i in $(seq 1 15); do [ "$(curl -s http://localhost:$HPORT/credentials/count | jq 'd["count"]')" = "$N" ] && break; sleep 1; done
echo "  issued+stored: $(curl -s http://localhost:$HPORT/credentials/count | jq 'd["count"]')   captured: $(wc -l < "$CORPUS") packed messages"

echo "════ 2. RESTART holder on holder_db (reload keys+connection from Postgres) ════"
kill $IPID $PXPID 2>/dev/null || true      # stop issuer + proxy
kill $HPID 2>/dev/null || true; sleep 2    # stop holder
AGENT_PORT=$HPORT AGENT_LABEL=holder STORE="$HSTORE" LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/holder2.log 2>&1 &
HPID2=$!
trap "kill $HPID2 2>/dev/null || true" EXIT
wait_up $HPORT
echo "  holder back up; persisted credentials.count=$(curl -s http://localhost:$HPORT/credentials/count | jq 'd["count"]')"

echo "════ 3. REPLAY corpus ×$TOTAL at holder inbound → processing throughput ════"
CORPUS="$CORPUS" TARGET="http://localhost:$HPORT" LEVELS="$LEVELS" TOTAL="$TOTAL" node "$REPLAY"
