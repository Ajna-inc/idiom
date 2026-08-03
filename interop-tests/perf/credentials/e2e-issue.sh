#!/usr/bin/env bash
# Full-path AnonCreds issuance between two idiom agents over a real DIDComm
# connection, anchored on the shared Kanon chain (LEDGER=kanon) — the same
# methodology as perf/didcomm (real OOB handshake, then run through the agent).
#
#   ./e2e-issue.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../../../src"
BIN="$SRC/target/debug/examples/http_server"
set -a; . "$HERE/kanon.env"; set +a

IPORT=3030; HPORT=3031
jq() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }

echo "→ starting issuer(:$IPORT) + holder(:$HPORT) on LEDGER=kanon"
AGENT_PORT=$IPORT AGENT_LABEL=issuer STORE=memory LEDGER=kanon RUST_LOG=${RUST_LOG:-error} "$BIN" >/tmp/issuer.log 2>&1 &
IPID=$!
AGENT_PORT=$HPORT AGENT_LABEL=holder STORE=memory LEDGER=kanon RUST_LOG=${RUST_LOG:-error} "$BIN" >/tmp/holder.log 2>&1 &
HPID=$!
trap "kill $IPID $HPID 2>/dev/null || true" EXIT
for p in $IPORT $HPORT; do for i in $(seq 1 40); do curl -sf "http://localhost:$p/health" >/dev/null 2>&1 && break; sleep 1; done; done

echo "→ OOB: issuer create-invitation, holder receive-invitation, wait for complete"
INV=$(curl -s -X POST "http://localhost:$IPORT/oob/create-invitation" -H 'content-type: application/json' -d '{}')
INVOBJ=$(echo "$INV" | jq 'json.dumps(d["invitation"])')
curl -s -X POST "http://localhost:$HPORT/oob/receive-invitation" -H 'content-type: application/json' -d "{\"invitation\":$INVOBJ}" >/dev/null
ICONN=""
for i in $(seq 1 25); do
  ICONN=$(curl -s "http://localhost:$IPORT/connections" | jq 'd[0]["id"] if d else ""')
  ISTATE=$(curl -s "http://localhost:$IPORT/connections" | jq 'd[0]["state"] if d else ""')
  [ -n "$ICONN" ] && echo "$ISTATE" | grep -qiE "complet|response|active" && break
  sleep 1
done
echo "  issuer connId=$ICONN ($ISTATE)"

echo "→ issuer: register schema + cred-def ON-CHAIN"
ISSUER_DID="did:kanon:org:${KANON_ORG_ID}"
S=$(curl -s -X POST "http://localhost:$IPORT/setup/schema" -H 'content-type: application/json' \
  -d "{\"name\":\"e2e\",\"version\":\"1.$(date +%s)\",\"attributes\":[\"name\",\"age\"],\"issuerId\":\"$ISSUER_DID\"}")
SID=$(echo "$S" | jq 'd["schemaId"]')
TAG="t$(date +%s)"  # unique tag so the on-chain cred-def id doesn't collide across runs
CD=$(curl -s -X POST "http://localhost:$IPORT/setup/cred-def" -H 'content-type: application/json' \
  -d "{\"schemaId\":\"$SID\",\"issuerId\":\"$ISSUER_DID\",\"tag\":\"$TAG\"}")
CDID=$(echo "$CD" | jq 'd["credDefId"]')
echo "  credDefId=$CDID"

echo "→ holder credentials before: $(curl -s http://localhost:$HPORT/credentials/count | jq 'd["count"]')"
echo "→ issuer: /issue/offer over the connection (holder auto-accepts, resolves cred-def from chain)"
curl -s -X POST "http://localhost:$IPORT/issue/offer" -H 'content-type: application/json' \
  -d "{\"connectionId\":\"$ICONN\",\"schemaId\":\"$SID\",\"credDefId\":\"$CDID\",\"attributes\":{\"name\":\"Alice\",\"age\":\"30\"}}"
echo
echo "→ waiting for holder to store the credential…"
for i in $(seq 1 30); do
  N=$(curl -s "http://localhost:$HPORT/credentials/count" | jq 'd["count"]')
  echo "  holder credentials.count=$N"
  [ "$N" != "0" ] && [ -n "$N" ] && { echo "✅ FULL PATH OK — credential issued + stored over DIDComm on the shared chain"; break; }
  sleep 1
done
echo "--- holder errors (if any) ---"; grep -iE "error|fail|panic" /tmp/holder.log | grep -viE "RUST_LOG|GET|POST" | tail -5 || true
