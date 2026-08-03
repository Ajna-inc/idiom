#!/usr/bin/env bash
# Capture real packed AnonCreds credential DIDComm messages from an idiom
# issuer→holder exchange on the shared Kanon chain, using the same capture proxy
# as the DIDComm bench. The corpus (offer + issue blobs) is written to
# corpus.ndjson for replay.
#
#   ./capture-issue.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../../../src"
BIN="$SRC/target/debug/examples/http_server"
PROXY="$HERE/../didcomm/capture-proxy.mjs"
CORPUS="$HERE/corpus.ndjson"
set -a; . "$HERE/kanon.env"; set +a

IPORT=3030; HPORT=3031; PPORT=4600
jq() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }

: > "$CORPUS"
echo "→ capture proxy :$PPORT → holder :$HPORT   corpus=$CORPUS"
PORT=$PPORT TARGET="http://localhost:$HPORT" CORPUS="$CORPUS" node "$PROXY" >/tmp/proxy.log 2>&1 &
PXPID=$!
echo "→ starting issuer(:$IPORT) + holder(:$HPORT, advertising proxy :$PPORT)"
AGENT_PORT=$IPORT AGENT_LABEL=issuer STORE=memory LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/issuer.log 2>&1 &
IPID=$!
AGENT_PORT=$HPORT AGENT_LABEL=holder AGENT_ENDPOINT="http://localhost:$PPORT" STORE=memory LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/holder.log 2>&1 &
HPID=$!
trap "kill $IPID $HPID $PXPID 2>/dev/null || true" EXIT
for p in $IPORT $HPORT $PPORT; do for i in $(seq 1 40); do curl -sf "http://localhost:$p/health" >/dev/null 2>&1 && break; sleep 1; done; done

echo "→ OOB connect"
INV=$(curl -s -X POST "http://localhost:$IPORT/oob/create-invitation" -H 'content-type: application/json' -d '{}')
INVOBJ=$(echo "$INV" | jq 'json.dumps(d["invitation"])')
curl -s -X POST "http://localhost:$HPORT/oob/receive-invitation" -H 'content-type: application/json' -d "{\"invitation\":$INVOBJ}" >/dev/null
ICONN=""; for i in $(seq 1 25); do
  ICONN=$(curl -s "http://localhost:$IPORT/connections" | jq 'd[0]["id"] if d else ""')
  ISTATE=$(curl -s "http://localhost:$IPORT/connections" | jq 'd[0]["state"] if d else ""')
  [ -n "$ICONN" ] && echo "$ISTATE" | grep -qiE "complet|response|active" && break; sleep 1
done
echo "  connId=$ICONN"

echo "→ register cred-def on-chain"
DID="did:kanon:org:${KANON_ORG_ID}"
SID=$(curl -s -X POST "http://localhost:$IPORT/setup/schema" -H 'content-type: application/json' \
  -d "{\"name\":\"cap\",\"version\":\"1.$(date +%s)\",\"attributes\":[\"name\",\"age\"],\"issuerId\":\"$DID\"}" | jq 'd["schemaId"]')
CDID=$(curl -s -X POST "http://localhost:$IPORT/setup/cred-def" -H 'content-type: application/json' \
  -d "{\"schemaId\":\"$SID\",\"issuerId\":\"$DID\",\"tag\":\"cap$(date +%s)\"}" | jq 'd["credDefId"]')

echo "→ truncate corpus (drop didexchange noise), then issue N credentials to capture the credential messages"
curl -s -X POST "http://localhost:$PPORT/__truncate" >/dev/null || true
N=${N:-5}
for i in $(seq 1 $N); do
  curl -s -X POST "http://localhost:$IPORT/issue/offer" -H 'content-type: application/json' \
    -d "{\"connectionId\":\"$ICONN\",\"schemaId\":\"$SID\",\"credDefId\":\"$CDID\",\"attributes\":{\"name\":\"H$i\",\"age\":\"30\"}}" >/dev/null
  sleep 1
done
# let the last exchange finish flowing through the proxy
for i in $(seq 1 10); do
  C=$(curl -s "http://localhost:$HPORT/credentials/count" | jq 'd["count"]'); [ "$C" = "$N" ] && break; sleep 1
done
echo "→ holder stored: $(curl -s http://localhost:$HPORT/credentials/count | jq 'd["count"]') credentials"
echo "→ CAPTURED corpus: $(wc -l < "$CORPUS") packed messages"
echo "→ message types in corpus:"
python3 - "$CORPUS" <<'PY'
import sys,json,base64
seen={}
for line in open(sys.argv[1]):
    try:
        b=base64.b64decode(json.loads(line)["b64"])
        # packed JWE — can't read type without unpack; just count + size
        seen["packed_jwe"]=seen.get("packed_jwe",0)+1
    except Exception: pass
for k,v in seen.items(): print(f"   {k}: {v}")
PY
