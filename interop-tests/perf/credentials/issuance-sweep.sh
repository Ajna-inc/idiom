#!/usr/bin/env bash
# ISSUANCE concurrency sweep: capture a request corpus once, then replay it at a
# range of client concurrencies (reseed + restart issuer between each) so we can
# see the throughput-vs-concurrency curve. A curve that plateaus early == the
# issuer serializes; one that scales with cores == we were just under-fed.
#
#   N=200 BIN=/tmp/http_server-release-opt LEVELS="1 2 4 8 16 32 64" ./issuance-sweep.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$HERE/../../../src"
BIN="${BIN:-$SRC/target/debug/examples/http_server}"; PROXY="$HERE/capture-response.mjs"
CORPUS="$HERE/requests.ndjson"
set -a; . "$HERE/kanon.env"; set +a
PG=postgres://postgres:pg@localhost:5555
psql() { docker exec idiom-bench-pg psql -U postgres -d "$1" -tAc "$2" 2>/dev/null; }
IPORT=3030; HPORT=3031; PPORT=4600; N=${N:-200}
LEVELS="${LEVELS:-1 2 4 8 16 32 64}"
jq() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
up() { for i in $(seq 1 40); do curl -sf "http://localhost:$1/health" >/dev/null 2>&1 && return; sleep 1; done; }
issued() { psql issuer_db "SELECT count(*) FROM kanon_generic_record WHERE record_type='anoncreds_credential_exchange' AND value->>'state'='CredentialIssued';"; }
reseed() { psql issuer_db "UPDATE kanon_generic_record SET value=jsonb_set(value,'{state}','\"OfferSent\"') WHERE record_type='anoncreds_credential_exchange';" >/dev/null; }

psql issuer_db "TRUNCATE kanon_generic_record; TRUNCATE kanon_key;" >/dev/null
psql holder_db "TRUNCATE kanon_generic_record; TRUNCATE kanon_key;" >/dev/null
: > "$CORPUS"

echo "════ CAPTURE $N requests ════"
PORT=$PPORT TARGET="http://localhost:$HPORT" CORPUS="$CORPUS" node "$PROXY" >/tmp/proxy.log 2>&1 & PXPID=$!
AGENT_PORT=$IPORT AGENT_LABEL=issuer STORE="kanon:$PG/issuer_db" LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/issuer.log 2>&1 & IPID=$!
AGENT_PORT=$HPORT AGENT_LABEL=holder AGENT_ENDPOINT="http://localhost:$PPORT" STORE="kanon:$PG/holder_db" LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/holder.log 2>&1 & HPID=$!
trap "kill $IPID $HPID $PXPID 2>/dev/null || true" EXIT
up $IPORT; up $HPORT; up $PPORT
INV=$(curl -s -X POST "http://localhost:$IPORT/oob/create-invitation" -d '{}' -H 'content-type: application/json')
curl -s -X POST "http://localhost:$HPORT/oob/receive-invitation" -H 'content-type: application/json' -d "{\"invitation\":$(echo "$INV" | jq 'json.dumps(d["invitation"])')}" >/dev/null
ICONN=""; for i in $(seq 1 25); do ICONN=$(curl -s "http://localhost:$IPORT/connections" | jq 'd[0]["id"] if d else ""'); [ -n "$ICONN" ] && curl -s "http://localhost:$IPORT/connections" | jq 'd[0]["state"]' | grep -qiE "complet|response" && break; sleep 1; done
DID="did:kanon:org:${KANON_ORG_ID}"
SID=$(curl -s -X POST "http://localhost:$IPORT/setup/schema" -H 'content-type: application/json' -d "{\"name\":\"sw\",\"version\":\"1.$(date +%s)\",\"attributes\":[\"name\",\"age\"],\"issuerId\":\"$DID\"}" | jq 'd["schemaId"]')
CDID=$(curl -s -X POST "http://localhost:$IPORT/setup/cred-def" -H 'content-type: application/json' -d "{\"schemaId\":\"$SID\",\"issuerId\":\"$DID\",\"tag\":\"sw$(date +%s)\"}" | jq 'd["credDefId"]')
curl -s -X POST "http://localhost:$PPORT/__truncate" >/dev/null || true
for i in $(seq 1 $N); do
  curl -s -X POST "http://localhost:$IPORT/issue/offer" -H 'content-type: application/json' -d "{\"connectionId\":\"$ICONN\",\"schemaId\":\"$SID\",\"credDefId\":\"$CDID\",\"attributes\":{\"name\":\"H$i\",\"age\":\"30\"}}" >/dev/null
done
for i in $(seq 1 30); do [ "$(issued)" = "$N" ] && break; sleep 1; done
echo "  captured $(wc -l < "$CORPUS") packed messages; issued(live)=$(issued)/$N"
kill $IPID $HPID $PXPID 2>/dev/null || true; sleep 2

echo "════ SWEEP concurrency: $LEVELS ════"
printf "  %-6s %-12s %-10s\n" conc creds/s per-req-ms
for C in $LEVELS; do
  reseed
  AGENT_PORT=$IPORT AGENT_LABEL=issuer STORE="kanon:$PG/issuer_db" LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/issuer2.log 2>&1 & IPID2=$!
  up $IPORT
  BEFORE=$(issued)
  python3 - "$CORPUS" "http://localhost:$IPORT" "$BEFORE" "$N" "$C" <<'PY'
import sys,json,base64,urllib.request,concurrent.futures,time,subprocess
msgs=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
target=sys.argv[2]; before=int(sys.argv[3]); N=int(sys.argv[4]); conc=int(sys.argv[5])
def issued():
    r=subprocess.run(["docker","exec","idiom-bench-pg","psql","-U","postgres","-d","issuer_db","-tAc",
        "SELECT count(*) FROM kanon_generic_record WHERE record_type='anoncreds_credential_exchange' AND value->>'state'='CredentialIssued';"],
        capture_output=True,text=True)
    try: return int(r.stdout.strip())
    except: return before
def post(m):
    body=base64.b64decode(m["b64"])
    req=urllib.request.Request(target+(m.get("path") or "/"),data=body,headers={"content-type":m.get("ctype") or "application/didcomm-envelope-enc"})
    try: urllib.request.urlopen(req,timeout=60).read()
    except Exception: pass
t0=time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
    list(ex.map(post,msgs))
last=before; stable=0; t_done=time.time()
while time.time()-t0 < 120:
    n=issued()
    if n>last: last=n; t_done=time.time(); stable=0
    else: stable+=1
    if last-before>=N or stable>=15: break
    time.sleep(0.2)
d=t_done-t0; s=last-before
rate=s/d if d>0 else 0
perreq=(conc*1000.0/rate) if rate>0 else 0
print(f"  {conc:<6} {rate:<12.1f} {perreq:<10.1f}")
PY
  kill $IPID2 2>/dev/null || true; sleep 1
done
echo "done."
