#!/usr/bin/env bash
# ISSUANCE benchmark: replay real credential REQUESTS at the idiom issuer so each
# drives a real create_credential (CL sign) over the full DIDComm path.
#
#  1. Capture N requests (proxy in front of the ISSUER; holder auto-requests).
#  2. Reseed: reset the issuer's exchanges to OfferSent (SQL) + restart it.
#     Auto-issue attrs are persisted on the record, so replay re-issues.
#  3. Replay the request corpus at the issuer → count signings + time.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$HERE/../../../src"
BIN="${BIN:-$SRC/target/debug/examples/http_server}"; PROXY="$HERE/capture-response.mjs"
CORPUS="$HERE/requests.ndjson"
set -a; . "$HERE/kanon.env"; set +a
PG=postgres://postgres:pg@localhost:5555
psql() { docker exec idiom-bench-pg psql -U postgres -d "$1" -tAc "$2" 2>/dev/null; }
IPORT=3030; HPORT=3031; PPORT=4600; N=${N:-20}
jq() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
up() { for i in $(seq 1 40); do curl -sf "http://localhost:$1/health" >/dev/null 2>&1 && return; sleep 1; done; }
issued() { psql issuer_db "SELECT count(*) FROM kanon_generic_record WHERE record_type='anoncreds_credential_exchange' AND value->>'state'='CredentialIssued';"; }

# fresh DBs
psql issuer_db "TRUNCATE kanon_generic_record; TRUNCATE kanon_key;" >/dev/null
psql holder_db "TRUNCATE kanon_generic_record; TRUNCATE kanon_key;" >/dev/null
: > "$CORPUS"

echo "════ 1. CAPTURE $N requests (response-proxy in front of HOLDER — the inline request is the offer POST's response) ════"
PORT=$PPORT TARGET="http://localhost:$HPORT" CORPUS="$CORPUS" node "$PROXY" >/tmp/proxy.log 2>&1 & PXPID=$!
AGENT_PORT=$IPORT AGENT_LABEL=issuer STORE="kanon:$PG/issuer_db" LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/issuer.log 2>&1 & IPID=$!
AGENT_PORT=$HPORT AGENT_LABEL=holder AGENT_ENDPOINT="http://localhost:$PPORT" STORE="kanon:$PG/holder_db" LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/holder.log 2>&1 & HPID=$!
trap "kill $IPID $HPID $PXPID 2>/dev/null || true" EXIT
up $IPORT; up $HPORT; up $PPORT
INV=$(curl -s -X POST "http://localhost:$IPORT/oob/create-invitation" -d '{}' -H 'content-type: application/json')
curl -s -X POST "http://localhost:$HPORT/oob/receive-invitation" -H 'content-type: application/json' -d "{\"invitation\":$(echo "$INV" | jq 'json.dumps(d["invitation"])')}" >/dev/null
ICONN=""; for i in $(seq 1 25); do ICONN=$(curl -s "http://localhost:$IPORT/connections" | jq 'd[0]["id"] if d else ""'); [ -n "$ICONN" ] && curl -s "http://localhost:$IPORT/connections" | jq 'd[0]["state"]' | grep -qiE "complet|response" && break; sleep 1; done
DID="did:kanon:org:${KANON_ORG_ID}"
SID=$(curl -s -X POST "http://localhost:$IPORT/setup/schema" -H 'content-type: application/json' -d "{\"name\":\"iss\",\"version\":\"1.$(date +%s)\",\"attributes\":[\"name\",\"age\"],\"issuerId\":\"$DID\"}" | jq 'd["schemaId"]')
CDID=$(curl -s -X POST "http://localhost:$IPORT/setup/cred-def" -H 'content-type: application/json' -d "{\"schemaId\":\"$SID\",\"issuerId\":\"$DID\",\"tag\":\"iss$(date +%s)\"}" | jq 'd["credDefId"]')
curl -s -X POST "http://localhost:$PPORT/__truncate" >/dev/null || true
for i in $(seq 1 $N); do
  curl -s -X POST "http://localhost:$IPORT/issue/offer" -H 'content-type: application/json' -d "{\"connectionId\":\"$ICONN\",\"schemaId\":\"$SID\",\"credDefId\":\"$CDID\",\"attributes\":{\"name\":\"H$i\",\"age\":\"30\"}}" >/dev/null
done
for i in $(seq 1 20); do [ "$(issued)" = "$N" ] && break; sleep 1; done
echo "  issued (live): $(issued)/$N   captured: $(wc -l < "$CORPUS") holder→issuer packed messages"
kill $IPID $HPID $PXPID 2>/dev/null || true; sleep 2

echo "════ 2. RESEED: reset issuer exchanges to OfferSent, restart issuer ════"
psql issuer_db "UPDATE kanon_generic_record SET value=jsonb_set(value,'{state}','\"OfferSent\"') WHERE record_type='anoncreds_credential_exchange';" >/dev/null
echo "  exchanges now OfferSent: $(psql issuer_db "SELECT count(*) FROM kanon_generic_record WHERE record_type='anoncreds_credential_exchange' AND value->>'state'='OfferSent';")   CredentialIssued: $(issued)"
AGENT_PORT=$IPORT AGENT_LABEL=issuer STORE="kanon:$PG/issuer_db" LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/issuer2.log 2>&1 & IPID2=$!
trap "kill $IPID2 2>/dev/null || true" EXIT
up $IPORT

echo "════ 3. REPLAY requests at issuer → real create_credential per request ════"
BEFORE=$(issued)
# The signing window = from first replay POST until the issued count stops
# climbing (settled). Poll issued() from a background watcher via the DB and
# print the elapsed once it plateaus, so the number is the real sign rate — not
# a fixed settle sleep.
case "$BIN" in *release*) BUILD=release;; *) BUILD=debug;; esac
python3 - "$CORPUS" "http://localhost:$IPORT" "$BEFORE" "$N" "$BUILD" <<'PY'
import sys,json,base64,urllib.request,concurrent.futures,time,subprocess
msgs=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
target=sys.argv[2]; before=int(sys.argv[3]); N=int(sys.argv[4]); build=sys.argv[5]
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
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
    list(ex.map(post,msgs))
# poll until the signed count plateaus (no change for 2s) or all N done
last=before; stable=0; t_done=time.time()
while time.time()-t0 < 90:
    n=issued()
    if n>last: last=n; t_done=time.time(); stable=0
    else: stable+=1
    if last-before>=N or stable>=10: break
    time.sleep(0.2)
d=t_done-t0; s=last-before
print(f"  replayed {len(msgs)} packed messages")
print(f"  signed {s}/{N} credentials in {d:.2f}s = {s/d:.1f} creds/s (full DIDComm issuance path, {build} build)" if d>0 else f"  signed {s}")
PY
