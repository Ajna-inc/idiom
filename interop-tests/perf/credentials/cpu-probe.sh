#!/usr/bin/env bash
# Sample issuer CPU% under sustained replay load to tell CPU-bound (cores busy)
# from I/O/lock-bound (cores idle-waiting). Reuses requests.ndjson corpus.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$HERE/../../../src"
BIN="${BIN:-/tmp/http_server-release-opt}"; CORPUS="$HERE/requests.ndjson"
set -a; . "$HERE/kanon.env"; set +a
PG=postgres://postgres:pg@localhost:5555
psql() { docker exec idiom-bench-pg psql -U postgres -d "$1" -tAc "$2" 2>/dev/null; }
IPORT=3030; CONC=${CONC:-48}; ROUNDS=${ROUNDS:-8}
up() { for i in $(seq 1 40); do curl -sf "http://localhost:$1/health" >/dev/null 2>&1 && return; sleep 1; done; }
reseed() { psql issuer_db "UPDATE kanon_generic_record SET value=jsonb_set(value,'{state}','\"OfferSent\"') WHERE record_type='anoncreds_credential_exchange';" >/dev/null; }

CORES=$(sysctl -n hw.ncpu)
echo "cores=$CORES  conc=$CONC  corpus=$(wc -l < "$CORPUS") msgs"
reseed
AGENT_PORT=$IPORT AGENT_LABEL=issuer STORE="kanon:$PG/issuer_db" LEDGER=kanon RUST_LOG=error "$BIN" >/tmp/issuer_cpu.log 2>&1 & IPID=$!
trap "kill $IPID 2>/dev/null || true" EXIT
up $IPORT
echo "issuer pid=$IPID"

# Background: continuously replay (reseed between rounds) to sustain load.
( for r in $(seq 1 $ROUNDS); do
    reseed
    python3 - "$CORPUS" "http://localhost:$IPORT" "$CONC" <<'PY'
import sys,json,base64,urllib.request,concurrent.futures
msgs=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
target=sys.argv[2]; conc=int(sys.argv[3])
def post(m):
    body=base64.b64decode(m["b64"])
    req=urllib.request.Request(target+(m.get("path") or "/"),data=body,headers={"content-type":m.get("ctype") or "application/didcomm-envelope-enc"})
    try: urllib.request.urlopen(req,timeout=60).read()
    except Exception: pass
with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
    list(ex.map(post,msgs))
PY
  done ) & LOADPID=$!

# Sample issuer CPU% (and total system) while load runs.
echo "sampling issuer CPU% (100% = 1 core; max = ${CORES}00%):"
peak=0
for i in $(seq 1 20); do
  cpu=$(ps -p $IPID -o %cpu= 2>/dev/null | tr -d ' ')
  [ -z "$cpu" ] && break
  awk -v c="$cpu" -v p="$peak" 'BEGIN{exit !(c+0>p+0)}' && peak=$cpu
  printf "  t%-2d issuer=%6s%%\n" "$i" "$cpu"
  sleep 0.5
done
kill $LOADPID 2>/dev/null || true
echo "PEAK issuer CPU = ${peak}%  (of ${CORES}00%  =>  $(awk -v p="$peak" -v c="$CORES" 'BEGIN{printf "%.1f", p/(c*100)*100}')% of machine)"
