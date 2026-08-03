#!/usr/bin/env bash
# OID4VCI ISSUANCE benchmark — full HTTP path, two idiom agents.
#
# The holder drives the real OID4VCI exchange against a peer issuer:
#   resolve offer (GET issuer /.well-known/openid-credential-issuer)
#   → POST /oid4vci/token (pre-authorized code → access token)
#   → POST /oid4vci/nonce (c_nonce)
#   → POST /oid4vci/credential (holder key-possession proof → SIGNED credential).
#
# The issuer's minter signs a real vc+sd-jwt or jwt_vc_json credential with a
# wallet-held Ed25519 key. No direct function calls — every credential crosses
# the wire. Reports creds/s per format.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$HERE/../../../src"
BIN="${BIN:-$SRC/target/debug/examples/http_server}"
IPORT=3060; HPORT=3061; N=${N:-50}
FORMATS=${FORMATS:-"sdjwt jwtvc"}
# Persistent Postgres (kanon) wallet for both agents — the fair, apples-to-apples
# store vs Credo/drizzle and ACA-Py/askar-postgres. Override STORE=memory to
# compare against the in-memory ceiling.
PG=${PG:-postgres://postgres:pg@localhost:5555}
STORE_KIND=${STORE_KIND:-kanon}
if [ "$STORE_KIND" = "kanon" ]; then
  for db in oid_issuer_db oid_holder_db; do
    docker exec idiom-bench-pg psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$db'" 2>/dev/null | grep -q 1 \
      || docker exec idiom-bench-pg psql -U postgres -c "CREATE DATABASE $db" >/dev/null 2>&1
    docker exec idiom-bench-pg psql -U postgres -d "$db" -c "TRUNCATE kanon_generic_record, kanon_key" >/dev/null 2>&1 || true
  done
  ISTORE="kanon:$PG/oid_issuer_db"; HSTORE="kanon:$PG/oid_holder_db"; STORELBL="kanon/postgres"
else
  ISTORE=memory; HSTORE=memory; STORELBL=memory
fi
up() { for i in $(seq 1 40); do curl -sf "http://localhost:$1/health" >/dev/null 2>&1 && return; sleep 0.5; done; }

echo "════ start issuer (:$IPORT) + holder (:$HPORT), STORE=$STORELBL ════"
AGENT_PORT=$IPORT AGENT_ENDPOINT="http://localhost:$IPORT" STORE="$ISTORE" RUST_LOG=error "$BIN" >/tmp/oid4vci_issuer.log 2>&1 & IPID=$!
AGENT_PORT=$HPORT AGENT_ENDPOINT="http://localhost:$HPORT" STORE="$HSTORE" RUST_LOG=error "$BIN" >/tmp/oid4vci_holder.log 2>&1 & HPID=$!
trap "kill $IPID $HPID 2>/dev/null || true" EXIT
up $IPORT; up $HPORT
case "$BIN" in *release*) BUILD=release;; *) BUILD=debug;; esac

for CFG in $FORMATS; do
  echo "════ format=$CFG  N=$N  ($BUILD build) ════"
  python3 - "$IPORT" "$HPORT" "$CFG" "$N" "$BUILD" <<'PY'
import sys,json,time,os,urllib.request,concurrent.futures
iport,hport,cfg,N,build=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),sys.argv[5]
issuer=f"http://localhost:{iport}"; holder=f"http://localhost:{hport}"
def post(url,obj):
    req=urllib.request.Request(url,data=json.dumps(obj).encode(),headers={"content-type":"application/json"})
    return json.load(urllib.request.urlopen(req,timeout=60))
# 1. mint N offers at the issuer (cheap, untimed)
offers=[post(f"{issuer}/oid4vci/offer",{"configId":cfg}) for _ in range(N)]
# 2. time the holder driving the full HTTP issuance for each offer
def recv(o):
    try:
        r=post(f"{holder}/oid4vci/receive-offer",{"offer":o,"configId":cfg})
        c=r.get("credential")
        return 1 if isinstance(c,str) and len(c)>40 else 0
    except Exception as e:
        return 0
t0=time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=int(os.environ.get("CONCURRENCY","16"))) as ex:
    ok=sum(ex.map(recv,offers))
d=time.time()-t0
print(f"  issued {ok}/{N} credentials in {d:.2f}s = {ok/d:.1f} creds/s (full OID4VCI HTTP path, {build} build)" if d>0 else f"  issued {ok}")
PY
done
