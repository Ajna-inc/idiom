#!/usr/bin/env bash
# Credo 0.7 OID4VCI issuance bench on Postgres (records=drizzle, kms=askar).
# Ensures the DB + drizzle migrations, then runs the bench.
#
# Node 22.18+ is required (native TS via --experimental-strip-types; tsx breaks
# the webcrypto-core CJS/ESM interop that Credo 0.7 relies on).
#
#   N=200 bash run.sh          # sequential
#   N=200 CONCURRENCY=8 bash run.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PG=${PG:-postgresql://postgres:pg@localhost:5555}

# Node 22 (has --experimental-strip-types).
N22="${NODE22:-$HOME/.nvm/versions/node/v22.20.0/bin/node}"
[ -x "$N22" ] || N22="$(command -v node)"

# Ensure credo_db + apply drizzle migrations (idempotent).
docker exec idiom-bench-pg psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='credo_db'" 2>/dev/null | grep -q 1 \
  || docker exec idiom-bench-pg psql -U postgres -c "CREATE DATABASE credo_db" >/dev/null
node "$HERE/node_modules/@credo-ts/drizzle-storage/bin.mjs" \
  --bundle core --bundle openid4vc migrate --dialect postgres --database-url "$PG/credo_db" >/dev/null 2>&1

DEBUG='' N=${N:-200} CONCURRENCY=${CONCURRENCY:-1} "$N22" --experimental-strip-types "$HERE/credo07-oid4vci-bench.ts" 2>&1 \
  | grep -vE "sphereon|Emitting|ExperimentalWarning|--import|eventName|initiator|system:|subsystem|^\}|^\{|data:|id:" \
  | grep -E "issued|error|Credo "
