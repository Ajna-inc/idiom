#!/usr/bin/env bash
# Stand up a standalone vanilla ACA-Py (oid4vc + sd_jwt_vc plugins, no ledger,
# no external auth server, no CRMS) and run the OID4VCI SD-JWT issuance bench.
# Builds the plugin image on first run. One command, reproducible.
#
#   N=200 bash acapy-oid4vci-bench.sh
#   N=200 CONCURRENCY=8 bash acapy-oid4vci-bench.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
IMG=oid4vc-bench
NAME=oid4vc-bench

# 1. Build the plugin image if missing (python3.13 + oid4vc/sd_jwt_vc via poetry).
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "building $IMG (first run)…"
  TMP="$(mktemp -d)"
  git clone --depth 1 --filter=blob:none --sparse https://github.com/openwallet-foundation/acapy-plugins.git "$TMP/ap" >/dev/null 2>&1
  ( cd "$TMP/ap" && git sparse-checkout set oid4vc >/dev/null 2>&1 && \
    cd oid4vc && DOCKER_DEFAULT_PLATFORM=linux/amd64 docker build --platform linux/amd64 -f docker/Dockerfile -t "$IMG" . )
  rm -rf "$TMP"
fi

# 2. Start the issuer if not already live.
if ! curl -sf http://localhost:3001/status/live >/dev/null 2>&1; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" -p 3001:3001 -p 8082:8082 \
    -e OID4VCI_HOST=0.0.0.0 -e OID4VCI_PORT=8082 -e OID4VCI_ENDPOINT=http://localhost:8082 \
    "$IMG" start \
    --inbound-transport http 0.0.0.0 3000 --outbound-transport http --endpoint http://localhost:3000 \
    --admin 0.0.0.0 3001 --admin-insecure-mode --no-ledger \
    --wallet-type askar --wallet-storage-type default --wallet-name issuer --wallet-key insecure --auto-provision \
    --plugin oid4vc --plugin sd_jwt_vc --log-level warning >/dev/null
  echo -n "waiting for ACA-Py admin"
  for i in $(seq 1 60); do curl -sf http://localhost:3001/status/live >/dev/null 2>&1 && { echo " — live"; break; }; echo -n .; sleep 1; done
fi

# 3. Run the bench (Python holder drives the full OID4VCI HTTP path).
N="${N:-200}" CONCURRENCY="${CONCURRENCY:-1}" python3 "$HERE/acapy-oid4vci-bench.py"
