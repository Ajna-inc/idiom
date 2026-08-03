#!/usr/bin/env bash
# Reproducible DIDComm replay benchmark helpers: export/wipe/seed the tenant
# wallet state (keys + connection records) so the same captured corpus can be
# replayed deterministically after a wipe.
#
#   ./bench.sh export        # save keys + connection records → seed/
#   ./bench.sh wipe          # delete ALL rows for the tenant profile
#   ./bench.sh seed          # restore keys + connection records from seed/
#   ./bench.sh clean-msgs    # delete only basicmessage rows (between replays)
#   ./bench.sh restart       # recreate the agent (reloads seeded keys)
#   ./bench.sh count         # show record-type counts for the profile
set -euo pipefail

PROFILE="${PROFILE:-13205721-b73d-4c6f-9a44-9b26b3fd3635}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$(cd "$HERE/../../../deploy" && pwd)"
SEEDDIR="$HERE/seed"
DC=(docker compose --env-file "$DEPLOY/.env" -f "$DEPLOY/compose.traction.yml" -f "$DEPLOY/compose.app.yml" -f "$DEPLOY/compose.local.yml" -p crms-e2e)

q() { "${DC[@]}" exec -T traction-db psql -U postgres -d traction_acapy "$@"; }

case "${1:-}" in
  export)
    mkdir -p "$SEEDDIR"
    q -tAc "COPY (SELECT * FROM kanon_key WHERE profile_id='$PROFILE') TO STDOUT" > "$SEEDDIR/key.tsv"
    q -tAc "COPY (SELECT * FROM kanon_generic_record WHERE profile_id='$PROFILE' AND record_type<>'basicmessage') TO STDOUT" > "$SEEDDIR/gr.tsv"
    echo "exported keys=$(wc -l < "$SEEDDIR/key.tsv") records=$(wc -l < "$SEEDDIR/gr.tsv")" ;;
  wipe)
    q -tAc "DELETE FROM kanon_key WHERE profile_id='$PROFILE'; DELETE FROM kanon_generic_record WHERE profile_id='$PROFILE'"
    echo "wiped profile $PROFILE" ;;
  seed)
    q -c "COPY kanon_key FROM STDIN" < "$SEEDDIR/key.tsv"
    q -c "COPY kanon_generic_record FROM STDIN" < "$SEEDDIR/gr.tsv"
    echo "seeded" ;;
  clean-msgs)
    q -tAc "DELETE FROM kanon_generic_record WHERE profile_id='$PROFILE' AND record_type='basicmessage'"
    echo "cleaned basicmessages" ;;
  count)
    q -tAc "SELECT record_type||'='||count(*) FROM kanon_generic_record WHERE profile_id='$PROFILE' GROUP BY record_type ORDER BY count(*) DESC LIMIT 8"
    q -tAc "SELECT 'keys='||count(*) FROM kanon_key WHERE profile_id='$PROFILE'" ;;
  restart)
    ( cd "$DEPLOY" && ACAPY_ENDPOINT="${ACAPY_ENDPOINT:-http://localhost:9500}" "${DC[@]}" up -d --no-deps --force-recreate traction-agent >/dev/null 2>&1 )
    echo "agent recreating (wait for :8031/status/live)" ;;
  *)
    echo "usage: $0 {export|wipe|seed|clean-msgs|count|restart}"; exit 1 ;;
esac
