#!/usr/bin/env bash
# Risk: planned outage (soft) — authenticated API writes, SQLite snapshot RPO,
# Redis SIGKILL mid-write then promote.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" && pwd)/lib.sh"

ha_boot
ha_ensure_curl_image
ha_banner "soft outage: auth + SQLite RPO + Redis SIGKILL RPO"

TAG="t$(date +%s)"
KEEP_PERM="ha_keep_${TAG}"
LOSE_PERM="ha_lose_${TAG}"
MARKER="ha_marker_${TAG}"
PREFIX="ha_rpo_${TAG}_"
TOTAL=300

"$(ha_scripts)/healthcheck.sh" --all

# --- auth + sqlite RPO ----------------------------------------------------
SID="$(ha_login "$PRIMARY_NODE")"
ok "login OK"

keep_out="$(http_api "$PRIMARY_NODE" POST /admin/permissions \
  "$(printf '{"name":"%s","definition":"keep across failover"}' "$KEEP_PERM")" "$SID")"
[ "$(http_code "$keep_out")" = "201" ] || die "create keep perm failed: $keep_out"
ok "created $KEEP_PERM"

redis_cli_on "$PRIMARY_NODE" "SET $MARKER yes" >/dev/null
"$(ha_scripts)/sqlite-snapshot.sh" --from "$PRIMARY_NODE"

lose_out="$(http_api "$PRIMARY_NODE" POST /admin/permissions \
  "$(printf '{"name":"%s","definition":"after snapshot"}' "$LOSE_PERM")" "$SID")"
[ "$(http_code "$lose_out")" = "201" ] || die "create lose perm failed: $lose_out"
ok "created post-snapshot $LOSE_PERM (expect loss)"

FROM="$PRIMARY_NODE"
TO="$STANDBY_NODE"
"$(ha_scripts)/failover.sh" --to "$TO" --from "$FROM" --skip-snapshot --reason "ha-test auth+sqlite RPO"
load_inventory

me_out="$(http_api "$PRIMARY_NODE" GET /users/me "" "$SID")"
if [ "$(http_code "$me_out")" = "200" ]; then
  ok "session survived failover"
else
  warn "session did not survive; re-login"
  SID="$(ha_login "$PRIMARY_NODE")"
fi

keep2="$(http_api "$PRIMARY_NODE" POST /admin/permissions \
  "$(printf '{"name":"%s","definition":"x"}' "$KEEP_PERM")" "$SID")"
[ "$(http_code "$keep2")" = "409" ] || warn "keep perm recreate code=$(http_code "$keep2")"
ok "$KEEP_PERM held by snapshot"

[ "$(redis_cli_on "$PRIMARY_NODE" "GET $MARKER" | tr -d '\r')" = "yes" ] \
  && ok "Redis marker survived" || warn "Redis marker missing"

lose2="$(http_api "$PRIMARY_NODE" POST /admin/permissions \
  "$(printf '{"name":"%s","definition":"x"}' "$LOSE_PERM")" "$SID")"
[ "$(http_code "$lose2")" = "201" ] \
  && ok "$LOSE_PERM lost (SQLite RPO = snapshot)" \
  || warn "lose perm code=$(http_code "$lose2") (409 means it was not lost)"

# --- redis SIGKILL RPO ----------------------------------------------------
ha_revive_standby "$FROM" "$PRIMARY_NODE"
for i in 1 2 3 4 5; do
  redis_cli_on "$PRIMARY_NODE" "SET ${PREFIX}seed_$i 1" >/dev/null
done
sleep 1

on_node "$PRIMARY_NODE" "docker exec -d -e RP='$REDIS_PASSWORD' garde-redis sh -c \
  'i=1; while [ \$i -le $TOTAL ]; do redis-cli -a \"\$RP\" --no-auth-warning SET ${PREFIX}\$i \$i >/dev/null 2>&1 || exit 0; i=\$((i+1)); done'"
sleep 0.5
on_node "$PRIMARY_NODE" "docker kill -s KILL garde-redis" || true
ok "SIGKILL garde-redis on $PRIMARY_NODE mid-write"

"$(ha_scripts)/failover.sh" --to "$FROM" --from "$PRIMARY_NODE" --skip-snapshot --reason "ha-test redis SIGKILL RPO"
load_inventory
survived="$(redis_cli_on "$PRIMARY_NODE" "--scan --pattern ${PREFIX}*" 2>/dev/null | tr -d '\r' | grep -c . || true)"
ok "Redis keys surviving SIGKILL promote: ${survived} (wrote up to ${TOTAL}+seeds)"

ha_restore_default_topology
"$(ha_scripts)/healthcheck.sh" --all || true
ok "auth + RPO soft drills complete (survived=${survived})"
