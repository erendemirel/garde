#!/usr/bin/env bash
# Risk: planned outage (hard) — AWS/provider power-off of the primary during a
# Redis write storm; measure how many keys the promoted replica still has.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" && pwd)/lib.sh"

ha_boot
ha_require_unseal_keys
ha_banner "hard outage: power-off mid-write Redis RPO"

TAG="pwoff$(date +%s)"
PREFIX="ha_pwoff_${TAG}_"
TOTAL=500

"$(ha_scripts)/healthcheck.sh" --all
"$(ha_scripts)/sqlite-snapshot.sh" --from "$PRIMARY_NODE"

FROM="$PRIMARY_NODE"
TO="$STANDBY_NODE"

for i in 1 2 3 4 5; do
  redis_cli_on "$FROM" "SET ${PREFIX}seed_$i 1" >/dev/null
done
sleep 1

on_node "$FROM" "docker exec -d -e RP='$REDIS_PASSWORD' garde-redis sh -c \
  'i=1; while [ \$i -le $TOTAL ]; do redis-cli -a \"\$RP\" --no-auth-warning SET ${PREFIX}\$i \$i >/dev/null 2>&1 || exit 0; i=\$((i+1)); done'"
sleep 0.4

"$(ha_scripts)/power.sh" "$FROM" off
ok "powered off $FROM mid-write"
dead=false
for _ in $(seq 1 60); do
  if ! on_node "$FROM" "true" 2>/dev/null; then dead=true; break; fi
  sleep 5
done
[ "$dead" = "true" ] || die "$FROM still reachable"

"$(ha_scripts)/failover.sh" --to "$TO" --from "$FROM" --power-off --skip-snapshot \
  --reason "ha-test power-off Redis RPO"
load_inventory

survived="$(redis_cli_on "$PRIMARY_NODE" "--scan --pattern ${PREFIX}*" 2>/dev/null | tr -d '\r' | grep -c . || true)"
ok "surviving keys ${PREFIX}* = ${survived} (target ~${TOTAL}+5 seeds)"
on_node "$PRIMARY_NODE" "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health"

"$(ha_scripts)/power.sh" "$FROM" on
retry_until 72 5 on_node "$FROM" "true" || die "$FROM did not return"
ha_unseal "$FROM"
ha_revive_standby "$FROM" "$PRIMARY_NODE"

ha_restore_default_topology
"$(ha_scripts)/healthcheck.sh" --all || true
ok "hard power-off Redis RPO complete (survived=${survived})"
