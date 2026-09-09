#!/usr/bin/env bash
# Risk: planned outage (hard) — provider power-off of the primary, then
# failover --power-off, revive + unseal + demote, fail back.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" && pwd)/lib.sh"

ha_boot
ha_require_unseal_keys
ha_banner "hard outage: provider power-off failover round-trip"

"$(ha_scripts)/healthcheck.sh" --all
"$(ha_scripts)/sqlite-snapshot.sh" --from "$PRIMARY_NODE"

FROM="$PRIMARY_NODE"
TO="$STANDBY_NODE"

"$(ha_scripts)/power.sh" "$FROM" off
ok "powered off $FROM"
dead=false
for _ in $(seq 1 60); do
  if ! on_node "$FROM" "true" 2>/dev/null; then dead=true; break; fi
  sleep 5
done
[ "$dead" = "true" ] || die "$FROM still reachable after power-off"

"$(ha_scripts)/failover.sh" --to "$TO" --from "$FROM" --power-off --reason "ha-test hard cutover"
load_inventory
on_node "$TO" "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health"
ok "hard cutover $FROM -> $TO OK"

"$(ha_scripts)/power.sh" "$FROM" on
retry_until 72 5 on_node "$FROM" "true" || die "$FROM did not return"
ha_unseal "$FROM"
ha_revive_standby "$FROM" "$TO"

"$(ha_scripts)/sqlite-snapshot.sh" --from "$TO"
"$(ha_scripts)/failover.sh" --to "$FROM" --from "$TO" --reason "ha-test hard failback"
load_inventory

ha_restore_default_topology
"$(ha_scripts)/healthcheck.sh" --all || true
ok "hard power-off failover round-trip complete"
