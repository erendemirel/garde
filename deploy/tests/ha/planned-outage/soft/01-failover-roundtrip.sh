#!/usr/bin/env bash
# Risk: planned outage (soft) — fence app stack over SSH, promote, move traffic,
# fail back, revive standby.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" && pwd)/lib.sh"

ha_boot
ha_banner "soft outage: failover round-trip"

FROM="$PRIMARY_NODE"
TO="$STANDBY_NODE"

"$(ha_scripts)/healthcheck.sh" --all
"$(ha_scripts)/sqlite-snapshot.sh" --from "$FROM"

"$(ha_scripts)/failover.sh" --to "$TO" --from "$FROM" --reason "ha-test soft cutover"
load_inventory
[ "$PRIMARY_NODE" = "$TO" ] || die "inventory primary is $PRIMARY_NODE, expected $TO"
redis_cli_on "$TO" "info replication" | tr -d '\r' | grep -q '^role:master'
on_node "$TO" "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health"
ok "cutover $FROM -> $TO OK"

ha_revive_standby "$FROM" "$TO"
"$(ha_scripts)/sqlite-snapshot.sh" --from "$TO"
"$(ha_scripts)/failover.sh" --to "$FROM" --from "$TO" --reason "ha-test soft failback"
load_inventory

ha_restore_default_topology
"$(ha_scripts)/healthcheck.sh" --all || true
ok "soft failover round-trip complete"
