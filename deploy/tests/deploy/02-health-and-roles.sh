#!/usr/bin/env bash
# Impact: none — full healthcheck plus explicit Redis/Vault topology asserts.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_boot
ha_banner "deploy: health + roles"

"$(ha_scripts)/healthcheck.sh" --all

# Redis topology
prim_role="$(redis_cli_on "$PRIMARY_NODE" "info replication" | tr -d '\r' | sed -n 's/^role://p')"
[ "$prim_role" = "master" ] || die "primary $PRIMARY_NODE redis role=$prim_role (want master)"
ok "Redis master on $PRIMARY_NODE"

stand_role="$(redis_cli_on "$STANDBY_NODE" "info replication" | tr -d '\r' | sed -n 's/^role://p')"
stand_link="$(redis_cli_on "$STANDBY_NODE" "info replication" | tr -d '\r' | sed -n 's/^master_link_status://p')"
[ "$stand_role" = "slave" ] || die "standby $STANDBY_NODE redis role=$stand_role (want slave)"
[ "$stand_link" = "up" ] || die "standby redis link=$stand_link (want up)"
ok "Redis replica on $STANDBY_NODE (link up)"

# Vault: at least 2 unsealed, exactly one Raft leader
unsealed=0
for node in $NODES; do
  if on_node "$node" "docker exec garde-vault vault status >/dev/null 2>&1"; then
    unsealed=$((unsealed + 1))
  fi
done
[ "$unsealed" -ge 2 ] || die "only $unsealed Vault member(s) unsealed"
ok "Vault unsealed on $unsealed/$(echo "$NODES" | wc -w | tr -d ' ') members"

leader="$(ha_find_vault_leader)" || die "no Vault Raft leader"
ok "Vault Raft leader is $leader"
