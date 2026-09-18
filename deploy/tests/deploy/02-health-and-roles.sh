#!/usr/bin/env bash
# Impact: none — full healthcheck plus Vault quorum and app-role asserts.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

ha_boot
ha_banner "deploy: health + roles"

"$(ha_scripts)/healthcheck.sh" --all

apps="$(app_nodes)"
[ -n "$apps" ] || die "no NODE*_ROLE=app in inventory"
ok "app nodes: $apps"

for node in $apps; do
  on_node "$node" "docker exec garde-api sh -c 'wget -q -O /dev/null --no-check-certificate https://127.0.0.1:8443/ready || wget -q -O /dev/null http://127.0.0.1:8443/ready'" \
    || die "$node /ready failed"
  ok "$node /ready"
done

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
