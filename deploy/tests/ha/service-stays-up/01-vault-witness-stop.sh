#!/usr/bin/env bash
# Risk: service stays up — stop Vault on the witness only (quorum remains 2/3).
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

ha_boot
ha_require_unseal_keys
ha_banner "service-stays-up: stop Vault on witness"

WITNESS=""
for node in $NODES; do
  [ "$(node_role "$node")" = "witness" ] && WITNESS="$node" && break
done
[ -n "$WITNESS" ] || die "no witness node in inventory"

"$(ha_scripts)/healthcheck.sh" --all
on_node "$PRIMARY_NODE" "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health"
ok "app healthy before witness Vault stop"

on_node "$WITNESS" "docker stop garde-vault"
ok "stopped garde-vault on $WITNESS"
sleep 3

on_node "$PRIMARY_NODE" "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health" \
  || die "app /health failed while witness Vault was down"
ok "app kept serving with witness Vault down"

on_node "$WITNESS" "docker start garde-vault"
sleep 5
ha_unseal "$WITNESS"
"$(ha_scripts)/healthcheck.sh" --all || true
ok "witness Vault restored"
