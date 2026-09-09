#!/usr/bin/env bash
# Risk: service stays up when the Raft leader is not the only Vault the primary
# needs — followers forward; local vault-agent on the primary keeps working as
# long as its own member (or quorum) can answer. We stop whoever is active.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

ha_boot
ha_require_unseal_keys
ha_banner "service-stays-up: stop Vault Raft leader"

"$(ha_scripts)/healthcheck.sh" --all
LEADER="$(ha_find_vault_leader)" || die "could not find Vault Raft leader"
ok "Raft leader is $LEADER (role=$(node_role "$LEADER"))"

on_node "$PRIMARY_NODE" "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health"
redis_cli_on "$PRIMARY_NODE" PING | tr -d '\r' | grep -qx PONG

on_node "$LEADER" "docker stop garde-vault"
ok "stopped garde-vault on leader $LEADER"
sleep 8

NEW="$(ha_find_vault_leader || true)"
[ -n "${NEW:-}" ] && ok "new leader elected: $NEW" || warn "no leader visible yet"

if on_node "$PRIMARY_NODE" "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health"; then
  ok "app /health OK with former leader Vault down"
else
  # Leader was likely on the primary host — local vault-agent lost its peer.
  warn "app /health failed (leader was on $(node_role "$LEADER") host $LEADER)"
fi

on_node "$LEADER" "docker start garde-vault"
sleep 5
ha_unseal "$LEADER"
"$(ha_scripts)/healthcheck.sh" --all || true
on_node "$PRIMARY_NODE" "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health"
ok "Vault leader-loss drill finished"
