#!/usr/bin/env bash
# Emit deploy/inventory.env as JSON for the Ansible playbooks.
#
#   bash ansible/inventory-to-json.sh
#
# Invoked with an explicit `bash` rather than as a dynamic inventory script, so
# it needs no executable bit and works the same on Windows checkouts.
#
# deploy/inventory.env stays the single source of truth for the topology. The
# shell tooling reads it directly; Ansible reads it through here.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
INVENTORY_FILE="${INVENTORY_FILE:-deploy/inventory.env}"

if [ ! -f "$INVENTORY_FILE" ]; then
  echo "inventory not found: $INVENTORY_FILE (copy deploy/inventory.example.env)" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a; . "$INVENTORY_FILE"; set +a

# Provider capabilities are declared by the driver, so read them from there
# rather than duplicating them in the inventory. Drivers are side-effect free
# when sourced, which is what makes this safe outside the shell library.
DRIVER="deploy/scripts/providers/${PROVIDER:-}.sh"
if [ -n "${PROVIDER:-}" ] && [ -f "$DRIVER" ]; then
  # shellcheck disable=SC1090
  . "$DRIVER"
else
  echo "warning: no driver for PROVIDER='${PROVIDER:-unset}'; assuming the host must bind the failover IP" >&2
  PROVIDER_REQUIRES_IP_BINDING=true
fi

node_var() {
  local name
  name="$(printf '%s_%s' "$1" "$2" | tr '[:lower:]-' '[:upper:]_')"
  printf '%s' "${!name:-}"
}

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

printf '{\n'
printf '  "ssh_user": "%s",\n'    "$(json_escape "${SSH_USER:-deploy}")"
printf '  "ssh_port": %s,\n'      "${SSH_PORT:-22}"
printf '  "remote_root": "%s",\n' "$(json_escape "${REMOTE_ROOT:-/opt/garde}")"
printf '  "wg_subnet": "%s",\n'   "$(json_escape "${WG_SUBNET:-10.10.0.0/24}")"
printf '  "wg_port": %s,\n'       "${WG_PORT:-51820}"
printf '  "provider": "%s",\n'     "$(json_escape "${PROVIDER:-}")"
printf '  "requires_ip_binding": %s,\n' "${PROVIDER_REQUIRES_IP_BINDING:-true}"
printf '  "failover_ip": "%s",\n'  "$(json_escape "${FAILOVER_IP:-}")"
printf '  "primary_node": "%s",\n' "$(json_escape "${PRIMARY_NODE:-}")"
printf '  "standby_node": "%s",\n' "$(json_escape "${STANDBY_NODE:-}")"
printf '  "snapshot_interval": "%s",\n' "$(json_escape "${SQLITE_SNAPSHOT_INTERVAL:-5min}")"
printf '  "nodes": [\n'

first=true
for node in ${NODES:?NODES missing from inventory}; do
  [ "$first" = true ] || printf ',\n'
  first=false
  printf '    {'
  printf '"name": "%s", '      "$(json_escape "$node")"
  printf '"role": "%s", '      "$(json_escape "$(node_var "$node" ROLE)")"
  printf '"wg_ip": "%s", '     "$(json_escape "$(node_var "$node" WG_IP)")"
  printf '"public_ip": "%s", ' "$(json_escape "$(node_var "$node" PUBLIC_IP)")"
  printf '"vault_id": "%s", '  "$(json_escape "$(node_var "$node" VAULT_ID)")"
  printf '"provider_id": "%s"' "$(json_escape "$(node_var "$node" PROVIDER_ID)")"
  printf '}'
done

printf '\n  ]\n}\n'
