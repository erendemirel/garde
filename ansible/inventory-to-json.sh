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

# Carriage returns stripped for the same reason lib.sh strips them: this file is
# routinely pasted between Windows editors and CI secrets.
# shellcheck disable=SC1090
set -a; . <(tr -d '\r' <"$INVENTORY_FILE"); set +a

# Provider capabilities are declared by the driver, so read them from there
# rather than duplicating them in the inventory. Goes through the shell library
# rather than sourcing the driver directly, because a driver may need to answer
# per-node questions - how to reach that host - and those need the library's
# helpers to be defined.
DRIVER="deploy/scripts/providers/${PROVIDER:-}.sh"
if [ -n "${PROVIDER:-}" ] && [ -f "$DRIVER" ]; then
  # shellcheck disable=SC1091
  . deploy/scripts/lib.sh
  load_inventory
else
  echo "warning: no driver for PROVIDER='${PROVIDER:-unset}'; assuming the host must bind the failover IP" >&2
  PROVIDER_REQUIRES_IP_BINDING=true
  PROVIDER_ADMIN_ACCESS=mesh
fi

# A plain comparison rather than provider_uses_tunnel, because the fallback
# branch above never sourced the library that defines it.
is_tunnel() { [ "${PROVIDER_ADMIN_ACCESS:-mesh}" = "tunnel" ]; }

node_var() {
  local name
  name="$(printf '%s_%s' "$1" "$2" | tr '[:lower:]-' '[:upper:]_')"
  printf '%s' "${!name:-}"
}

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

printf '{\n'
printf '  "ssh_user": "%s",\n'    "$(json_escape "${SSH_USER:-deploy}")"
printf '  "bootstrap_user": "%s",\n' "$(json_escape "${BOOTSTRAP_SSH_USER:-root}")"
printf '  "ssh_port": %s,\n'      "${SSH_PORT:-22}"
printf '  "remote_root": "%s",\n' "$(json_escape "${REMOTE_ROOT:-/opt/garde}")"
printf '  "wg_subnet": "%s",\n'   "$(json_escape "${WG_SUBNET:-10.10.0.0/24}")"
printf '  "wg_port": %s,\n'       "${WG_PORT:-51820}"
printf '  "provider": "%s",\n'     "$(json_escape "${PROVIDER:-}")"
printf '  "requires_ip_binding": %s,\n' "${PROVIDER_REQUIRES_IP_BINDING:-true}"
printf '  "admin_access": "%s",\n' "$(json_escape "${PROVIDER_ADMIN_ACCESS:-mesh}")"
printf '  "admin_ssh_sources": "%s",\n' \
  "$(json_escape "${ADMIN_SSH_SOURCES:-${PROVIDER_ADMIN_SSH_SOURCES:-}}")"
printf '  "failover_ip": "%s",\n'  "$(json_escape "${FAILOVER_IP:-}")"
printf '  "primary_node": "%s",\n' "$(json_escape "${PRIMARY_NODE:-}")"
printf '  "standby_node": "%s",\n' "$(json_escape "${STANDBY_NODE:-}")"
printf '  "snapshot_interval": "%s",\n' "$(json_escape "${SQLITE_SNAPSHOT_INTERVAL:-5min}")"
printf '  "nodes": [\n'

first=true
for node in ${NODES:?NODES missing from inventory}; do
  [ "$first" = true ] || printf ',\n'
  first=false

  # Resolved before printing, and checked. A driver rejects a malformed
  # NODE*_PROVIDER_ID here, and swallowing that would hand Ansible an empty
  # host to connect to instead of telling you what is wrong.
  admin_host=""; admin_proxy=""; admin_name=""
  if is_tunnel; then
    # The same alias the shell tooling pins host keys to. Ansible connects to
    # the provider's id for the host, which changes whenever an instance is
    # replaced; pinning to that instead would invalidate DEPLOY_KNOWN_HOSTS
    # every time, and the two tools would disagree about the same host.
    admin_name="$(admin_alias "$node")"
    admin_host="$(provider_admin_host "$node")" \
      || { echo "error: cannot resolve the admin host for $node" >&2; exit 1; }
    admin_proxy="$(provider_admin_proxy_command "$node")" \
      || { echo "error: cannot build the tunnel command for $node" >&2; exit 1; }
    [ -n "$admin_host" ] \
      || { echo "error: $PROVIDER has no admin host for $node" >&2; exit 1; }
  fi

  printf '    {'
  printf '"name": "%s", '      "$(json_escape "$node")"
  printf '"role": "%s", '      "$(json_escape "$(node_var "$node" ROLE)")"
  printf '"wg_ip": "%s", '     "$(json_escape "$(node_var "$node" WG_IP)")"
  printf '"public_ip": "%s", ' "$(json_escape "$(node_var "$node" PUBLIC_IP)")"
  printf '"mesh_endpoint": "%s", ' \
    "$(json_escape "$(node_var "$node" MESH_ENDPOINT)")"
  printf '"vault_id": "%s", '  "$(json_escape "$(node_var "$node" VAULT_ID)")"
  printf '"admin_host": "%s", '  "$(json_escape "$admin_host")"
  printf '"admin_alias": "%s", ' "$(json_escape "$admin_name")"
  printf '"admin_proxy_command": "%s", ' "$(json_escape "$admin_proxy")"
  printf '"provider_id": "%s"' "$(json_escape "$(node_var "$node" PROVIDER_ID)")"
  printf '}'
done

printf '\n  ]\n}\n'
