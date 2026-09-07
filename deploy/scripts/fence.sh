#!/usr/bin/env bash
# Stop a node from acting as the application primary.
#
#   ./deploy/scripts/fence.sh node1
#   ./deploy/scripts/fence.sh node1 --power-off      # host is unreachable
#
# Fencing exists to prevent split brain. Two nodes both believing they are the
# primary means two Redis writers and two writers against permissions.db, and
# the resulting divergence cannot be merged afterwards.
#
# The Vault Raft member is deliberately left running: it is a cluster peer, not
# an application role, and quorum wants it alive.
#
# If the host is unreachable over the mesh, --power-off asks the hosting
# provider to stop the server instead, which is the only fencing available when
# SSH is gone.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory
load_provider

NODE=""; POWER_OFF=false
while [ $# -gt 0 ]; do
  case "$1" in
    --power-off) POWER_OFF=true; shift ;;
    -h|--help)   sed -n '2,18p' "$0"; exit 0 ;;
    *)           NODE="$1"; shift ;;
  esac
done
[ -n "$NODE" ] || die "usage: fence.sh <node> [--power-off]"
require_node "$NODE"

reachable=false
if on_node "$NODE" "true" 2>/dev/null; then reachable=true; fi

if [ "$reachable" = "true" ]; then
  step "Stopping the application stack on $NODE"
  # Caddy first: stop taking traffic before the data services go down.
  on_node "$NODE" "cd '$REMOTE_ROOT' && docker compose --env-file .env -f compose/app.yml -p garde-app stop caddy" || true
  on_node "$NODE" "cd '$REMOTE_ROOT' && docker compose --env-file .env -f compose/app.yml -p garde-app stop garde ui redis vault-agent" || true

  running="$(on_node "$NODE" "docker ps --filter 'name=garde-api' --filter 'name=garde-redis' --filter 'name=garde-caddy' --format '{{.Names}}' | tr '\n' ' '")"
  if [ -n "${running// /}" ]; then
    die "$NODE still has application containers running: $running"
  fi
  ok "$NODE application stack is stopped (Vault member left running)"
  summary "Fenced $NODE by stopping its application stack"
else
  warn "$NODE is not reachable over the mesh"
  if [ "$POWER_OFF" = "true" ]; then
    [ -n "$(node_provider_id "$NODE")" ] \
      || die "no provider id configured for $NODE, cannot power it off (set NODE*_PROVIDER_ID)"
    step "Powering off $NODE through $PROVIDER_NAME"
    "$DEPLOY_DIR/scripts/power.sh" "$NODE" off
    ok "power-off requested"
    summary "Fenced $NODE by powering the server off"
  else
    warn "not fencing: the host may still be running and writing"
    warn "re-run with --power-off to stop the server through $PROVIDER_NAME"
    exit 1
  fi
fi
