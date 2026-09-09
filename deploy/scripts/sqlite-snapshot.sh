#!/usr/bin/env bash
# Trigger a permissions.db snapshot on the primary and verify it landed.
#
#   ./deploy/scripts/sqlite-snapshot.sh
#   ./deploy/scripts/sqlite-snapshot.sh --from node2
#
# The snapshot procedure itself lives on the host, at
# {REMOTE_ROOT}/scripts/snapshot.sh, installed by the Ansible snapshot role.
# Keeping one implementation matters: `VACUUM INTO` plus an integrity check is
# the delicate part, and two copies of it would eventually disagree.
#
# The same script is what garde-snapshot.timer runs every few minutes on the
# primary. This wrapper exists so CI and operators can force a snapshot on
# demand - before a risky deploy, or as the last act before a planned failover.
#
# Distribution happens node to node over the mesh, using the keys the Ansible
# role sets up. Nothing travels through the control machine.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory

FROM_NODE="${PRIMARY_NODE:?PRIMARY_NODE missing from inventory}"
while [ $# -gt 0 ]; do
  case "$1" in
    --from) FROM_NODE="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
require_node "$FROM_NODE"

HOST_SCRIPT="$REMOTE_ROOT/scripts/snapshot.sh"

step "Running the snapshot on $FROM_NODE"
if ! on_node "$FROM_NODE" "test -x '$HOST_SCRIPT'"; then
  die "$HOST_SCRIPT is missing on $FROM_NODE.
     Install it with the Ansible baseline:
       cd ansible && ansible-playbook playbooks/bootstrap.yml --limit $FROM_NODE"
fi

on_node "$FROM_NODE" "$HOST_SCRIPT"

# --- verify -----------------------------------------------------------------

step "Verifying snapshot freshness"
max_age="${SQLITE_SNAPSHOT_MAX_AGE_SECONDS:-1800}"
failures=0

for node in $NODES; do
  case "$(node_role "$node")" in
    app-primary|app-standby|witness) ;;
    *) continue ;;
  esac

  age="$(on_node "$node" "
    f='$REMOTE_ROOT/backup/permissions.db'
    if [ -f \"\$f\" ]; then echo \$(( \$(date +%s) - \$(stat -c %Y \"\$f\") )); else echo -1; fi" 2>/dev/null || echo -1)"

  if [ "$age" = "-1" ]; then
    warn "$node has no snapshot"
    failures=$((failures + 1))
  elif [ "$age" -gt "$max_age" ]; then
    warn "$node snapshot is ${age}s old (max ${max_age}s)"
    failures=$((failures + 1))
  else
    ok "$node snapshot ${age}s old"
  fi
done

size="$(on_node "$FROM_NODE" "stat -c %s '$REMOTE_ROOT/backup/permissions.db'" 2>/dev/null || echo 0)"

if [ "$failures" -gt 0 ]; then
  summary "Snapshot from $FROM_NODE completed with $failures distribution problem(s)"
  die "$failures node(s) do not have a current snapshot"
fi

summary "permissions.db snapshot distributed from $FROM_NODE ($size bytes)"
