#!/usr/bin/env bash
# Impact: none — take a fresh permissions.db snapshot and verify distribution.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_boot
ha_banner "deploy: snapshot freshness"

"$(ha_scripts)/sqlite-snapshot.sh" --from "$PRIMARY_NODE"

max_age="${SQLITE_SNAPSHOT_MAX_AGE_SECONDS:-1800}"
for node in $NODES; do
  age="$(on_node "$node" "
    f='$REMOTE_ROOT/backup/permissions.db'
    if [ -f \"\$f\" ]; then echo \$(( \$(date +%s) - \$(stat -c %Y \"\$f\") )); else echo -1; fi")"
  [ "$age" != "-1" ] || die "$node has no permissions.db snapshot"
  [ "$age" -le "$max_age" ] || die "$node snapshot ${age}s old (max ${max_age}s)"
  ok "$node snapshot ${age}s old"
done
