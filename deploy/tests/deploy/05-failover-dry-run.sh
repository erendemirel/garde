#!/usr/bin/env bash
# Impact: none — failover preflight only (no fence, no IP move).
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_boot
ha_banner "deploy: failover dry-run"

"$(ha_scripts)/failover.sh" --dry-run --to "$STANDBY_NODE" --from "$PRIMARY_NODE"
ok "failover dry-run would proceed ($PRIMARY_NODE -> $STANDBY_NODE)"
