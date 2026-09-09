#!/usr/bin/env bash
# Risk: none — read-only checks, dry-run failover.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

ha_boot
ha_banner "no-outage: health + failover dry-run"

"$(ha_scripts)/healthcheck.sh" --all
"$(ha_scripts)/failover.sh" --dry-run --to "${STANDBY_NODE}" --from "${PRIMARY_NODE}"

ok "cluster healthy; dry-run failover would proceed"
