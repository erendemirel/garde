#!/usr/bin/env bash
# Run the post-deploy verification suite (no service outage).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$ROOT/../ha/lib.sh"

ha_boot
ha_banner "deploy verification suite"

# shellcheck disable=SC2012
for script in $(ls "$ROOT"/[0-9]*.sh 2>/dev/null | sort); do
  ha_banner "RUN $script"
  bash "$script"
done

ha_banner "deploy verification finished"
ok "all deploy verification drills passed"
