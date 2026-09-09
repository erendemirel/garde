#!/usr/bin/env bash
# Run bring-up wrapper + doctor verification (no cloud apply, no outage).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$ROOT/../ha/lib.sh"

ha_banner "bring-up / doctor suite"

# shellcheck disable=SC2012
for script in $(ls "$ROOT"/[0-9]*.sh 2>/dev/null | sort); do
  ha_banner "RUN $script"
  bash "$script"
done

ha_banner "bring-up / doctor suite finished"
ok "all bring-up / doctor drills passed"
