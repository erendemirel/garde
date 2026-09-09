#!/usr/bin/env bash
# Run a slice of the HA infra suite.
#
#   ./deploy/tests/ha/run.sh no-outage
#   ./deploy/tests/ha/run.sh service-stays-up
#   ./deploy/tests/ha/run.sh soft
#   ./deploy/tests/ha/run.sh hard
#   ./deploy/tests/ha/run.sh all
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$ROOT/lib.sh"

SUITE="${1:-}"
[ -n "$SUITE" ] || die "usage: run.sh <no-outage|service-stays-up|soft|hard|all>"

run_dir() {
  local dir="$1" script
  [ -d "$dir" ] || die "missing suite dir: $dir"
  ha_banner "suite $(basename "$dir")"
  # shellcheck disable=SC2012
  for script in $(ls "$dir"/[0-9]*.sh 2>/dev/null | sort); do
    ha_banner "RUN $script"
    bash "$script"
  done
}

case "$SUITE" in
  no-outage)
    run_dir "$ROOT/no-outage"
    ;;
  service-stays-up)
    run_dir "$ROOT/service-stays-up"
    ;;
  soft)
    run_dir "$ROOT/planned-outage/soft"
    ;;
  hard)
    run_dir "$ROOT/planned-outage/hard"
    ;;
  all)
    run_dir "$ROOT/no-outage"
    run_dir "$ROOT/service-stays-up"
    run_dir "$ROOT/planned-outage/soft"
    run_dir "$ROOT/planned-outage/hard"
    ;;
  *)
    die "unknown suite '$SUITE' (want no-outage|service-stays-up|soft|hard|all)"
    ;;
esac

ha_banner "suite '$SUITE' finished"
ok "all selected HA drills passed"
