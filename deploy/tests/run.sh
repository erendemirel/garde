#!/usr/bin/env bash
# Top-level infra test entrypoint.
#
#   ./deploy/tests/run.sh deploy
#   ./deploy/tests/run.sh ha <no-outage|service-stays-up|soft|hard|all>
#   ./deploy/tests/run.sh all-safe
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CMD="${1:-}"
[ -n "$CMD" ] || {
  printf 'usage: run.sh <deploy|ha|all-safe> [ha-suite]\n' >&2
  exit 1
}
shift || true

case "$CMD" in
  deploy)
    exec bash "$ROOT/deploy/run.sh"
    ;;
  ha)
    exec bash "$ROOT/ha/run.sh" "${1:-all}"
    ;;
  all-safe)
    bash "$ROOT/deploy/run.sh"
    bash "$ROOT/ha/run.sh" no-outage
    bash "$ROOT/ha/run.sh" service-stays-up
    ;;
  *)
    printf 'unknown command: %s\n' "$CMD" >&2
    exit 1
    ;;
esac
