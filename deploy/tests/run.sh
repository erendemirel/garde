#!/usr/bin/env bash
# Top-level infra test entrypoint.
#
#   ./deploy/tests/run.sh bringup
#   ./deploy/tests/run.sh deploy
#   ./deploy/tests/run.sh all-safe
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CMD="${1:-}"
[ -n "$CMD" ] || {
  printf 'usage: run.sh <bringup|deploy|all-safe>\n' >&2
  exit 1
}
shift || true

case "$CMD" in
  bringup)
    exec bash "$ROOT/bringup/run.sh"
    ;;
  deploy)
    exec bash "$ROOT/deploy/run.sh"
    ;;
  all-safe)
    bash "$ROOT/bringup/run.sh"
    bash "$ROOT/deploy/run.sh"
    ;;
  ha)
    printf 'Unknown suite: ha (use bringup | deploy | all-safe)\n' >&2
    exit 1
    ;;
  *)
    printf 'unknown command: %s\n' "$CMD" >&2
    exit 1
    ;;
esac
