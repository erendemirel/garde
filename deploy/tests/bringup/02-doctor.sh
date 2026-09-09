#!/usr/bin/env bash
# Impact: none — live doctor stages against inventory (read-only probes).
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_banner "bringup: doctor.sh (non-strict + strict)"

# Doctor loads inventory itself; skip REDIS_PASSWORD / full provider_preflight.
[ -f "$INVENTORY_FILE" ] || die "inventory missing: $INVENTORY_FILE"
# shellcheck disable=SC1090
set -a; . <(sed 's/\r$//' "$INVENTORY_FILE"); set +a

DOCTOR="$REPO_ROOT/deploy/scripts/doctor.sh"
[ -f "$DOCTOR" ] || die "missing $DOCTOR"
sed -i 's/\r$//' "$DOCTOR" 2>/dev/null || true

provider_arg=()
case "${PROVIDER:-}" in
  aws) provider_arg=(--provider aws) ;;
esac

bash "$DOCTOR" "${provider_arg[@]}"
ok "doctor (non-strict) exit 0"

bash "$DOCTOR" "${provider_arg[@]}" --strict
ok "doctor --strict exit 0"

summary "bringup: doctor OK"
