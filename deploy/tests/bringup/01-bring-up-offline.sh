#!/usr/bin/env bash
# Impact: none — offline checks for terraform/aws/bring-up.sh (no AWS apply).
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_banner "bringup: bring-up.sh offline checks"

BRINGUP="$REPO_ROOT/terraform/aws/bring-up.sh"
[ -f "$BRINGUP" ] || die "missing $BRINGUP"
sed -i 's/\r$//' "$BRINGUP" 2>/dev/null || true

# Missing terraform.tfvars must fail before terraform CLI is required.
set +e
out="$(bash "$BRINGUP" --plan-only 2>&1)"
ec=$?
set -e
[ "$ec" -eq 1 ] || die "bring-up --plan-only without tfvars expected exit 1, got $ec"
printf '%s\n' "$out" | grep -q 'terraform.tfvars' || die "bring-up error should mention terraform.tfvars"
ok "bring-up exits 1 when terraform.tfvars is missing"

# upsert_inventory merge semantics (source the function from the wrapper).
# shellcheck disable=SC1091
source <(sed -n '/^upsert_inventory()/,/^}/p' "$BRINGUP")
tmp="$(mktemp)"
printf 'A=1\nB=keep\n' >"$tmp"
upsert_inventory "$tmp" A 2
upsert_inventory "$tmp" C 3
grep -qx 'A=2' "$tmp" || die "upsert did not replace A"
grep -qx 'B=keep' "$tmp" || die "upsert clobbered B"
grep -qx 'C=3' "$tmp" || die "upsert did not append C"
rm -f "$tmp"
ok "upsert_inventory replaces/appends without clobbering siblings"

summary "bringup: bring-up.sh offline OK"
