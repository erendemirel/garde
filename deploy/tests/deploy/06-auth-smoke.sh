#!/usr/bin/env bash
# Impact: none — login + /users/me. Skipped when SUPERUSER_* unset.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

ha_boot
ha_banner "deploy: auth smoke"

if [ -z "${SUPERUSER_EMAIL:-}" ] || [ -z "${SUPERUSER_PASSWORD:-}" ]; then
  warn "SUPERUSER_EMAIL / SUPERUSER_PASSWORD unset — skipping auth smoke"
  exit 0
fi

TARGET="$(app_nodes | awk '{print $1}')"
[ -n "$TARGET" ] || die "no app node for auth smoke"

ha_ensure_curl_image
SID="$(ha_login "$TARGET")"
me="$(http_api "$TARGET" GET /users/me "" "$SID")"
[ "$(http_code "$me")" = "200" ] || die "/users/me failed: $me"
ok "authenticated /users/me on $TARGET"
