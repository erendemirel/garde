#!/usr/bin/env bash
# Impact: none — login + /users/me. Skipped when SUPERUSER_* unset.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_boot
ha_banner "deploy: auth smoke"

if [ -z "${SUPERUSER_EMAIL:-}" ] || [ -z "${SUPERUSER_PASSWORD:-}" ]; then
  warn "SUPERUSER_EMAIL / SUPERUSER_PASSWORD unset — skipping auth smoke"
  exit 0
fi

ha_ensure_curl_image
SID="$(ha_login "$PRIMARY_NODE")"
me="$(http_api "$PRIMARY_NODE" GET /users/me "" "$SID")"
[ "$(http_code "$me")" = "200" ] || die "/users/me failed: $me"
ok "authenticated /users/me on $PRIMARY_NODE"
