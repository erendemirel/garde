#!/usr/bin/env bash
# Impact: none — public HTTPS via real domains. Skipped for placeholder DNS.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_boot
ha_banner "deploy: public HTTPS"

if printf '%s' "${API_DOMAIN:-}${APP_DOMAIN:-}" | grep -qiE 'example\.(com|org|net)'; then
  warn "placeholder domains ($API_DOMAIN / $APP_DOMAIN) — skipping public HTTPS"
  exit 0
fi

need_cmd curl
for url in "https://${API_DOMAIN}/health" "https://${APP_DOMAIN}/"; do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$url" || echo 000)"
  [ "$code" = "200" ] || die "$url -> $code"
  ok "$url -> $code"
done
