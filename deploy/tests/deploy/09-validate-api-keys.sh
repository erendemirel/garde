#!/usr/bin/env bash
# Impact: none — proves /validate credential rules on the live API process
# (shared API_KEY and per-tenant keys), without needing the public edge or the
# mesh service listener.
#
# Soft-skips when SUPERUSER_* / API_KEY are unset, or when the running image
# does not yet expose POST /admin/api-keys.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_boot
ha_banner "deploy: validate API keys"

TARGET="${PRIMARY_NODE:?PRIMARY_NODE missing from inventory}"
FAKE_SESSION_ID='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

ha_ensure_curl_image

if [ -z "${API_KEY:-}" ]; then
  warn "API_KEY unset — skipping validate credential checks"
  exit 0
fi

# Probe /validate through the API container network (not the public edge).
validate_local() {
  local key="$1" remote="/tmp/garde-validate-key.$$"
  on_node "$TARGET" "printf '%s' $(printf '%q' "$key") > $remote"
  on_node "$TARGET" "docker run --rm --network container:garde-api -v $remote:/key:ro $HA_CURL_IMG \
    sh -c \"curl -sS -o /tmp/vb -w '%{http_code}' --max-time 15 \
      -H \\\"X-API-Key: \\\$(cat /key)\\\" \
      -H 'X-Session-ID: $FAKE_SESSION_ID' \
      'http://127.0.0.1:8443/validate'; echo; cat /tmp/vb\""
  on_node "$TARGET" "rm -f $remote" >/dev/null 2>&1 || true
}

parse_code() { printf '%s' "$1" | head -n1 | tr -d '\r'; }
parse_body() { printf '%s' "$1" | tail -n +2; }

out="$(validate_local "$API_KEY")"
code="$(parse_code "$out")"
body="$(parse_body "$out" | tr '[:upper:]' '[:lower:]')"
case "$code:$body" in
  401:*session\ invalid*)
    ok "shared API_KEY authenticates /validate on the app listener (session rejected after auth)" ;;
  *)
    die "shared API_KEY probe returned code=$code body=$body (want 401 session invalid)" ;;
esac

out="$(validate_local 'not-a-real-key')"
code="$(parse_code "$out")"
body="$(parse_body "$out" | tr '[:upper:]' '[:lower:]')"
case "$code:$body" in
  401:*unauthorized*)
    ok "garbage credentials are refused on /validate" ;;
  *)
    die "garbage key probe returned code=$code body=$body (want 401 unauthorized)" ;;
esac

# --- per-tenant keys (requires superuser + the new admin routes) ------------

if [ -z "${SUPERUSER_EMAIL:-}" ] || [ -z "${SUPERUSER_PASSWORD:-}" ]; then
  warn "SUPERUSER_EMAIL/PASSWORD unset — skipping per-tenant API key checks"
  exit 0
fi

token="$(ha_login "$TARGET")"

# Does this image expose the admin API-key routes?
probe="$(http_api "$TARGET" GET /admin/api-key-scopes "" "$token")"
probe_code="$(http_code "$probe")"
if [ "$probe_code" = "404" ]; then
  warn "GET /admin/api-key-scopes -> 404 — running image has no per-tenant API key routes yet; skipping"
  exit 0
fi
[ "$probe_code" = "200" ] \
  || die "GET /admin/api-key-scopes -> $probe_code (want 200 for superuser)"

client_id="deploy_ci_$(date +%s)"
create_body="$(printf '{"client_id":"%s","name":"ci-validate","scopes":["validate"]}' "$client_id")"
created="$(http_api "$TARGET" POST /admin/api-keys "$create_body" "$token")"
[ "$(http_code "$created")" = "201" ] \
  || die "POST /admin/api-keys failed: $created"

tenant_key="$(http_body "$created" | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')"
key_id="$(http_body "$created" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')"
[ -n "$tenant_key" ] && [ -n "$key_id" ] \
  || die "create response missing key/id: $(http_body "$created")"

cleanup_keys() {
  http_api "$TARGET" DELETE "/admin/clients/${client_id}/api-keys" "" "$token" >/dev/null 2>&1 || true
}
trap cleanup_keys EXIT

out="$(validate_local "$tenant_key")"
code="$(parse_code "$out")"
body="$(parse_body "$out" | tr '[:upper:]' '[:lower:]')"
case "$code:$body" in
  401:*session\ invalid*)
    ok "per-tenant API key authenticates /validate" ;;
  *)
    die "per-tenant key probe returned code=$code body=$body (want 401 session invalid)" ;;
esac

# Revoke and confirm refusal.
revoked="$(http_api "$TARGET" DELETE "/admin/api-keys/${key_id}" "" "$token")"
[ "$(http_code "$revoked")" = "200" ] \
  || die "DELETE /admin/api-keys/$key_id failed: $revoked"

out="$(validate_local "$tenant_key")"
code="$(parse_code "$out")"
body="$(parse_body "$out" | tr '[:upper:]' '[:lower:]')"
case "$code:$body" in
  401:*unauthorized*)
    ok "revoked per-tenant key is refused on /validate" ;;
  *)
    die "revoked key probe returned code=$code body=$body (want 401 unauthorized)" ;;
esac

# Negative contract the UI depends on.
bad="$(http_api "$TARGET" POST /admin/api-keys \
  "$(printf '{"client_id":"%s","name":"no-scopes"}' "$client_id")" "$token")"
[ "$(http_code "$bad")" = "400" ] \
  || die "create without scopes returned $(http_code "$bad") (want 400)"
ok "create without scopes is refused"

ok "validate API key checks passed"
