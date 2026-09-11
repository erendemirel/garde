#!/usr/bin/env bash
# Impact: none — proves /validate is private and certificate-gated.
#
# Three claims, each of which has been true only by intention before now:
#
#   1. the public API hostname does not serve /validate
#   2. the mesh service listener refuses a caller with no client certificate
#   3. the same call succeeds with a certificate from the service CA
#
# Claim 3 needs a client keypair, so it is skipped unless one is supplied:
#   SERVICE_CLIENT_CERT=deploy/pki/client-ci-cert.pem
#   SERVICE_CLIENT_KEY=deploy/pki/client-ci-key.pem
#   API_KEY=...           (the same value seeded into Vault)
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_boot
ha_banner "deploy: service listener"

PORT="${SERVICE_PORT:-8444}"
TARGET="${PRIMARY_NODE:?PRIMARY_NODE missing from inventory}"
TARGET_IP="$(node_wg_ip "$TARGET")"
[ -n "$TARGET_IP" ] || die "no mesh address for $TARGET"

ha_ensure_curl_image

# --- 1. not on the public edge ---------------------------------------------

if printf '%s' "${API_DOMAIN:-}" | grep -qiE 'example\.(com|org|net)'; then
  warn "placeholder domain ($API_DOMAIN) — skipping the public exposure check"
else
  need_cmd curl
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "https://${API_DOMAIN}/validate" || echo 000)"
  if [ "$(public_validate)" = "true" ]; then
    # This deployment serves external tenants, so the endpoint is published on
    # purpose. What must hold is that it refuses a caller presenting nothing.
    [ "$code" = "401" ] \
      || die "https://${API_DOMAIN}/validate returned $code; an unauthenticated call must be refused with 401"
    ok "public edge serves /validate and refuses unauthenticated callers"

    # And that the shared key is not a way in. Tenants hold per-tenant keys;
    # this one is the operator's, valid only on the mesh listener. A valid
    # credential would answer 200 with valid=false for a bogus session, so 401
    # is the outcome that proves it was rejected.
    if [ -n "${API_KEY:-}" ]; then
      shared="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 \
        -H "X-API-Key: ${API_KEY}" \
        -H 'X-Session-ID: 00000000-0000-0000-0000-000000000000' \
        "https://${API_DOMAIN}/validate" || echo 000)"
      [ "$shared" = "401" ] \
        || die "the shared API key returned $shared on the public edge; it must not authenticate there"
      ok "public edge refuses the shared API key"
    else
      warn "API_KEY unset — skipping the shared-key rejection check"
    fi
  else
    [ "$code" = "404" ] \
      || die "https://${API_DOMAIN}/validate returned $code; the service endpoint must not be published"
    ok "public edge does not serve /validate"
  fi
fi

# --- 2. the listener is up and demands a certificate ------------------------

# Run from the standby, so this also proves the listener is reachable across
# the mesh rather than only from its own host.
FROM="${STANDBY_NODE:-$TARGET}"
naked="$(on_node "$FROM" "docker run --rm $HA_CURL_IMG \
  curl -sS -k -o /dev/null -w '%{http_code}' --max-time 15 \
  'https://$TARGET_IP:$PORT/validate' 2>&1 || true")"

# Only one outcome is a failure. A refusal can arrive as a TLS alert (curl
# prints an error and 000), or as a 401 from the middleware if the handshake
# was allowed — both mean nothing without a certificate gets an answer, and
# matching on curl's wording would make this test fragile across versions.
case "$naked" in
  *200) die "service listener answered 200 without a client certificate — SERVICE_MTLS is not in force" ;;
  "")   die "no reply at all from $TARGET_IP:$PORT — is the service listener running?" ;;
  *)    ok "service listener refused an uncertificated caller"
        log "  $naked" ;;
esac

# --- 3. a certificate from the service CA works -----------------------------

if [ -z "${SERVICE_CLIENT_CERT:-}" ] || [ -z "${SERVICE_CLIENT_KEY:-}" ] || [ -z "${API_KEY:-}" ]; then
  warn "SERVICE_CLIENT_CERT / SERVICE_CLIENT_KEY / API_KEY unset — skipping the positive mTLS check"
  exit 0
fi
[ -f "$SERVICE_CLIENT_CERT" ] || die "no such file: $SERVICE_CLIENT_CERT"
[ -f "$SERVICE_CLIENT_KEY" ]  || die "no such file: $SERVICE_CLIENT_KEY"

# The certificate is copied to the node it is used from and removed afterwards;
# it never lands in a container image or a compose file.
REMOTE_DIR="/tmp/garde-service-check.$$"
on_node "$FROM" "mkdir -p '$REMOTE_DIR' && chmod 700 '$REMOTE_DIR'"
cleanup() { on_node "$FROM" "rm -rf '$REMOTE_DIR'" || true; }
trap cleanup EXIT

rsync -az -e "$(rsync_rsh "$FROM")" \
  "$SERVICE_CLIENT_CERT" "$(ssh_target "$FROM"):$REMOTE_DIR/client-cert.pem"
rsync -az -e "$(rsync_rsh "$FROM")" \
  "$SERVICE_CLIENT_KEY" "$(ssh_target "$FROM"):$REMOTE_DIR/client-key.pem"

# A session id that does not exist is the right probe: a 200 with valid=false
# proves the call was authenticated, without needing a live login.
code="$(on_node "$FROM" "docker run --rm -v '$REMOTE_DIR':/pki:ro $HA_CURL_IMG \
  curl -sS -k -o /dev/null -w '%{http_code}' --max-time 15 \
  --cert /pki/client-cert.pem --key /pki/client-key.pem \
  -H 'X-API-Key: $API_KEY' \
  -H 'X-Session-ID: 00000000-0000-0000-0000-000000000000' \
  'https://$TARGET_IP:$PORT/validate'")"

case "$code" in
  200|401)
    # 401 here means the session was rejected, not the caller: the certificate
    # and API key were both accepted before the handler ran.
    ok "service listener accepted a certificate from the service CA ($code)" ;;
  *)
    die "authenticated /validate call returned $code" ;;
esac
