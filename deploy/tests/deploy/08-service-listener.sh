#!/usr/bin/env bash
# Impact: none — proves /validate is private and certificate-gated when the
# service listener is deployed, and that a published public copy refuses the
# shared API_KEY.
#
# Claims:
#
#   1. the public API hostname does not serve /validate (or, with
#      PUBLIC_VALIDATE=true, serves it but refuses unauthenticated callers and
#      the shared API_KEY)
#   2. the mesh service listener refuses a caller with no client certificate
#   3. the same call succeeds with a certificate from the service CA (+ shared
#      or per-tenant key)
#
# Claims 2–3 soft-skip when the service listener is not running on the primary
# (single-listener deployments). Claim 3 also needs:
#   SERVICE_CLIENT_CERT=deploy/pki/client-ci-cert.pem
#   SERVICE_CLIENT_KEY=deploy/pki/client-ci-key.pem
#   API_KEY=...           (the same value seeded into Vault)
#
# Session ids must be well-formed (86-char base64url). A UUID fails format
# validation with 400 and cannot distinguish "key accepted" from "key refused".
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_boot
ha_banner "deploy: service listener"

PORT="${SERVICE_PORT:-8444}"
TARGET="${PRIMARY_NODE:?PRIMARY_NODE missing from inventory}"
TARGET_IP="$(node_wg_ip "$TARGET")"
[ -n "$TARGET_IP" ] || die "no mesh address for $TARGET"

# Well-formed, never-issued session id — passes ValidateSessionID, fails lookup.
FAKE_SESSION_ID='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

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
    # this one is the operator's, valid only on the mesh listener.
    # Distinguishing outcomes: key accepted → "session invalid"; key refused →
    # plain "unauthorized". Both are HTTP 401.
    if [ -n "${API_KEY:-}" ]; then
      shared_body="$(mktemp)"
      shared="$(curl -sS -o "$shared_body" -w '%{http_code}' --max-time 20 \
        -H "X-API-Key: ${API_KEY}" \
        -H "X-Session-ID: ${FAKE_SESSION_ID}" \
        "https://${API_DOMAIN}/validate" || echo 000)"
      shared_msg="$(tr '[:upper:]' '[:lower:]' < "$shared_body")"
      rm -f "$shared_body"
      [ "$shared" = "401" ] \
        || die "the shared API key returned $shared on the public edge; it must not authenticate there"
      case "$shared_msg" in
        *session\ invalid*)
          die "the shared API key authenticated on the public edge (got session invalid); it must be refused there" ;;
        *unauthorized*)
          ok "public edge refuses the shared API key" ;;
        *)
          die "the shared API key returned 401 with unexpected body: $shared_msg" ;;
      esac
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

# Is the service listener even configured? Single-listener deployments never
# open :8444; failing them here would make the whole deploy suite unusable
# until the mesh listener is deliberately enabled.
listener_up="$(on_node "$TARGET" "ss -lntp 2>/dev/null | grep -q ':$PORT' && echo yes || (netstat -lntp 2>/dev/null | grep -q ':$PORT' && echo yes || echo no)")"
if [ "$listener_up" != "yes" ]; then
  # Also accept "bound inside the container only" — compose may publish on the
  # mesh address without the host ss seeing a global listen.
  listener_up="$(on_node "$TARGET" "docker exec garde-api sh -c 'ss -lntp 2>/dev/null | grep -q :$PORT || netstat -lntp 2>/dev/null | grep -q :$PORT' && echo yes || echo no" 2>/dev/null || echo no)"
fi

if [ "$listener_up" != "yes" ]; then
  warn "service listener not listening on :$PORT — skipping mesh mTLS checks (single-listener layout, or SERVICE_LISTENER not enabled yet)"
  exit 0
fi

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

# Auth success with a never-issued session is 401 "session invalid" — not 200.
# A UUID fails format checks with 400 and cannot prove the key was accepted.
# Write the body onto the shared REMOTE_DIR so we can read it after the container exits.
code="$(on_node "$FROM" "docker run --rm -v '$REMOTE_DIR':/pki:rw $HA_CURL_IMG \
  sh -c \"curl -sS -k -o /pki/validate.body -w '%{http_code}' --max-time 15 \
    --cert /pki/client-cert.pem --key /pki/client-key.pem \
    -H 'X-API-Key: $API_KEY' \
    -H 'X-Session-ID: $FAKE_SESSION_ID' \
    'https://$TARGET_IP:$PORT/validate'\")"
msg="$(on_node "$FROM" "tr '[:upper:]' '[:lower:]' < '$REMOTE_DIR/validate.body' 2>/dev/null || true")"

case "$code" in
  401)
    case "$msg" in
      *session\ invalid*)
        ok "service listener accepted a certificate from the service CA (session rejected after auth)" ;;
      *)
        die "authenticated /validate call returned 401 without session-invalid body: $msg" ;;
    esac
    ;;
  200)
    ok "service listener accepted a certificate from the service CA (200)" ;;
  *)
    die "authenticated /validate call returned $code" ;;
esac
