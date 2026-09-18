#!/usr/bin/env bash
# Report the health of the cluster.
#
#   ./deploy/scripts/healthcheck.sh --all
#   ./deploy/scripts/healthcheck.sh node1 --public
#
# Checks per node: container state, Vault seal/leader status, and on app nodes
# garde's /ready probe. With --public it also walks the real edge path over HTTPS.
#
# Exit code is non-zero if any critical check fails, so CI can gate on it.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory

TARGETS=""; CHECK_PUBLIC=false; FAILURES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --all)    TARGETS="$NODES"; shift ;;
    --public) CHECK_PUBLIC=true; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) TARGETS="$TARGETS $1"; shift ;;
  esac
done
[ -n "${TARGETS// /}" ] || TARGETS="$NODES"

fail() { FAILURES=$((FAILURES + 1)); printf '%sfail%s   %s\n' "$_c_red" "$_c_reset" "$*" >&2; }

for node in $TARGETS; do
  require_node "$node"
  role="$(node_role "$node")"
  step "$node ($role)"

  if ! on_node "$node" "true" 2>/dev/null; then
    fail "$node unreachable over the mesh"
    continue
  fi

  # --- Vault ---------------------------------------------------------------
  vault_json="$(on_node "$node" "docker exec garde-vault vault status -format=json 2>/dev/null || true")"
  if [ -z "$vault_json" ]; then
    fail "$node: vault not responding"
  else
    sealed="$(printf '%s' "$vault_json"  | grep -o '"sealed"[: ]*[a-z]*'      | grep -o 'true\|false' || echo unknown)"
    initialized="$(printf '%s' "$vault_json" | grep -o '"initialized"[: ]*[a-z]*' | grep -o 'true\|false' || echo unknown)"
    leader="$(printf '%s' "$vault_json" | grep -o '"leader_address"[: ]*"[^"]*"' | sed 's/.*"\(http[^"]*\)".*/\1/' || true)"
    if [ "$initialized" != "true" ]; then
      fail "$node: vault not initialized"
    elif [ "$sealed" = "true" ]; then
      # Not fatal on its own: the other members carry the cluster.
      if [ -n "${VAULT_KMS_KEY_ID:-}" ]; then
        warn "$node: vault is SEALED - check KMS/IMDS (awskms); Shamir: deploy/scripts/unseal.sh $node"
      else
        warn "$node: vault is SEALED - run deploy/scripts/unseal.sh $node"
      fi
    else
      ok "vault unsealed, leader=${leader:-unknown}"
    fi
  fi

  # --- App nodes -----------------------------------------------------------
  case "$role" in
    app)
      if on_node "$node" "docker exec garde-api sh -c 'wget -q -O /dev/null --no-check-certificate https://127.0.0.1:8443/ready || wget -q -O /dev/null http://127.0.0.1:8443/ready'"; then
        ok "garde /ready responding"
      else
        fail "$node: garde /ready failed"
      fi

      # Floating-IP lane only: where the provider routes the address rather than
      # delivering it, app nodes that may receive the address should already have
      # it bound. Managed LB / NAT providers skip this — the guest never sees it.
      if [ "$PROVIDER_REQUIRES_IP_BINDING" = "true" ] && [ -n "${FAILOVER_IP:-}" ]; then
        if on_node "$node" "ip -4 -oneline address show | grep -qF '$FAILOVER_IP'"; then
          ok "edge IP $FAILOVER_IP bound"
        else
          warn "$node: $FAILOVER_IP is not bound (needed before floating_ip traffic can land here)"
        fi
      fi
      ;;
    witness)
      if on_node "$node" "docker inspect -f '{{.State.Running}}' garde-prometheus 2>/dev/null | grep -q true"; then
        ok "prometheus running"
      else
        warn "$node: prometheus not running"
      fi
      ;;
  esac

  unhealthy="$(on_node "$node" "docker ps --filter 'health=unhealthy' --format '{{.Names}}' | tr '\n' ' '")"
  [ -n "${unhealthy// /}" ] && fail "$node: unhealthy containers: $unhealthy" || ok "no unhealthy containers"
done

# --- public edge -----------------------------------------------------------
if [ "$CHECK_PUBLIC" = "true" ]; then
  step "Public edge"
  for url in "https://${API_DOMAIN}/health" "https://${APP_DOMAIN}/"; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$url" || echo 000)"
    if [ "$code" = "200" ]; then ok "$url -> $code"; else fail "$url -> $code"; fi
  done

  # /validate can validate any user's session, so what counts as healthy here
  # depends on whether this deployment serves external callers.
  validate_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "https://${API_DOMAIN}/validate" || echo 000)"
  if [ "$(public_validate)" = "true" ]; then
    case "$validate_code" in
      401) ok "https://${API_DOMAIN}/validate -> 401 (published, unauthenticated calls refused)" ;;
      404) fail "https://${API_DOMAIN}/validate -> 404 with PUBLIC_VALIDATE=true; set the public_validate key in Vault" ;;
      000) fail "https://${API_DOMAIN}/validate -> unreachable" ;;
      *)   fail "https://${API_DOMAIN}/validate -> $validate_code; an unauthenticated call must be refused" ;;
    esac

    fake_sid='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    shared_body="$(mktemp)"
    shared_code="$(curl -sS -o "$shared_body" -w '%{http_code}' --max-time 15 \
      -H 'X-API-Key: TestApiKey123!TestApiKey123!' \
      -H "X-Session-ID: ${fake_sid}" \
      "https://${API_DOMAIN}/validate" || echo 000)"
    shared_msg="$(tr '[:upper:]' '[:lower:]' < "$shared_body")"
    rm -f "$shared_body"
    if [ "$shared_code" != "401" ]; then
      fail "legacy shared secret on public /validate -> $shared_code (must be refused with 401)"
    elif printf '%s' "$shared_msg" | grep -q 'session invalid'; then
      fail "legacy shared secret authenticated on the public edge (session invalid)"
    elif printf '%s' "$shared_msg" | grep -q 'unauthorized'; then
      ok "https://${API_DOMAIN}/validate refuses legacy shared-secret credentials"
    else
      fail "legacy shared secret on public /validate -> 401 with unexpected body"
    fi
  else
    case "$validate_code" in
      404) ok "https://${API_DOMAIN}/validate -> 404 (not published, as intended)" ;;
      000) fail "https://${API_DOMAIN}/validate -> unreachable; cannot confirm it is unpublished" ;;
      *)   fail "https://${API_DOMAIN}/validate -> $validate_code; the service endpoint is exposed on the public edge" ;;
    esac
  fi
fi

step "Result"
if [ "$FAILURES" -eq 0 ]; then
  ok "all checks passed"
  summary "Health check passed for: $TARGETS"
else
  summary "Health check FAILED with $FAILURES problem(s)"
  die "$FAILURES check(s) failed"
fi
