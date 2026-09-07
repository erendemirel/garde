#!/usr/bin/env bash
# Report the health of the cluster.
#
#   ./deploy/scripts/healthcheck.sh --all
#   ./deploy/scripts/healthcheck.sh node1 --public
#
# Checks per node: container state, Vault seal/leader status, Redis replication
# role, garde's own /health, and the age of the permissions.db snapshot.
# With --public it also walks the real edge path over HTTPS.
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
      # Not fatal on its own: the other two members carry the cluster.
      warn "$node: vault is SEALED - run deploy/scripts/unseal.sh $node"
    else
      ok "vault unsealed, leader=${leader:-unknown}"
    fi
  fi

  # --- App nodes -----------------------------------------------------------
  case "$role" in
    app-primary|app-standby)
      redis_role="$(on_node "$node" "set -a; . '$REMOTE_ROOT/.env'; set +a; \
        docker exec garde-redis redis-cli -a \"\$REDIS_PASSWORD\" --no-auth-warning info replication 2>/dev/null \
        | tr -d '\r' | sed -n 's/^role://p'")"
      case "$redis_role" in
        master) ok "redis role=master" ;;
        slave)
          link="$(on_node "$node" "set -a; . '$REMOTE_ROOT/.env'; set +a; \
            docker exec garde-redis redis-cli -a \"\$REDIS_PASSWORD\" --no-auth-warning info replication 2>/dev/null \
            | tr -d '\r' | sed -n 's/^master_link_status://p'")"
          if [ "$link" = "up" ]; then ok "redis role=replica, link up"
          else fail "$node: redis replica link is '$link'"; fi
          ;;
        *) fail "$node: could not read redis role" ;;
      esac

      # Expected role vs actual: catches a split brain early.
      if [ "$node" = "${PRIMARY_NODE:-}" ] && [ "$redis_role" != "master" ]; then
        fail "$node is the inventory primary but redis is not master"
      fi
      if [ "$node" = "${STANDBY_NODE:-}" ] && [ "$redis_role" = "master" ]; then
        fail "$node is the inventory standby but redis is master (split brain?)"
      fi

      if on_node "$node" "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health"; then
        ok "garde /health responding"
      else
        fail "$node: garde /health failed"
      fi

      # Both app nodes must hold the failover IP at all times. The standby
      # needs it before a cutover, not during one, and a missing binding is
      # invisible until the moment it matters.
      if [ -n "${FAILOVER_IP:-}" ]; then
        if on_node "$node" "ip -4 -oneline address show | grep -qF '$FAILOVER_IP'"; then
          ok "failover IP $FAILOVER_IP bound"
        else
          fail "$node: $FAILOVER_IP is not bound - routed traffic would be dropped"
        fi
      fi

      snapshot_age="$(on_node "$node" "
        f='$REMOTE_ROOT/backup/permissions.db'
        if [ -f \"\$f\" ]; then echo \$(( \$(date +%s) - \$(stat -c %Y \"\$f\") )); else echo -1; fi")"
      if [ "$snapshot_age" = "-1" ]; then
        [ "$role" = "app-standby" ] && fail "$node: no permissions.db snapshot present" \
                                   || log "no snapshot on the primary (expected: it is the source)"
      else
        max_age="${SQLITE_SNAPSHOT_MAX_AGE_SECONDS:-1800}"
        if [ "$snapshot_age" -gt "$max_age" ]; then
          fail "$node: permissions.db snapshot is ${snapshot_age}s old (max ${max_age}s)"
        else
          ok "permissions.db snapshot ${snapshot_age}s old"
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
fi

step "Result"
if [ "$FAILURES" -eq 0 ]; then
  ok "all checks passed"
  summary "Health check passed for: $TARGETS"
else
  summary "Health check FAILED with $FAILURES problem(s)"
  die "$FAILURES check(s) failed"
fi
