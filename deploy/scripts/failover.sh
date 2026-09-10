#!/usr/bin/env bash
# Promote the standby node to primary.
#
#   ./deploy/scripts/failover.sh                       # standby from inventory
#   ./deploy/scripts/failover.sh --to node2 --reason "node1 host failure"
#   ./deploy/scripts/failover.sh --dry-run
#
# This is a short, controlled outage, not a seamless switch. Expect roughly
# 30-90 seconds, dominated by the provider applying the new traffic route.
#
# Order is deliberate:
#   1. verify the standby can actually take over (before breaking anything)
#   2. fence the old primary, so it cannot keep writing
#   3. install the newest permissions.db snapshot on the new primary
#   4. promote Redis there, permanently
#   5. move the public IP
#   6. verify the whole path end to end
#
# Fencing comes before promotion on purpose: two live primaries diverge, and
# nothing merges a split brain afterwards.
#
# Some providers rate-limit moving traffic - netcup enforces 301 seconds between
# two reassignments of the same IP, Hetzner enforces nothing. The driver
# declares its own figure and this script waits for it, so on a rate-limited
# provider the direction of a cutover is a decision you commit to.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory
load_provider

TO_NODE="${STANDBY_NODE:-}"
FROM_NODE="${PRIMARY_NODE:-}"
REASON=""; DRY_RUN=false; POWER_OFF=false; SKIP_SNAPSHOT=false

while [ $# -gt 0 ]; do
  case "$1" in
    --to)            TO_NODE="$2"; shift 2 ;;
    --from)          FROM_NODE="$2"; shift 2 ;;
    --reason)        REASON="$2"; shift 2 ;;
    --dry-run)       DRY_RUN=true; shift ;;
    --power-off)     POWER_OFF=true; shift ;;
    --skip-snapshot) SKIP_SNAPSHOT=true; shift ;;
    -h|--help)       sed -n '2,22p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$TO_NODE" ]   || die "no target node (set STANDBY_NODE in the inventory or pass --to)"
[ -n "$FROM_NODE" ] || die "no source node (set PRIMARY_NODE in the inventory or pass --from)"
[ "$TO_NODE" != "$FROM_NODE" ] || die "source and target are the same node"
require_node "$TO_NODE"; require_node "$FROM_NODE"

run() { if [ "$DRY_RUN" = "true" ]; then printf '  would run: %s\n' "$*"; else "$@"; fi; }

printf '\n'
log "failover plan"
log "  from:   $FROM_NODE ($(node_role "$FROM_NODE"))"
log "  to:     $TO_NODE ($(node_role "$TO_NODE"))"
log "  via:    $PROVIDER_NAME -> $(node_provider_id "$TO_NODE")"
log "  reason: ${REASON:-not given}"
printf '\n'

# --- 1. preconditions -----------------------------------------------------

step "1/6 Verifying the target can take over"

on_node "$TO_NODE" "true" 2>/dev/null || die "$TO_NODE is not reachable - it cannot become primary"

for container in garde-redis garde-vault-agent; do
  on_node "$TO_NODE" "docker inspect -f '{{.State.Running}}' $container 2>/dev/null | grep -q true" \
    || die "$container is not running on $TO_NODE"
done
ok "$TO_NODE has a warm application stack"

# On providers that route rather than deliver the address, sending traffic to a
# host that has not bound it is a black hole: the route change succeeds, the
# site stays down, and a cooldown may then block moving it back. Check before
# touching anything.
if [ "$PROVIDER_REQUIRES_IP_BINDING" = "true" ] && [ -n "${FAILOVER_IP:-}" ]; then
  if on_node "$TO_NODE" "ip -4 -oneline address show | grep -qF '$FAILOVER_IP'"; then
    ok "$TO_NODE has $FAILOVER_IP bound on its interface"
  else
    die "$TO_NODE does not have $FAILOVER_IP bound - it would drop the routed traffic.
     Fix it with the Ansible baseline, then retry:
       cd ansible && ansible-playbook playbooks/bootstrap.yml --limit $TO_NODE"
  fi
fi

# Vault must have quorum, otherwise the new primary cannot read secrets after
# any restart.
unsealed=0
for node in $NODES; do
  if on_node "$node" "docker exec garde-vault vault status >/dev/null 2>&1" 2>/dev/null; then
    unsealed=$((unsealed + 1))
  fi
done
if [ "$unsealed" -lt 2 ]; then
  die "only $unsealed Vault member(s) unsealed - restore quorum before failing over"
fi
ok "$unsealed/3 Vault members unsealed"

snapshot_age="$(on_node "$TO_NODE" "
  f='$REMOTE_ROOT/backup/permissions.db'
  if [ -f \"\$f\" ]; then echo \$(( \$(date +%s) - \$(stat -c %Y \"\$f\") )); else echo -1; fi")"
if [ "$snapshot_age" = "-1" ]; then
  die "$TO_NODE has no permissions.db snapshot - it would come up with an empty permission catalog"
fi
log "permissions.db snapshot on $TO_NODE is ${snapshot_age}s old"
if [ "$snapshot_age" -gt "${SQLITE_SNAPSHOT_MAX_AGE_SECONDS:-1800}" ]; then
  warn "that is older than SQLITE_SNAPSHOT_MAX_AGE_SECONDS"
  warn "permission changes made since then will be lost"
fi

# Checked here, before anything is broken, rather than at the moment of the
# move. A cooldown discovered after fencing and promotion would leave the site
# down with no way to route traffic to the node that is now serving.
cooldown_left="$(traffic_cooldown_remaining)"
if [ "$cooldown_left" -gt 0 ]; then
  die "$PROVIDER_NAME will not move traffic again for ${cooldown_left}s.
     Fencing now would take the site down with no way to redirect traffic to $TO_NODE."
fi
cooldown="$(traffic_cooldown_seconds)"
if [ "$cooldown" -gt 0 ]; then
  reversal="cannot be undone for $(( cooldown / 60 )) minutes"
else
  reversal="can be reversed immediately on $PROVIDER_NAME"
fi
ok "traffic can be moved now"

if [ "$DRY_RUN" = "false" ]; then
  confirm "Fail over from $FROM_NODE to $TO_NODE? This causes a brief outage and $reversal."
fi

started="$(date +%s)"

# --- 2. fence -------------------------------------------------------------

step "2/6 Fencing $FROM_NODE"
if [ "$POWER_OFF" = "true" ]; then
  run "$DEPLOY_DIR/scripts/fence.sh" "$FROM_NODE" --power-off
else
  run "$DEPLOY_DIR/scripts/fence.sh" "$FROM_NODE" || {
    warn "fencing failed and the old primary may still be writing"
    warn "re-run with --power-off to stop the server through $PROVIDER_NAME"
    die "aborting before promotion to avoid a split brain"
  }
fi

# --- 3. fresh snapshot, if the old primary is still alive ------------------

step "3/6 Installing the permissions database on $TO_NODE"
if [ "$SKIP_SNAPSHOT" = "false" ] && on_node "$FROM_NODE" "docker inspect -f '{{.State.Running}}' garde-api 2>/dev/null | grep -q true" 2>/dev/null; then
  log "old primary still has a running garde container, taking a final snapshot"
  run "$DEPLOY_DIR/scripts/sqlite-snapshot.sh" --from "$FROM_NODE"
else
  log "using the last distributed snapshot (${snapshot_age}s old)"
fi

# garde must not be running while its database file is replaced.
# The API image runs as UID 65532; the deploy user has no sudo, so the copy
# runs through a throwaway container and chowns for that UID.
run on_node "$TO_NODE" "
  set -e
  cd '$REMOTE_ROOT'
  docker compose --env-file .env -f compose/app.yml -p garde-app stop garde >/dev/null 2>&1 || true
  docker run --rm \
    -v '$REMOTE_ROOT/backup/permissions.db:/src/permissions.db:ro' \
    -v '$REMOTE_ROOT/data:/data' \
    alpine:3.19 \
    sh -c 'cp /src/permissions.db /data/permissions.db && rm -f /data/permissions.db-wal /data/permissions.db-shm && chown -R 65532:65532 /data && chmod 644 /data/permissions.db'
"
ok "permissions.db installed"

# --- 4. promote redis -----------------------------------------------------

step "4/6 Promoting Redis on $TO_NODE"
run "$DEPLOY_DIR/scripts/redis-promote.sh" "$TO_NODE"

run on_node "$TO_NODE" "cd '$REMOTE_ROOT' && docker compose --env-file .env -f compose/app.yml -p garde-app up -d garde"

if [ "$DRY_RUN" = "false" ]; then
  retry_until 24 5 on_node "$TO_NODE" \
    "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health" \
    || die "garde did not become healthy on $TO_NODE - the IP has NOT been moved yet"
  ok "garde is healthy on $TO_NODE"
fi

# --- 5. move the public IP ------------------------------------------------

step "5/6 Routing public traffic to $TO_NODE"
run enforce_traffic_cooldown
run provider_route_traffic_to "$TO_NODE"
run record_traffic_move

# --- 6. verify ------------------------------------------------------------

step "6/6 Verifying the public path"
if [ "$DRY_RUN" = "false" ]; then
  # Budget three times the propagation the driver declares, so a slow provider
  # is not reported as a failed cutover.
  verify_attempts=$(( (PROVIDER_TRAFFIC_PROPAGATION_SECONDS * 3) / 5 ))
  [ "$verify_attempts" -lt 12 ] && verify_attempts=12

  public_ok=false
  if [ -n "${API_DOMAIN:-}" ] && [ "$API_DOMAIN" != "app.example.com" ] \
      && ! printf '%s' "$API_DOMAIN" | grep -qiE 'example\.(com|org|net)$'; then
    if retry_until "$verify_attempts" 5 sh -c "curl -sf --max-time 10 'https://${API_DOMAIN}/health' >/dev/null"; then
      ok "https://${API_DOMAIN}/health is serving from $TO_NODE"
      public_ok=true
    fi
  fi

  # Domains are often still placeholders during a first provider bring-up.
  # Prefer the provider's own location check (EIP association on AWS), then
  # fall back to probing the failover address so cutovers are verified without
  # real DNS/ACME.
  if [ "$public_ok" = "false" ]; then
    loc="$(provider_traffic_location 2>/dev/null || true)"
    if [ -n "$loc" ] && [ "$loc" = "$TO_NODE" ]; then
      ok "$PROVIDER_NAME reports traffic on $TO_NODE"
      public_ok=true
    fi
  fi

  if [ "$public_ok" = "false" ] && [ -n "${FAILOVER_IP:-}" ]; then
    if retry_until "$verify_attempts" 5 \
         sh -c "curl -sf --max-time 10 -H 'Host: ${API_DOMAIN:-localhost}' \
           'http://${FAILOVER_IP}/health' >/dev/null \
           || curl -skf --max-time 10 -H 'Host: ${API_DOMAIN:-localhost}' \
           'https://${FAILOVER_IP}/health' >/dev/null"; then
      ok "failover IP $FAILOVER_IP answers /health after the move"
      public_ok=true
    fi
  fi

  if [ "$public_ok" = "false" ]; then
    warn "the public health check did not pass yet"
    warn "$PROVIDER_NAME applies the route asynchronously (up to ${PROVIDER_TRAFFIC_PROPAGATION_SECONDS}s); re-check shortly"
  fi
fi

# --- bookkeeping ----------------------------------------------------------

elapsed=$(( $(date +%s) - started ))

if [ "$DRY_RUN" = "false" ]; then
  step "Updating inventory role pointers"
  to_role_key="$(printf '%s' "$TO_NODE" | tr '[:lower:]' '[:upper:]')_ROLE"
  from_role_key="$(printf '%s' "$FROM_NODE" | tr '[:lower:]' '[:upper:]')_ROLE"
  if [ -w "$INVENTORY_FILE" ]; then
    sed -i.bak \
      -e "s/^PRIMARY_NODE=.*/PRIMARY_NODE=$TO_NODE/" \
      -e "s/^STANDBY_NODE=.*/STANDBY_NODE=$FROM_NODE/" \
      -e "s/^${to_role_key}=.*/${to_role_key}=app-primary/" \
      -e "s/^${from_role_key}=.*/${from_role_key}=app-standby/" \
      "$INVENTORY_FILE"
    ok "inventory now records $TO_NODE as primary (and NODE*_ROLE swapped)"
  fi
  warn "roles have swapped. Update the DEPLOY_INVENTORY secret to match:"
  warn "  PRIMARY_NODE=$TO_NODE STANDBY_NODE=$FROM_NODE"
  warn "  ${to_role_key}=app-primary ${from_role_key}=app-standby"
fi

printf '\n'
ok "failover complete in ${elapsed}s"
summary "## Failover: $FROM_NODE -> $TO_NODE"
summary ""
summary "- reason: ${REASON:-not given}"
summary "- duration: ${elapsed}s"
summary "- permissions.db snapshot age at cutover: ${snapshot_age}s"
if [ "$cooldown" -gt 0 ]; then
  summary "- traffic cannot move again for ${cooldown}s ($PROVIDER_NAME rate limit)"
else
  summary "- $PROVIDER_NAME has no cooldown; failing back is possible immediately"
fi
summary ""
summary "Next: revive $FROM_NODE as standby with redis-replicate.sh (docs/DEPLOY.md, 'Rebuilding after failover')."
