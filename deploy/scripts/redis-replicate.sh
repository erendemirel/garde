#!/usr/bin/env bash
# Point a node's Redis at the current PRIMARY_NODE as a permanent replica.
#
#   ./deploy/scripts/redis-replicate.sh node1
#
# Inverse of redis-promote.sh. After a failover the old primary still has a
# primary redis.conf (and an in-memory master role). sync-config will not
# overwrite that file, and `compose up` will not restart a running Redis, so a
# revived host can come back as a second master until this script runs.
#
# Order: rewrite redis.conf first, then REPLICAOF against the live process, so
# a later container restart cannot undo the demotion.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory

NODE="${1:-}"
[ -n "$NODE" ] || die "usage: redis-replicate.sh <node>"
require_node "$NODE"

PRIMARY="${PRIMARY_NODE:?PRIMARY_NODE missing from inventory}"
[ "$NODE" != "$PRIMARY" ] || die "$NODE is PRIMARY_NODE - refusing to make the primary a replica"

role="$(node_role "$NODE")"
case "$role" in
  app-standby|app-primary) ;;
  *) die "$NODE has role '$role' - only app nodes run Redis" ;;
esac
if [ "$role" = "app-primary" ]; then
  warn "$NODE is still marked app-primary in the inventory"
  warn "set NODE*_ROLE=app-standby before the next sync-config / deploy"
fi

: "${REDIS_PASSWORD:?REDIS_PASSWORD must be set}"
primary_ip="$(node_wg_ip "$PRIMARY")"
[ -n "$primary_ip" ] || die "no WireGuard IP for primary $PRIMARY"

redis_cli() {
  local node="$1"; shift
  on_node "$node" "set -a; . '$REMOTE_ROOT/.env'; set +a; \
    docker exec garde-redis redis-cli -a \"\$REDIS_PASSWORD\" --no-auth-warning $*"
}

repl_field() {
  redis_cli "$1" "info replication" 2>/dev/null | tr -d '\r' | sed -n "s/^$2://p"
}

step "Writing replica redis.conf on $NODE (-> $PRIMARY / $primary_ip)"
on_node "$NODE" "mkdir -p '$REMOTE_ROOT/config/redis'"
tmp="$(mktemp)"
sed -e "s|@@REDIS_PASSWORD@@|$REDIS_PASSWORD|g" \
    -e "s|@@REPLICAOF@@|replicaof $primary_ip 6379|g" \
    "$DEPLOY_DIR/config/redis/redis.conf.tpl" > "$tmp"
# redis.conf is owned by uid 999; the deploy user cannot rsync over it. Stage
# beside it and swap through a helper container (same pattern as promote).
rsh="$(rsync_rsh "$NODE")"
rsync -az -e "$rsh" "$tmp" "$(ssh_target "$NODE"):$REMOTE_ROOT/config/redis/redis.conf.incoming"
rm -f "$tmp"
on_node "$NODE" "docker run --rm \
  -v '$REMOTE_ROOT/config/redis':/mnt \
  alpine:3.19 \
  sh -c 'mv /mnt/redis.conf.incoming /mnt/redis.conf && chown 999:999 /mnt/redis.conf && chmod 640 /mnt/redis.conf'"
if ! on_node "$NODE" "docker run --rm -v '$REMOTE_ROOT/config/redis:/mnt:ro' alpine:3.19 \
      grep -E '^replicaof ' /mnt/redis.conf >/dev/null"; then
  die "redis.conf on $NODE is missing the replicaof line after write"
fi
ok "redis.conf now replicates from $primary_ip"

step "Demoting live Redis on $NODE"
on_node "$NODE" "docker inspect -f '{{.State.Running}}' garde-redis 2>/dev/null | grep -q true" \
  || die "garde-redis is not running on $NODE"
redis_cli "$NODE" "replicaof $primary_ip 6379" >/dev/null

i=0
while [ "$i" -lt 24 ]; do
  [ "$(repl_field "$NODE" role)" = "slave" ] && break
  i=$((i + 1))
  sleep 2
done
[ "$(repl_field "$NODE" role)" = "slave" ] \
  || die "demotion failed, role is still '$(repl_field "$NODE" role)'"

if [ "$(repl_field "$NODE" master_link_status)" != "up" ]; then
  warn "replica role set but link not up yet - waiting for catch-up"
  i=0
  while [ "$i" -lt 36 ]; do
    [ "$(repl_field "$NODE" master_link_status)" = "up" ] && break
    i=$((i + 1))
    sleep 2
  done
fi
[ "$(repl_field "$NODE" master_link_status)" = "up" ] \
  || die "replica link to $PRIMARY did not come up"

ok "$NODE is a Redis replica of $PRIMARY (link up)"
summary "Redis demoted on $NODE -> replica of $PRIMARY"
