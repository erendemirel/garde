#!/usr/bin/env bash
# Promote a Redis replica to primary, permanently.
#
#   ./deploy/scripts/redis-promote.sh node2
#
# `REPLICAOF NO ONE` alone would be undone by the next container restart,
# because the replicaof line still sits in redis.conf. `CONFIG REWRITE` strips
# it, so the promotion survives restarts. Doing only the first half is a classic
# way to lose writes hours later when something restarts the container.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory

NODE="${1:-}"
[ -n "$NODE" ] || die "usage: redis-promote.sh <node>"
require_node "$NODE"

redis_cli() {
  local node="$1"; shift
  on_node "$node" "set -a; . '$REMOTE_ROOT/.env'; set +a; \
    docker exec garde-redis redis-cli -a \"\$REDIS_PASSWORD\" --no-auth-warning $*"
}

role_of() {
  redis_cli "$1" "info replication" 2>/dev/null | tr -d '\r' | sed -n 's/^role://p'
}

step "Checking current role on $NODE"
current="$(role_of "$NODE")"
case "$current" in
  master)
    ok "$NODE is already a primary"
    # Still ensure the on-disk config will not demote it on restart.
    ;;
  slave) log "$NODE is a replica, promoting" ;;
  *)     die "could not determine the Redis role on $NODE (got '$current')" ;;
esac

# How far behind is this replica? Worth recording before the link is cut.
if [ "$current" = "slave" ]; then
  offset_info="$(redis_cli "$NODE" "info replication" | tr -d '\r' | grep -E 'master_link_status|slave_read_repl_offset|master_last_io_seconds_ago' || true)"
  log "replication state before promotion:"
  printf '%s\n' "$offset_info" | sed 's/^/    /'
fi

step "Promoting $NODE"
if [ "$current" = "slave" ]; then
  redis_cli "$NODE" "replicaof no one" >/dev/null
fi
# CONFIG REWRITE often cannot replace a bind-mounted redis.conf (atomic rename
# fails across the mount). Strip replicaof via a helper container so the
# promotion survives a restart even when the deploy user cannot write the file.
redis_cli "$NODE" "config rewrite" >/dev/null || true
on_node "$NODE" "docker run --rm \
  -v '$REMOTE_ROOT/config/redis:/mnt' \
  alpine:3.19 \
  sh -c 'sed -i -e \"/^replicaof /d\" -e \"/^REPLICAOF /d\" /mnt/redis.conf && chown 999:999 /mnt/redis.conf && chmod 640 /mnt/redis.conf'"

new_role="$(role_of "$NODE")"
[ "$new_role" = "master" ] || die "promotion failed, role is still '$new_role'"

# redis.conf is root-owned (written through the helper above); the deploy user
# cannot grep it directly. Re-read via the same alpine mount used to edit it.
if on_node "$NODE" "docker run --rm \
  -v '$REMOTE_ROOT/config/redis:/mnt:ro' \
  alpine:3.19 \
  sh -c 'grep -E \"^(replicaof|REPLICAOF) \" /mnt/redis.conf'"; then
  die "redis.conf still contains a replicaof line - the promotion would not survive a restart"
fi

ok "$NODE is now a Redis primary and will stay one across restarts"
summary "Redis promoted on $NODE"
