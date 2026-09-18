#!/usr/bin/env bash
# Restart garde when Vault Agent has renewed the service-listener TLS leaf.
#
# Agent writes /run/secrets/service_tls_*.pem and stamps
# /run/secrets/service_tls_renewed_at. TLS is bound at garde process start, so
# a restart is required to pick up a new leaf.
#
# Cron example (on each app node, every hour):
#   15 * * * * cd /opt/garde && ./deploy/scripts/service-tls-reload.sh
#
# Or from the operator host against inventory nodes:
#   ./deploy/scripts/service-tls-reload.sh --remote

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

REMOTE=false
[ "${1:-}" = "--remote" ] && REMOTE=true

reload_local() {
  local stamp container
  stamp="/run/secrets/service_tls_renewed_at"
  # Inside the compose project, secrets live on the app-secrets volume — check
  # via the agent or api container.
  container=""
  if docker inspect garde-api >/dev/null 2>&1; then
    container=garde-api
  elif docker inspect garde-vault-agent >/dev/null 2>&1; then
    container=garde-vault-agent
  else
    warn "no garde-api / garde-vault-agent container on this host"
    return 0
  fi

  if ! docker exec "$container" test -s /run/secrets/service_tls_renewed_at 2>/dev/null; then
    log "no service_tls_renewed_at stamp — Agent has not rendered a PKI leaf yet"
    return 0
  fi

  # Restart when the stamp is newer than the running api container's start time.
  local stamp_epoch start_epoch
  stamp_epoch="$(docker exec "$container" sh -c 'date -u -r /run/secrets/service_tls_renewed_at +%s 2>/dev/null || date -u -d "$(cat /run/secrets/service_tls_renewed_at)" +%s')"
  start_epoch="$(docker inspect -f '{{.State.StartedAt}}' garde-api 2>/dev/null | date -u -f - +%s 2>/dev/null || true)"
  if [ -z "$start_epoch" ]; then
    # Busybox/alpine date variants differ; fall back to always restart if stamp exists and --force
    if [ "${FORCE_RELOAD:-}" = "1" ]; then
      step "FORCE_RELOAD=1 — restarting garde-api"
      docker restart garde-api
      ok "garde-api restarted"
    else
      log "could not compare start time; set FORCE_RELOAD=1 to restart anyway"
    fi
    return 0
  fi

  if [ "$stamp_epoch" -gt "$start_epoch" ]; then
    step "service TLS renewed after garde start — restarting garde-api"
    docker restart garde-api
    ok "garde-api restarted to load new leaf"
  else
    ok "garde-api already running with current service TLS leaf"
  fi
}

if [ "$REMOTE" = true ]; then
  load_inventory
  for node in $NODES; do
    is_app_node "$node" || continue
    step "service-tls-reload on $node"
    on_node "$node" "cd '$REMOTE_ROOT' && FORCE_RELOAD='${FORCE_RELOAD:-}' ./deploy/scripts/service-tls-reload.sh" \
      || on_node "$node" "cd '$REMOTE_ROOT' && FORCE_RELOAD='${FORCE_RELOAD:-}' bash deploy/scripts/service-tls-reload.sh"
  done
else
  reload_local
fi
