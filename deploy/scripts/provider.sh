#!/usr/bin/env bash
# The hosting-provider seam. Sourced by lib.sh; do not execute.
#
# Everything provider-specific in this deployment reaches the outside world
# through three verbs and five declared facts. Nothing outside
# deploy/scripts/providers/ names a provider.
#
# The verbs are intent, not mechanism:
#
#   provider_route_traffic_to <node>   make public traffic arrive at this node
#   provider_traffic_location          which node is it arriving at now?
#   provider_set_power <node> <state>  off | on | reset
#
# "Route traffic" rather than "assign the failover IP" on purpose. A floating
# IP is how netcup and Hetzner do it, but a provider without one would swap a
# DNS record and a provider with a load balancer would change its backend pool.
# Naming the intent keeps those implementable; naming the mechanism would not.
#
# The declared facts exist because providers differ in properties, not only in
# behaviour, and a property expressed as a function is a property you end up
# branching on:
#
#   PROVIDER_NAME                          human-readable, for messages
#   PROVIDER_CREDENTIALS                   env var names the driver needs
#   PROVIDER_TRAFFIC_COOLDOWN_SECONDS      enforced wait between two moves
#   PROVIDER_TRAFFIC_PROPAGATION_SECONDS   how long a move takes to take effect
#   PROVIDER_REQUIRES_IP_BINDING           must the host configure the address?
#
# Because those are data, failover.sh contains no provider conditionals at all:
# a provider with no cooldown declares 0 and the same wait logic does nothing.
#
# Policy stays here and in the callers, never in a driver. Ordering, fencing,
# verification and the cooldown wait are identical whoever the host is; a driver
# that made those decisions would give you subtly different failover behaviour
# per provider, discoverable only during an incident.

PROVIDER_DIR="$DEPLOY_DIR/scripts/providers"
TRAFFIC_STATE_FILE="${TRAFFIC_STATE_FILE:-$DEPLOY_DIR/.traffic-last-move}"

PROVIDER_REQUIRED_FUNCTIONS="provider_route_traffic_to provider_traffic_location provider_set_power provider_preflight"
PROVIDER_REQUIRED_FACTS="PROVIDER_NAME PROVIDER_CREDENTIALS PROVIDER_TRAFFIC_COOLDOWN_SECONDS PROVIDER_TRAFFIC_PROPAGATION_SECONDS PROVIDER_REQUIRES_IP_BINDING"

available_providers() {
  local f
  for f in "$PROVIDER_DIR"/*.sh; do
    [ -e "$f" ] || continue
    printf '%s ' "$(basename "$f" .sh)"
  done
}

# Load the driver named by PROVIDER and verify it honours the contract.
# Call after load_inventory.
load_provider() {
  local name="${PROVIDER:-}" file fn fact
  [ -n "$name" ] || die "PROVIDER is not set in the inventory (available: $(available_providers))"

  file="$PROVIDER_DIR/$name.sh"
  [ -f "$file" ] || die "no driver for provider '$name' (available: $(available_providers))"

  # shellcheck disable=SC1090
  . "$file"

  # Checked rather than assumed: a driver that half-implements the contract
  # should fail at load, not two steps into a failover.
  for fn in $PROVIDER_REQUIRED_FUNCTIONS; do
    command -v "$fn" >/dev/null 2>&1 || die "driver '$name' does not implement $fn()"
  done
  for fact in $PROVIDER_REQUIRED_FACTS; do
    [ -n "${!fact+set}" ] || die "driver '$name' does not declare $fact"
  done
}

# Credentials are checked only when a driver is about to be used, so that
# read-only commands and dry runs work without them.
provider_require_credentials() {
  local var missing=""
  for var in $PROVIDER_CREDENTIALS; do
    [ -n "${!var:-}" ] || missing="$missing $var"
  done
  [ -z "$missing" ] || die "$PROVIDER_NAME needs these environment variables:$missing"
}

# --- traffic cooldown ------------------------------------------------------
#
# Generic, driven by the declared fact. The inventory may raise it but the
# driver's value is the floor of what the provider will actually accept.

traffic_cooldown_seconds() {
  local declared="$PROVIDER_TRAFFIC_COOLDOWN_SECONDS"
  local configured="${FAILOVER_IP_COOLDOWN_SECONDS:-$declared}"
  if [ "$configured" -lt "$declared" ]; then printf '%s' "$declared"
  else printf '%s' "$configured"; fi
}

traffic_cooldown_remaining() {
  local cooldown last now remaining
  cooldown="$(traffic_cooldown_seconds)"
  { [ "$cooldown" -gt 0 ] && [ -f "$TRAFFIC_STATE_FILE" ]; } || { printf '0'; return; }
  last="$(cat "$TRAFFIC_STATE_FILE" 2>/dev/null || echo 0)"
  now="$(date +%s)"
  remaining=$(( cooldown - (now - last) ))
  if [ "$remaining" -gt 0 ]; then printf '%s' "$remaining"; else printf '0'; fi
}

enforce_traffic_cooldown() {
  local remaining; remaining="$(traffic_cooldown_remaining)"
  [ "$remaining" -eq 0 ] || die "$PROVIDER_NAME rate limit: ${remaining}s left before traffic can be moved again.
     Waiting is mandatory - an early attempt is rejected, and a rejected call
     mid-failover is worse than the wait."
}

record_traffic_move() { date +%s >"$TRAFFIC_STATE_FILE"; }
