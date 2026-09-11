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
# Two further facts have defaults, so a driver declares them only if it differs.
# Both describe how the *control plane* reaches a host, which turned out to vary
# more than traffic routing does:
#
#   PROVIDER_ADMIN_ACCESS      mesh | tunnel     default: mesh
#   PROVIDER_IMAGE_TRANSPORT   ssh  | url        default: ssh
#
# `mesh` means the nodes carry public addresses and the control plane dials them
# over WireGuard. Every VPS provider works this way. `tunnel` means the provider
# brokers the connection to a host that has no public address at all, and the
# driver must implement:
#
#   provider_admin_host <node>            hostname to hand ssh
#   provider_admin_proxy_command <node>   ProxyCommand that reaches it
#
# `ssh` transports images by streaming `docker save` into `docker load`. `url`
# exists because the tunnels the hyperscalers provide are for administrative
# traffic and explicitly not for bulk transfer, so those drivers stage the image
# elsewhere and hand the host a short-lived URL to fetch it from:
#
#   provider_publish_image <file>         upload; echo a URL the node can GET
#
# The host never gains a credential either way, which is the property the
# original registry-free design existed to protect.

# One more fact, also defaulted, describes *what* routing traffic means on
# this provider rather than how the control plane gets in:
#
#   PROVIDER_TRAFFIC_MODES   floating_ip [managed_lb]   default: floating_ip
#
# `floating_ip` is the original model: one address, moved between hosts, and
# the standby serves the instant it lands. Every VPS provider works this way.
#
# `managed_lb` exists because AWS and GCP answer this problem natively with a
# load balancer in front of instances, and forcing the floating-IP shape onto
# them costs real machinery - hosts with no public address, tunnels, staged
# images - for a worse result. In that mode the balancer holds the public
# address and the certificate, and "route traffic to this node" means "make
# this node the registered target".
#
# The mode is chosen by TRAFFIC_MODE in the inventory, and the verbs do not
# change: traffic.sh and failover.sh call provider_route_traffic_to either way.
# Only the driver knows which mechanism is behind it.
PROVIDER_TRAFFIC_MODES_DEFAULT="floating_ip"

PROVIDER_ADMIN_ACCESS_DEFAULT="mesh"
PROVIDER_IMAGE_TRANSPORT_DEFAULT="ssh"

# Tunnelled SSH does not arrive from the mesh subnet, so the firewall has to
# admit it from somewhere else. A driver declares the range when the provider
# publishes a fixed one; otherwise ADMIN_SSH_SOURCES in the inventory supplies
# it. Empty on mesh providers, where the mesh rule already covers SSH.
PROVIDER_ADMIN_SSH_SOURCES_DEFAULT=""
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

  # Defaults first, so the driver only has to declare what differs.
  PROVIDER_ADMIN_ACCESS="$PROVIDER_ADMIN_ACCESS_DEFAULT"
  PROVIDER_IMAGE_TRANSPORT="$PROVIDER_IMAGE_TRANSPORT_DEFAULT"
  PROVIDER_ADMIN_SSH_SOURCES="$PROVIDER_ADMIN_SSH_SOURCES_DEFAULT"
  PROVIDER_TRAFFIC_MODES="$PROVIDER_TRAFFIC_MODES_DEFAULT"

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

  case "$PROVIDER_ADMIN_ACCESS" in
    mesh) ;;
    tunnel)
      for fn in provider_admin_host provider_admin_proxy_command; do
        command -v "$fn" >/dev/null 2>&1 \
          || die "driver '$name' declares tunnel access but does not implement $fn()"
      done
      [ -n "$(admin_ssh_sources)" ] || die "\
$PROVIDER_NAME reaches hosts through a tunnel, so SSH does not arrive from the
     mesh subnet and the firewall would lock it out. Set ADMIN_SSH_SOURCES in
     the inventory to the range the tunnel arrives from." ;;
    *) die "driver '$name' declares PROVIDER_ADMIN_ACCESS='$PROVIDER_ADMIN_ACCESS' (expected mesh or tunnel)" ;;
  esac

  case "$PROVIDER_IMAGE_TRANSPORT" in
    ssh) ;;
    url)
      command -v provider_publish_image >/dev/null 2>&1 \
        || die "driver '$name' declares url image transport but does not implement provider_publish_image()" ;;
    *) die "driver '$name' declares PROVIDER_IMAGE_TRANSPORT='$PROVIDER_IMAGE_TRANSPORT' (expected ssh or url)" ;;
  esac

  case " $PROVIDER_TRAFFIC_MODES " in
    *" $(traffic_mode) "*) ;;
    *) die "\
TRAFFIC_MODE='$(traffic_mode)' is not something $PROVIDER_NAME can do here.
     This driver supports: $PROVIDER_TRAFFIC_MODES
     managed_lb needs a load balancer the driver can repoint, which only the
     hyperscaler drivers have." ;;
  esac
}

# floating_ip unless the inventory says otherwise. Read through a function so
# no caller has to remember the default.
traffic_mode() { printf '%s' "${TRAFFIC_MODE:-floating_ip}"; }

# True when the control plane reaches hosts through a provider-brokered tunnel
# rather than over the WireGuard mesh.
provider_uses_tunnel() { [ "${PROVIDER_ADMIN_ACCESS:-mesh}" = "tunnel" ]; }

# The inventory wins: a driver's value is a sensible default for providers that
# publish a fixed range, not a fact the operator cannot correct.
admin_ssh_sources() {
  printf '%s' "${ADMIN_SSH_SOURCES:-${PROVIDER_ADMIN_SSH_SOURCES:-}}"
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
