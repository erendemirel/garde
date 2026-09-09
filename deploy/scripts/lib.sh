#!/usr/bin/env bash
# Shared helpers for the garde deploy scripts.
# Source this, do not execute it:  . "$(dirname "$0")/lib.sh"

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$DEPLOY_DIR/.." && pwd)"
INVENTORY_FILE="${INVENTORY_FILE:-$DEPLOY_DIR/inventory.env}"

# --- output ---------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  _c_red=$'\033[31m'; _c_yellow=$'\033[33m'; _c_green=$'\033[32m'
  _c_blue=$'\033[34m'; _c_reset=$'\033[0m'
else
  _c_red=""; _c_yellow=""; _c_green=""; _c_blue=""; _c_reset=""
fi

log()  { printf '%s[%s]%s %s\n' "$_c_blue"  "$(date -u +%H:%M:%S)" "$_c_reset" "$*"; }
ok()   { printf '%s  ok%s   %s\n' "$_c_green" "$_c_reset" "$*"; }
warn() { printf '%swarn%s   %s\n' "$_c_yellow" "$_c_reset" "$*" >&2; }
die()  { printf '%sfail%s   %s\n' "$_c_red" "$_c_reset" "$*" >&2; exit 1; }

step() { printf '\n%s==>%s %s\n' "$_c_blue" "$_c_reset" "$*"; }

# Print to the GitHub Actions job summary when running in CI, otherwise stdout.
summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$*" >>"$GITHUB_STEP_SUMMARY"
  else
    printf '%s\n' "$*"
  fi
}

# --- inventory ------------------------------------------------------------

load_inventory() {
  [ -f "$INVENTORY_FILE" ] || die "inventory not found: $INVENTORY_FILE (copy deploy/inventory.example.env)"

  # Carriage returns are stripped rather than tolerated. This file travels by
  # copy-paste - through an editor, through a GitHub secret - and a Windows
  # checkout stores it with CRLF endings legitimately. Sourcing that as-is is
  # worse than failing outright: a few lines error loudly while every other
  # value silently gains a trailing carriage return, so FAILOVER_IP stops
  # matching any address the provider has heard of, with nothing in any error
  # message to say why.
  #
  # Done silently and unconditionally, because on Windows there is nothing here
  # for anyone to fix.
  # shellcheck disable=SC1090
  set -a; . <(tr -d '\r' <"$INVENTORY_FILE"); set +a
  : "${NODES:?NODES missing from inventory}"
  : "${SSH_USER:?SSH_USER missing from inventory}"
  : "${REMOTE_ROOT:?REMOTE_ROOT missing from inventory}"

  # The driver decides how the control plane reaches a host, so it has to be
  # loaded before any SSH happens rather than only before a failover. Loading
  # costs nothing: credentials are checked when a verb is called, not here.
  [ -z "${PROVIDER:-}" ] || load_provider
}

# node_var node1 WG_IP  ->  value of NODE1_WG_IP
node_var() {
  local node="$1" suffix="$2" name
  name="$(printf '%s_%s' "$node" "$suffix" | tr '[:lower:]-' '[:upper:]_')"
  printf '%s' "${!name:-}"
}

node_role()      { node_var "$1" ROLE; }
node_wg_ip()     { node_var "$1" WG_IP; }
node_public_ip() { node_var "$1" PUBLIC_IP; }
node_vault_id()  { node_var "$1" VAULT_ID; }

# The address a peer dials to reach this node's WireGuard listener. Usually the
# node's public address. Where the control plane arrives through a provider
# tunnel the nodes have no public address at all and peer over the private
# network instead, which is what NODE*_MESH_ENDPOINT overrides.
node_mesh_endpoint() {
  local v; v="$(node_var "$1" MESH_ENDPOINT)"
  [ -n "$v" ] || v="$(node_public_ip "$1")"
  printf '%s' "$v"
}

# The provider's own identifier for the machine: an opaque vXXXXXXXX string on
# netcup, a numeric id on Hetzner. Only drivers should care what it looks like.
node_provider_id() { node_var "$1" PROVIDER_ID; }

# Reverse lookup, so a driver can answer "which node holds the traffic" with a
# node name instead of an id the rest of the tooling would have to decode.
node_for_provider_id() {
  local want="$1" node
  for node in $NODES; do
    if [ "$(node_provider_id "$node")" = "$want" ]; then
      printf '%s' "$node"
      return 0
    fi
  done
  return 0
}

require_node() {
  local node="$1"
  case " $NODES " in
    *" $node "*) ;;
    *) die "unknown node '$node' (known: $NODES)" ;;
  esac
}

# Resolve a role name (app-primary/app-standby/witness) to a node name.
node_with_role() {
  local want="$1" node
  for node in $NODES; do
    if [ "$(node_role "$node")" = "$want" ]; then printf '%s' "$node"; return 0; fi
  done
  return 1
}

# --- ssh ------------------------------------------------------------------

# SSH never uses a node's public address. Where that leaves it depends on how
# the provider expects a control plane to arrive:
#
#   mesh    dial the node's WireGuard address (every VPS provider)
#   tunnel  the provider brokers the connection to a host with no public
#           address, and sshd is not reachable from the internet at all
#
# Both end at the same sshd with the same key. Only the path differs.
ADMIN_SSH_CONFIG="${ADMIN_SSH_CONFIG:-$DEPLOY_DIR/.ssh-config}"

# Stable per-node name used in tunnel mode. Host keys are pinned to this rather
# than to an address, so DEPLOY_KNOWN_HOSTS survives an instance being replaced.
admin_alias() { printf 'garde-%s' "$1"; }

# A ProxyCommand contains spaces, and neither rsync's -e string nor a
# word-split option list can carry that intact. An ssh config file can, so
# tunnel mode routes everything through one.
ensure_admin_ssh_config() {
  provider_uses_tunnel || return 0
  [ "${_admin_ssh_config_written:-}" = "$ADMIN_SSH_CONFIG" ] && return 0

  local node alias
  {
    printf '# Generated by deploy/scripts/lib.sh. Do not edit.\n'
    for node in $NODES; do
      alias="$(admin_alias "$node")"
      printf '\nHost %s\n' "$alias"
      printf '  HostName %s\n' "$(provider_admin_host "$node")"
      printf '  User %s\n' "$SSH_USER"
      printf '  Port %s\n' "${SSH_PORT:-22}"
      printf '  HostKeyAlias %s\n' "$alias"
      printf '  ProxyCommand %s\n' "$(provider_admin_proxy_command "$node")"
    done

    # Multiplexing matters far more here than on a mesh provider. Opening a
    # tunnel costs a round trip to the provider's API and a second or two of
    # setup, and a failover makes a dozen sequential connections to the same
    # host - so without this the tunnel setup, not the work, would dominate the
    # time to recover. Later connections reuse the first one's tunnel.
    #
    # %C is a hash of the connection, which keeps the socket path short enough
    # for the length limit on a Unix socket.
    printf '\nHost *\n'
    printf '  ControlMaster auto\n'
    printf '  ControlPath %s/garde-cm-%%C\n' "${TMPDIR:-/tmp}"
    printf '  ControlPersist 120s\n'
  } >"$ADMIN_SSH_CONFIG"
  chmod 600 "$ADMIN_SSH_CONFIG"
  _admin_ssh_config_written="$ADMIN_SSH_CONFIG"
}

ssh_target() {
  local node="$1" host
  if provider_uses_tunnel; then
    admin_alias "$node"
    return 0
  fi
  host="$(node_wg_ip "$node")"
  [ -n "$host" ] || die "no WireGuard IP configured for $node"
  printf '%s@%s' "$SSH_USER" "$host"
}

# Populates SSH_ARGS in the caller's scope. No element contains a space, which
# is what lets rsync reuse it as a plain -e string below.
ssh_args_for() {
  local node="$1"
  if provider_uses_tunnel; then
    ensure_admin_ssh_config
    SSH_ARGS=( -F "$ADMIN_SSH_CONFIG" )
  else
    SSH_ARGS=( -p "${SSH_PORT:-22}" )
  fi
  # shellcheck disable=SC2206
  SSH_ARGS+=( ${SSH_OPTS:-} )
}

on_node() {
  local node="$1"; shift
  require_node "$node"
  local -a SSH_ARGS; ssh_args_for "$node"
  ssh "${SSH_ARGS[@]}" "$(ssh_target "$node")" "$@"
}

# Same as on_node but feeds stdin through (used by ship-image.sh).
on_node_stdin() {
  local node="$1"; shift
  require_node "$node"
  local -a SSH_ARGS; ssh_args_for "$node"
  ssh "${SSH_ARGS[@]}" "$(ssh_target "$node")" "$@"
}

rsync_to_node() {
  local node="$1" src="$2" dest="$3"
  require_node "$node"
  rsync -az --delete -e "$(rsync_rsh "$node")" "$src" "$(ssh_target "$node"):$dest"
}

# The -e value for callers that need their own rsync flags. They must use this
# rather than assembling `ssh -p ... $SSH_OPTS` themselves, or they will miss
# the tunnel config and try to dial a host alias that does not resolve.
rsync_rsh() {
  local node="$1"
  local -a SSH_ARGS; ssh_args_for "$node"
  printf 'ssh %s' "${SSH_ARGS[*]}"
}

# Run docker compose for one stack on a node.
compose_on() {
  local node="$1" stack="$2"; shift 2
  on_node "$node" "cd '$REMOTE_ROOT' && docker compose --env-file .env -f 'compose/$stack.yml' -p 'garde-$stack' $*"
}

# --- misc -----------------------------------------------------------------

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

confirm() {
  [ "${ASSUME_YES:-false}" = "true" ] && return 0
  local prompt="$1" answer
  read -r -p "$prompt [type 'yes' to continue] " answer
  [ "$answer" = "yes" ] || die "aborted"
}

# Wait until a command succeeds, or fail after N attempts.
retry_until() {
  local attempts="$1" delay="$2"; shift 2
  local i=0
  while [ "$i" -lt "$attempts" ]; do
    if "$@"; then return 0; fi
    i=$((i + 1))
    sleep "$delay"
  done
  return 1
}

# --- provider seam --------------------------------------------------------
#
# Definitions only. Scripts that talk to the hosting provider call
# load_provider() after load_inventory(), because the driver to load is named
# by the inventory.
# shellcheck disable=SC1091
. "$DEPLOY_DIR/scripts/provider.sh"
