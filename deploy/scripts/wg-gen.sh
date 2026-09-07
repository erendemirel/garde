#!/usr/bin/env bash
# Generate the WireGuard mesh: one config per node, plus CI and operator peers.
#
#   ./deploy/scripts/wg-gen.sh
#
# Output goes to deploy/.wg/ (gitignored):
#   node1.conf node2.conf node3.conf   -> installed by the Ansible bootstrap playbook
#   ci.conf                            -> store as the WG_CI_CONF GitHub secret
#   ops.conf                           -> your workstation
#   keys/                              -> private/public keys, keep offline
#
# The mesh carries all node-to-node traffic (Vault Raft, Redis replication,
# snapshot transfer) and all SSH. Nothing else should be reachable between hosts.
#
# The operator peer is not optional. Once the firewall closes public SSH, the
# mesh is the only way to reach a host, and the Ansible playbook, the unseal
# script and the Vault ceremony all run from your workstation.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

need_cmd wg
load_inventory

WG_DIR="$DEPLOY_DIR/.wg"
KEY_DIR="$WG_DIR/keys"
mkdir -p "$KEY_DIR"
chmod 700 "$WG_DIR" "$KEY_DIR"

# Where the provider brokers control-plane access, the CI runner and the
# operator do not join the mesh at all - they tunnel straight to each host - so
# there are no roaming peers to generate keys or configs for. The mesh then
# carries only node-to-node traffic.
if provider_uses_tunnel; then
  PEERS="$NODES"
  ROAMING_PEERS=""
else
  PEERS="$NODES ci ops"
  ROAMING_PEERS="ci ops"
fi

# --- keys -----------------------------------------------------------------

step "Generating keys (existing keys are kept)"
for peer in $PEERS; do
  if [ ! -f "$KEY_DIR/$peer.key" ]; then
    (umask 077; wg genkey >"$KEY_DIR/$peer.key")
    wg pubkey <"$KEY_DIR/$peer.key" >"$KEY_DIR/$peer.pub"
    ok "created keypair for $peer"
  else
    log "keeping existing keypair for $peer"
  fi
done

peer_ip() {
  case "$1" in
    ci)  printf '%s' "${CI_WG_IP:?CI_WG_IP missing from inventory}" ;;
    ops) printf '%s' "${OPS_WG_IP:?OPS_WG_IP missing from inventory}" ;;
    *)   node_wg_ip "$1" ;;
  esac
}

# The CI runner and the operator workstation both roam, so they dial in and the
# nodes only need to know their keys.
is_roaming_peer() { [ "$1" = "ci" ] || [ "$1" = "ops" ]; }

# --- node configs ---------------------------------------------------------

step "Writing node configs"
for node in $NODES; do
  conf="$WG_DIR/$node.conf"
  {
    printf '# %s (%s) - install as /etc/wireguard/wg0.conf\n' "$node" "$(node_role "$node")"
    printf '[Interface]\n'
    printf 'Address = %s/24\n' "$(peer_ip "$node")"
    printf 'ListenPort = %s\n' "${WG_PORT:-51820}"
    printf 'PrivateKey = %s\n' "$(cat "$KEY_DIR/$node.key")"
    printf 'SaveConfig = false\n'

    for other in $PEERS; do
      [ "$other" = "$node" ] && continue
      printf '\n[Peer]\n'
      printf '# %s\n' "$other"
      printf 'PublicKey = %s\n' "$(cat "$KEY_DIR/$other.pub")"
      printf 'AllowedIPs = %s/32\n' "$(peer_ip "$other")"
      if ! is_roaming_peer "$other"; then
        printf 'Endpoint = %s:%s\n' "$(node_mesh_endpoint "$other")" "${WG_PORT:-51820}"
        printf 'PersistentKeepalive = 25\n'
      fi
    done
  } >"$conf"
  chmod 600 "$conf"
  ok "$conf"
done

# --- roaming peer configs -------------------------------------------------

write_roaming_conf() {
  local peer="$1" description="$2" conf="$WG_DIR/$peer.conf"
  step "Writing $peer peer config"
  {
    printf '# %s\n' "$description"
    printf '[Interface]\n'
    printf 'Address = %s/32\n' "$(peer_ip "$peer")"
    printf 'PrivateKey = %s\n' "$(cat "$KEY_DIR/$peer.key")"

    for node in $NODES; do
      printf '\n[Peer]\n'
      printf '# %s\n' "$node"
      printf 'PublicKey = %s\n' "$(cat "$KEY_DIR/$node.pub")"
      printf 'AllowedIPs = %s/32\n' "$(node_wg_ip "$node")"
      printf 'Endpoint = %s:%s\n' "$(node_mesh_endpoint "$node")" "${WG_PORT:-51820}"
      printf 'PersistentKeepalive = 25\n'
    done
  } >"$conf"
  chmod 600 "$conf"
  ok "$conf"
}

for peer in $ROAMING_PEERS; do
  case "$peer" in
    ci)  write_roaming_conf ci  "GitHub Actions runner peer - store as the WG_CI_CONF secret" ;;
    ops) write_roaming_conf ops "Operator workstation peer - install as your local wg0.conf" ;;
  esac
done

if provider_uses_tunnel; then
  cat <<EOF

Next steps:
  1. Bootstrap the hosts (installs each node config for you):
       cd ansible && ansible-playbook playbooks/bootstrap.yml -e use_mesh=false \\
         -e deploy_pubkey_file=~/.ssh/garde_deploy.pub
  2. Keep deploy/.wg/keys/ offline. Rotating a key means regenerating every config.

No ci.conf or ops.conf: on $PROVIDER_NAME you reach the hosts through the
provider's own tunnel, not by joining the mesh. Make sure your workstation is
authenticated to $PROVIDER_NAME and can open one before you close public SSH.
EOF
else
  cat <<EOF

Next steps:
  1. Bring up your own peer, or you will lock yourself out once the firewall
     closes public SSH:
       sudo cp deploy/.wg/ops.conf /etc/wireguard/wg0.conf
       sudo wg-quick up wg0
  2. Bootstrap the hosts (installs each node config for you):
       cd ansible && ansible-playbook playbooks/bootstrap.yml -e use_mesh=false \\
         -e deploy_pubkey_file=~/.ssh/garde_deploy.pub
  3. Store deploy/.wg/ci.conf as the GitHub secret WG_CI_CONF
  4. Keep deploy/.wg/keys/ offline. Rotating a key means regenerating every config.
EOF
fi
