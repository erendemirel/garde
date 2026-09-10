#!/usr/bin/env bash
# Render and push configuration to a node.
#
#   ./deploy/scripts/sync-config.sh node1
#   ./deploy/scripts/sync-config.sh --all
#
# Only small text files travel here: compose files, Caddyfile, Vault HCL,
# Prometheus config and the per-host .env. Application code never lands on a
# host — images are shipped separately by ship-image.sh.
#
# Secrets consumed from the environment (supplied by CI or your shell),
# depending on DNS_PROVIDER (defaults to PROVIDER):
#   always:     REDIS_PASSWORD, GRAFANA_ADMIN_PASSWORD
#   netcup:     NETCUP_CUSTOMER_NUMBER, NETCUP_API_KEY, NETCUP_API_PASSWORD
#   aws:        AWS_ACME_ACCESS_KEY_ID, AWS_ACME_SECRET_ACCESS_KEY
#               (plus AWS_REGION from inventory; VAULT_KMS_KEY_ID enables awskms)

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory
need_cmd rsync

TARGETS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --all) TARGETS="$NODES"; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) TARGETS="$TARGETS $1"; shift ;;
  esac
done
[ -n "${TARGETS// /}" ] || die "usage: sync-config.sh <node>... | --all"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# render <template> <output> KEY=VALUE...
render() {
  local tpl="$1" out="$2"; shift 2
  local content; content="$(cat "$tpl")"
  local pair key value
  for pair in "$@"; do
    key="${pair%%=*}"; value="${pair#*=}"
    content="${content//@@$key@@/$value}"
  done
  printf '%s\n' "$content" >"$out"
}

# Emit an optional seal stanza. AWS inventories set VAULT_KMS_KEY_ID (from
# terraform output); without it the cluster stays on Shamir.
seal_block() {
  if [ -z "${VAULT_KMS_KEY_ID:-}" ]; then
    return 0
  fi
  : "${AWS_REGION:?AWS_REGION required when VAULT_KMS_KEY_ID is set}"
  cat <<EOF
seal "awskms" {
  region     = "${AWS_REGION}"
  kms_key_id = "${VAULT_KMS_KEY_ID}"
}
EOF
}

# DNS follows the compute provider. Override with DNS_PROVIDER only when the
# zone genuinely lives somewhere else (rare; not the supported path).
dns_provider() { printf '%s' "${DNS_PROVIDER:-${PROVIDER:?PROVIDER missing from inventory}}"; }

# Emit the Caddy acme_dns block for the active DNS provider. Credentials stay
# as Caddy env placeholders; the values land in the node .env below.
acme_dns_block() {
  case "$(dns_provider)" in
    netcup)
      cat <<'EOF'
	acme_dns netcup {
		customer_number {$NETCUP_CUSTOMER_NUMBER}
		api_key {$NETCUP_API_KEY}
		api_password {$NETCUP_API_PASSWORD}
	}
EOF
      ;;
    aws)
      # Dedicated ACME IAM user (not the compute CI key). Region comes from
      # inventory / AWS_REGION so Route53 API calls land in the right place.
      cat <<'EOF'
	acme_dns route53 {
		access_key_id {$AWS_ACME_ACCESS_KEY_ID}
		secret_access_key {$AWS_ACME_SECRET_ACCESS_KEY}
		region {$AWS_REGION}
	}
EOF
      ;;
    *)
      die "DNS provider '$(dns_provider)' has no ACME DNS-01 wiring yet.
     DNS follows PROVIDER (or DNS_PROVIDER). Supported today: netcup, aws.
     To add one: compile its caddy-dns module in deploy/images/caddy/Dockerfile,
     add a branch here, pass credentials into the node .env, and add a
     terraform/<provider>/ DNS root that points app/api at FAILOVER_IP."
      ;;
  esac
}

require_dns_secrets() {
  local placeholder=false
  if printf '%s' "${API_DOMAIN:-}${APP_DOMAIN:-}" | grep -qiE 'example\.(com|org|net)'; then
    placeholder=true
  fi

  case "$(dns_provider)" in
    netcup)
      if [ -z "${NETCUP_CUSTOMER_NUMBER:-}" ] || [ -z "${NETCUP_API_KEY:-}" ] || [ -z "${NETCUP_API_PASSWORD:-}" ]; then
        if [ "$placeholder" = "true" ]; then
          warn "NETCUP_* unset; placeholder domains — DNS-01 will not issue certificates yet"
          NETCUP_CUSTOMER_NUMBER="${NETCUP_CUSTOMER_NUMBER:-0}"
          NETCUP_API_KEY="${NETCUP_API_KEY:-unused}"
          NETCUP_API_PASSWORD="${NETCUP_API_PASSWORD:-unused}"
        else
          die "NETCUP_CUSTOMER_NUMBER / NETCUP_API_KEY / NETCUP_API_PASSWORD required for DNS-01"
        fi
      fi
      ;;
    aws)
      if [ -z "${AWS_ACME_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_ACME_SECRET_ACCESS_KEY:-}" ]; then
        if [ "$placeholder" = "true" ]; then
          warn "AWS_ACME_* unset; placeholder domains — DNS-01 will not issue certificates yet"
          AWS_ACME_ACCESS_KEY_ID="${AWS_ACME_ACCESS_KEY_ID:-unused}"
          AWS_ACME_SECRET_ACCESS_KEY="${AWS_ACME_SECRET_ACCESS_KEY:-unused}"
        else
          die "AWS_ACME_ACCESS_KEY_ID / AWS_ACME_SECRET_ACCESS_KEY required for Route53 DNS-01"
        fi
      fi
      : "${AWS_REGION:?AWS_REGION required for Route53 DNS-01 (set in inventory)}"
      ;;
  esac
}

require_dns_secrets

for node in $TARGETS; do
  require_node "$node"
  role="$(node_role "$node")"
  wg_ip="$(node_wg_ip "$node")"
  vault_id="$(node_vault_id "$node")"

  step "Staging config for $node ($role)"
  rm -rf "${STAGE:?}"/*
  mkdir -p "$STAGE/compose" "$STAGE/config/vault/templates" "$STAGE/config/caddy" \
           "$STAGE/config/redis" "$STAGE/config/prometheus" "$STAGE/config/grafana"

  cp "$DEPLOY_DIR"/compose/*.yml "$STAGE/compose/"

  # Caddyfile is rendered per DNS provider so the standby renews against the
  # same API the A records live in. The ACME block is spliced in rather than
  # passed through render(): multiline values break @@KEY@@ substitution.
  {
    sed '/@@ACME_DNS_BLOCK@@/q' "$DEPLOY_DIR/config/caddy/Caddyfile.tpl" | sed '$d'
    acme_dns_block
    sed '1,/@@ACME_DNS_BLOCK@@/d' "$DEPLOY_DIR/config/caddy/Caddyfile.tpl"
  } >"$STAGE/config/caddy/Caddyfile"

  # --- Vault Raft config: peers are every other node -----------------------
  retry_join=""
  for peer in $NODES; do
    [ "$peer" = "$node" ] && continue
    retry_join="${retry_join}  retry_join {
    leader_api_addr = \"http://$(node_wg_ip "$peer"):8200\"
  }
"
  done
  # SEAL_BLOCK is spliced (not passed through render) so newlines stay intact.
  {
    sed '/@@SEAL_BLOCK@@/q' "$DEPLOY_DIR/config/vault/raft.hcl.tpl" | sed '$d'
    seal_block
    sed '1,/@@SEAL_BLOCK@@/d' "$DEPLOY_DIR/config/vault/raft.hcl.tpl"
  } >"$STAGE/config/vault/raft.hcl.partial"
  render "$STAGE/config/vault/raft.hcl.partial" "$STAGE/config/vault/raft.hcl" \
    "VAULT_NODE_ID=$vault_id" "NODE_WG_IP=$wg_ip" "RETRY_JOIN=${retry_join%$'\n'}"
  rm -f "$STAGE/config/vault/raft.hcl.partial"

  # The Vault Agent config is shared with the single-host stack; the agent
  # reaches its own node's Raft member through an extra_hosts entry.
  cp "$REPO_ROOT/vault/agent-config.hcl" "$STAGE/config/vault/agent-config.hcl"
  cp "$REPO_ROOT"/vault/templates/*.tpl "$STAGE/config/vault/templates/" 2>/dev/null || true

  # --- Prometheus (witness only) -------------------------------------------
  if [ "$role" = "witness" ]; then
    node_targets=""; cadvisor_targets=""; vault_targets=""
    for peer in $NODES; do
      peer_ip="$(node_wg_ip "$peer")"
      node_targets="${node_targets}      - targets: [\"$peer_ip:9100\"]
        labels: {node: \"$peer\", role: \"$(node_role "$peer")\"}
"
      cadvisor_targets="${cadvisor_targets}      - targets: [\"$peer_ip:8080\"]
        labels: {node: \"$peer\"}
"
      vault_targets="${vault_targets}      - targets: [\"$peer_ip:8200\"]
        labels: {node: \"$peer\", vault_id: \"$(node_vault_id "$peer")\"}
"
    done
    render "$DEPLOY_DIR/config/prometheus/prometheus.yml.tpl" "$STAGE/config/prometheus/prometheus.yml" \
      "NODE_EXPORTER_TARGETS=${node_targets%$'\n'}" \
      "CADVISOR_TARGETS=${cadvisor_targets%$'\n'}" \
      "VAULT_TARGETS=${vault_targets%$'\n'}"
    cp "$DEPLOY_DIR/config/prometheus/alerts.yml" "$STAGE/config/prometheus/"
    cp "$DEPLOY_DIR/config/grafana/datasources.yml" "$STAGE/config/grafana/"
  fi

  # --- per-host .env --------------------------------------------------------
  {
    printf '# Generated by sync-config.sh for %s (%s). Do not edit by hand.\n' "$node" "$role"
    printf 'NODE_NAME=%s\n' "$node"
    printf 'NODE_ROLE=%s\n' "$role"
    printf 'NODE_WG_IP=%s\n' "$wg_ip"
    printf 'VAULT_NODE_ID=%s\n' "$vault_id"
    printf 'GARDE_IMAGE=%s\n' "${GARDE_IMAGE:-garde/api}"
    printf 'UI_IMAGE=%s\n' "${UI_IMAGE:-garde/ui}"
    printf 'CADDY_IMAGE=%s\n' "${CADDY_IMAGE:-garde/caddy}"
    printf 'IMAGE_TAG=%s\n' "${IMAGE_TAG:-latest}"
    printf 'APP_NET_SUBNET=%s\n' "${APP_NET_SUBNET:-172.28.0.0/16}"
    printf 'APP_DOMAIN=%s\n' "${APP_DOMAIN:-}"
    printf 'API_DOMAIN=%s\n' "${API_DOMAIN:-}"
    printf 'ACME_EMAIL=%s\n' "${ACME_EMAIL:-}"
    printf 'REDIS_PASSWORD=%s\n' "${REDIS_PASSWORD:-}"
    printf 'GRAFANA_ADMIN_PASSWORD=%s\n' "${GRAFANA_ADMIN_PASSWORD:-}"
    printf 'DNS_PROVIDER=%s\n' "$(dns_provider)"
    # Vault awskms and the AWS provider both need a region in the host .env
    # (compose passes AWS_REGION into the Vault container).
    if [ -n "${VAULT_KMS_KEY_ID:-}" ] || [ "${PROVIDER}" = "aws" ]; then
      : "${AWS_REGION:?AWS_REGION required for PROVIDER=aws or VAULT_KMS_KEY_ID}"
      printf 'AWS_REGION=%s\n' "${AWS_REGION}"
    fi
    [ -n "${VAULT_KMS_KEY_ID:-}" ] && printf 'VAULT_KMS_KEY_ID=%s\n' "${VAULT_KMS_KEY_ID}"
    case "$(dns_provider)" in
      netcup)
        printf 'NETCUP_CUSTOMER_NUMBER=%s\n' "${NETCUP_CUSTOMER_NUMBER}"
        printf 'NETCUP_API_KEY=%s\n' "${NETCUP_API_KEY}"
        printf 'NETCUP_API_PASSWORD=%s\n' "${NETCUP_API_PASSWORD}"
        ;;
      aws)
        printf 'AWS_ACME_ACCESS_KEY_ID=%s\n' "${AWS_ACME_ACCESS_KEY_ID}"
        printf 'AWS_ACME_SECRET_ACCESS_KEY=%s\n' "${AWS_ACME_SECRET_ACCESS_KEY}"
        # Region already emitted when PROVIDER=aws or VAULT_KMS_KEY_ID is set.
        if [ "${PROVIDER}" != "aws" ] && [ -z "${VAULT_KMS_KEY_ID:-}" ]; then
          : "${AWS_REGION:?AWS_REGION required for Route53 DNS-01}"
          printf 'AWS_REGION=%s\n' "${AWS_REGION}"
        fi
        ;;
    esac
  } >"$STAGE/.env"
  chmod 600 "$STAGE/.env"

  step "Pushing config to $node"
  # --delete would remove host-owned state (vault/role-id, data/), so the sync
  # is additive and scoped to the directories this script owns.
  rsh="$(rsync_rsh "$node")"
  rsync -az -e "$rsh" --delete \
    "$STAGE/compose/" "$(ssh_target "$node"):$REMOTE_ROOT/compose/"
  rsync -az -e "$rsh" \
    "$STAGE/config/" "$(ssh_target "$node"):$REMOTE_ROOT/config/"
  rsync -az -e "$rsh" \
    "$STAGE/.env" "$(ssh_target "$node"):$REMOTE_ROOT/.env"

  on_node "$node" "chmod 600 '$REMOTE_ROOT/.env' && mkdir -p '$REMOTE_ROOT/vault' '$REMOTE_ROOT/data' '$REMOTE_ROOT/backup' '$REMOTE_ROOT/certs' '$REMOTE_ROOT/configs'"
  # API runs as UID 65532; bind-mounted data/ must be writable by that user.
  on_node "$node" "docker run --rm -v '$REMOTE_ROOT/data:/data' alpine:3.19 \
    sh -c 'chown -R 65532:65532 /data && chmod 755 /data'"

  # --- Redis config: created once, then owned by Redis ---------------------
  if [ "$role" = "app-primary" ] || [ "$role" = "app-standby" ]; then
    : "${REDIS_PASSWORD:?REDIS_PASSWORD must be set to render redis.conf}"
    if on_node "$node" "test -f '$REMOTE_ROOT/config/redis/redis.conf'"; then
      log "redis.conf already exists on $node, leaving it alone"
      log "  (it records the current primary/replica state; failover rewrites it)"
    else
      replicaof=""
      if [ "$role" = "app-standby" ]; then
        primary_ip="$(node_wg_ip "${PRIMARY_NODE:?PRIMARY_NODE missing from inventory}")"
        replicaof="replicaof $primary_ip 6379"
      fi
      render "$DEPLOY_DIR/config/redis/redis.conf.tpl" "$STAGE/redis.conf" \
        "REDIS_PASSWORD=$REDIS_PASSWORD" "REPLICAOF=$replicaof"
      rsync -az -e "$(rsync_rsh "$node")" \
        "$STAGE/redis.conf" "$(ssh_target "$node"):$REMOTE_ROOT/config/redis/redis.conf"
      # uid 999 is the redis user in the official image, and it must be able to
      # rewrite this file during failover. The deploy user is not root, so the
      # ownership change runs in a throwaway container via the docker socket.
      on_node "$node" "docker run --rm -v '$REMOTE_ROOT/config/redis':/mnt alpine:3.19 \
        sh -c 'chown 999:999 /mnt/redis.conf && chmod 640 /mnt/redis.conf'"
      ok "rendered redis.conf on $node ($([ -n "$replicaof" ] && echo replica || echo primary))"
    fi
  fi

  ok "$node config synced (DNS=$(dns_provider))"
done

if [ -n "${VAULT_KMS_KEY_ID:-}" ]; then
  warn "VAULT_KMS_KEY_ID is set — raft.hcl now has seal awskms."
  warn "Do not restart Vault until vault-seal-migrate.sh (existing Shamir) or vault-cluster-init.sh (fresh) has run."
fi
