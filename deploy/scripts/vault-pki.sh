#!/usr/bin/env bash
# Vault PKI for garde's private service listener.
#
# Replaces the openssl offline CA (service-pki.sh --offline) as the primary path:
#
#   ./deploy/scripts/vault-pki.sh enable              # once: mount engines + roles (also done by init-vault-prod)
#   ./deploy/scripts/vault-pki.sh issue-server        # optional offline/push path (Agent pkiCert is preferred)
#   ./deploy/scripts/vault-pki.sh issue-client <name> # caller cert → deploy/pki/
#   ./deploy/scripts/vault-pki.sh push [node...]      # rsync CA+server PEMs to app nodes
#   ./deploy/scripts/vault-pki.sh ca-pem              # write ca-cert.pem only
#   ./deploy/scripts/vault-pki.sh renew-hint          # print Agent renew + reload instructions
#
# Preferred automation: init-vault-prod enables PKI; Vault Agent renders and
# renews the server leaf into /run/secrets/service_tls_*.pem; cron
# deploy/scripts/service-tls-reload.sh restarts garde after renew.
# issue-client remains operator-driven (callers outside Agent).

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

PKI_DIR="${PKI_DIR:-$DEPLOY_DIR/pki}"
ROOT_PATH="${VAULT_PKI_ROOT_PATH:-pki}"
INT_PATH="${VAULT_PKI_INT_PATH:-pki_int}"
SERVER_ROLE="${VAULT_PKI_SERVER_ROLE:-garde-service}"
CLIENT_ROLE="${VAULT_PKI_CLIENT_ROLE:-garde-client}"
LEAF_TTL="${VAULT_PKI_LEAF_TTL:-7680h}" # 320d — under the 825d openssl default

ACTION="${1:-}"
shift || true

need_cmd vault
load_inventory

service_domain() {
  printf '%s' "${SERVICE_CERT_DOMAIN:-${COOKIE_DOMAIN:?set COOKIE_DOMAIN in the inventory (or SERVICE_CERT_DOMAIN)}}"
}

require_vault() {
  [ -n "${VAULT_ADDR:-}" ] || die "VAULT_ADDR is required"
  vault status >/dev/null 2>&1 || die "Vault is sealed or unreachable at $VAULT_ADDR"
}

# Subject alternative names for the listener certificate.
server_ip_sans() {
  local node ips="127.0.0.1"
  for node in $NODES; do
    local ip; ip="$(node_wg_ip "$node")"
    [ -n "$ip" ] && ips="$ips,$ip"
  done
  printf '%s' "$ips"
}

server_alt_names() {
  printf '%s' "garde-api,localhost,garde.$(service_domain)"
}

case "$ACTION" in
  enable)
    require_vault
    step "Enabling Vault PKI mounts and garde roles"
    vault secrets enable -path="$ROOT_PATH" pki 2>/dev/null || true
    vault secrets tune -max-lease-ttl=87600h "$ROOT_PATH" 2>/dev/null || true
    vault secrets enable -path="$INT_PATH" pki 2>/dev/null || true
    vault secrets tune -max-lease-ttl=43800h "$INT_PATH" 2>/dev/null || true

    # Root CA (internal). Idempotent-ish: generate only if no self-signed issuer yet.
    if ! vault read -format=json "$ROOT_PATH/cert/ca" >/dev/null 2>&1; then
      vault write -field=certificate "$ROOT_PATH/root/generate/internal" \
        common_name="garde service root" ttl=87600h \
        key_bits=4096 >/dev/null
    fi
    vault write "$ROOT_PATH/config/urls" issuing_certificates="$VAULT_ADDR/v1/$ROOT_PATH" \
      crl_distribution_points="$VAULT_ADDR/v1/$ROOT_PATH/crl" >/dev/null

    # Intermediate
    if ! vault read -format=json "$INT_PATH/cert/ca" >/dev/null 2>&1; then
      csr=$(vault write -format=json "$INT_PATH/intermediate/generate/internal" \
        common_name="garde service intermediate" ttl=43800h key_bits=4096 \
        | jq -r '.data.csr')
      cert=$(vault write -format=json "$ROOT_PATH/root/sign-intermediate" csr="$csr" \
        format=pem_bundle ttl=43800h | jq -r '.data.certificate')
      vault write "$INT_PATH/intermediate/set-signed" certificate="$cert" >/dev/null
    fi
    vault write "$INT_PATH/config/urls" issuing_certificates="$VAULT_ADDR/v1/$INT_PATH" \
      crl_distribution_points="$VAULT_ADDR/v1/$INT_PATH/crl" >/dev/null

    domain="$(service_domain)"
    vault write "$INT_PATH/roles/$SERVER_ROLE" \
      allowed_domains="$domain,garde-api,localhost" \
      allow_subdomains=true \
      allow_bare_domains=true \
      allow_localhost=true \
      allow_ip_sans=true \
      server_flag=true \
      client_flag=false \
      key_bits=4096 \
      max_ttl="$LEAF_TTL" \
      ttl="$LEAF_TTL" >/dev/null

    vault write "$INT_PATH/roles/$CLIENT_ROLE" \
      allowed_domains="$domain" \
      allow_bare_domains=true \
      allow_subdomains=false \
      server_flag=false \
      client_flag=true \
      key_bits=4096 \
      max_ttl="$LEAF_TTL" \
      ttl="$LEAF_TTL" >/dev/null

    ok "Vault PKI ready: $INT_PATH/roles/{$SERVER_ROLE,$CLIENT_ROLE}"
    log "Add pki_int/issue/* and pki_int/cert/ca to the garde AppRole policy (init-vault-prod.sh does this)."
    ;;

  issue-server)
    require_vault
    need_cmd jq
    step "Issuing service listener certificate from Vault PKI"
    domain="$(service_domain)"
    mkdir -p "$PKI_DIR"
    chmod 700 "$PKI_DIR"
    json=$(vault write -format=json "$INT_PATH/issue/$SERVER_ROLE" \
      common_name="garde.$domain" \
      alt_names="$(server_alt_names)" \
      ip_sans="$(server_ip_sans)" \
      ttl="$LEAF_TTL")
    printf '%s' "$json" | jq -r '.data.certificate' > "$PKI_DIR/service-cert.pem"
    printf '%s' "$json" | jq -r '.data.private_key' > "$PKI_DIR/service-key.pem"
    chmod 600 "$PKI_DIR/service-key.pem"
    vault read -field=certificate "$INT_PATH/cert/ca" > "$PKI_DIR/ca-cert.pem"
    chmod 644 "$PKI_DIR/ca-cert.pem" "$PKI_DIR/service-cert.pem"
    ok "service-cert.pem / service-key.pem / ca-cert.pem written to $PKI_DIR"
    log "alt_names=$(server_alt_names) ip_sans=$(server_ip_sans)"
    ;;

  issue-client)
    require_vault
    need_cmd jq
    name="${1:?usage: vault-pki.sh issue-client <service-name>}"
    step "Issuing client certificate for $name from Vault PKI"
    domain="$(service_domain)"
    json=$(vault write -format=json "$INT_PATH/issue/$CLIENT_ROLE" \
      common_name="$domain" \
      alt_names="$domain" \
      ttl="$LEAF_TTL" \
      format=pem)
    # Put O=$name into the filename; Vault role CN is the domain (mTLS SAN check).
    cert=$(printf '%s' "$json" | jq -r '.data.certificate')
    key=$(printf '%s' "$json" | jq -r '.data.private_key')
    mkdir -p "$PKI_DIR"
    printf '%s\n' "$cert" > "$PKI_DIR/client-$name-cert.pem"
    printf '%s\n' "$key" > "$PKI_DIR/client-$name-key.pem"
    chmod 600 "$PKI_DIR/client-$name-key.pem"
    vault read -field=certificate "$INT_PATH/cert/ca" > "$PKI_DIR/ca-cert.pem"
    ok "client-$name-cert.pem / client-$name-key.pem written to $PKI_DIR"
    log "give the caller both files plus ca-cert.pem, and an issued API key from POST /admin/api-keys"
    ;;

  ca-pem)
    require_vault
    mkdir -p "$PKI_DIR"
    vault read -field=certificate "$INT_PATH/cert/ca" > "$PKI_DIR/ca-cert.pem"
    chmod 644 "$PKI_DIR/ca-cert.pem"
    ok "ca-cert.pem written to $PKI_DIR"
    ;;

  push)
    [ -f "$PKI_DIR/service-cert.pem" ] || die "no listener certificate — run: $0 issue-server"
    [ -f "$PKI_DIR/ca-cert.pem" ] || die "no CA — run: $0 issue-server or $0 ca-pem"
    targets="$*"
    if [ -z "$targets" ]; then
      for node in $NODES; do
        is_app_node "$node" && targets="$targets $node"
      done
    fi
    for node in $targets; do
      require_node "$node"
      step "Pushing service PKI to $node"
      rsh="$(rsync_rsh "$node")"
      on_node "$node" "mkdir -p '$REMOTE_ROOT/certs'"
      rsync -az -e "$rsh" \
        "$PKI_DIR/ca-cert.pem" "$PKI_DIR/service-cert.pem" "$PKI_DIR/service-key.pem" \
        "$(ssh_target "$node"):$REMOTE_ROOT/certs/"
      on_node "$node" "docker run --rm -v '$REMOTE_ROOT/certs':/mnt alpine:3.19 \
        sh -c 'chown 65532:65532 /mnt/service-key.pem /mnt/service-cert.pem /mnt/ca-cert.pem && chmod 600 /mnt/service-key.pem && chmod 644 /mnt/service-cert.pem /mnt/ca-cert.pem'"
      ok "$node has the CA and its listener certificate"
    done
    summary "Service PKI pushed to:$targets"
    log "Prefer Agent-rendered paths when service_listener=true:"
    log "  secret/garde/service_tls_cert_path = /run/secrets/service_tls_cert.pem"
    log "  (push remains for offline openssl / emergency copies under /app/certs)"
    ;;

  renew-hint)
    cat <<'EOF'
Server leaf renewal is automated:
  1. Vault Agent pkiCert templates write /run/secrets/service_tls_{cert,key,ca}.pem
  2. On renew, Agent stamps /run/secrets/service_tls_renewed_at
  3. Cron or run: ./deploy/scripts/service-tls-reload.sh [--remote]

Client certificates are still issued per caller:
  ./deploy/scripts/vault-pki.sh issue-client <service-name>

Ensure Vault KV paths (set by init when service_listener=true):
  service_tls_cert_path=/run/secrets/service_tls_cert.pem
  service_tls_key_path=/run/secrets/service_tls_key.pem
  service_tls_ca_path=/run/secrets/service_tls_ca.pem

Agent env: SERVICE_CERT_DOMAIN=<domain> NODE_WG_IP=<mesh-ip>
EOF
    ;;

  *)
    sed -n '2,24p' "$0"
    exit 1
    ;;
esac
