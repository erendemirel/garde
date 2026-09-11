#!/usr/bin/env bash
# The private CA behind garde's service listener.
#
#   ./deploy/scripts/service-pki.sh init             # create the CA (once)
#   ./deploy/scripts/service-pki.sh server           # issue the listener cert
#   ./deploy/scripts/service-pki.sh client <name>    # issue a caller's cert
#   ./deploy/scripts/service-pki.sh push [node...]   # send CA + server cert out
#
# Why a separate CA at all. The public edge serves browsers with a publicly
# trusted certificate, and browsers must never be asked for one in return.
# Services calling /validate are the opposite case: there are few of them, you
# know all of them, and a certificate is the only credential that cannot be
# copied out of a config file and replayed from somewhere else. Mixing the two
# on one CA would mean every browser-facing certificate could also authenticate
# a service.
#
# Why not Let's Encrypt for the service listener: it is reachable only over the
# mesh, has no public name, and would fail every challenge. A private CA is
# also the only way to have client certificates at all.
#
# The CA private key never leaves the operator host. Nodes receive the CA
# certificate and their own server keypair; callers receive a client keypair.
# Keep deploy/pki/ out of version control (it already is) and back it up the
# way you back up the Vault credentials file.
#
# Client certificates must carry the deployment's domain: garde checks the CN
# (or its registrable suffix) and the SANs against DOMAIN_NAME before accepting
# a call, so a certificate from this CA issued for someone else's domain is
# still refused.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

PKI_DIR="${PKI_DIR:-$DEPLOY_DIR/pki}"
CA_DAYS="${CA_DAYS:-3650}"
LEAF_DAYS="${LEAF_DAYS:-825}"

ACTION="${1:-}"
shift || true

need_cmd openssl
load_inventory

# The name the certificates are issued under. garde compares client
# certificates against DOMAIN_NAME in Vault, and COOKIE_DOMAIN in the inventory
# is the same registrable domain.
service_domain() {
  printf '%s' "${SERVICE_CERT_DOMAIN:-${COOKIE_DOMAIN:?set COOKIE_DOMAIN in the inventory (or SERVICE_CERT_DOMAIN)}}"
}

ca_files_exist() { [ -f "$PKI_DIR/ca-cert.pem" ] && [ -f "$PKI_DIR/ca-key.pem" ]; }

require_ca() {
  ca_files_exist || die "no CA in $PKI_DIR — run: $0 init"
}

# Subject alternative names for the listener certificate. Callers dial a node's
# mesh address, so every mesh address is a valid name for it; the container
# name and localhost cover calls from the same host.
server_san_list() {
  local node sans="DNS:garde-api,DNS:localhost,IP:127.0.0.1"
  sans="$sans,DNS:garde.$(service_domain)"
  for node in $NODES; do
    local ip; ip="$(node_wg_ip "$node")"
    [ -n "$ip" ] && sans="$sans,IP:$ip"
  done
  printf '%s' "$sans"
}

case "$ACTION" in
  init)
    if ca_files_exist; then
      ok "CA already exists in $PKI_DIR (delete it deliberately to start over)"
      exit 0
    fi
    mkdir -p "$PKI_DIR"
    chmod 700 "$PKI_DIR"
    step "Creating the garde service CA in $PKI_DIR"
    openssl req -x509 -newkey rsa:4096 -sha256 -days "$CA_DAYS" -nodes \
      -keyout "$PKI_DIR/ca-key.pem" -out "$PKI_DIR/ca-cert.pem" \
      -subj "/CN=garde service CA/O=garde" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    chmod 600 "$PKI_DIR/ca-key.pem"
    ok "CA created — back up $PKI_DIR/ca-key.pem offline; it is not recoverable"
    ;;

  server)
    require_ca
    step "Issuing the service listener certificate"
    openssl req -newkey rsa:4096 -sha256 -nodes \
      -keyout "$PKI_DIR/service-key.pem" -out "$PKI_DIR/service-req.pem" \
      -subj "/CN=garde.$(service_domain)/O=garde" 2>/dev/null
    openssl x509 -req -in "$PKI_DIR/service-req.pem" -days "$LEAF_DAYS" -sha256 \
      -CA "$PKI_DIR/ca-cert.pem" -CAkey "$PKI_DIR/ca-key.pem" -CAcreateserial \
      -out "$PKI_DIR/service-cert.pem" \
      -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$(server_san_list)") 2>/dev/null
    rm -f "$PKI_DIR/service-req.pem"
    chmod 600 "$PKI_DIR/service-key.pem"
    ok "service-cert.pem / service-key.pem written to $PKI_DIR"
    log "names: $(server_san_list)"
    ;;

  client)
    require_ca
    name="${1:?usage: service-pki.sh client <service-name>}"
    step "Issuing a client certificate for $name"
    # The CN carries the domain because that is what garde validates. The
    # service's own name goes in the O field, where it shows up in logs without
    # changing the check.
    openssl req -newkey rsa:4096 -sha256 -nodes \
      -keyout "$PKI_DIR/client-$name-key.pem" -out "$PKI_DIR/client-$name-req.pem" \
      -subj "/CN=$(service_domain)/O=$name" 2>/dev/null
    openssl x509 -req -in "$PKI_DIR/client-$name-req.pem" -days "$LEAF_DAYS" -sha256 \
      -CA "$PKI_DIR/ca-cert.pem" -CAkey "$PKI_DIR/ca-key.pem" -CAcreateserial \
      -out "$PKI_DIR/client-$name-cert.pem" \
      -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:%s\n' "$(service_domain)") 2>/dev/null
    rm -f "$PKI_DIR/client-$name-req.pem"
    chmod 600 "$PKI_DIR/client-$name-key.pem"
    ok "client-$name-cert.pem / client-$name-key.pem written to $PKI_DIR"
    log "give the caller both files plus ca-cert.pem, and an API key"
    ;;

  push)
    require_ca
    [ -f "$PKI_DIR/service-cert.pem" ] || die "no listener certificate — run: $0 server"
    targets="$*"
    if [ -z "$targets" ]; then
      # Only the app nodes run garde; the witness has no service listener.
      for node in $NODES; do
        case "$(node_role "$node")" in app-primary|app-standby) targets="$targets $node" ;; esac
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
      # garde runs as UID 65532 and reads these read-only; the private key must
      # not be world-readable on the host either.
      on_node "$node" "docker run --rm -v '$REMOTE_ROOT/certs':/mnt alpine:3.19 \
        sh -c 'chown 65532:65532 /mnt/service-key.pem /mnt/service-cert.pem /mnt/ca-cert.pem && chmod 600 /mnt/service-key.pem && chmod 644 /mnt/service-cert.pem /mnt/ca-cert.pem'"
      ok "$node has the CA and its listener certificate"
    done
    summary "Service PKI pushed to:$targets"
    log "Vault must point at them:"
    log "  secret/garde/service_tls_cert_path = /app/certs/service-cert.pem"
    log "  secret/garde/service_tls_key_path  = /app/certs/service-key.pem"
    log "  secret/garde/service_tls_ca_path   = /app/certs/ca-cert.pem"
    ;;

  *)
    sed -n '2,29p' "$0"
    exit 1
    ;;
esac
