#!/usr/bin/env bash
# One-time initialisation of the 3-member Vault Raft cluster.
# Operator-only: this handles root tokens and unseal keys, so it never runs in CI.
#
#   ./deploy/scripts/vault-cluster-init.sh --secrets prod.secrets
#
# What it does, in order:
#   1. initialises Vault on the first member (5 key shares, threshold 3)
#   2. unseals that member, waits for the other two to join through retry_join
#   3. unseals the joined members with the same keys
#   4. enables KV v2 and AppRole, writes the garde policy and role
#   5. distributes role-id / secret-id to the two application nodes
#   6. seeds secrets from the given KEY=value file
#
# Safe to re-run. Initialising is the one step that cannot be repeated, and the
# script detects that it already happened and resumes from the unseal instead.
# That matters because a run can stop halfway for reasons that say nothing about
# the cluster - a slow member, a dropped connection - and the half-configured
# state it leaves behind has no Vault in it that the app stack can use.
#
# Unseal keys and the root token are written to vault-credentials.json in the
# repository root, which is gitignored. Move it to offline storage and delete
# the local copy: losing it means losing the Vault data permanently, and
# leaving it on a laptop defeats the point of Vault.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory
need_cmd jq

[ -z "${CI:-}" ] || die "refusing to run in CI - this handles root tokens and unseal keys"

SECRETS_FILE=""; KEY_SHARES=5; KEY_THRESHOLD=3
while [ $# -gt 0 ]; do
  case "$1" in
    --secrets)   SECRETS_FILE="$2"; shift 2 ;;
    --shares)    KEY_SHARES="$2"; shift 2 ;;
    --threshold) KEY_THRESHOLD="$2"; shift 2 ;;
    -h|--help)   sed -n '2,26p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

CREDS_FILE="$REPO_ROOT/vault-credentials.json"
FIRST_NODE="$(printf '%s' "$NODES" | awk '{print $1}')"

vault_on() {
  local node="$1"; shift
  on_node "$node" "docker exec -e VAULT_ADDR=http://127.0.0.1:8200 ${VAULT_TOKEN:+-e VAULT_TOKEN=$VAULT_TOKEN} garde-vault $*"
}

# --- 1. initialise --------------------------------------------------------

step "1/6 Initialising Vault on $FIRST_NODE"
if vault_on "$FIRST_NODE" "vault status -format=json" 2>/dev/null | jq -e '.initialized == true' >/dev/null 2>&1; then
  # Resume rather than refuse. Everything from here on is idempotent, and a run
  # interrupted partway - one member slow to unseal, a dropped connection - used
  # to leave the cluster initialised but with no AppRole and no secrets, and no
  # supported way forward. Initialising is the only step that cannot be repeated,
  # and the check above is what establishes it has already happened.
  [ -f "$CREDS_FILE" ] || die "$FIRST_NODE is already initialised, but $CREDS_FILE is missing.
     Its unseal keys are the only way into this cluster. Restore that file and
     re-run. If it is gone for good, so is the data: destroy the raft volumes
     and start over with
       ./deploy/scripts/deploy.sh vault --no-ship"
  jq -e '.root_token' "$CREDS_FILE" >/dev/null 2>&1 \
    || die "$CREDS_FILE holds no root token - cannot resume with it"
  warn "already initialised - resuming from the unseal step"
else
  [ -f "$CREDS_FILE" ] && die "$CREDS_FILE already exists - refusing to overwrite existing credentials"

  # Staged through a temp file and moved into place only once it parses. Writing
  # the redirect straight to CREDS_FILE creates the file before the command runs,
  # so an init that fails for any reason leaves an empty one behind - and the
  # guard above then refuses every retry, claiming to protect credentials that do
  # not exist. The recovery for that looks alarmingly like "delete your unseal
  # keys", which is not something to ask of anyone mid-incident.
  umask 077
  CREDS_TMP="$CREDS_FILE.partial"
  trap 'rm -f "$CREDS_TMP"' EXIT

  vault_on "$FIRST_NODE" "vault operator init -key-shares=$KEY_SHARES -key-threshold=$KEY_THRESHOLD -format=json" >"$CREDS_TMP" \
    || die "vault operator init failed on $FIRST_NODE - nothing was written"
  jq -e '.root_token' "$CREDS_TMP" >/dev/null 2>&1 \
    || die "init did not return a root token - nothing was written"

  mv "$CREDS_TMP" "$CREDS_FILE"
  trap - EXIT
  chmod 600 "$CREDS_FILE"
  ok "initialised, credentials written to $CREDS_FILE"
fi

mapfile -t UNSEAL_KEYS < <(jq -r '.unseal_keys_b64[]' "$CREDS_FILE")
ROOT_TOKEN="$(jq -r '.root_token' "$CREDS_FILE")"

node_is_unsealed() {
  on_node "$1" "docker exec garde-vault vault status >/dev/null 2>&1"
}

unseal_node() {
  local node="$1" i=0
  node_is_unsealed "$node" && return 0

  while [ "$i" -lt "$KEY_THRESHOLD" ]; do
    # Errors are tolerated: a member that reached the threshold on an earlier
    # attempt answers the remaining keys with a status dump, not a failure.
    on_node "$node" "docker exec -e VAULT_ADDR=http://127.0.0.1:8200 garde-vault vault operator unseal '${UNSEAL_KEYS[$i]}' >/dev/null" || true
    i=$((i + 1))
  done

  # Unsealing finishes asynchronously. A joining member completes its raft join
  # and enters standby before it reports unsealed, which takes a second or two,
  # so checking once straight after the final key races that and calls a
  # perfectly healthy node a failure.
  retry_until 15 2 node_is_unsealed "$node"
}

# --- 2/3. unseal all members ---------------------------------------------

step "2/6 Unsealing $FIRST_NODE"
unseal_node "$FIRST_NODE" || die "could not unseal $FIRST_NODE"
ok "$FIRST_NODE unsealed and is the Raft leader"

step "3/6 Joining and unsealing the remaining members"
for node in $NODES; do
  [ "$node" = "$FIRST_NODE" ] && continue
  log "waiting for $node to reach the leader through retry_join"
  # A joined-but-sealed member reports initialized=true, sealed=true.
  if retry_until 30 4 on_node "$node" \
      "docker exec garde-vault vault status -format=json 2>/dev/null | grep -q '\"initialized\": true'"; then
    unseal_node "$node" || die "could not unseal $node"
    ok "$node joined and unsealed"
  else
    die "$node never joined the cluster - check mesh connectivity to $(node_wg_ip "$FIRST_NODE"):8200"
  fi
done

# --- 4. auth and policy ---------------------------------------------------

step "4/6 Configuring KV v2, AppRole and the garde policy"
export VAULT_TOKEN="$ROOT_TOKEN"

vault_on "$FIRST_NODE" "vault secrets enable -path=secret kv-v2" >/dev/null 2>&1 || true
vault_on "$FIRST_NODE" "vault auth enable approle" >/dev/null 2>&1 || true

on_node "$FIRST_NODE" "docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN='$ROOT_TOKEN' garde-vault \
  vault policy write garde -" <<'POLICY'
path "secret/data/garde/*" {
  capabilities = ["read"]
}
path "database/creds/garde-redis" {
  capabilities = ["read"]
}
POLICY

vault_on "$FIRST_NODE" "vault write auth/approle/role/garde token_policies=garde token_ttl=1h token_max_ttl=4h secret_id_ttl=0" >/dev/null
ok "AppRole role 'garde' created"

# --- 5. distribute AppRole credentials ------------------------------------

step "5/6 Distributing AppRole credentials to the application nodes"
role_id="$(vault_on "$FIRST_NODE" "vault read -field=role_id auth/approle/role/garde/role-id")"

for node in $NODES; do
  case "$(node_role "$node")" in
    app-primary|app-standby) ;;
    *) continue ;;
  esac
  # Each app node gets its own secret-id, so one can be revoked without
  # disturbing the other.
  secret_id="$(vault_on "$FIRST_NODE" "vault write -f -field=secret_id auth/approle/role/garde/secret-id")"
  on_node "$node" "
    mkdir -p '$REMOTE_ROOT/vault'
    printf '%s' '$role_id'   >'$REMOTE_ROOT/vault/role-id'
    printf '%s' '$secret_id' >'$REMOTE_ROOT/vault/secret-id'
    # Vault Agent runs as uid 100 in the official image. 0600 owned by deploy
    # is unreadable inside the container; the compose bind-mount cannot remap
    # ownership without a privileged helper. 0644 is acceptable: role-id is
    # not secret alone, and secret-id is host-local behind the mesh firewall.
    chmod 644 '$REMOTE_ROOT/vault/role-id' '$REMOTE_ROOT/vault/secret-id'
  "
  ok "$node has AppRole credentials"
done

# --- 6. seed secrets ------------------------------------------------------

step "6/6 Seeding secrets"
if [ -n "$SECRETS_FILE" ]; then
  [ -f "$SECRETS_FILE" ] || die "secrets file not found: $SECRETS_FILE"
  count=0
  while IFS='=' read -r key value || [ -n "$key" ]; do
    case "$key" in ''|\#*) continue ;; esac
    key="$(printf '%s' "$key" | tr -d '[:space:]')"
    value="$(printf '%s' "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [ -n "$key" ] || continue
    lower_key="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')"
    vault_on "$FIRST_NODE" "vault kv put 'secret/garde/$lower_key' value='$value'" >/dev/null
    count=$((count + 1))
  done <"$SECRETS_FILE"
  ok "seeded $count secrets"
else
  warn "no --secrets file given; seed secrets before deploying the app stack"
fi

unset VAULT_TOKEN

cat <<EOF

Cluster is initialised.

Do this now, before anything else:
  1. Move $CREDS_FILE to offline storage (password manager, encrypted backup).
  2. Delete the local copy once it is safely stored.
  3. Confirm you can read the unseal keys back - a member will need them after
     every reboot, and there is no auto-unseal in this deployment.

Values that must match this topology, in Vault:
  redis_host       = redis
  use_tls          = false          (Caddy terminates TLS)
  cookie_secure    = true
  trusted_proxies  = ${APP_NET_SUBNET:-172.28.0.0/16}
  domain_name      = ${COOKIE_DOMAIN:-<your registrable domain>}
  cors_allow_origins = https://${APP_DOMAIN:-app.example.com}

Then deploy the application stack:
  ./deploy/scripts/deploy.sh app
EOF
