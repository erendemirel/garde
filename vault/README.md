# Vault Configuration

## Architecture

```
┌─────────────┐    injects       ┌─────────────┐    writes to     ┌─────────────┐    watches    ┌─────────────┐
│     CI      │ ───────────────→ │    Vault    │ ───────────────→ │   tmpfs     │ ←─────────────│    garde    │
│    /CD      │   AppRole +      │   Server    │   Vault Agent    │ /run/secrets│   file watcher│    app      │
│  Pipeline   │   Secrets        │   (dynamic   │   (auto-updates │             │   (hot reload)│   (handles  │
│             │                  │   secrets)   │   on rotation)  │             │               │   rotation) │
└─────────────┘                  └─────────────┘                  └─────────────┘               └─────────────┘
```

## Setup

### 1. Configure Vault Server

```bash
# Enable KV secrets engine
vault secrets enable -path=secret kv-v2

# Store the application secrets (static config), e.g.:
vault kv put secret/garde/tls \
  use_tls=true \
  tls_cert_path=/vault/certs/server-cert.pem \
  tls_key_path=/vault/certs/server-key.pem \
  tls_ca_path=/vault/certs/ca-cert.pem
# There are four logical secret paths:
# 1. secret/garde/config - Main app config (redis host/port, domain, superuser email/password, admin_users_json, api_key, etc.)
# 2. secret/garde/tls - TLS/mTLS settings (use_tls, cert/key/CA entries if stored here)
# 3. secret/garde/redis – optional static Redis password (only if not using dynamic creds)
# 4. database/creds/garde-redis – dynamic Redis credentials from the DB secrets engine (used by redis_password.tpl)
```

### 2. Configure AppRole Authentication

```bash
# Enable AppRole auth
vault auth enable approle

# Create policy for garde
vault policy write garde - <<EOF
path "secret/data/garde/*" {
  capabilities = ["read"]
}
path "database/creds/garde-redis" {
  capabilities = ["read"]
}
EOF

# Create AppRole
vault write auth/approle/role/garde \
  token_policies="garde" \
  token_ttl=1h \
  token_max_ttl=4h

# Get role id and secret id
vault read auth/approle/role/garde/role-id
vault write -f auth/approle/role/garde/secret-id
```

### 3. Configure Vault Agent

Save the role-id and secret-id to files:

```bash
# These files should NOT be in version control
echo "your-role-id" > vault/role-id
echo "your-secret-id" > vault/secret-id
```

### 4. (Optional) Dynamic Redis Credentials

For automatic Redis credential rotation:

```bash
# Enable database secrets engine
vault secrets enable database

# Configure Redis connection
vault write database/config/redis \
  plugin_name=redis-database-plugin \
  allowed_roles="garde-redis" \
  host=redis \
  port=6379 \
  username=default \
  password=admin-password

# Create role for garde
vault write database/roles/garde-redis \
  db_name=redis \
  creation_statements='["~*", "+@all", "-@admin"]' \
  default_ttl=1h \
  max_ttl=24h
```

## Files

| File | Purpose |
|------|---------|
| `agent-config.hcl` | Vault Agent configuration |
| `templates/*.tpl` | Templates for secret files |
| `role-id` | AppRole role ID (DO NOT COMMIT) |
| `secret-id` | AppRole secret ID (DO NOT COMMIT) |
| `templates/redis_password.tpl` | Renders dynamic Redis password from `database/creds/garde-redis` to `/run/secrets/redis_password` |
| `templates/secrets.tpl` | Renders static app config from `secret/garde/config` to `/run/secrets/static` |

## Security Notes

- `role-id` and `secret-id` files are in `.gitignore`
- Secrets are written to tmpfs
- Vault Agent auto-renews tokens
- Templates rerender when secrets rotate
- The app hot-reloads secrets (superuser/admin credentials, Redis creds) when files under `/run/secrets` change

## Development Profile Notes

- The `dev` Docker Compose profile seeds secrets from `dev.secrets`, starts Vault in dev mode, and runs Vault Agent with `vault/agent-config-dev.hcl`.
- The agent writes to `/run/secrets`; the app watches for changes and reconnects to Redis/reloads credentials automatically.

