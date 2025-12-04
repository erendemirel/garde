# Vault Configuration

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────┐
│   Vault     │ ──→ │ Vault Agent │ ──→ │   tmpfs     │ ──→ │  garde  │
│   Server    │     │  (sidecar)  │     │ /run/secrets│     │   app   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────┘
```

## Setup

### 1. Configure Vault Server

```bash
# Enable KV secrets engine
vault secrets enable -path=secret kv-v2

# Store the secrets
vault kv put secret/garde/config \
  redis_host=redis \
  redis_port=6379 \
  domain_name=localhost \
  superuser_email=admin@example.com \
  api_key=YourapiKey123!

vault kv put secret/garde/redis \
  password=your-redis-password

# And others..
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

## Security Notes

- `role-id` and `secret-id` files are in `.gitignore`
- Secrets are written to tmpfs
- Vault Agent auto-renews tokens
- Templates rerender when secrets rotate

