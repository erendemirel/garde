# Vault Configuration

## Table of Contents
- [Architecture](#architecture)
- [Setup](#setup)
  - [1. Configure Vault Server](#1-configure-vault-server)
  - [2. Configure AppRole Authentication](#2-configure-approle-authentication)
  - [3. Configure Vault Agent](#3-configure-vault-agent)
  - [4. Dynamic Redis Credentials (optional)](#4-optional-dynamic-redis-credentials)
- [Files](#files)
- [Single VPS production (Docker Compose)](#single-vps-production-docker-compose--ui-in-separate-container)
- [Security Notes](#security-notes)
- [Development (dev profile)](#development-profile-notes)

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

# Store application secrets: one path per key (agent writes one file per secret to /run/secrets).
# Key names are lowercase; the agent and app expect the same set as in dev.secrets / agent-config.hcl.
# Example (for the single-VPS Docker Compose stack below, use redis_host=redis to match the Compose service name):
vault kv put secret/garde/redis_host value=redis
vault kv put secret/garde/redis_port value=6379
vault kv put secret/garde/redis_password value=your-redis-password
vault kv put secret/garde/domain_name value=your-domain.com
vault kv put secret/garde/superuser_email value=admin@example.com
vault kv put secret/garde/superuser_password value=YourSecurePassword
vault kv put secret/garde/api_key value=YourApiKey20CharsMin!
# ... and other keys (see dev.secrets or Required Mandatory Secrets in docs/INSTALLATION.md).

# Optional: use dynamic Redis credentials from the database secrets engine instead of static redis_password.
# Then use templates/redis_password.tpl in the agent (see section 4 and agent-config.hcl comments).
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

### 4. (Optional) Dynamic Redis credentials

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
| `agent-config.hcl` | Vault Agent config (production): writes one file per secret to `/run/secrets` |
| `agent-config-dev.hcl` | Vault Agent config for dev profile |
| `templates/*.tpl` | Templates for secret files |
| `role-id` | AppRole role ID (DO NOT COMMIT) |
| `secret-id` | AppRole secret ID (DO NOT COMMIT) |
| `templates/redis_password.tpl` | Optional: dynamic Redis password from `database/creds/garde-redis` |
| `init-vault-prod.sh` | One-time init for single-VPS prod stack: AppRole, policy, role, seed from `prod.secrets` |

## Single VPS production (Docker Compose + UI in separate container)

Vault (dev mode), Vault Agent, Redis, garde API, and the web UI run in separate containers on one host using `docker-compose.prod.yml`. For VPS deployment steps (firewall, TLS, updates), see [Deploying to a VPS](../docs/INSTALLATION.md#deploying-to-a-vps) in the installation guide.

### Prerequisites

- Docker and Docker Compose
- A secrets file for production (e.g. copy `dev.secrets` to `prod.secrets` and set real values)

### One-time setup

1. **Create `prod.secrets`**  
   Copy `dev.secrets` to `prod.secrets` and set production values. For this stack, set `REDIS_HOST=redis` (the Compose service name). Ensure `CORS_ALLOW_ORIGINS` includes the UI origin (e.g. `http://localhost`, `https://your-ui-domain.com`).

2. **Set environment variables** (e.g. in `.env` next to `docker-compose.prod.yml`):
   - `VAULT_TOKEN` – root or admin token (for the included Vault in dev mode; use the same as `VAULT_DEV_ROOT_TOKEN_ID` if you keep the default).
   - `REDIS_PASSWORD` – same value as `REDIS_PASSWORD` in `prod.secrets` (used by the Redis container).

3. **Start Vault and run init once:**
   ```bash
   docker compose -f docker-compose.prod.yml up -d vault
   docker compose -f docker-compose.prod.yml --profile init run --rm vault-init
   ```
   This enables AppRole, creates the garde policy/role, writes `vault/role-id` and `vault/secret-id`, and seeds secrets from `prod.secrets`.

4. **Start the full stack:**
   ```bash
   docker compose -f docker-compose.prod.yml up -d --build
   ```

### Optional configuration

- **API URL for the UI**  
  If the browser will call the API at a different URL (e.g. behind a reverse proxy), set `PUBLIC_API_URL` when bringing up the stack (or in `.env`), e.g. `PUBLIC_API_URL=https://api.example.com`. The UI image is built with this value.

- **Dynamic Redis credentials**  
  To use Vault’s database engine for Redis instead of a static password, configure the database engine in Vault, then in `vault/agent-config.hcl` comment out the static `redis_password` template block and uncomment the `redis_password.tpl` block.

### Access

| Service | URL |
|---------|-----|
| UI | http://localhost:80 |
| API | http://localhost:8443 |
| Vault | http://localhost:8200 (dev mode; for production use an external Vault or harden this instance) |

## Security Notes

- `role-id` and `secret-id` files are in `.gitignore`
- Secrets are written to tmpfs
- Vault Agent auto-renews tokens
- Templates rerender when secrets rotate
- The app hot-reloads secrets (superuser/admin credentials, Redis creds) when files under `/run/secrets` change

## Development (dev profile)

- The `dev` Docker Compose profile seeds secrets from `dev.secrets`, starts Vault in dev mode, and runs Vault Agent with `agent-config-dev.hcl`.
- The agent writes one file per secret to `/run/secrets`; the app watches for changes and reconnects to Redis/reloads credentials automatically.
- Start with: `docker compose --profile dev up --build`. See [Development Installation](../docs/INSTALLATION.md#development-installation) in the installation guide.

