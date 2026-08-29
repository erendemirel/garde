# Vault Configuration

## Table of Contents
- [Architecture](#architecture)
- [Setup](#setup)
  - [1. Configure Vault Server](#1-configure-vault-server)
  - [2. Configure AppRole Authentication](#2-configure-approle-authentication)
  - [3. Configure Vault Agent](#3-configure-vault-agent)
  - [4. Dynamic Redis Credentials (optional)](#4-optional-dynamic-redis-credentials)
- [Files](#files)
- [Single-VPS Docker Compose stack](#single-vps-docker-compose-stack)
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

This section is for **manually** configuring a Vault server (your own cluster or a self-managed instance outside Compose). Follow steps 1–3 in order; step 4 is optional (dynamic Redis).

**If you use the [Single-VPS Docker Compose stack](#single-vps-docker-compose-stack):** Vault still runs as a real server (not `-dev`). Compose provides `vault/server.hcl`, `unseal-prod.sh`, and `init-vault-prod.sh`. Follow [Deploying to a VPS](../docs/INSTALLATION.md#deploying-to-a-vps) for the operator flow (init → unseal → AppRole → agent). The manual steps below match what those scripts automate.

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
| `server.hcl` | Vault **server** config for prod Compose (file storage, non-dev mode) |
| `agent-config.hcl` | Vault Agent config (production): AppRole auth, writes secrets to `/run/secrets` |
| `agent-config-dev.hcl` | Vault Agent config for local `dev` profile (static token) |
| `templates/*.tpl` | Templates for secret files |
| `role-id` / `secret-id` | AppRole credentials written by init (DO NOT COMMIT) |
| `templates/redis_password.tpl` | Optional: dynamic Redis password from `database/creds/garde-redis` |
| `init-vault-prod.sh` | One-time AppRole + policy + seed from `prod.secrets` (requires unsealed Vault + root token) |
| `unseal-prod.sh` | Unseal helper using `vault-unseal-keys` (Compose profile `ops`) |
| `init-vault.sh` | Dev-profile seed script (Vault `-dev` only) |

## Single-VPS Docker Compose stack

`docker-compose.prod.yml` runs a **production-mode** Vault server (persistent `vault_data` volume + `server.hcl`), Vault Agent (AppRole), Redis, garde, and the web UI.

**Operator flow (summary):**

1. `up -d vault` → `vault operator init` → save `vault-credentials.json` offline  
2. Build `vault-unseal-keys` from that JSON → `--profile ops run vault-unseal`  
3. Set `VAULT_TOKEN` (root) in `.env` → `--profile init run vault-init` (AppRole + seed)  
4. `up -d --build` — Agent uses `role-id` / `secret-id`, not the root token  
5. After reboot: unseal again, then start the rest of the stack  

Full step-by-step: [Deploying to a VPS](../docs/INSTALLATION.md#deploying-to-a-vps). For an external Vault cluster instead of the Compose `vault` service, follow [Setup](#setup) above, point Agent/`VAULT_ADDR` at your cluster, and omit the Compose Vault service.

> [!NOTE]
> Dev mode (`vault server -dev`) is used only by `docker compose --profile dev`. Production Compose does not use it.
## Security Notes

- `role-id`, `secret-id`, `vault-credentials.json`, and `vault-unseal-keys` are gitignored — never commit them
- Secrets are written to tmpfs (`/run/secrets`)
- Vault Agent authenticates with AppRole and auto-renews tokens
- Templates rerender when secrets rotate
- Prod Vault listens on `127.0.0.1:8200` only in Compose; do not expose it publicly
- The app reloads the in-memory secret map when files under `/run/secrets` change. Only some keys apply live (API key, CORS, cookies, feature flags, SMTP, Redis reconnect, superuser/admin bootstrap). **TLS binding, trusted proxies, rate-limit / rapid-request thresholds, and log level require a restart.** See [Configuration hot reload](../docs/INSTALLATION.md#configuration-hot-reload).
## Development (dev profile)

- The `dev` Docker Compose profile seeds secrets from `dev.secrets`, starts Vault in dev mode, and runs Vault Agent with `agent-config-dev.hcl`.
- `init-vault.sh` writes the Vault Agent token into a shared Docker volume (`vault-agent-token`); you do **not** need a host-side `vault/dev-token` file.
- The agent writes one file per secret to `/run/secrets`; the app watches for changes and reconnects to Redis/reloads credentials as described above.
- Start with: `docker compose --profile dev up --build`. See [Development Installation](../docs/INSTALLATION.md#development-installation) in the installation guide.

