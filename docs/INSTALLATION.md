# Installation Guide

## Table of Contents
- [Development Installation](#development-installation)
- [Production Installation](#production-installation)
  - [Deploying to a VPS](#deploying-to-a-vps)
  - [Required mandatory secrets](#required-mandatory-secrets-in-vault)
  - [TLS and mTLS](#tls-and-mtls-configuration)
  - [Additional configuration (optional)](#additional-production-configuration-optional)
  - [Web UI](#web-ui-production)
- [Verifying Installation](#verifying-installation)
- [Vault Guide](#vault-guide)
- [Detailed Integration Guide For Service Integrations](#detailed-integration-guide-for-service-integrations)

## Development Installation

### Prerequisites
- Docker & Docker Compose (17.06+ and v2.0+)

### Steps
1. **Clone the repository**
   ```bash
   git clone https://github.com/erendemirel/garde.git
   cd garde
   ```

2. **Review development configuration (Optional)**
   - There are two types of things to configure: secrets, permissions, and groups. On dev, secrets are managed via `dev.secrets` (already populated with defaults); permissions and groups use a built-in SQLite database and require no configuration.
   - Modify as needed for your environment. The easiest way to learn about secrets and permission system is:
       - **For secrets:** Following the comments inside `dev.secrets` file,  
       - **For permission and group system:** Following [Permission and Group Management](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md#5-permission-and-group-management) section in integration guide to understand how they work. You can also have a look at this section in [Key Concepts](https://github.com/erendemirel/garde/tree/master?tab=readme-ov-file#security-without-role-paradoxes) to have the bigger picture.

3. **Start the development stack**
   ```bash
   docker compose --profile dev up --build
   ```

4. **Access the application**
   - API: `http://localhost:8443`
   - Swagger docs: `http://localhost:8443/swagger/index.html`

5. **Web UI (Optional)**   

   - Navigate to `web/` directory and run `bun start` (or `npm start`). No configuration needed, everything is set up. It automatically proxies `/api` requests to `http://localhost:8443` via Vite dev server.

### What happens automatically
- Vault starts in development mode
- Secrets from `dev.secrets` are seeded into Vault
- Vault Agent writes secrets to tmpfs (`/run/secrets`)
- Application reads secrets and connects to Redis
- Configuration hot-reload is automatically enabled

---

## Production Installation

### Prerequisites
- HashiCorp Vault
- Redis
- Docker & Docker Compose
- TLS certificates (for mTLS)

### Deployment paths

**If you run Vault and Redis yourself** (e.g. external or self-managed cluster), use this path:

1. **Setup Vault cluster** with AppRole authentication. See [Vault Guide – Manual setup](https://github.com/erendemirel/garde/blob/master/vault/README.md#setup) (follow steps 1–3 in that doc; step 4 is optional).
2. **Setup Redis**
3. **Configure TLS and mTLS** (see [TLS and mTLS](#tls-and-mtls-configuration) below).
4. **Deploy** using docker-compose or your orchestrator.

**If you use the single-VPS Docker Compose stack** below, you do not perform step 1 manually—the one-time init does Vault setup for you. Go to [Deploying to a VPS](#deploying-to-a-vps).

**Single VPS with Docker Compose:** A supported production pattern is running everything on one host with Docker Compose (Vault, Agent, Redis, garde, and the web UI in separate containers). The stack is defined in `docker-compose.prod.yml`. The steps below are the full flow: prerequisites, secrets, one-time Vault init, starting the stack, then VPS hardening and ongoing ops. For Vault/Agent details (init script, agent config), see [vault/README.md](https://github.com/erendemirel/garde/blob/master/vault/README.md).

### Deploying to a VPS

1. **Provision the VPS** (Ubuntu 24.04 or similar). Install Docker and Docker Compose:
   ```bash
   apt update && apt install -y docker.io docker-compose-v2
   systemctl enable --now docker
   ```

2. **Get the project** on the VPS (clone the repo or copy files, e.g. with `rsync` or `scp`).

3. **Create `prod.secrets`** (copy from `dev.secrets`, set production values). For the single-VPS Docker Compose stack, set `REDIS_HOST=redis` (the Compose service name). Set `CORS_ALLOW_ORIGINS` to the URL users will use for the UI (e.g. `https://auth.yourdomain.com` or `http://<VPS_IP>`). Create a `.env` in the project root with `VAULT_TOKEN` (same as `VAULT_DEV_ROOT_TOKEN_ID` if using the default), `REDIS_PASSWORD` (same as in `prod.secrets`), and optionally `PUBLIC_API_URL` if the API will be at a different URL (e.g. behind a reverse proxy).

4. **One-time Vault init, then start the stack:**
   ```bash
   docker compose -f docker-compose.prod.yml up -d vault
   docker compose -f docker-compose.prod.yml --profile init run --rm vault-init
   docker compose -f docker-compose.prod.yml up -d --build
   ```
   The init step enables AppRole, creates the garde policy/role, writes `vault/role-id` and `vault/secret-id`, and seeds secrets from `prod.secrets`. Do not commit those files.

5. **Firewall:** Allow SSH (22), UI (80 or 443), and API (8443) as needed. Do not expose Vault (8200) to the internet.

6. **TLS (recommended):** Put a reverse proxy (e.g. Caddy or nginx) in front; terminate TLS and proxy to the UI and API containers. Set `PUBLIC_API_URL` and `CORS_ALLOW_ORIGINS` to your public URLs and rebuild the UI container.

**Ongoing operations** (single-VPS stack):

- **Updates:** Pull (or rsync) the latest code, then run `docker compose -f docker-compose.prod.yml up -d --build`.
- **Logs:** `docker compose -f docker-compose.prod.yml logs -f garde` (or `ui`, `vault-agent`, etc.).
- **Restarts:** `docker compose -f docker-compose.prod.yml restart garde` (or another service name).

### Required mandatory secrets in Vault
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/redis_host` | Redis server hostname (for single-VPS Docker Compose: use `redis`, the Compose service name) |
| `secret/garde/redis_port` | Redis server port |
| `secret/garde/redis_password` | Redis authentication password |
| `secret/garde/domain_name` | Your domain (for cookies and TLS) |
| `secret/garde/superuser_email` | Superuser account email (The user is auto-created) |
| `secret/garde/superuser_password` | Superuser password (The user is auto-created) |
| `secret/garde/api_key` | API key (20+ chars, mixed case/symbols) |

### TLS and mTLS configuration

**Server TLS (required for mTLS):**
- Valid TLS certificate from trusted CA
- Certificate chain with intermediate certificates
- SAN including all domain variants

**Required Vault secrets:**
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/use_tls` | Set to `true` |
| `secret/garde/tls_cert_path` | Path to server certificate |
| `secret/garde/tls_key_path` | Path to server private key |
| `secret/garde/tls_ca_path` | Path to client CA certificate |

> [!IMPORTANT]
> Built-in TLS must be enabled for mTLS and API-key authentication to work. Without TLS, or your own TLS, only basic authentication is available.

### Additional production configuration (optional)

**Email/SMTP** (for password reset, MFA):
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/smtp_host` | SMTP server hostname |
| `secret/garde/smtp_port` | SMTP server port |
| `secret/garde/smtp_user` | SMTP authentication username |
| `secret/garde/smtp_password` | SMTP authentication password |
| `secret/garde/smtp_from` | Sender email address |

> [!WARNING]
> Without sending emails, garde cannot reset users' passwords.

**Security & Behavior Settings**:
| Vault Secret Path | Description |
|-------------------|-------------|
| `secret/garde/cors_allow_origins` | Allowed CORS origins (comma-separated) |
| `secret/garde/enforce_mfa` | Enforce MFA for all users |
| `secret/garde/rate_limit` | IP-based rate limiting: `public_limit,window_seconds[,authenticated_limit[,admin_limit]]` (e.g., `100,60,200,500` = 100 req/60s public, 200 authenticated, 500 admin). Use `0,0` to disable. |
| `secret/garde/rapid_request_config` | User-based rapid request detection for authenticated endpoints with role-aware thresholds: `max_per_min,min_interval_ms` (e.g., `120,10` means 120 requests per minute with 10ms minimum interval). Admins get 3x threshold, superusers get 5x threshold. Use `0,0` to disable. |
| `secret/garde/disable_user_agent_check` | Disable UA validation |
| `secret/garde/disable_ip_blacklisting` | Disable automatic IP blocking |
| `secret/garde/disable_multiple_ip_check` | Disable concurrent session IP detection |
| `secret/garde/cookie_same_site` | Session cookie SameSite: `lax` (default), `strict`, or `none`. Default `lax` so cookie based auth works when UI and API are on different origins(e.g. dev). Use `strict` when UI and API are same-origin. |
| `secret/garde/testing_mode` | Set to `true` to relax mTLS checks (e.g. for testing). Do not use in production. |

**Admin Configuration**:
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/admin_users_json` | JSON object: `{"admin1@example.com":"Pass1!","admin2@example.com":"Pass2!"}`. Admins are auto-created/updated at startup and on secret reload. Public/admin-created signup cannot create these accounts. |

**Permissions & Groups**:
- Permissions and groups are managed via SQLite database.
- The database is stored at `data/permissions.db` and is automatically created on first run.
- **Database Schema:**
  - `permissions` table: `id` (INTEGER PRIMARY KEY AUTOINCREMENT), `name` (TEXT NOT NULL UNIQUE), `definition` (TEXT NOT NULL)
  - `groups` table: `id` (INTEGER PRIMARY KEY AUTOINCREMENT), `name` (TEXT NOT NULL UNIQUE), `definition` (TEXT NOT NULL)
  - `permission_visibility` table: `permission_id` (INTEGER NOT NULL), `group_id` (INTEGER NOT NULL), PRIMARY KEY (permission_id, group_id) with FOREIGN KEY constraints
- Superusers can manage permissions, groups, and visibility mappings via API endpoints (see [Superuser-Only Permission and Group Management](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md#f-superuser-only-permission-and-group-management) in the integration guide).
- See [Permission and Group Management](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md#5-permission-and-group-management) for detailed information.

> [!TIP]
> The built-in SQLite database doesn't require any configuration or infrastructure.

**Logging:** `secret/garde/log_level` (DEBUG/INFO/WARN/ERROR), `secret/garde/gin_mode` (debug/release)

### Web UI (production)

- **Single VPS (Docker Compose):** The UI runs in the `ui` container; set `PUBLIC_API_URL` and `CORS_ALLOW_ORIGINS` as described in [Single VPS production](https://github.com/erendemirel/garde/blob/master/vault/README.md#single-vps-production-docker-compose--ui-in-separate-container).
- **Other deployments:** Build the UI with the API URL, then serve the built files yourself (e.g. nginx, CDN). Set `PUBLIC_API_URL` at build time:
  ```bash
  export PUBLIC_API_URL=https://your-api-domain.com
  cd web && npm run build
  ```
  Or add `PUBLIC_API_URL=https://your-api-domain.com` to a `.env` file in `web/` before building.

---

## Verifying Installation

Try a login after the stack is up:

```bash
# With TLS (replace with your domain):
curl -X POST https://your-domain/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"your_superuser_email\",\"password\":\"your_superuser_password\"}"

# Without TLS (e.g. single-VPS stack or dev):
curl -X POST http://localhost:8443/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"your_superuser_email\",\"password\":\"your_superuser_password\"}"
```

---

## Vault Guide

See [Vault Guide](https://github.com/erendemirel/garde/blob/master/vault/README.md)

---

## Detailed Integration Guide For Service Integrations

See the [Integration Guide](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md)
