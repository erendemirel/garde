# Installation Guide

## Table of Contents
- [Development Installation](#development-installation)
- [Production Installation](#production-installation)
- [Verifying Installation](#verifying-installation)
- [Vault Guide](#vault-guide)
- [Detailed Integration Guide For Service Integrations](#detailed-integration-guide-for-service-integrations)

## Development Installation

#### Prerequisites
- Docker & Docker Compose (17.06+ and v2.0+)

#### Steps
1. **Clone the repository**
   ```bash
   git clone https://github.com/erendemirel/garde.git
   cd garde
   ```

2. **Review development configuration (Optional)**
   - There are two types of things to configure. Secrets, permissions and groups. On dev, secrets are managed via `dev.secrets` file which is already populated with default values, permissions and groups are managed via an built-in SQLLite database, and requires no configuration.
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

#### What happens automatically
- Vault starts in development mode
- Secrets from `dev.secrets` are seeded into Vault
- Vault Agent writes secrets to tmpfs (`/run/secrets`)
- Application reads secrets and connects to Redis
- Configuration hot-reload is automatically enabled

---

## Production Installation

#### Prerequisites
- HashiCorp Vault
- Redis
- Docker & Docker Compose
- TLS certificates (for mTLS)

#### Production Configuration Steps
1. **Setup Vault cluster** with AppRole authentication. See [Vault Guide](https://github.com/erendemirel/garde/blob/master/vault/README.md)
2. **Setup Redis**
3. **Configure TLS and mTLS** (see below)
4. **Deploy using docker-compose** or your orchestrator

#### Required Mandatory Secrets in Vault
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/redis_host` | Redis server hostname |
| `secret/garde/redis_port` | Redis server port |
| `secret/garde/redis_password` | Redis authentication password |
| `secret/garde/domain_name` | Your domain (for cookies and TLS) |
| `secret/garde/superuser_email` | Superuser account email (The user is auto-created) |
| `secret/garde/superuser_password` | Superuser password (The user is auto-created) |
| `secret/garde/api_key` | API key (20+ chars, mixed case/symbols) |

#### TLS and mTLS Configuration
**Server TLS (Required for mTLS):**
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
| `secret/garde/api_key` | API key for mTLS authentication |

> [!IMPORTANT]
> Built-in TLS must be enabled for mTLS and API-key authentication to work. Without TLS, or your own TLS, only basic authentication is available.

#### Additional Production Configuration
**Email/SMTP Configuration** (for password reset, MFA):
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
| `secret/garde/rate_limit` | IP-based rate limiting for public/unauthenticated endpoints: `limit,interval_seconds` (e.g., `100,60` means 100 requests per 60 seconds). Use `0,0` to disable. |
| `secret/garde/rapid_request_config` | User-based rapid request detection for authenticated endpoints with role-aware thresholds: `max_per_min,min_interval_ms` (e.g., `120,10` means 120 requests per minute with 10ms minimum interval). Admins get 3x threshold, superusers get 5x threshold. Use `0,0` to disable. |
| `secret/garde/disable_user_agent_check` | Disable UA validation |
| `secret/garde/disable_ip_blacklisting` | Disable automatic IP blocking |
| `secret/garde/disable_multiple_ip_check` | Disable concurrent session IP detection |

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
> The in-built SQLLite database doesn't require any configuration or infrastructure

**Other Production Configuration**
- Logging: `secret/garde/log_level` (DEBUG/INFO/WARN/ERROR), `secret/garde/gin_mode` (debug/release)

#### Web UI (Optional)   

Navigate to `web/` directory and run `bun start` or `npm start` (requires Bun or npm). It requires **no secrets, config files, or backend specific setup**. It only needs the API URL at build time:

   - Set `PUBLIC_API_URL` environment variable at build time:
       ```bash
       export PUBLIC_API_URL=https://your-api-domain.com
       bun run build
       ```
       Or create a `.env` file in the `web/` directory:
       ```
       PUBLIC_API_URL=https://your-api-domain.com
       ```

---

## Verifying Installation

Try a login after the stack is up:

```bash
curl -X POST https://your-domain/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"your_superuser_email\",\"password\":\"your_superuser_password\"}"
```

---

## Vault Guide

See [Vault Guide](https://github.com/erendemirel/garde/blob/master/vault/README.md)

---

## Detailed Integration Guide For Service Integrations

See the [Integration Guide](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md)
