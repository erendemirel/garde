# Installation Guide

## Table of Contents
- [Development Installation](#development-installation)
- [Production Installation](#production-installation)
- [Verifying Installation](#verifying-installation)
- [Vault Guide](#vault-guide)
- [Example Configuration Files](#example-configuration-files)
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
   - Check `dev.secrets` for default secrets; configure `configs/permissions.json` and `configs/groups.json` for permission and group systems.
   - Modify as needed for your environment. The easiest way for this is:
       - **For secrets:** Following the comments inside `dev.secrets` file,  
       - **For configurations:** Seeing [Example Configuration Files](#example-configuration-files) for example JSONs, and following [Permission and Group Management](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md#5-permission-and-group-management) section in integration guide to understand how they work and how to structure the JSONs. You can also have a look at this section in [Key Concepts](https://github.com/erendemirel/garde/tree/master?tab=readme-ov-file#security-without-role-paradoxes) to have the bigger picture.

> [!TIP]
> Both permission and group systems are optional. Remove the JSON files from `/configs` to disable them. When disabled, only the superuser maintains full access

3. **Start the development stack**
   ```bash
   docker compose --profile dev up --build
   ```

4. **Access the application**
   - API: `http://localhost:8443`
   - Swagger docs: `http://localhost:8443/swagger/index.html`

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
| `secret/garde/rate_limit` | IP rate limiting: `limit,interval_seconds` (e.g., `100,60`). Use `0,0` to disable. |
| `secret/garde/rapid_request_config` | User-based rapid request detection: `max_per_min,min_interval_ms` (e.g., `120,10`). Use `0,0` to disable. |
| `secret/garde/disable_user_agent_check` | Disable UA validation |
| `secret/garde/disable_ip_blacklisting` | Disable automatic IP blocking |
| `secret/garde/disable_multiple_ip_check` | Disable concurrent session IP detection |

**Admin Configuration**:
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/admin_users_json` | JSON object: `{"admin1@example.com":"Pass1!","admin2@example.com":"Pass2!"}`. Admins are auto-created/updated at startup and on secret reload. Public/admin-created signup cannot create these accounts. |

**Permissions & Groups**:
- Configure `configs/permissions.json` and `configs/groups.json` in your deployment.
- Mount these files to `/app/configs/` in the container.

> [!TIP]
> Both systems(permission, group) are optional for production. Omit the files from your deployment to disable them. Superuser access remains 
unaffected. See [Permission and Group Management](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md#5-permission-and-group-management) for more info

**Other Production Configuration**
- Logging: `secret/garde/log_level` (DEBUG/INFO/WARN/ERROR), `secret/garde/gin_mode` (debug/release)

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

## Example Configuration Files

- Secrets structure: [secrets/.gitkeep](https://github.com/erendemirel/garde/blob/master/secrets/.gitkeep)
- Permissions List (optional): [permissions.json](https://github.com/erendemirel/garde/blob/master/configs/permissions.json)
- Groups List (optional): [groups.json](https://github.com/erendemirel/garde/blob/master/configs/groups.json)

---

## Detailed Integration Guide For Service Integrations

See the [Integration Guide](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md)
