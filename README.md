# garde

A lightweight yet secure authentication API. Uses Redis as primary database.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Endpoint Documentation](#endpoint-documentation)
- [Installation](#installation)
  - [Mandatory Steps](#mandatory-steps)
  - [Conditional or Optional Steps](#conditional-or-optional-steps)
- [Verifying Installation](#verifying-installation)
- [Example Configuration Files](#example-configuration-files)
- [Integration Guide](#integration-guide)
- [Security Mandates](#security-mandates)
- [Contributing](#contributing)

---

## Features

**Security**: Rate limiting(IP based and user based), behavior detection, session security, input sanitization, request size limiting, key rotation, mTLS, MFA

**Authentication**: Three modes (browser, API, API key) with server side session management

**Permissions**: Easy permission system avoiding traditional role/scope paradoxes and request/approval system

**Implementation**: Vault secrets, data encryption, secure error handling, privacy protection

**Hot Reload**: All secrets and config changes without restart

> [!TIP]
> garde avoids traditional "roles" or "scopes" as they often lead to insecure permission paradoxes. Additionally, it enables users to request permissions from admins.

---

## Quick Start

1. Download the source code

2. Set up Vault and configure secrets (see [Secrets Configuration](#2-configure-secrets))

3. Run `docker compose --profile dev up`

> [!NOTE]
> Secrets are stored in **tmpfs**. Vault Agent automatically rotates credentials.

> [!NOTE]
> For endpoint documentation, see [endpoints](#endpoint-documentation)<br>
> For detailed installation guide, see [installation](#installation)<br>
> For integration guide, refer to [integration guide](#integration-guide)<br>

--- 

## Endpoint Documentation

See [endpoints](https://garde-api-docs.netlify.app)

> [!TIP]
> This documentation page will also be available at https://localhost:8443/swagger/index.html on your own API instance once the server starts (if you've set a different port and domain, use those instead of localhost and 8443).

---

## Installation

### Mandatory Steps

---

#### 1. Download the source code

#### 2. Configure Secrets

garde uses **HashiCorp Vault** for secrets management.

> [!NOTE]
> Secrets are written to `/run/secrets` (tmpfs) by Vault Agent. The app watches for changes and automatically reloads (without restart).

**Required secrets in Vault:**
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/redis_host` | Redis server hostname |
| `secret/garde/redis_port` | Redis server port |
| `secret/garde/redis_password` | Redis authentication password |
| `secret/garde/domain_name` | Your domain (for cookies and TLS) |
| `secret/garde/superuser_email` | Superuser account email (registers manually) |
| `secret/garde/api_key` | API key (20+ chars, upper/lower/number/special) |

**Optional secrets:**
| Secret Path | Description | Default |
|-------------|-------------|---------|
| `secret/garde/redis_db` | Redis database number | `0` |
| `secret/garde/port` | Server port | `8443` |
| `secret/garde/use_tls` | Enable TLS | `false` |
| `secret/garde/gin_mode` | Gin framework mode | `debug` |
| `secret/garde/log_level` | Log level (DEBUG/INFO/WARN/ERROR) | `INFO` |

##### Architecture

```
┌─────────────┐    writes to     ┌─────────────┐    watches    ┌─────────────┐
│    Vault    │ ───────────────→ │   tmpfs     │ ←─────────────│    garde    │
│   Server    │   Vault Agent    │ /run/secrets│   file watcher│    app      │
└─────────────┘                  └─────────────┘               └─────────────┘
                                       
                                  
```

##### Development Setup

For development, secrets are loaded from `dev.secrets` file via Vault:

```bash
# Start the full stack (Vault + Redis + App)
docker compose --profile dev up --build
```

This automatically:
1. Starts Vault in dev mode
2. Seeds secrets from `dev.secrets` into Vault
3. Vault Agent writes secrets to tmpfs (`/run/secrets`)
4. App reads secrets and connects to Redis

See `vault/` directory for Vault Agent configuration examples.

#### 3. Run the application

##### a. Without the project's docker-compose:

- Install [Go](https://go.dev/doc/install)
- Build and run the app:
```bash
go mod download
go build -o garde ./cmd
./garde
```
##### b. With the project's docker-compose:

```bash
# Development (includes Vault, Redis, and App)
docker compose --profile dev up --build
```

For production, you would configure a proper Vault cluster and use AppRole authentication instead of the dev token.


### Conditional or Optional Steps

---

#### 1. Configure built-in TLS (Conditional)
Configure the application to use built-in TLS.

> [!IMPORTANT]  
> If you don't use built-in TLS, you cannot use mTLS and API-key authentication

- Gather your SSL certificates:

  - Valid TLS certificate from trusted CA (not self-signed)
  - Certificate chain must include intermediate certificates
  - SAN must include all domain variants (e.g., example.com, *.example.com)

- Add to secrets directory:

| Secret File | Description |
|------------|-------------|
| `use_tls` | Set to `true` to enable TLS |
| `tls_cert_path` | Path to your server certificate |
| `tls_key_path` | Path to your server private key |
| `port` | HTTPS port (optional, default: 8443) |

#### 2. Configure mTLS and set API key (Conditional)
Required only if auth service will communicate with internal services.

> [!IMPORTANT]  
> Built-in TLS must be enabled for mTLS and API-key authentication to work

Add to secrets directory:

| Secret File | Description |
|------------|-------------|
| `tls_ca_path` | Path to client CA cert (comma-separated for multiple) |
| `api_key` | API key (20+ chars, complexity required) |

#### 3. Configure Log Level (Optional)
Control the verbosity of application logs for troubleshooting and monitoring.

Add to secrets directory:

| Secret File | Description |
|------------|-------------|
| `log_level` | DEBUG, INFO, WARN, or ERROR |
| `gin_mode` | debug or release |

#### 4. Mail Server Configuration (Conditional)
Set configurations to be able to send mails. Resetting password functionality requires sending a mail.

> [!WARNING]  
> Without sending emails, garde cannot reset users' passwords

##### DNS Records Required
- MX record pointing to mail.your-domain.com
- SPF record: `v=spf1 mx -all`
- PTR (reverse DNS) record for your IP

Add to secrets directory:

| Secret File | Description |
|------------|-------------|
| `smtp_host` | SMTP server hostname |
| `smtp_port` | SMTP server port (default: 587) |
| `smtp_user` | SMTP authentication username |
| `smtp_password` | SMTP authentication password |
| `smtp_from` | Sender email address |

#### 5. Permissions and Groups System (Conditional)

In addition to secrets, there are also configurations for application and business logic. These include permissions and groups, defined in JSON files under the `/configs` directory: `permissions.json` and `groups.json`.

The permissions list defines all permissions that your authentication API instance will support, such as access to specific menus in your application dashboard or any other permission you'd like your users to have. If you want to use permissions, you must define them in this file.

The groups list helps organize users and admins. Admins can only manage users who share at least one group with them.

> [!NOTE]
> Superuser is exempt from permissions-groups logic

Both the permissions and groups systems are optional. 

> [!TIP]
> To disable either system, simply remove the corresponding file (`permissions.json` and/or `groups.json`) from your `/configs` directory. For more information, refer to the integration guide and review the sample JSON files in the `/configs` directory

##### Permissions
Set in `/configs/permissions.json`:
```json
{
    "permission_a": {
        "name": "Permission A",
        "description": "Ability to perform some action",
        "groups": ["x", "z"]  // must match the group names inside groups.json
    }
}
```

##### Groups
Set in `/configs/groups.json`:
```json
{
    "x": {
        "name": "X Group",
        "description": "Users of group x"
    }
}
```

#### 6. Other Configurations (Optional)

These optional settings are also stored in Vault and written to `/run/secrets` by Vault Agent:

| Vault Secret Path | Description |
|-------------------|-------------|
| `secret/garde/cors_allow_origins` | Allowed CORS origins (comma-separated) |
| `secret/garde/enforce_mfa` | Set to `true` to enforce MFA for all users |
| `secret/garde/admin_users` | Comma-separated admin user emails |
| `secret/garde/rate_limit` | IP-based rate limiting. Format: `limit,interval_seconds` (e.g., `100,60` = max 100 requests per 60 seconds per IP). Set to `0,0` to disable (not recommended for production) |
| `secret/garde/rapid_request_config` | User-based rapid request detection. Format: `max_per_min,min_interval_ms` (e.g., `120,10` = max 120 req/min, block if requests are <10ms apart). Detects automated/bot behavior. Set to `0,0` to disable |
| `secret/garde/disable_user_agent_check` | Set to `true` to disable User-Agent header validation. When enabled, requests with suspicious User-Agent patterns (bot/crawler identifiers) are flagged |
| `secret/garde/disable_ip_blacklisting` | Set to `true` to disable automatic IP blocking. When enabled, IPs are blocked after repeated failed logins or rate limit violations |
| `secret/garde/disable_multiple_ip_check` | Set to `true` to disable concurrent session IP detection. When enabled, sessions from multiple IPs simultaneously are flagged as suspicious |

> [!NOTE]
> ALL configuration goes through Vault. The app reads from `/run/secrets` (tmpfs), which is populated by Vault Agent.

##### Admin Management
There are two types of administrative users - superuser, and admins.
Superuser is only one, and they can perform any operation. Admins are less privileged, but can be many.

Add `admin_users` secret with comma-separated admin emails. Users whose emails are listed here have admin privileges.
- Admin status is determined by checking if user's email is in `ADMIN_USERS`
- To add/remove admins, update the `ADMIN_USERS` secret (hot reload supported)
- Only superuser can assign initial groups to users with no groups

##### Group-Based Access Control
Admins can only manage users who **already share at least one group** with them:

| Admin Groups | Target User Groups | Can Admin Manage? | Can Admin Modify Groups? |
|--------------|-------------------|-------------------|--------------------------|
| `[A]` | `[A]` | ✅ Yes | ✅ Only to groups admin is in |
| `[A, B]` | `[A]` | ✅ Yes | ✅ Can add to A or B |
| `[A]` | `[B]` | ❌ No | ❌ No shared groups |
| `[A]` | `[]` (none) | ❌ No | ❌ No shared groups |

- **When groups.json is disabled:** Admins can manage all users (no group restrictions)

#### 7. Network Configuration (When required)
##### Required Ports
```ini
${PORT:-8443}  # HTTP(S) port (defaults to 8443 if PORT not set)
```

##### Reverse Proxy Setup
Configure Nginx/Apache to:
- Terminate TLS (if not using app's built-in TLS)
- Set `X-Forwarded-For` header
- Forward WebSocket connections

Example Nginx configuration:
```nginx
location / {
    proxy_pass https://localhost:8443;
    proxy_ssl_verify off;  # Only for self-signed certs
    proxy_set_header X-Real-IP $remote_addr;
}
```

##### Firewall Rules
- Allow inbound: Your auth API instance port
- Allow outbound: Redis (if using your own), mail server (if enabled)

> [!NOTE]  
> All configuration changes are automatically detected via file watcher - no restart needed. This includes secrets in `/run/secrets` and config files (`permissions.json`, `groups.json`).

## Verifying Installation

Try a login:

```bash
curl -X POST https://your-domain/login -H "Content-Type: application/json" -d "{\"email\":\"your_email\",\"password\":\"your_password\"}"
```


## Example Configuration Files

- Secrets structure: [secrets/.gitkeep](https://github.com/erendemirel/garde/blob/master/secrets/.gitkeep)
- Permissions List (optional): [permissions.json](https://github.com/erendemirel/garde/blob/master/configs/permissions.json)
- Groups List (optional): [groups.json](https://github.com/erendemirel/garde/blob/master/configs/groups.json)

## Integration Guide

For more information on how garde works and how to integrate, see [integration guide](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md)

## Security Mandates

- Rotate these frequently:
  - `api_key`
- Rotate these often:
  - `redis_password`
- Enable HSTS with preload directive in production
- Configure TLS on the firewall if not using the in-built one
- Place a proxy server in front of your Redis (if you are using the in-built one, place in front of "redis_network" Docker network)
- Do not set `rate_limit` to `0,0` in production (this disables IP based rate limiter)
- Do not set `rapid_request_config` to `0,0` in production (this disables user ID based rate limiter)
- Do not set `disable_user_agent_check` to `true` in production
- Do not set `disable_ip_blacklisting` to `true` in production
- Do not set `disable_multiple_ip_check` to `true` in production
- Set `enforce_mfa` to `true` in production
- Use separate CA certificates for different client groups
- Rotate certificates at least once a year
- Use HashiCorp Vault or similar for secrets management


## Contributing

See [contribution guide](https://github.com/erendemirel/garde/blob/master/docs/CONTRIBUTING.md)



