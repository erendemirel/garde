# garde

A lightweight yet secure authentication API. Uses Redis as primary database.

---

## Table of Contents

- [Features](#features)
- [Key Concepts](#key-concepts)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Endpoint Documentation](#endpoint-documentation)
- [Installation](#installation)
  - [Development Installation](#development-installation)
  - [Production Installation](#production-installation)
- [Verifying Installation](#verifying-installation)
- [Example Configuration Files](#example-configuration-files)
- [Integration Guide](#integration-guide)
- [Security Mandates](#security-mandates)
- [Contributing](#contributing)

---

## Features

- **Security**: Rate limiting(IP based and user based), behavior detection, session security, input sanitization, request size limiting, key rotation, mTLS, MFA<br>
- **Authentication**: Three modes (browser, API, API key) with server side session management<br>
- **Permissions**: Easy permission system avoiding traditional role/scope paradoxes and request/approval system<br>
- **Implementation**: Vault secrets, data encryption, secure error handling, privacy protection<br>
- **Hot Reload**: All secrets and config changes without restart<br>

> [!TIP]
> garde avoids traditional "roles" or "scopes" as they often lead to insecure permission paradoxes. Additionally, it enables users to request permissions from admins.

### Key Concepts

#### Three Authentication Modes:
- **Browser Authentication**: Traditional web login with secure HTTP-only cookies
- **API Authentication**: Direct API calls using session tokens
- **API Key Authentication**: Service-to-service communication with API keys and mTLS

#### Hierarchical Admin System:
- **Superuser**: Single privileged user with unlimited access (defined by email)
- **Admins**: Multiple users with administrative privileges (defined by email list)
- **Users**: Regular users who can request permission changes from admins

#### Security Without Role Paradoxes:
garde avoids traditional "roles" and "scopes" that often create security paradoxes:
- **Granular Permissions**: Individual permissions instead of role bundles
- **Permission Requests**: Users request changes, admins approve or modify
- **No Over-Privileging**: Admins get exactly the access they need
- **JSON Configuration**: Permissions defined in `permissions.json` with descriptions

#### Group-Based Access Control:
Admins can only manage users they share groups with:

| Admin Groups | Target User Groups | Can Admin Manage? | Can Admin Modify Groups? |
|--------------|-------------------|-------------------|--------------------------|
| `[A]` | `[A]` | ✅ Yes | ✅ Only to groups admin is in |
| `[A, B]` | `[A]` | ✅ Yes | ✅ Can add to A or B |
| `[A]` | `[B]` | ❌ No | ❌ No shared groups |
| `[A]` | `[]` (none) | ❌ No | ❌ No shared groups |

> [!NOTE]
> Superuser is exempt from all permissions and groups logic, maintaining full access regardless of configuration


#### Built-in TLS & mTLS Security:
- **Built-in TLS**: garde includes native TLS support
- **mTLS for Services**: Mutual TLS authentication enables secure service-to-service communication
- **API Key + mTLS**: API keys combined can be combined with mTLS for even more secure communication between services

#### Secrets Architecture:
garde uses HashiCorp Vault for secrets management:

```
┌─────────────┐    injects       ┌─────────────┐    writes to     ┌─────────────┐    watches    ┌─────────────┐
│     CI      │ ───────────────→ │    Vault    │ ───────────────→ │   tmpfs     │ ←─────────────│    garde    │
│    /CD      │   AppRole +      │   Server    │   Vault Agent    │ /run/secrets│   file watcher│    app      │
│  Pipeline   │   Secrets        │   (dynamic   │   (auto-updates │             │   (hot reload)│   (handles  │
│             │                  │   secrets)   │   on rotation)  │             │               │   rotation) │
└─────────────┘                  └─────────────┘                  └─────────────┘               └─────────────┘
```

- **Vault Agent Sidecar**: Automatically fetches and rotates secrets
- **tmpfs Storage**: Secrets never touch persistent disk
- **Hot Reload**: All configuration changes applied without application restart
- **File Watching**: Monitors `/run/secrets` directory for changes

#### Configurable Security Features:
Offers configurable rate limiter, switchable behavior detection and MFA.

---

## Requirements

- **Go**: 1.23.0 or later
- **Redis**: 6.0 or later
- **Docker and Docker Compose**: 17.06+ and v2.0+
- **HashiCorp Vault**: 1.15 or later

---

## Quick Start

**Get up and running in minutes with the complete development environment:**

```bash
# Clone the repository
git clone https://github.com/erendemirel/garde.git
cd garde

# Start the complete development environment
docker compose --profile dev up --build
```

This automatically sets up:
- **Vault** (dev mode)
- **Redis** 
- **garde** application

> [!TIP]
> The development setup is fully self-contained and includes everything you need to get started immediately.

Access your application at `http://localhost:8443` once it starts up. You can login with `test.admin@test.com`(Superuser) or `test.admin@test.com`(Admin) after setting their passwords(Via create new user)

---

## Endpoint Documentation

See [endpoints](https://garde-api-docs.netlify.app)

> [!TIP]
> This documentation page will also be available at https://localhost:8443/swagger/index.html on your own API instance once the server starts (if you've set a different port and domain, use those instead of localhost and 8443).

---

## Installation

### Development Installation

#### Prerequisites
- Docker & Docker Compose (17.06+ and v2.0+)

#### Steps
1. **Clone the repository**
   ```bash
   git clone https://github.com/erendemirel/garde.git
   cd garde
   ```

2. **Review development configuration (Optional)**
   - Check `dev.secrets` file for default secrets and, configure `configs/permissions.json` and `configs/groups.json` for permission and group systems
   - Modify as needed for your environment. You can follow the comments inside `dev.secrets` file,  [Configuration Guide](#configuration-guide) and information in [Production Installation](#production-installation) section

3. **Start the development stack**
   ```bash
   docker compose --profile dev up --build
   ```

4. **Access the application**
   - API: `http://localhost:8443`
   - Swagger docs: `http://localhost:8443/swagger/index.html`

#### What happens automatically:
- Vault starts in development mode
- Secrets from `dev.secrets` are seeded into Vault
- Vault Agent writes secrets to tmpfs (`/run/secrets`)
- Application reads secrets and connects to Redis
- Configuration hot-reload is automatically enabled

> [!TIP]
> Both permission and group systems are optional. Simply remove the respective JSON files from `/configs` to disable them. When disabled, only superuser maintains full access. See [Configuration Guide](#configuration-guide) for more info

### Production Installation

#### Prerequisites
- HashiCorp Vault
- Redis
- Docker & Docker Compose
- TLS certificates (for mTLS)

#### Required Secrets in Vault
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/redis_host` | Redis server hostname |
| `secret/garde/redis_port` | Redis server port |
| `secret/garde/redis_password` | Redis authentication password |
| `secret/garde/domain_name` | Your domain (for cookies and TLS) |
| `secret/garde/superuser_email` | Superuser account email |
| `secret/garde/api_key` | API key (20+ chars, mixed case/symbols) |

#### Production Configuration Steps

1. **Setup Vault cluster** with AppRole authentication
2. **Setup Redis**
3. **Configure TLS and mTLS** (see below)
4. **Deploy using docker-compose** or orchestration platform

#### TLS and mTLS Configuration (Production)

For production deployments, TLS is strongly recommended:

**Server TLS (Required for mTLS):**
- Valid TLS certificate from trusted CA
- Certificate chain with intermediate certificates
- SAN including all domain variants

**Required Vault secrets:**
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/use_tls` | Set to `true` or `false` |
| `secret/garde/tls_cert_path` | Path to server certificate |
| `secret/garde/tls_key_path` | Path to server private key |
| `secret/garde/tls_ca_path` | Path to client CA certificate |
| `secret/garde/api_key` | API key for mTLS authentication |

> [!IMPORTANT]
> Built-in TLS must be enabled for mTLS and API-key authentication to work. Without TLS, only basic authentication is available.

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
> Without sending emails, garde cannot reset users' passwords

**Security & Behavior Settings**:
| Vault Secret Path | Description |
|-------------------|-------------|
| `secret/garde/cors_allow_origins` | Allowed CORS origins (comma-separated) |
| `secret/garde/enforce_mfa` | Set to `true` to enforce MFA for all users |
| `secret/garde/rate_limit` | IP-based rate limiting. Format: `limit,interval_seconds` (e.g., `100,60` = max 100 requests per 60 seconds per IP). Set to `0,0` to disable (not recommended for production) |
| `secret/garde/rapid_request_config` | User-based rapid request detection. Format: `max_per_min,min_interval_ms` (e.g., `120,10` = max 120 req/min, block if requests are <10ms apart). Detects automated/bot behavior. Set to `0,0` to disable |
| `secret/garde/disable_user_agent_check` | Set to `true` to disable User-Agent header validation. When enabled, requests with suspicious User-Agent patterns (bot/crawler identifiers) are flagged |
| `secret/garde/disable_ip_blacklisting` | Set to `true` to disable automatic IP blocking. When enabled, IPs are blocked after repeated failed logins or rate limit violations |
| `secret/garde/disable_multiple_ip_check` | Set to `true` to disable concurrent session IP detection. When enabled, sessions from multiple IPs simultaneously are flagged as suspicious |

**Admin Configuration**:
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/admin_users` | Comma-separated list of admin email addresses |

**Permissions & Groups**:
- Configure `configs/permissions.json` and `configs/groups.json` in your deployment
- Mount these files to `/app/configs/` in the container

> [!TIP]
> Both systems(permission, group) are optional for production. Omit the files from your deployment to disable them. Superuser access remains unaffected. See [Configuration Guide](#configuration-guide) for more info

#### Other Production Configuration

**Logging:**
- `secret/garde/log_level`: DEBUG, INFO, WARN, or ERROR
- `secret/garde/gin_mode`: debug or release

### Configuration Guide

#### Permissions and Groups (Optional)

garde supports flexible permission and group management through JSON configuration files:

- **Permissions** (`/configs/permissions.json`): Define granular permissions for your application
- **Groups** (`/configs/groups.json`): Organize users and control admin access levels

Both systems are optional, remove the files to disable them. See sample files in `/configs/` and the [Integration Guide](#integration-guide) for detailed configuration.

### Next Steps

After installation, you can:

1. **Access the API** at `http://localhost:8443`
2. **View API documentation** at `http://localhost:8443/swagger/index.html`
3. **Register the superuser** using the email from `dev.secrets`
4. **Configure additional features** (TLS, email, permissions) as needed

For detailed configuration options, see the [Integration Guide](#integration-guide).

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

## Contributing

See [contribution guide](https://github.com/erendemirel/garde/blob/master/docs/CONTRIBUTING.md)



