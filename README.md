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
- [Integration Guide](#integration-guide)
- [Contributing](#contributing)

---

## Features

- **Security**: Rate limiting (IP-based for public endpoints, user-based with role-aware thresholds for authenticated endpoints), behavior detection, session security, input sanitization, request size limiting, Vault-managed secret rotation, mTLS, MFA<br>
- **Authentication**: Three modes (browser, API, API key) with server side session management<br>
- **Permissions**: Named permissions + groups with visibility controls (not OAuth scopes), plus a request/approval workflow. Superuser/Admin/User are bootstrap privilege tiers, separate from app permissions<br>
- **Implementation**: Vault secrets, Argon2 password hashing, MFA secrets encrypted at rest, secure error handling, privacy protection<br>
- **Hot Reload**: Selected secrets and credentials reload without restart (see below)<br>
- **Web UI**: Optional built-in SvelteKit based web interface for user and admin management<br>

> [!TIP]
> garde avoids OAuth-style "scopes" that often lead to insecure permission paradoxes. Application access is expressed as named permissions visible to groups. Users can request permission changes from admins. A fixed Superuser / Admin / User privilege tier still exists for bootstrap administration.

---

### Key Concepts

#### Three Authentication Modes:
- **Browser Authentication**: Traditional web login with secure HTTP-only cookies
- **API Authentication**: Direct API calls using session tokens
- **API Key Authentication**: Service-to-service communication with API keys and mTLS

#### Hierarchical Admin System:
- **Superuser**: Single privileged user with unlimited access (defined by email)
- **Admins**: Multiple users with administrative privileges (defined by email list)
- **Users**: Regular users who can request permission changes from admins

These tiers are **not** application permissions. App-level access uses named permissions and groups (see below).

#### Security Without Scope Paradoxes:
garde separates bootstrap privilege (Superuser/Admin) from application permissions:
- **Permission Requests**: Users request changes, admins approve or modify
- **Permission Visibility**: Permissions are visible to specific groups - users only see and can request permissions visible to their groups. Similarly, admins can only approve/reject permissions visible to their groups.

#### Group-Based Access Control and Permission Visibility:
Admins can manage a user only if they share at least one group with that user. They may add a group only if they themselves are in that group, and they may remove any groups once that shared-group requirement is met. In addition to this, permissions have visibility to groups. A permission is visible to a group if there's a mapping in the `permission_visibility` table that controls what users see and perform. Admins and users can see only the permissions visible to their groups:

| Admin Groups | Target User Groups | Permissions: Add | Permissions: Remove | Groups: Add | Groups: Remove |
|--------------|-------------------|------------------|---------------------|-------------|----------------|
| `[]` | `[A]` | ❌ No shared groups | ❌ No shared groups | ❌ No shared groups | ❌ No shared groups |
| `[A]` | `[A]` | Permissions visible to A | Any permission | ❌ None | A |
| `[A]` | `[A, B]` | Permissions visible to A only | Any permission | ❌ None | A, B |
| `[A, B]` | `[A]` | Permissions visible to A or B | Any permission | B | A |
| `[A]` | `[B]` | ❌ No shared groups | ❌ No shared groups | ❌ No shared groups | ❌ No shared groups |
| `[A]` | `[]` (none) | ❌ No shared groups | ❌ No shared groups | ❌ No shared groups | ❌ No shared groups |

Initial group assignments can only be done by Superuser.

> [!NOTE]
> Superuser is exempt from all permissions and groups logic, maintaining full access regardless of configuration

For a worked example of request → approve, see [Permission and Group Management](docs/API_INTEGRATION_GUIDE.md#5-permission-and-group-management).

#### Built-in TLS & mTLS Security:
- **Built-in TLS**: garde includes native TLS support
- **mTLS for Services**: Mutual TLS authentication enables secure service-to-service communication
- **API Key + mTLS**: API keys can be combined with mTLS for even more secure communication between services

For production layout (reverse proxy vs built-in `USE_TLS`), see [TLS and mTLS](docs/INSTALLATION.md#tls-and-mtls-configuration).

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

- **Vault Agent Sidecar**: Automatically fetches and rotates secret files under `/run/secrets`
- **tmpfs Storage**: Secrets never touch persistent disk
- **File Watching**: garde reloads the in-memory secret map when `/run/secrets` changes; **not every secret applies live** (see below)

##### What hot-reloads without restart

Secret files under `/run/secrets` refresh the in-memory map automatically, but **TLS, trusted proxies, rate-limit thresholds, rapid-request config, and log level need a process restart**. API key, CORS, cookies, feature flags, SMTP, Redis reconnect, and superuser/admin bootstrap apply live.

See the full table: [Configuration hot reload](docs/INSTALLATION.md#configuration-hot-reload).

#### Configurable Security Features:
Offers configurable rate limiter, switchable behavior detection and MFA.

#### Data storage notes:
- **Redis**: users, sessions, rate limits, OTPs, and encrypted MFA secrets (`user_mfa:{id}`); password hashes live in a dedicated key (`user_password:{id}`), not in the user JSON blob
- **SQLite** (`data/permissions.db`): permission catalog, groups, and `permission_visibility` mappings

---

## Requirements

- **Go**: 1.23.0 or later
- **Redis**: 6.0 or later
- **Docker and Docker Compose**: 17.06+ and v2.0+
- **HashiCorp Vault**: 1.15 or later

---

## Quick Start

**Run the application in seconds:**

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
> The development setup is fully self-contained and includes everything you need to get started immediately

Access your application at `http://localhost:8443` once it starts up. You can login with `test.superuser@test.com`(Superuser) or `test.admin@test.com`(Admin) using the password ` DevAdminTest123!`  for both.

> [!NOTE]
> The `dev` profile auto-creates the Vault Agent token during `init-vault.sh` (no host `vault/dev-token` file needed). Secrets are seeded from `dev.secrets`.

> [!TIP]
> A web UI is included in the `web/` directory. To run it, navigate to the `web/` folder and use `bun start` (or `npm start`). The UI connects to the API at `http://localhost:8443`.

---

## Endpoint Documentation

> [!TIP]
> Swagger documentation will be available at http://localhost:8443/swagger/index.html on your own API instance once the server starts (use `https://` only when built-in TLS is enabled).

---

## Installation

See [Installation Guide](docs/INSTALLATION.md)


## Integration Guide

For more information on how garde works and how to integrate, see [integration guide](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md)

## Contributing

See [contribution guide](https://github.com/erendemirel/garde/blob/master/docs/CONTRIBUTING.md)



