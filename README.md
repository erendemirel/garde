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

- **Security**: Rate limiting (IP-based for public endpoints, user-based with role-aware thresholds for authenticated endpoints), behavior detection, session security, input sanitization, request size limiting, key rotation, mTLS, MFA<br>
- **Authentication**: Three modes (browser, API, API key) with server side session management<br>
- **Permissions**: Easy permission system avoiding traditional role/scope paradoxes and request/approval system<br>
- **Implementation**: Vault secrets, data encryption, secure error handling, privacy protection<br>
- **Hot Reload**: All secrets changes without restart<br>
- **Web UI**: Optional built-in SvelteKit based web interface for user and admin management<br>

> [!TIP]
> garde avoids traditional "roles" or "scopes" as they often lead to insecure permission paradoxes or maintainability issues. Additionally, it enables users to request permissions from admins

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

#### Security Without Role Paradoxes:
garde avoids traditional "roles" and "scopes" that often create security paradoxes:
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


#### Built-in TLS & mTLS Security:
- **Built-in TLS**: garde includes native TLS support
- **mTLS for Services**: Mutual TLS authentication enables secure service-to-service communication
- **API Key + mTLS**: API keys can be combined with mTLS for even more secure communication between services

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

**Get up and running in seconds with the complete development environment:**

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

Access your application at `http://localhost:8443` once it starts up. You can login with `test.superuser@test.com`(Superuser) or `test.admin@test.com`(Admin) using the password DevAdminTest123! for both.

> [!TIP]
> A web UI is included in the `web/` directory. To run it, navigate to the `web/` folder and use `bun start` (or `npm start`). The UI connects to the API at `http://localhost:8443`.

---

## Endpoint Documentation

See [endpoints](https://erendemirel.github.io/garde)

> [!TIP]
> This documentation page will also be available at https://localhost:8443/swagger/index.html on your own API instance once the server starts (if you've set a different port and domain, use those instead of localhost and 8443)

---

## Installation

See [Installation Guide](docs/INSTALLATION.md)


## Integration Guide

For more information on how garde works and how to integrate, see [integration guide](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md)

## Contributing

See [contribution guide](https://github.com/erendemirel/garde/blob/master/docs/CONTRIBUTING.md)



