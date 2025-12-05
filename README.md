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

- **Security**: Rate limiting(IP based and user based), behavior detection, session security, input sanitization, request size limiting, key rotation, mTLS, MFA<br>
- **Authentication**: Three modes (browser, API, API key) with server side session management<br>
- **Permissions**: Easy permission system avoiding traditional role/scope paradoxes and request/approval system<br>
- **Implementation**: Vault secrets, data encryption, secure error handling, privacy protection<br>
- **Hot Reload**: All secrets and config changes without restart<br>

> [!TIP]
> garde avoids traditional "roles" or "scopes" as they often lead to insecure permission paradoxes. Additionally, it enables users to request permissions from admins

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
- **Permission Requests**: Users request changes, admins approve or modify. Users can display all permissions and groups
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

---

## Endpoint Documentation

See [endpoints](https://garde-api-docs.netlify.app)

> [!TIP]
> This documentation page will also be available at https://localhost:8443/swagger/index.html on your own API instance once the server starts (if you've set a different port and domain, use those instead of localhost and 8443)

---

## Installation

See [Installation Guide](docs/INSTALLATION.md)


## Integration Guide

For more information on how garde works and how to integrate, see [integration guide](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md)

## Contributing

See [contribution guide](https://github.com/erendemirel/garde/blob/master/docs/CONTRIBUTING.md)



