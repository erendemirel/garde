# garde

A lightweight yet secure authentication API. App nodes are stateless and active-active. Run it as a public login surface, keep privileged and machine traffic on a private network, or turn the public auth surface off so almost nothing is exposed.

---

## Table of Contents

- [Key Concepts](#key-concepts)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Endpoint Documentation](#endpoint-documentation)
- [Installation](#installation)
- [Deploy (multi node)](#deploy-multi-node)
- [API Integration](#api-integration)
- [Contributing](#contributing)

---

### Key Concepts

#### Authentication modes:
- **Browser / API session**: Cookie or `Authorization: Bearer <session_id>`
- **PAT** (`garde_pat_…`): User-issued script/CI credential; managed under **Access tokens**; not valid on `/validate`
- **Internal `/validate`**: Private network — client certificate + issued API key
- **External `/validate`**: Per-tenant API key over ordinary HTTPS when you publish it

#### Hierarchical Admin System:
- **Superuser** / **Admins** / **Users** — bootstrap privilege tiers (email config), not application permissions. App access uses named permissions and groups.

#### Security Without Scope Paradoxes:
Named permissions (not OAuth scopes) with a request/approval workflow. Visibility is group-scoped: users and admins only see or act on permissions visible to their groups.

> [!TIP]
> garde avoids OAuth-style "scopes" that often lead to insecure permission paradoxes. Application access is expressed as named permissions visible to groups. Users can request permission changes from admins. A fixed Superuser / Admin / User privilege tier still exists for bootstrap administration.

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

#### Listeners, TLS, and public surface:
garde splits **who** can reach **what**, because browsers and backend services need different trust models:

- **Public side** — what the internet (or your users) hit. By default that includes login, registration, and self-service. You can turn that surface off so the public side only answers health checks and a tiny config endpoint; people then sign in only on the private network.
- **Private side** — for your own services and operators. Session validation for machines lives here (certificate + API key). Admin tools live here too when the private listener is on. If the public auth surface is off, login moves here as well.
- **Browsers** use ordinary HTTPS (proxy, load balancer, or garde itself) — not client certificates in the usual setup.
- **Partner systems** that cannot join your private network can still call session validation with a per-tenant API key over HTTPS, when you choose to expose that path.

How to wire listeners and certificates is in the install guide: [TLS and mTLS](docs/INSTALLATION.md#tls-and-mtls-configuration), [Integration Guide](docs/API_INTEGRATION_GUIDE.md).

#### Secrets and storage:
Vault Agent writes secrets to a tmpfs; garde reloads many of them without a restart. PostgreSQL is the durable store (users, permissions, tokens, encrypted MFA secrets); Redis holds ephemeral state (sessions, OTPs, rate limits). Same image for single-VPS and multi-node HA.

```
┌─────────────┐    injects       ┌─────────────┐    writes to     ┌─────────────┐    watches    ┌─────────────┐
│     CI      │ ───────────────→ │    Vault    │ ───────────────→ │   tmpfs     │ ←─────────────│    garde    │
│    /CD      │   AppRole +      │   Server    │   Vault Agent    │ /run/secrets│   file watcher│    app      │
│  Pipeline   │   Secrets        │   (dynamic   │   (auto-updates │             │   (hot reload)│   (handles  │
│             │                  │   secrets)   │   on rotation)  │             │               │   rotation) │
└─────────────┘                  └─────────────┘                  └─────────────┘               └─────────────┘
```

#### Web UI:
An optional SvelteKit app in `web/` talks to the same API as any other client (cookie sessions). It covers:

- **Sign-in flows** — login, register, forgot password, email verification (when those are enabled on the public surface)
- **Account** — dashboard, password change, MFA setup/disable, active sessions (revoke one or the rest), personal access tokens, and requesting permission/group updates
- **Admin** — list and edit users in shared groups (approve/reject pending updates, lock/unlock, MFA enforce, revoke sessions)
- **Superuser** — permissions and groups catalogue, tenant API keys for `/validate`, and full user management

Production can serve the built UI from its own container or static host; locally you run it with Bun against the API on port 8443 (see Quick Start).

---

## Requirements

- **Go**: 1.27 or later (see `go.mod`)
- **PostgreSQL**: 16 or later
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
- **PostgreSQL**
- **Redis**
- **garde** application

> [!TIP]
> The development setup is fully self-contained and includes everything you need to get started immediately

Access your application at `http://localhost:8443` once it starts up. You can login with `test.superuser@test.com` (Superuser) or `test.admin@test.com` (Admin) using the password `DevAdminTest123!` for both.

> [!NOTE]
> The Vault Agent token is created automatically; secrets are seeded from `dev.secrets`.

> [!TIP]
> **Web UI:** from `web/`, run `bun install` then `bun start` (or `bun run dev`). It connects to the API at `http://localhost:8443`. Sign in with the same superuser or admin accounts above to explore account, admin, and superuser screens.

---

## Endpoint Documentation

> [!TIP]
> Swagger is available at http://localhost:8443/swagger/index.html in the default local setup. Health checks: `GET /live`, `GET /ready`, and `GET /health`.

---

## Installation

See the [Installation Guide](docs/INSTALLATION.md) for development setup, single-VPS production, secrets, TLS/mTLS, and the web UI.

## Deploy (multi node)

For an active-active layout (Vault Raft, shared PostgreSQL + Redis, load balancer or floating IP), see [Deploy](docs/DEPLOY.md). AWS-specific checklist: [AWS bring-up](docs/AWS_BRINGUP.md).

## API Integration

For calling garde from your apps (sessions, tokens, private vs public validation, permissions), see the [API Integration Guide](docs/API_INTEGRATION_GUIDE.md).

## Contributing

See [contribution guide](https://github.com/erendemirel/garde/blob/master/docs/CONTRIBUTING.md)
