# garde

A lightweight yet secure authentication API. App nodes are stateless and active-active. Run it as a public login surface, keep privileged and machine traffic on a private network, or turn the public auth surface off so almost nothing is exposed.

---

## Table of Contents

- [Key Concepts](#key-concepts)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Deploy (multi node)](#deploy-multi-node)
- [API Integration](#api-integration)
- [Contributing](#contributing)

---

## Key Concepts

### Authentication modes

- **Browser / API session**: Cookie or `Authorization: Bearer <session_id>`
- **PAT** (`garde_pat_…`): User-issued script/CI credential; managed under **Access tokens**; not valid on `/validate`
- **Internal `/validate`**: Private network — client certificate + issued API key
- **External `/validate`**: Per-tenant API key over ordinary HTTPS when you publish it

### Privilege tiers and permissions

**Superuser / Admin / User** come from Vault email lists — bootstrap who can administer the system. Application access is separate: named permissions and groups in PostgreSQL, with a request/approve flow instead of OAuth-style scopes.

Admins are not global operators. They can only touch users who share a group, and they can only grant permissions their own groups can see (`permission_visibility`). Superuser is exempt and is the only principal that can assign a user’s first group.

> [!TIP]
> garde avoids OAuth-style "scopes" that often lead to insecure permission paradoxes

Capability matrix and a request → approve walkthrough: [Permission and Group Management](docs/API_INTEGRATION_GUIDE.md#5-permission-and-group-management).

### Listeners, TLS, and public surface

garde splits **who** can reach **what**, because browsers and backend services need different trust models:

- **Public side** — what the internet (or your users) hit. By default that includes login, registration, and self-service. You can turn that surface off so the public side only answers health checks and a tiny config endpoint; people then sign in only on the private network.
- **Private side** — for your own services and operators. Session validation for machines lives here (certificate + API key). Admin tools live here too when the private listener is on. If the public auth surface is off, login moves here as well.
- **Browsers** use ordinary HTTPS (proxy, load balancer, or garde itself) — not client certificates in the usual setup.
- **Partner systems** that cannot join your private network can still call session validation with a per-tenant API key over HTTPS, when you choose to expose that path.

How to wire listeners and certificates: [TLS and mTLS](docs/INSTALLATION.md#tls-and-mtls-configuration), [Integration Guide](docs/API_INTEGRATION_GUIDE.md).

### Secrets and storage

CI/CD seeds Vault; Vault Agent renders into a tmpfs (`/run/secrets`); garde watches the files and hot-reloads what it can without a restart. PostgreSQL holds durable state (users, permissions, tokens, encrypted MFA secrets); Redis holds ephemeral state (sessions, OTPs, rate limits). Same image for local dig and multi-node HA.

Pipeline diagram and operator notes: [Vault Architecture](vault/README.md#architecture).

### Web UI

An optional SvelteKit app in `web/` talks to the same API as any other client (cookie sessions). It covers:

- **Sign-in flows** — login, register, forgot password, email verification (when those are enabled on the public surface)
- **Account** — dashboard, password change, MFA setup/disable, active sessions (revoke one or the rest), personal access tokens, and requesting permission/group updates
- **Admin** — list and edit users in shared groups (approve/reject pending updates, lock/unlock, MFA enforce, revoke sessions)
- **Superuser** — permissions and groups catalogue, tenant API keys for `/validate`, and full user management

Production can serve the built UI from its own container or static host; locally you run it with Bun against the API on port 8443 (see [Quick Start](#quick-start)).

---

## Requirements

- **Go**: 1.27 or later
- **PostgreSQL**: 16 or later
- **Redis**: 6.0 or later
- **Docker and Docker Compose**: 17.06+ and v2.0+
- **HashiCorp Vault**: 1.15 or later

---

## Quick Start

You can start the dev stack on your local computer in seconds without configuring anything:

```bash
# Clone the repository
git clone https://github.com/erendemirel/garde.git
cd garde

# Start the complete development environment
docker compose --profile dev up --build
```

This starts Vault (dev mode), PostgreSQL, Redis, and garde. Secrets are seeded from `dev.secrets`; the Vault Agent token is created automatically.

Access the API at `http://localhost:8443`. Login: `test.superuser@test.com` or `test.admin@test.com`, password `DevAdminTest123!` for both.

**Swagger:** `http://localhost:8443/swagger/index.html`. Probes: `GET /live`, `GET /ready`.

**Web UI:** from `web/`, run `bun install` then `bun run dev` (Vite proxies `/api` to `http://localhost:8443`). Sign in with the same accounts to explore account, admin, and superuser screens.

---

## Installation

See the [Installation Guide](docs/INSTALLATION.md) for development setup, single-VPS production, secrets, TLS/mTLS, and the web UI.

## Deploy (multi node)

For an active-active layout (Vault Raft, shared PostgreSQL + Redis, load balancer or floating IP), see [Deploy](docs/DEPLOY.md). AWS-specific checklist: [AWS bring-up](docs/AWS_BRINGUP.md).

## API Integration

For calling garde from your apps (sessions, tokens, private vs public validation, permissions), see the [API Integration Guide](docs/API_INTEGRATION_GUIDE.md).

## Contributing

See [contribution guide](https://github.com/erendemirel/garde/blob/master/docs/CONTRIBUTING.md)
