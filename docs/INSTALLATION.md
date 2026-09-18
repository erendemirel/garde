# Installation Guide

## Table of Contents
- [Development Installation](#development-installation)
- [Production Installation](#production-installation)
  - [Deploying to a VPS](#deploying-to-a-vps)
  - [Required mandatory secrets](#required-mandatory-secrets-in-vault)
  - [TLS and mTLS](#tls-and-mtls-configuration)
  - [Additional configuration (optional)](#additional-production-configuration-optional)
  - [Configuration hot reload](#configuration-hot-reload)
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
   - Secrets are managed via `dev.secrets` (already populated with defaults, including `POSTGRES_*` and `REDIS_*`). Permissions and groups live in PostgreSQL with the rest of the durable user data; the `dev` compose profile starts Postgres for you.
   - Modify as needed for your environment. The easiest way to learn about secrets and permission system is:
       - **For secrets:** Following the comments inside `dev.secrets` file,  
       - **For permission and group system:** Following [Permission and Group Management](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md#5-permission-and-group-management) section in integration guide to understand how they work. You can also have a look at this section in [Key Concepts](https://github.com/erendemirel/garde/tree/master?tab=readme-ov-file#security-without-scope-paradoxes) to have the bigger picture.

3. **Start the development stack**
   ```bash
   docker compose --profile dev up --build
   ```

4. **Access the application**
   - API: `http://localhost:8443`
   - Ready: `http://localhost:8443/ready` (Postgres + Redis); also `/live` and `/health`
   - Swagger docs (when `ENABLE_SWAGGER=true`): `http://localhost:8443/swagger/index.html`

5. **Web UI (Optional)**   

   - Navigate to `web/` directory and run `bun start`. No configuration needed, everything is set up. It automatically proxies `/api` requests to `http://localhost:8443` via Vite dev server.

### What happens automatically
- Vault starts in development mode
- `init-vault.sh` writes the Vault Agent token into a shared Docker volume (no host `vault/dev-token` file required)
- Secrets from `dev.secrets` are seeded into Vault
- Vault Agent writes secrets to tmpfs (`/run/secrets`)
- PostgreSQL and Redis start; the application connects to both
- Secret file watching is enabled; see [Configuration hot reload](#configuration-hot-reload) for what applies live vs what needs a restart

---

## Production Installation

### Prerequisites
- HashiCorp Vault
- Redis (shared; ephemeral sessions, rate limits, OTPs)
- PostgreSQL (shared; durable authority — users, credentials, catalog, PATs, tenant keys)
- Docker & Docker Compose
- TLS certificates, if you enable built-in TLS or the service listener (`deploy/scripts/service-pki.sh` generates the latter)

### Deployment paths

**If you run Vault, Redis, and PostgreSQL yourself** (e.g. external or managed services), use this path:

1. **Setup Vault cluster** with AppRole authentication. See [Vault Guide – Manual setup](https://github.com/erendemirel/garde/blob/master/vault/README.md#setup) (follow steps 1–3 in that doc; step 4 is optional).
2. **Setup Redis and PostgreSQL**; seed `redis_host` and `DATABASE_URL` / `POSTGRES_*` into Vault
3. **Configure TLS and mTLS** (see [TLS and mTLS](#tls-and-mtls-configuration) below).
4. **Deploy** using docker-compose or your orchestrator.

**If you use the single-VPS Docker Compose stack** below, Vault runs in **production server mode** (persistent file storage). You still initialize, unseal, and configure AppRole once—then Vault Agent uses AppRole for day-to-day secret delivery. Go to [Deploying to a VPS](#deploying-to-a-vps).

**Single VPS with Docker Compose:** A supported production pattern is running everything on one host with Docker Compose (Vault server, Vault Agent, Redis, Postgres, garde, and the web UI). The stack is defined in `docker-compose.prod.yml`. It does **not** use `vault server -dev`. For Vault/Agent details, see [vault/README.md](https://github.com/erendemirel/garde/blob/master/vault/README.md).

**Multi-node active-active:** If losing a single host is unacceptable, see [Deploying garde (active-active)](DEPLOY.md). That layout runs a multi-member Vault Raft cluster, identical app nodes against shared PostgreSQL and Redis, and a public ALB (or floating IP).

### Deploying to a VPS

1. **Provision the VPS** (Ubuntu 24.04 or similar). Install Docker and Docker Compose:
   ```bash
   apt update && apt install -y docker.io docker-compose-v2 jq
   systemctl enable --now docker
   ```

2. **Get the project** on the VPS (clone the repo or copy files, e.g. with `rsync` or `scp`).

3. **Create `prod.secrets`** (copy from `dev.secrets`, set production values). For the single-VPS stack, set `REDIS_HOST=redis` and `POSTGRES_HOST=postgres` (Compose service names), or set `DATABASE_URL`. Set `CORS_ALLOW_ORIGINS` to the URL users will use for the UI. Create a `.env` in the project root with `REDIS_PASSWORD` and `POSTGRES_PASSWORD` (same values as in `prod.secrets`) and optionally `PUBLIC_API_URL`. You will add `VAULT_TOKEN` after the next step.

4. **Start Vault (server mode) and initialize once:**
   ```bash
   docker compose -f docker-compose.prod.yml up -d vault

   # First boot only — creates root token + unseal keys. Store offline; never commit.
   docker compose -f docker-compose.prod.yml exec vault \
     vault operator init -key-shares=5 -key-threshold=3 -format=json > vault-credentials.json
   chmod 600 vault-credentials.json

   jq -r '.unseal_keys_b64[]' vault-credentials.json > vault-unseal-keys
   chmod 600 vault-unseal-keys

   # Put root token in .env for the one-time AppRole init (and future reseeds)
   echo "VAULT_TOKEN=$(jq -r .root_token vault-credentials.json)" >> .env
   chmod 600 .env
   ```

5. **Unseal Vault, configure AppRole, then start the stack:**
   ```bash
   # Unseal (also required after every host reboot — Vault seals on restart)
   docker compose -f docker-compose.prod.yml --profile ops run --rm vault-unseal

   # One-time: enable AppRole, write vault/role-id + vault/secret-id, seed prod.secrets
   docker compose -f docker-compose.prod.yml --profile init run --rm vault-init

   docker compose -f docker-compose.prod.yml up -d --build
   ```
   Vault Agent authenticates with **AppRole** (`vault/role-id`, `vault/secret-id`), not with the root token. Do not commit those files or `vault-credentials.json` / `vault-unseal-keys`. Init writes them mode `600` under `./vault/` (`0700` directory). Keep them host-private; agent renders application secrets into a **tmpfs** at `/run/secrets`, not onto `./data`.

6. **Firewall:** Allow SSH (22), UI (80 or 443), and API (8443) as needed. Vault is bound to `127.0.0.1:8200` only—do not publish it publicly.

7. **TLS (recommended for browser/UI):** Put a reverse proxy (e.g. Caddy or nginx) in front; terminate HTTPS there and proxy to the UI and API containers. Keep garde’s `use_tls` **false** (or enable built-in TLS if preferred — browsers no longer need client certs for login). Set `cookie_secure=true` and `trusted_proxies` to the proxy when TLS is terminated at the edge. Set `PUBLIC_API_URL` and `CORS_ALLOW_ORIGINS` to your public URLs and rebuild the UI container. See [TLS and mTLS](#tls-and-mtls-configuration).

**After reboot:** Vault comes back sealed. Unseal before (or while) bringing dependents up:
```bash
docker compose -f docker-compose.prod.yml up -d vault
docker compose -f docker-compose.prod.yml --profile ops run --rm vault-unseal
docker compose -f docker-compose.prod.yml up -d
```

**Ongoing operations** (single-VPS stack):

- **Updates:** Pull (or rsync) the latest code, then run `docker compose -f docker-compose.prod.yml up -d --build` (unseal first if Vault was restarted).
- **Logs:** `docker compose -f docker-compose.prod.yml logs -f garde` (or `ui`, `vault-agent`, `vault`, etc.).
- **Restarts:** `docker compose -f docker-compose.prod.yml restart garde` (or another service name).
- **Reseed secrets:** edit `prod.secrets`, ensure Vault is unsealed and `VAULT_TOKEN` is set, then `docker compose -f docker-compose.prod.yml --profile init run --rm vault-init`.
- **Rotate AppRole after compromise:** with Vault unsealed and a root (or AppRole-admin) token, mint a new secret-id, replace `./vault/secret-id` (`chmod 600`), restart `vault-agent`, and destroy old secret-ids when possible. See [Vault Security Notes](../vault/README.md#security-notes).

> [!IMPORTANT]
> Production Vault requires offline credentials (`vault-credentials.json`). On the multi-node path with AWS KMS auto-unseal, day-to-day reboots do not need Shamir keys; keep recovery keys for break-glass. The single-VPS Compose stack below still uses Shamir unseal after reboot. Losing credentials without a backup means permanent loss of access to the Vault data volume.
### Required mandatory secrets in Vault
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/database_url` **or** discrete `postgres_host` / `postgres_port` / `postgres_user` / `postgres_password` / `postgres_db` (/ `postgres_sslmode`) | PostgreSQL durable store (single-VPS Compose: `postgres_host=postgres`) |
| `secret/garde/redis_host` | Redis server hostname (for single-VPS Docker Compose: use `redis`, the Compose service name) |
| `secret/garde/redis_port` | Redis server port |
| `secret/garde/redis_password` | Redis authentication password |
| `secret/garde/redis_tls` | Optional. `true` to use TLS for Redis (also implied when `REDIS_URL` starts with `rediss://`). Default `false` for local Compose Redis. |
| `secret/garde/domain_name` | Your domain (for cookies and TLS) |
| `secret/garde/superuser_email` | Superuser account email (The user is auto-created) |
| `secret/garde/superuser_password` | Superuser password (The user is auto-created) |
| `secret/garde/mfa_encryption_key` | **Required.** Key used to encrypt MFA TOTP secrets at rest. Any string (SHA-256'd to 32 bytes) or base64-encoded 32-byte key. Changing it does not re-encrypt existing MFA secrets. |

### TLS and mTLS configuration

garde serves two audiences with opposite needs, and each has its own switch.
They are easy to confuse, so start here:

| Audience | What it needs | Setting | Default |
|----------|---------------|---------|---------|
| **Browsers / UI** | HTTPS, and **never** a client certificate prompt | `browser_mtls` | `off` |
| **Your services calling `/validate`** | A client certificate **and** an API key, on a private path | `service_mtls` | `required` |
| **External callers of `/validate`** | HTTPS and a key issued to them alone, with no certificate to maintain | `public_validate` | unset (endpoint is private) |

One process-wide switch cannot do both: a listener that demands certificates
cannot serve a login page, and a listener that never asks for one cannot
authenticate a service. So garde can run two listeners.

#### Recommended production layout (browser + services)

1. **Browsers and the web UI** talk HTTPS only to a reverse proxy or load balancer (Caddy, nginx, ALB, …). It forwards to garde over the private network (Compose network / localhost). Do **not** expose Redis, PostgreSQL, or Vault publicly.
2. Leave **`secret/garde/use_tls` = `false`** on the browser-facing listener (or enable built-in TLS if you prefer HTTPS on garde itself). Set **`cookie_secure=true`** and **`trusted_proxies`** to the proxy CIDR when TLS is terminated at the edge. Leave **`browser_mtls` = `off`**.
3. Set **`cookie_same_site`** for your topology: `strict` when UI and API share a site; `lax` (default) when they are different origins (common in dev); `none` when you need cross-site cookies (requires Secure cookies over HTTPS).
4. **Turn on the service listener** so `/validate` leaves the public hostname entirely:

| Secret | Value |
|--------|-------|
| `service_listener` | `true` |
| `service_port` | `8444` |
| `service_mtls` | `required` |
| `service_tls_cert_path` | `/app/certs/service-cert.pem` |
| `service_tls_key_path` | `/app/certs/service-key.pem` |
| `service_tls_ca_path` | `/app/certs/ca-cert.pem` |

Generate the CA and certificates with Vault PKI (preferred — Agent auto-renews
the server leaf):

```bash
# First bring-up: init-vault-prod.sh already runs PKI enable when you seed Vault.
# Or on the operator host:
./deploy/scripts/vault-pki.sh enable
# Client certs for calling services (server leaf comes from Vault Agent):
./deploy/scripts/vault-pki.sh issue-client <service-name>
# After Agent renews a leaf, restart garde if needed:
./deploy/scripts/service-tls-reload.sh --remote
```

Offline openssl fallback: `deploy/scripts/service-pki.sh`.
Each caller also needs an issued API key from `POST /admin/api-keys`.

> [!IMPORTANT]
> Terminating TLS at a proxy means client certificates never reach garde. If
> your edge terminates TLS and you leave `/validate` on the public listener, it
> is protected by an API key alone. That is why enabling `service_listener`
> moves the endpoint by default.

#### External callers of `/validate`

Some callers are not yours: they cannot join your private network, and asking
them to install and renew a client certificate is how partner integrations
break. For those, set `public_validate` = `true` and issue each caller its own
key with `POST /admin/api-keys` (superuser only).

On every `/validate` listener — public or private — garde accepts **per-caller
keys only**. Internal services on the mesh still present mTLS client
certificates **and** an issued key.

Per-tenant keys are stored as a SHA-256 (the plaintext is shown once, at
issue), expire after 90 days unless issued otherwise, carry a per-key rate
limit, record when they were last used, and are revocable one at a time with
`DELETE /admin/api-keys/{key_id}` or all at once for a single holder with
`DELETE /admin/tenants/{tenant_id}/api-keys`. See
[External Callers](API_INTEGRATION_GUIDE.md#4-external-callers-per-tenant-api-keys).

In a deployment fronted by the multi-node Caddy config, the edge blocks `/validate`
independently, so publishing it also takes `PUBLIC_VALIDATE=true` in the
inventory. Two switches, so that one mistaken value cannot expose the endpoint.

#### Single-listener deployments (the older layout)

Without `service_listener`, `/validate` stays on the main listener and still
requires an issued per-caller key (`POST /admin/api-keys`). Optional mTLS on
that path follows `use_tls` + `tls_ca_path` / `browser_mtls` as before.

#### Browser client certificates

`browser_mtls` accepts `off`, `optional` or `required`, and needs `use_tls` plus
`tls_ca_path`. Use `required` only on a hostname that exists to serve
certificate holders — on a public login page it locks out every user who does
not have one. The service listener is unaffected either way.

**Cookies:** `Secure` follows `COOKIE_SECURE` when set; otherwise it is true if `USE_TLS` is true, or if `COOKIE_SAME_SITE=none`. Behind an HTTPS reverse proxy with `use_tls=false`, set `cookie_secure=true`.

**Client IP:** Set `TRUSTED_PROXIES` to your reverse-proxy CIDR(s) so `X-Forwarded-For` is honored. When unset, forwarded headers are ignored (prevents ClientIP spoofing).

> [!IMPORTANT]
> For a public UI, prefer edge TLS and `use_tls=false` with `cookie_secure=true` and `trusted_proxies` set to the proxy — and put `/validate` on the service listener rather than leaving it on the public one.

**Server TLS materials (required when `use_tls=true`):**
- Valid TLS certificate from a trusted CA
- Certificate chain with intermediate certificates
- SAN including all domain variants
- Client CA used to verify service client certificates on `/validate`

**Required Vault secrets (built-in TLS / mTLS):**
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/use_tls` | `true` to enable built-in HTTPS |
| `secret/garde/tls_cert_path` | Path to server certificate |
| `secret/garde/tls_key_path` | Path to server private key |
| `secret/garde/tls_ca_path` | Path to client CA (enables mTLS checks on `/validate`) |

> [!NOTE]
> Without built-in `use_tls`, cookie/session authentication still works. Put HTTPS at your reverse proxy for production browser traffic. Service-call mTLS does not depend on `use_tls` at all when the service listener is on: that listener always speaks TLS and has its own certificates.

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
| `secret/garde/rate_limit` | IP/user rate limiting with a configurable sliding window: `public_limit,window_seconds[,authenticated_limit[,admin_limit]]` (e.g., `100,60,200,500` = 100 req/60s public, 200 authenticated, 500 admin). Use `0,0` to disable. Separate from rapid-request detection. |
| `secret/garde/rapid_request_config` | User-based rapid request detection (fixed 1-minute sliding window) with role-aware thresholds: `max_per_min,min_interval_ms` (e.g., `120,10` means 120 requests per minute with 10ms minimum interval). Admins get 3x threshold, superusers get 5x threshold. Use `0,0` to disable. |
| `secret/garde/enable_swagger` | Expose Swagger UI at `/swagger/index.html`. Default `false`. Enable for local exploration only. |
| `secret/garde/disable_user_agent_check` | Disable UA validation (known bot/automation agents). Legitimate API clients such as curl are allowed when this check is on. |
| `secret/garde/disable_ip_blacklisting` | Disable automatic IP blocking |
| `secret/garde/disable_multiple_ip_check` | Disable concurrent session IP detection |
| `secret/garde/cookie_same_site` | Session cookie SameSite: `lax` (default), `strict`, or `none`. Use `strict` when UI and API are same-site; `lax` when different origins (e.g. dev); `none` for cross-site cookies (needs HTTPS so the cookie can be Secure). See [TLS and mTLS](#tls-and-mtls-configuration). |
| `secret/garde/cookie_secure` | Optional. `true`/`false` to force the cookie `Secure` flag. When unset: follows `use_tls`, or forced true if `cookie_same_site=none`. Set `true` behind HTTPS reverse proxies with `use_tls=false`. |
| `secret/garde/trusted_proxies` | Optional. Comma-separated proxy CIDRs/IPs trusted for `X-Forwarded-For`. When unset, forwarded headers are ignored. |
| `secret/garde/testing_mode` | Set to `true` to relax mTLS checks (e.g. for testing). Do not use in production. |
| `secret/garde/browser_mtls` | Client certificates on the public listener: `off` (default), `optional`, `required`. Needs `use_tls` and `tls_ca_path`. Leave `off` for anything browsers reach. |
| `secret/garde/service_listener` | `true` to serve `/validate` on a separate private listener. Moves it off the public listener unless `public_validate` says otherwise. |
| `secret/garde/service_port` | Port for that listener. Default `8444`; must differ from `port`. |
| `secret/garde/service_mtls` | `required` (default) or `off`. `off` leaves `/validate` on the API key and the network alone. |
| `secret/garde/service_tls_cert_path`, `…_key_path`, `…_ca_path` | The listener's keypair and the CA that signs callers. Required when `service_listener` is `true`. |
| `secret/garde/public_validate` | Also serve `/validate` on the public listener, for external callers. Defaults to the opposite of `service_listener`. Callers present issued per-tenant keys (`POST /admin/api-keys`). |

**Admin Configuration**:
| Secret Path | Description |
|-------------|-------------|
| `secret/garde/admin_users_json` | JSON object: `{"admin1@example.com":"Pass1!","admin2@example.com":"Pass2!"}`. Admins are auto-created/updated at startup and on secret reload. Public/admin-created signup cannot create these accounts. |
| `secret/garde/admin_scopes_json` | Optional. JSON object of email→scope list, e.g. `{"helpdesk@example.com":["garde:users:read","garde:users:write"]}`. Narrows what the admins it names may do on the admin routes. Known scopes: `garde:users:read`, `garde:users:write`, `garde:users:delete`, `garde:sessions:revoke`. An admin with no entry keeps all four. An explicit `[]` denies all four. Every address must also appear in `admin_users_json` or startup fails. |

Admin scopes are provisioned here rather than through the admin API on purpose: an admin's own authorization data must not live somewhere an admin can write it. Superusers are unaffected — they hold every scope and may not be listed.

**Permissions & Groups**:
- Permission/group catalog, visibility, user membership, and credentials live in **PostgreSQL**. Sessions and other short-lived state stay in **Redis**.
- Configure via `DATABASE_URL` or `POSTGRES_*` secrets (see vault/README.md). Schema is applied by embedded migrations at startup.
- **Privilege tiers vs permissions:** Superuser/Admin/User (from Vault email lists) are bootstrap privilege tiers. Named permissions + groups are application access rights. See [Permission and Group Management](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md#5-permission-and-group-management) for the full model, admin matrix, and a request→approve walkthrough.
- Superusers can manage permissions, groups, and visibility mappings via API endpoints (see [Superuser-Only Permission and Group Management](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md#f-superuser-only-permission-and-group-management) in the integration guide).

> [!TIP]
> On AWS, `terraform/aws/rds.tf` can provision Multi-AZ Postgres; seed the endpoint into Vault after apply.

**Logging:** `secret/garde/log_level` (DEBUG/INFO/WARN/ERROR), `secret/garde/gin_mode` (debug/release)

### Configuration hot reload

Vault Agent (or a manual edit under `/run/secrets`) updates secret files; garde reloads the **in-memory map** automatically. That does **not** mean every setting rebinds at runtime.

#### Applies live (no restart)

| Secret / key | Behavior |
|--------------|----------|
| Per-tenant API keys | Issued, revoked and rate-limited through the admin API, not through Vault; changes take effect on the caller's next request |
| `cors_allow_origins` | Read on each request |
| `cookie_same_site`, `cookie_secure` | Applied when setting/clearing session cookies |
| `domain_name` | Cookie domain + mTLS CN/SAN checks |
| `enforce_mfa`, `testing_mode` | Read on relevant auth/mTLS paths |
| `disable_user_agent_check`, `disable_ip_blacklisting`, `disable_multiple_ip_check` | Read when those checks run |
| `smtp_*` | Read when sending mail |
| `mfa_encryption_key` | Used for new encrypt/decrypt calls (**does not** re-encrypt existing MFA secrets). **Required** at startup |
| `redis_*` | Reload hook reconnects the Redis client |
| `database_url`, `postgres_*` | Reload hook rebuilds the Postgres pool so rotated credentials take effect |
| `superuser_email`, `superuser_password`, `admin_users_json` | Reload hook re-runs bootstrap (password rotations apply). Reloads that fail `ValidateConfig` (weak password, missing required keys, …) are **rejected** and the previous secret map is kept |
| `admin_scopes_json` | Resolved per request, so scope changes apply to the admin's next call. A reload that leaves it unparseable denies every scoped admin route until it is fixed, rather than restoring full admin access |
| `gin_mode` | Reload (and startup) call `gin.SetMode` from the secret — Gin does not read `/run/secrets` on its own |

#### Requires process restart

| Secret / key | Why |
|--------------|-----|
| `use_tls`, `tls_cert_path`, `tls_key_path`, `tls_ca_path`, `port` | HTTP/TLS listener and cert material are bound at startup |
| `browser_mtls`, `service_mtls`, `public_validate` | The client-certificate policy is part of the handshake configuration, and which routes exist is decided when the listeners are built |
| `service_listener`, `service_port`, `service_tls_*` | Same: a second listener is opened, or not, at startup |
| `trusted_proxies` | Gin trusted-proxy list is set once on the engine |
| `rate_limit` | Numeric thresholds are parsed into the rate-limiter struct at startup |
| `rapid_request_config` | Parsed once into package-level thresholds at startup |
| `enable_swagger` | Swagger routes are registered only at startup |
| `log_level` | Logger level is configured at startup |

**Ops tip:** After rotating TLS material, trusted proxies, rate limits, rapid-request thresholds, or log level, restart the `garde` container/process. After rotating only API keys, CORS, cookies, SMTP, feature flags, or admin passwords, a Vault Agent rewrite of `/run/secrets` is enough.

> [!NOTE]
> `RATE_LIMIT=0` / `0,0` is inspected in some middleware paths live, but changing from e.g. `100,60` to `200,60` still needs a restart.

### Web UI (production)

- **Single VPS (Docker Compose):** The UI runs in the `ui` container; set `PUBLIC_API_URL` and `CORS_ALLOW_ORIGINS` as described in [Single VPS production](https://github.com/erendemirel/garde/blob/master/vault/README.md#single-vps-production-docker-compose--ui-in-separate-container).
- **Other deployments:** Build the UI with the API URL, then serve the built files yourself (e.g. nginx, CDN). Set `PUBLIC_API_URL` at build time:
  ```bash
  export PUBLIC_API_URL=https://your-api-domain.com
  cd web && bun run build
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
