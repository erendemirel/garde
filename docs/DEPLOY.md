# Deploying garde (active-active)

A production layout with Vault HA, **identical app nodes** behind a public edge,
shared PostgreSQL (durable) and shared Redis (ephemeral), and a single control
point in GitHub Actions. Hosting and DNS follow `PROVIDER` (netcup, AWS, …).

This is one of several ways to run garde. If you want a single VPS with one
Compose file, use [Deploying to a VPS](INSTALLATION.md#deploying-to-a-vps)
instead.

## Table of Contents

- [What this gives you](#what-this-gives-you)
- [Topology](#topology)
- [Design decisions worth knowing](#design-decisions-worth-knowing)
- [Prerequisites](#prerequisites)
- [First-time setup](#first-time-setup)
- [Vault secrets for this topology](#vault-secrets-for-this-topology)
- [Service authentication (`/validate`)](#service-authentication-validate)
- [Traffic modes: floating IP or managed load balancer](#traffic-modes-floating-ip-or-managed-load-balancer)
- [Day-to-day operations](#day-to-day-operations)
- [Runbook: unsealing Vault](#runbook-unsealing-vault)
- [Runbook: rotate AppRole secret-id](#runbook-rotate-approle-secret-id)
- [AWS bring-up checklist](AWS_BRINGUP.md)
- [What is not automated](#what-is-not-automated)

---

## What this gives you

| Failure | Result |
|---------|--------|
| A Vault member restarts | Cluster keeps serving; AWS/KMS auto-unseals that member |
| One app host dies | Remaining healthy app nodes keep serving (ALB / remaining capacity) |
| Shared Redis blips | Sessions/ephemeral data may be lost; durable state stays in Postgres |
| Shared Postgres outage | App `/ready` fails; restore from RDS Multi-AZ / backups |
| All three hosts reboot | AWS: auto-unseal via KMS; other providers: Shamir unseal ceremony |

App nodes are active-active against shared PostgreSQL and Redis. Durable writes
go to Postgres; sessions and other ephemeral state go to Redis.

---

## Topology

```
                       Internet
                          │
              [ public ALB  or  floating IP ]
                          │
        ┌─────────────────┴─────────────────┐
        │                                   │
   node1  app                          node2  app
    caddy + garde + vault-agent         (identical)
    vault raft member                   vault raft member
        │                                   │
        └──────────── WireGuard ────────────┘
                          │
                    node3  witness
                     vault raft + prometheus/grafana

   Shared (outside app hosts):
     PostgreSQL  — durable authority (RDS Multi-AZ or external)
     Redis       — sessions / ephemeral (ElastiCache or external)
```

Sizing: give app nodes enough CPU for TLS termination and Argon2 hashing; the
witness only needs a Vault member and monitoring. Prefer managed Redis and
Postgres in the same VPC (see `terraform/aws/rds.tf` and `elasticache.tf`).

Everything except Caddy's public ports is bound to the WireGuard address or the
private VPC. Vault, metrics, SSH and the `/validate` service listener are not on
the public edge.

---

## Design decisions worth knowing

**Every app node talks to the same Redis and the same PostgreSQL.** Endpoints
come from Vault (`redis_host`, `DATABASE_URL` / `POSTGRES_*`).

**Certificates:** DNS-01 on floating-IP providers so every app node can renew
without holding the edge address; under `managed_lb` the platform owns TLS.

**`/validate` is not on the public edge by default.** It answers on the mesh
service listener behind a client certificate. See
[Service authentication](#service-authentication-validate).

**No registry.** CI builds images and streams them with `docker save` over SSH.

**Auto-unseal on AWS.** `VAULT_KMS_KEY_ID` + instance profile; non-AWS keeps Shamir.

**The hosting provider sits behind one seam** (`deploy/scripts/providers/`).
Traffic verbs still exist for floating-IP moves and for registering LB targets.

**Ansible owns the hosts, scripts own the procedures.** Packages, users,
firewall and WireGuard live in `ansible/`. Deploy and Vault init stay in
`deploy/scripts/`.

---

## Prerequisites

- At least one app host and one witness (Ubuntu 24.04 or similar) — typically three
- Shared PostgreSQL and shared Redis reachable from every app node
- For AWS: prefer `traffic_mode = "managed_lb"` (ALB + multi-target)
- A domain on the provider's DNS for ACME / alias records
- Workstation: `bash`, `wg`, `rsync`, `jq`, `docker`, `ssh`, `ansible` (2.15+)
- A GitHub repository with Actions enabled

---

## First-time setup

### 1. Fill in the inventory

```bash
cp deploy/inventory.example.env deploy/inventory.env
$EDITOR deploy/inventory.env
```

Set node IPs, roles (`app` / `witness`), domains, and traffic mode. Seed Redis
and Postgres into Vault (not into the inventory).

### 2. Generate the WireGuard mesh

```bash
./deploy/scripts/wg-gen.sh
sudo cp deploy/.wg/ops.conf /etc/wireguard/wg0.conf
sudo wg-quick up wg0
```

### 3. Bootstrap the hosts

```bash
cd ansible
ansible-playbook playbooks/bootstrap.yml \
  -e use_mesh=false \
  -e deploy_pubkey_file=~/.ssh/garde_deploy.pub
# later runs:
ansible-playbook playbooks/bootstrap.yml
```

The playbook allows **N identical app nodes** plus at least one witness. It no
longer installs snapshot timers or failover-IP roles.

### 4–5. Vault cluster + init

```bash
IMAGE_TAG=bootstrap ./deploy/scripts/deploy.sh vault --no-ship
cp dev.secrets prod.secrets
$EDITOR prod.secrets
./deploy/scripts/vault-cluster-init.sh --secrets prod.secrets
```

Move `vault-credentials.json` offline.

### 6. Point DNS / register edge

- **AWS `managed_lb`:** Terraform creates ALB + alias records; app instances are
  attached to the target group. Health checks remove broken nodes.
- **floating_ip:** point `app`/`api` at `FAILOVER_IP`, then
  `./deploy/scripts/traffic.sh route <app-node>`.

### 7. Configure GitHub secrets/vars

Same shape as before (`DEPLOY_INVENTORY`, `DEPLOY_SSH_KEY`, `DEPLOY_KNOWN_HOSTS`,
`WG_CI_CONF` where needed, DNS-01 and compute credentials, `REDIS_PASSWORD`,
`GRAFANA_ADMIN_PASSWORD`). There is no failover or snapshot workflow.

### 8. Deploy the app stack

```bash
./deploy/scripts/deploy.sh all
./deploy/scripts/healthcheck.sh --all --public
```

Compose health probes HTTPS then HTTP on `127.0.0.1:8443/ready` (works with or without built-in TLS).

---

## Vault secrets for this topology

| Secret | Typical value | Notes |
|--------|---------------|--------|
| `redis_host` | ElastiCache primary endpoint (or external Redis hostname) | **Not** the old local compose service name on multi-node |
| `redis_port` | `6379` | |
| `redis_password` | AUTH token | Same as CI `REDIS_PASSWORD` when used for tooling |
| `redis_tls` | `true` for ElastiCache in-transit encryption | Optional; also set when using a `rediss://` URL |
| `database_url` **or** `postgres_host` + `postgres_*` | RDS / external Postgres | Required for durable state |
| `postgres_sslmode` | `require` on RDS | Optional if using `database_url` |
| other keys | as in `dev.secrets` / INSTALLATION.md | Unchanged |

Terraform outputs `postgres_endpoint` and `redis_primary_endpoint` when you pass
`postgres_password` / `redis_auth_token` into `terraform/aws`.

---

## Service authentication (`/validate`)

Mesh mTLS listener by default; optional `PUBLIC_VALIDATE=true` for external
tenants. Every caller presents an issued per-caller API key.

**PKI automation:** `init-vault-prod.sh` enables the Vault PKI mounts/roles.
Vault Agent renders and renews the server leaf into
`/run/secrets/service_tls_*.pem` (`pkiCert` templates). Cron
`deploy/scripts/service-tls-reload.sh` restarts garde after renew (TLS is
bound at process start). Client certs: `vault-pki.sh issue-client <name>`.
Offline openssl: `service-pki.sh`.

---

## Traffic modes: floating IP or managed load balancer

| | `floating_ip` | `managed_lb` (preferred on AWS) |
|--|---------------|----------------------------------|
| Address | One IP, operator-routed | ALB owns the address |
| TLS | Caddy DNS-01 on hosts | ACM on the ALB |
| App capacity | One node holds the IP at a time | Multiple healthy app targets |

Active-active data access does not depend on the edge mode: every app node can
serve once registered / holding the address.

---

## Day-to-day operations

```bash
./deploy/scripts/deploy.sh app
./deploy/scripts/healthcheck.sh --all --public
./deploy/scripts/doctor.sh
./deploy/tests/run.sh all-safe
```

CI: `.github/workflows/deploy.yml` (cluster-mutation concurrency). Unit tests
use Postgres 16 and `CGO_ENABLED=0`.

---

## Runbook: unsealing Vault

AWS/KMS: wait for auto-unseal. Shamir: `./deploy/scripts/unseal.sh <node>` with
offline keys.

## Runbook: rotate AppRole secret-id

Generate a new secret-id on the Vault leader, redistribute to every **app** node
under `$REMOTE_ROOT/vault/secret-id`, restart `vault-agent` / `garde` on those
nodes. See vault/README.md Security Notes.

---

## What is not automated

- Creating the shared Postgres/Redis outside Terraform (or seeding Vault after
  Terraform creates them)
- Registrar NS delegation
- First Vault init ceremony and offline key custody
- Issuing service **client** certificates to calling services (`vault-pki.sh issue-client`)
- Issuing per-caller `/validate` API keys (`POST /admin/api-keys`) and distributing them to services
- (Server leaf renew is Agent-automated; `service-tls-reload.sh` still needs cron or a manual run after renew)
