# Deploying garde on three hosts (HA)

A production layout with Vault HA, a warm application standby, and a single
control point in GitHub Actions. Hosting and DNS follow `PROVIDER` (netcup,
AWS, …) — see [Switching hosting provider](#switching-hosting-provider).

This is one of several ways to run garde. If you want a single VPS with one
Compose file, use [Deploying to a VPS](INSTALLATION.md#deploying-to-a-vps)
instead — everything here is heavier, and it only pays off if you actually need
to survive losing a host.

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
- [Runbook: failover](#runbook-failover)
- [Runbook: rebuilding after failover](#runbook-rebuilding-after-failover)
- [HA infra test suite](#ha-infra-test-suite)
- [AWS bring-up checklist](AWS_BRINGUP.md)
- [What is not automated](#what-is-not-automated)

---

## What this gives you

| Failure | Result |
|---------|--------|
| A Vault member restarts | Cluster keeps serving; AWS/KMS auto-unseals that member |
| One host dies | Vault keeps quorum (2 of 3); app fails over in ~30-90s |
| The primary app node dies | Scripted cutover: Redis promoted, IP moved, standby serves |
| All three hosts reboot | AWS: auto-unseal via KMS; other providers: Shamir unseal ceremony |

It does **not** give you zero downtime. Failover is a short, controlled outage,
and netcup rate-limits the failover IP to one reassignment per 301 seconds, so
the direction of a cutover is a decision you make once and live with for at
least five minutes.

---

## Topology

```
                       Internet
                          │
                 [ failover IP ]  ── routed to the primary
                          │
        ┌─────────────────▼─────────────────┐
        │ node1   app-primary               │
        │  caddy (only public listener)     │
        │  garde + vault-agent              │
        │  redis PRIMARY                    │
        │  permissions.db (writer)          │
        │  vault raft member 1              │
        └────────────┬──────────────────────┘
                     │  WireGuard mesh 10.10.0.0/24
        ┌────────────┴───────────┬─────────────────────────┐
        ▼                        ▼                         
 node2  app-standby        node3  witness                  
  caddy (warm, DNS-01)      vault raft member 3            
  garde (warm, no traffic)  prometheus + grafana           
  redis REPLICA             snapshot target                
  permissions.db (copy)                                    
  vault raft member 2                                      
```

Sizing: give node1 and node2 enough CPU for TLS termination and Argon2 password
hashing; node3 only needs a Vault member and monitoring.

Everything except Caddy's 80/443 is bound to the WireGuard address. Redis,
Vault, the metrics exporters and SSH are unreachable from the internet.

---

## Design decisions worth knowing

**Each garde talks to its own local Redis and its own local Vault member.**
Vault Raft followers forward to the leader transparently, and the standby's
Redis becomes writable the moment it is promoted. That means failover changes
no secret and no config — only the IP moves and Redis is promoted. There is no
`redis_host` to rewrite and no Vault reseed.

**Both app nodes hold the failover IP, all the time.** Routing the IP in the
netcup panel is only half the operation: if the target host has not configured
the address on its interface, the kernel drops the packets and the cutover
achieves nothing. The Ansible baseline binds it as a `/32` on both app nodes, so
the standby is already able to serve when the route lands. Only one node ever
receives traffic, so holding it on both costs nothing and keeps configuration
out of the emergency path.

**Certificates are issued over DNS-01, not HTTP-01.** The standby never holds
the public IP, so it could not answer an HTTP-01 challenge, and its certificates
would expire exactly when failover needs them. **DNS follows the hosting
provider:** Caddy renews against that provider's DNS API (netcup CCP, AWS Route
53, …) so both app nodes can renew independently without holding the failover
address. All of this applies to the floating-IP lane; under a managed load
balancer the platform owns the certificate and none of it exists — see
[Traffic modes](#traffic-modes-floating-ip-or-managed-load-balancer).

**`/validate` is not on the public edge.** It validates any user's session for
any caller with the API key, so it answers on a second listener published on
the mesh address only, behind a client certificate from a private CA. Browsers
are never asked for one. See
[Service authentication](#service-authentication-validate).

**No registry.** CI builds images and streams them with `docker save` over SSH
into `docker load` on the far side. The hosts hold no registry credentials, no
source code and no compiler.

**Auto-unseal on AWS.** With `PROVIDER=aws`, Terraform creates a KMS CMK and an
EC2 instance profile; inventory carries `VAULT_KMS_KEY_ID`. Vault uses
`seal "awskms"` so members unseal themselves after reboot. Recovery keys from
init stay offline for break-glass only — they never enter GitHub. Non-AWS
providers keep Shamir and still use `unseal.sh` after a restart.

**The hosting provider sits behind one seam.** Everything provider-specific
*about compute and traffic* reaches the outside world through three verbs —
route traffic to a node, report where traffic is, set a host's power — plus
five declared facts. Drivers live in `deploy/scripts/providers/`; `netcup`,
`hetzner`, `ovh`, `ionos`, `scaleway`, `aws` and `gcp` ship today, selected by
`PROVIDER` in the inventory. Nothing outside that directory names a compute
provider.

The verbs are intent rather than mechanism: "route traffic to this node", not
"assign the failover IP". A floating IP is how the VPS providers do it; the AWS
and GCP drivers can instead repoint a managed load balancer, selected by
`TRAFFIC_MODE`, and the callers cannot tell the difference. The facts exist
because providers differ in *properties*, not only
behaviour — netcup enforces 301 seconds between traffic moves and Hetzner
enforces nothing, so the driver declares the number and the generic code waits
for it. That is why `failover.sh` contains no provider conditionals at all.

Policy never lives in a driver. Ordering, fencing, verification and the cooldown
wait are identical whoever the host is; a driver that made those decisions would
give you subtly different failover behaviour per provider, discoverable only
during an incident.

**Ansible owns the hosts, scripts own the procedures.** The split is between
"a state to converge on" and "an ordered sequence with decisions in it".
Package sets, users, firewall rules and the snapshot timer are the former, so
they live in `ansible/` and are safe to re-apply at any time. Deploying,
initialising Vault and failing over are the latter — a failover has to fence
before it promotes — so they stay as scripts in `deploy/scripts/`. Ansible also
never runs from CI: it needs root, and CI deliberately only holds a non-sudo
key.

**DNS lives with the hosting provider, not behind the compute seam.** Failover
moves the address under stable `app.` / `api.` names; Terraform only creates
those A records (and never owns failover routing). Each provider has its own
small DNS surface — Route 53 inside `terraform/aws/` — plus a matching Caddy
`acme_dns` module selected by
`PROVIDER` (override with `DNS_PROVIDER` only if the zone truly lives
elsewhere). DNS API credentials are separate from compute credentials.

**SQLite stays SQLite.** `permissions.db` is around 40 KB of rarely changing
catalog. It is snapshotted with `VACUUM INTO`, which produces a consistent file
while the app runs, and shipped to the other nodes. Recovery point equals the
snapshot interval; sessions and users live in Redis and replicate continuously.

---

## Prerequisites

- Three hosts (Ubuntu 24.04 or similar) on the chosen provider — see
  [Switching hosting provider](#switching-hosting-provider)
- One movable public address (failover IP / Elastic IP / floating IP) that DNS
  will point at
- A domain on **that provider's DNS** (netcup CCP nameservers, Route 53, …) so
  ACME DNS-01 and the A records share one API
- On your workstation: `bash`, `wg`, `rsync`, `jq`, `docker`, `ssh`, and
  `ansible` (2.15+) with `ansible-galaxy collection install -r ansible/requirements.yml`
- A GitHub repository with Actions enabled

Ansible is an operator tool here, not a CI one. It owns the host baseline —
packages, Docker, the `deploy` user, WireGuard, the firewall, the snapshot
timer — and runs as `root` from your workstation. Deploys, the Vault ceremony
and failover stay in `deploy/scripts/`, because those are ordered procedures
with decisions in them rather than a state to converge on.

---

## First-time setup

### 1. Fill in the inventory

```bash
cp deploy/inventory.example.env deploy/inventory.env
$EDITOR deploy/inventory.env
```

Set the public IPs, the netcup SCP server ids (`GET /servers`), your domains and
the failover IP. Everything else has a working default.

### 2. Generate the WireGuard mesh

```bash
./deploy/scripts/wg-gen.sh
```

This writes `deploy/.wg/` (gitignored): one config per node, `ci.conf` for the
GitHub runner and `ops.conf` for your workstation. Keep `deploy/.wg/keys/`
offline.

Bring up your own peer before going any further:

```bash
sudo cp deploy/.wg/ops.conf /etc/wireguard/wg0.conf
sudo wg-quick up wg0
```

This is not optional. The next step closes public SSH, after which the mesh is
the only way to reach a host — Vault init/migration, baseline re-runs and the
initial ceremony all happen from your workstation.

### 3. Bootstrap the hosts

```bash
cd ansible
ansible-playbook playbooks/bootstrap.yml \
  -e use_mesh=false \
  -e deploy_pubkey_file=~/.ssh/garde_deploy.pub
```

`use_mesh=false` tells the playbook to connect over the public IPs as `root`,
which is the only route that exists before the mesh comes up. It installs
Docker and WireGuard, creates the `deploy` user, brings up the mesh and closes
the firewall on all three hosts. Every run after this one connects over the
mesh, so drop the flag:

```bash
ansible-playbook playbooks/bootstrap.yml                 # converge all three
ansible-playbook playbooks/bootstrap.yml --limit node2   # one host
ansible-playbook playbooks/bootstrap.yml --check --diff  # show drift, change nothing
```

The playbook reads `deploy/inventory.env` through `ansible/inventory-to-json.sh`,
so the topology is defined in exactly one place. There is no separate Ansible
inventory to keep in sync — which matters most after a failover, when the roles
have moved.

The `deploy` user it creates deliberately has **no sudo**. That account is what
CI authenticates as, and it only needs the Docker socket. Privileged host
changes go through this playbook as `root` instead, so a leaked CI key cannot
reconfigure a machine.

### 4. Start the Vault cluster

```bash
IMAGE_TAG=bootstrap ./deploy/scripts/deploy.sh vault --no-ship
```

All three members start and report as uninitialised.

### 5. Initialise Vault (once, by a human)

```bash
cp dev.secrets prod.secrets
$EDITOR prod.secrets           # production values, see the next section
./deploy/scripts/vault-cluster-init.sh --secrets prod.secrets
```

This initialises the cluster, brings all three members to unsealed (KMS or
Shamir), creates the AppRole, distributes credentials to the app nodes and
seeds secrets.

It writes `vault-credentials.json` in the repository root. **Move it offline and
delete the local copy.** Losing recovery/unseal keys means losing break-glass
access permanently. On AWS, day-to-day reboots use KMS; the file is still
required for generate-root / rekey.

### 6. Point DNS at the failover IP

DNS follows `PROVIDER`. Failover never updates these records — it only moves
the address underneath them.

**AWS** (Route 53 inside `terraform/aws/` — set `dns_zone` or `dns_zone_id`):

```bash
cd terraform/aws
# dns_zone = "example.com"  in terraform.tfvars
terraform apply
terraform output dns_nameservers   # delegate the registrar if the zone is new
terraform output -raw acme_access_key_id
terraform output -raw acme_secret_access_key   # store as AWS_ACME_* secrets
```

For other compute providers, create the app/api A records in that provider’s
DNS panel (or its own Terraform root) pointing at `FAILOVER_IP`. There is no
separate netcup Terraform root in this repo anymore.

Then route traffic to the primary once:

```bash
./deploy/scripts/traffic.sh route node1
./deploy/scripts/traffic.sh status
```

On providers that route rather than NAT the address, the bootstrap playbook has
already bound it on both app nodes. `traffic.sh route` refuses to proceed if
the target has not bound it.

### 7. Configure GitHub

**Secrets:**

| Secret | Contents |
|--------|----------|
| `DEPLOY_INVENTORY` | The whole `deploy/inventory.env` file |
| `DEPLOY_SSH_KEY` | Private deploy key (e.g. contents of `~/.ssh/garde_deploy`, including `BEGIN`/`END` lines and real newlines) |
| `DEPLOY_KNOWN_HOSTS` | Host keys pinned the same way SSH will check them. **AWS/GCP (tunnel):** lines must start with `garde-node1`, `garde-node2`, `garde-node3` (see `~/.ssh/known_hosts` on the operator host after a successful `on_node`). **Mesh providers:** mesh IPs from `ssh-keyscan`. Wrong form → “unreachable” with no useful earlier error |
| `WG_CI_CONF` | Contents of `deploy/.wg/ci.conf` |
| `REDIS_PASSWORD` | Same value as `REDIS_PASSWORD` in `prod.secrets` |
| `NETCUP_CUSTOMER_NUMBER`, `NETCUP_API_KEY`, `NETCUP_API_PASSWORD` | netcup DNS-01 + Terraform DNS (`PROVIDER=netcup`) |
| `NETCUP_SCP_REFRESH_TOKEN` | netcup driver: traffic routing and power control |
| `HCLOUD_TOKEN` | Hetzner Cloud driver, if `PROVIDER=hetzner` |
| `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY` | OVHcloud driver, if `PROVIDER=ovh` |
| `IONOS_TOKEN` | IONOS Cloud driver, if `PROVIDER=ionos` |
| `SCW_SECRET_KEY` | Scaleway driver, if `PROVIDER=scaleway` |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | AWS compute driver (EIP / fence / tunnel / S3). **Repository** secrets if Snapshot (no Environment) should see them — Environment-only secrets under `production` are invisible to scheduled Snapshot runs |
| `AWS_ACME_ACCESS_KEY_ID`, `AWS_ACME_SECRET_ACCESS_KEY` | AWS Route 53 DNS-01 for Caddy (from `terraform output acme_*`) |
| `GCP_SERVICE_ACCOUNT_KEY` | Google driver, if `PROVIDER=gcp`; the workflow writes it to a file and points `GOOGLE_APPLICATION_CREDENTIALS` at it |
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin |

**Variables:** `API_DOMAIN` (used by the deploy workflow), plus `DNS_ZONE` and
`FAILOVER_IP` (used by the infra workflow). `AWS_REGION`, `AWS_IMAGE_BUCKET` and
`GOOGLE_CLOUD_PROJECT` if you deploy to either hyperscaler — also as
**repository** variables when Snapshot needs them.

`WG_CI_CONF` is not required on AWS or GCP: the runner does not join the mesh
there. Their credentials are set at job level rather than on the deploy step,
because on those providers even checking whether a host is reachable means
opening an authorised tunnel.

If `SSH_OPTS` in the inventory pins `-i /root/.ssh/...` (or another
workstation path), that is fine for local ops; `mesh-access` rewrites
`IdentityFile` / `UserKnownHostsFile` to the runner's `~/.ssh/id_ed25519` so
the same `DEPLOY_INVENTORY` secret works in Actions.

`API_DOMAIN` is duplicated here and in the inventory on purpose: the build job
bakes it into the UI bundle before the inventory secret is loaded. The two must
agree, or the UI ships pointing at the wrong API.

**Environments:** create `production` and `failover`, both with required
reviewers. `failover` causes an outage, so it should never run unattended.

Get the SCP refresh token once with:

```bash
curl -s -X POST 'https://www.servercontrolpanel.de/realms/scp/protocol/openid-connect/token' \
  -d 'client_id=scp' -d 'grant_type=password' -d 'scope=offline_access openid' \
  -d 'username=<customer-number>' -d 'password=<scp-password>' | jq -r .refresh_token
```

It lasts 30 days of inactivity. Consider whitelisting source IPs under
**REST API Settings** in the SCP; note that GitHub runners have dynamic
addresses, so a whitelist means running those scripts from a node instead.

### 8. Deploy everything

```bash
./deploy/scripts/build-images.sh
IMAGE_TAG=<tag> ./deploy/scripts/deploy.sh all
```

Or run the **Deploy** workflow with `stack: all`. From here on, CI is the normal
path.

### 9. Confirm the snapshot timer

Snapshots are scheduled **on the hosts** (provider VMs), not by GitHub.

The bootstrap playbook installs `garde-snapshot.timer` on both app nodes.
Only the Redis **master** actually runs `VACUUM INTO` and pushes copies; the
standby's timer is armed but no-ops until failover promotes Redis there. That
keeps RPO ≈ `SQLITE_SNAPSHOT_INTERVAL` (default 5 minutes) without depending on
GitHub cron, and without re-running Ansible after a cutover.

```bash
ssh deploy@10.10.0.1 systemctl list-timers garde-snapshot.timer
# or from the control plane:
on_node node1 'systemctl list-timers garde-snapshot.timer --no-pager'
```

The snapshot procedure itself lives on the host at
`/opt/garde/scripts/snapshot.sh`. Both the timer and
`deploy/scripts/sqlite-snapshot.sh` run that same script, so `VACUUM INTO` and
the integrity check exist in one place. Copies travel node to node over the
mesh using per-node keys the playbook generates and authorises; they never pass
through the CI runner.

The **Snapshot and verify** GitHub Action is a **secondary** net only (every
six hours + manual). It needs the same tunnel/mesh secrets as Deploy. Do not
treat its schedule as the recovery-point mechanism.
---

## Vault secrets for this topology

Beyond the [required secrets](INSTALLATION.md#required-mandatory-secrets-in-vault),
these values are specific to running behind Caddy on the mesh:

| Secret | Value | Why |
|--------|-------|-----|
| `redis_host` | `redis` | Each node has its own local Redis under that service name |
| `use_tls` | `false` | The edge terminates TLS; the public listener speaks HTTP inside the network |
| `browser_mtls` | `off` | Browsers must never be asked for a client certificate |
| `cookie_secure` | `true` | Traffic is HTTPS even though garde speaks HTTP |
| `trusted_proxies` | `172.28.0.0/16` | The fixed app network subnet, so `X-Forwarded-For` is honoured |
| `domain_name` | your registrable domain | Makes `app.` and `api.` same-site for cookies, **and** is what client certificates are checked against |
| `cors_allow_origins` | `https://app.example.com` | The UI origin |
| `cookie_same_site` | `lax` | Subdomains of one registrable domain are same-site |
| `service_listener` | `true` | Serves `/validate` on a second, private listener |
| `service_mtls` | `required` | Calling services authenticate with a certificate, not only an API key |
| `service_tls_cert_path` | `/app/certs/service-cert.pem` | Written by `service-pki.sh push` |
| `service_tls_key_path` | `/app/certs/service-key.pem` | Written by `service-pki.sh push` |
| `service_tls_ca_path` | `/app/certs/ca-cert.pem` | The service CA that signs callers |

`public_validate` is deliberately absent: with `service_listener` on, garde
stops serving `/validate` on the public listener unless you set it to `true`.
Leave it out unless you have callers who are not yours — see
[external callers](#external-callers-per-tenant-api-keys), which is the only
configuration where publishing it is a reasonable thing to do.

Reseed after changing `prod.secrets` by re-running `vault-cluster-init.sh`'s
seeding step, or by writing individual keys with `vault kv put`.

---

## Service authentication (`/validate`)

`/validate` answers "is this session valid?" for any session, to any caller
holding the API key. That makes it the most powerful endpoint garde has and the
one that should be hardest to reach — so it does not answer on the hostname
browsers use.

```
browsers ──► public edge (TLS) ──► UI + auth API        no client certificate
services ──► WireGuard mesh ──► garde:8444 /validate    client certificate + API key
```

The two audiences have independent policies, because one switch cannot serve
both: a listener that demands certificates cannot serve a login page, and a
listener that never asks for one cannot authenticate a service.

| Setting | Audience | Default | Notes |
|---------|----------|---------|-------|
| `browser_mtls` | public listener | `off` | `optional` / `required` only for a host that exists to serve certificate holders |
| `service_mtls` | service listener | `required` | `off` is accepted and logged as a warning; the endpoint then rests on the API key and the mesh alone |
| `public_validate` | public listener | follows `service_listener` | Mounting `/validate` publicly again |

Caddy refuses `/validate` on the public hostname regardless, so both the
application config and the edge have to be wrong before the endpoint is
exposed.

### Issuing the certificates

The service CA is separate from the public one on purpose: a certificate that
proves a website's identity to a browser should not also authenticate a service
to your auth server.

```bash
./deploy/scripts/service-pki.sh init            # once; back up deploy/pki/ca-key.pem offline
./deploy/scripts/service-pki.sh server          # the listener's keypair
./deploy/scripts/service-pki.sh push            # to both app nodes
./deploy/scripts/service-pki.sh client billing  # one per calling service
```

The CA private key stays on the operator host. Nodes get the CA certificate and
the listener keypair; each caller gets its own client keypair, revocable by
re-issuing the CA and re-pushing.

Client certificates carry the deployment's registrable domain in the CN,
because garde checks it against `domain_name` before accepting a call. A
certificate from this CA issued for a different domain is refused.

### Calling it

```bash
curl --cert client-billing-cert.pem --key client-billing-key.pem --cacert ca-cert.pem \
     -H "X-API-Key: $API_KEY" \
     -H "X-Session-ID: $SESSION_ID" \
     "https://10.10.0.1:8444/validate"
```

Address the node by its mesh IP: the listener certificate covers every mesh
address in the cluster, so the same command works after a failover with only
the address changed.

### External callers: per-tenant API keys

Everything above assumes the caller is yours: it sits on the mesh, and you can
install a certificate next to it. A third party can do neither. Handing them a
client certificate they have to renew is how partner integrations break at 3am,
and certificate lifecycle is not a skill you can require of every customer.

So external callers get the other standard answer — server TLS, and a bearer
credential that belongs to them alone:

```bash
curl -X POST https://api.example.com/admin/api-keys \
     -H "Authorization: Bearer $SUPERUSER_SESSION" \
     -H 'Content-Type: application/json' \
     -d '{"tenant_id":"acme","name":"acme-prod","scopes":["validate"],"rate_limit":600}'
```

The response carries the plaintext key once, and never again — only its
SHA-256 is stored. Scopes have to be listed; there is no default grant. The key
expires after 90 days unless `expires_in` says otherwise or `never_expires` is
set deliberately.

`GET /admin/api-keys` lists what has been issued with each key's last-used
time, `?tenant_id=acme` narrows it to one holder, and revocation works at
either grain: `DELETE /admin/api-keys/{key_id}` for one key, or
`DELETE /admin/tenants/{tenant_id}/api-keys` for everything a compromised
holder has.

Because `tenant_id` groups keys, rolling a credential needs no downtime: issue
a second key for the same holder, let the caller cut over, then revoke the
first.

| | Internal services | External tenants |
|---|---|---|
| Reaches | mesh listener, `:8444` | public edge |
| Authenticates with | client certificate + shared `api_key` | per-tenant key, `X-API-Key` |
| Revoking one caller | re-issue the CA, re-push, restart | one `DELETE`, effective immediately |
| Revoking a whole holder | same, cluster-wide | one `DELETE` on the client |
| Credential lifetime | certificate validity | 90 days by default, one year maximum |
| Rate limited by | mesh access | the key, so tenants behind one NAT do not share a budget |

**The shared `api_key` does not work on the public edge.** That is the point of
the split: a single long-lived secret held by every caller, in front of an
endpoint that can validate any user's session, is the exposure this design
exists to remove. It stays valid on the mesh listener, where callers are yours
and present a certificate as well.

Publishing the endpoint takes two switches, so that neither alone is enough:

```bash
PUBLIC_VALIDATE=true          # in deploy/inventory.env — opens Caddy
vault kv put secret/garde/public_validate value=true   # mounts the route
```

Leave `public_validate_shared_key` unset in this layout. It exists for
single-listener deployments, which have to state whether the shared key may
authenticate their public `/validate`
([the older layout](INSTALLATION.md#single-listener-deployments-the-older-layout)).
Here the mesh listener has already answered that, so setting it to `true` is a
startup error rather than something quietly ignored.

`healthcheck.sh --public` follows the inventory value: with `PUBLIC_VALIDATE`
unset it fails if `/validate` answers at all, and with it set it fails unless
an unauthenticated call is refused with 401.

---

## Traffic modes: floating IP or managed load balancer

`TRAFFIC_MODE` in the inventory decides what "route traffic to this node"
means. The failover procedure does not change — fence, promote Redis, route
traffic, verify — because the driver hides the mechanism.

| | `floating_ip` (default) | `managed_lb` |
|---|---|---|
| Providers | all seven | `aws`, `gcp` |
| Public address | one address, moved between hosts | held by the balancer |
| Public TLS | Caddy on the hosts, ACME **DNS-01** | ACM / Google-managed, on the balancer |
| Standby readiness | warm: both nodes hold the address and renew certificates | warm: the standby is simply an unregistered target |
| Routing | provider API moves the address | target registration / backend membership |
| A broken primary | an operator or a drill triggers failover | health checks pull it out, then failover promotes Redis |
| Cost | none beyond the address | balancer hours |

**Why both exist.** DNS-01 and a warm Caddy are what make a floating IP work
for a standby that never holds the public address, and that design ports to
every VPS provider unchanged. On AWS and GCP the same design costs real
machinery — hosts with no public address, tunnels for SSH, images staged
through a bucket — to reproduce something the platform already offers. Rather
than pick one, the seam carries both: use the platform's answer on the
platforms that have one, and keep the portable answer everywhere else.

**What does not change between them.** The mesh, Vault Raft, Redis
replication, snapshots, fencing before promotion, and the private service
listener. The security model is identical; only the public edge differs.

### Switching to `managed_lb` on AWS

```bash
cd terraform/aws
# terraform.tfvars
#   traffic_mode = "managed_lb"
#   dns_zone     = "example.com"      # needed so ACM can validate
terraform apply
terraform output -raw inventory_fragment >> ../../deploy/inventory.env
```

The fragment carries `TRAFFIC_MODE`, `AWS_TARGET_GROUP_ARN`, `LB_SOURCE_CIDRS`
and `LB_TRUSTED_PROXIES`. Then re-run the host baseline and a deploy, and point
the balancer at the primary:

```bash
cd ansible && ansible-playbook playbooks/bootstrap.yml   # firewall follows the mode
./deploy/scripts/deploy.sh app
./deploy/scripts/traffic.sh route node1
./deploy/scripts/healthcheck.sh --all --public
```

What changes on the hosts: `sync-config.sh` renders `Caddyfile.lb.tpl` instead
of the ACME one, binds Caddy's 443 to loopback, and opens :80 to the balancer's
range only. Terraform stops creating the ACME IAM user, since nothing answers a
challenge any more.

Terraform deliberately creates no target group attachments. Membership is
operational state that failover owns; a Terraform-managed attachment would
fight `traffic.sh` on every apply.

### `managed_lb` on GCP

The driver implements the same verbs with one zonal unmanaged instance group
per node, all attached to a single backend service, and routing means making
sure only one group holds its instance:

```
NODE1_INSTANCE_GROUP=europe-west1-b/garde-node1
NODE2_INSTANCE_GROUP=europe-west1-c/garde-node2
LB_SOURCE_CIDRS="35.191.0.0/16 130.211.0.0/22"
LB_TRUSTED_PROXIES="35.191.0.0/16 130.211.0.0/22"
```

There is no `terraform/gcp/` root in this repository: GCP has always been a
driver rather than a provisioned module here. Build the load balancer, the
Google-managed certificate and the two instance groups with `gcloud` or your
own Terraform, then fill those keys in. The health check must target `/healthz`
on port 80, which is what the load-balancer Caddyfile serves.

---

## Day-to-day operations

| Task | Command |
|------|---------|
| Deploy everything | **Deploy** workflow, `stack: all` |
| Deploy only the app | **Deploy** workflow, `stack: app` |
| Deploy to one node | **Deploy** workflow with `node: node2` |
| See what would change | **Deploy** workflow with `dry_run: true` |
| Check health | `./deploy/scripts/healthcheck.sh --all --public` |
| Where is traffic pointed? | `./deploy/scripts/traffic.sh status` |
| Power a host on/off | `./deploy/scripts/power.sh node1 off` |
| Snapshot now | **Snapshot and verify** workflow |
| Change host config | Edit `ansible/roles/…`, then `ansible-playbook playbooks/bootstrap.yml` |
| Audit host drift | `ansible-playbook playbooks/bootstrap.yml --check --diff` |
| Rotate AppRole after leak | See [Runbook: rotate AppRole secret-id](#runbook-rotate-approle-secret-id) |
| Logs | `ssh deploy@10.10.0.1 'cd /opt/garde && docker compose -f compose/app.yml -p garde-app logs -f garde'` |
| Grafana | Tunnel to `10.10.0.3:3000` over the mesh |

Deploys update the standby app node before the primary, so a bad build is caught
on the node that serves no traffic. Vault members are updated one at a time so
quorum survives.

---

## Runbook: unsealing Vault

### AWS (KMS auto-unseal)

After a normal reboot, members unseal themselves. If one stays sealed, check
instance profile, IMDS hop limit (≥2), and KMS permissions — do not put unseal
keys into CI.

Migrating an existing Shamir cluster:

```bash
# After terraform apply + inventory has VAULT_KMS_KEY_ID
./deploy/scripts/sync-config.sh --all
# Immediately migrate — any Vault restart with awskms in config but
# without -migrate leaves that member sealed until migration finishes.
VAULT_UNSEAL_KEYS_FILE=/path/to/shamir-keys ./deploy/scripts/vault-seal-migrate.sh
```

`VAULT_UNSEAL_KEYS_FILE` must be line-oriented Shamir keys (one b64 share per
line), not the raw `vault-credentials.json`. Extract with:
`jq -r '.unseal_keys_b64[]' vault-credentials.json > /secure/path/keys.txt`.

### Shamir (non-AWS, or pre-migration)

A member is sealed after any restart. The cluster keeps serving while two of
three are unsealed, so this is urgent but not an emergency.

```bash
./deploy/scripts/unseal.sh node2          # prompts for 3 of 5 keys
./deploy/scripts/unseal.sh --all
```

The script refuses to run in CI. Keys come from your prompt or from a file you
point `VAULT_UNSEAL_KEYS_FILE` at; they never go into GitHub.

If all three are sealed, unseal them one by one — the first one back becomes the
leader and the others rejoin.

---

## Runbook: rotate AppRole secret-id

AppRole credentials on app nodes (`$REMOTE_ROOT/vault/role-id` and
`secret-id`) are long-lived machine identities (`secret_id_ttl=0`, kept after
agent read). That is intentional for reboot survival; protect the host files
(`vault/` `0700`, credentials `600`) and rotate when they may be leaked.

```bash
# From a workstation with Vault access (root token or AppRole admin policy):
ROLE_ID=$(vault read -field=role_id auth/approle/role/garde/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/garde/secret-id)

# On each app-primary / app-standby node:
#   printf '%s' "$ROLE_ID"   > /opt/garde/vault/role-id
#   printf '%s' "$SECRET_ID" > /opt/garde/vault/secret-id
#   chmod 700 /opt/garde/vault && chmod 600 /opt/garde/vault/role-id /opt/garde/vault/secret-id
#   cd /opt/garde && docker compose -f compose/app.yml -p garde-app restart vault-agent

# Destroy accessors for old secret-ids when your Vault build lists them:
#   vault list auth/approle/role/garde/secret-id
#   vault write -f auth/approle/role/garde/secret-id/destroy secret_id=<old>
```

Re-running `./deploy/scripts/vault-cluster-init.sh` also redistributes a fresh
secret-id (and re-seeds secrets). Prefer the targeted mint+copy above if you
only need credential rotation. Application secrets stay on the agent’s **tmpfs**
(`/run/secrets`); Vault itself stays on the mesh — never publish `:8200`
publicly.

---

## Runbook: failover

**Before you start:** failing over may be one-way for a cooldown the provider
declares (netcup: 301 seconds; AWS/Hetzner: none). Confirm the primary is
genuinely unhealthy rather than briefly slow.

Run the **Failover** workflow with a reason, or from a workstation:

```bash
./deploy/scripts/failover.sh --reason "node1 host failure"
./deploy/scripts/failover.sh --dry-run          # checks only, changes nothing
./deploy/scripts/failover.sh --power-off        # old primary unreachable
```

What happens, in order:

1. **Verify** the standby is warm, has Vault quorum and a recent snapshot
   (and, on providers that route rather than NAT, that the failover address is
   bound on the target)
2. **Fence** the old primary so it cannot keep writing
3. **Install** the newest `permissions.db` snapshot on the new primary
4. **Promote** Redis there, permanently (`REPLICAOF NO ONE` plus rewriting
   `redis.conf`)
5. **Move** the failover IP through the provider driver
6. **Verify** traffic location (and `https://$API_DOMAIN/health` when DNS is real)

Fencing comes before promotion deliberately. Two live primaries diverge, and
nothing merges a split brain afterwards. If the old primary is unreachable over
the mesh, the script stops rather than guessing — `--power-off` stops the
server through the provider API, which is the only fencing left when SSH is
gone.

**Immediately afterwards**, `failover.sh` updates `PRIMARY_NODE` /
`STANDBY_NODE` and the matching `NODE*_ROLE` values in a writable
`inventory.env`. Still update the `DEPLOY_INVENTORY` secret to match. If you
skip the secret, the next CI deploy can render the wrong Redis role.

Then re-run the baseline so the host-level pieces follow the roles:

```bash
cd ansible && ansible-playbook playbooks/bootstrap.yml
```

That converges host state (firewall, deploy keys, …). The snapshot timer is
already armed on both app nodes; after Redis promotion the new master starts
snapshotting on the next timer tick without waiting for this playbook. Still
run bootstrap when you need other role-tied host state updated.

Until Redis is promoted on the new primary, the only on-demand snapshots you
get are from `sqlite-snapshot.sh` or the GitHub **Snapshot and verify**
workflow (secondary safety net).

---

## Runbook: rebuilding after failover

Once the old primary is healthy again, it becomes the new standby.

1. Bring the host back. On AWS with KMS, Vault auto-unseals; on Shamir, run
   `./deploy/scripts/unseal.sh <node>`. Re-run the baseline playbook if the
   host was rebuilt from scratch.
2. Confirm the inventory lists it as standby (`NODE*_ROLE=app-standby`,
   `STANDBY_NODE=...`). `failover.sh` updates these when it can write
   `inventory.env`; still update the `DEPLOY_INVENTORY` secret.
3. Demote Redis so the revived host cannot stay a second master. A powered-off
   primary keeps its old primary `redis.conf` and comes back with an in-memory
   master role; `sync-config` will not overwrite that file, and `compose up`
   will not restart a running Redis:

```bash
./deploy/scripts/redis-replicate.sh node1   # former primary
./deploy/scripts/sync-config.sh node1
./deploy/scripts/deploy.sh app --node node1
```

4. Verify: `./deploy/scripts/healthcheck.sh --all` should show one master, one
   replica with `link up`, and no split-brain warning.

Failing back later is a normal failover in the other direction — same script,
same cooldown.

---

## HA infra test suite

Live-cluster drills live under `deploy/tests/`. Suites:

| Suite | Path | Impact |
|-------|------|--------|
| Bring-up / doctor | `deploy/tests/bringup/` | None — bring-up.sh offline + doctor |
| Deploy verification | `deploy/tests/deploy/` | None — mesh, health, roles, EIP location, snapshot, dry-run |
| HA / failover | `deploy/tests/ha/` | Mixed — see table below |

```bash
export REDIS_PASSWORD=... ASSUME_YES=true
export VAULT_UNSEAL_KEYS_FILE=/path/to/unseal-keys.txt   # hard / vault drills
export SUPERUSER_EMAIL=... SUPERUSER_PASSWORD=...       # auth drills

./deploy/tests/run.sh bringup          # bring-up offline + doctor
./deploy/tests/run.sh deploy           # post-deploy smoke
./deploy/tests/run.sh all-safe         # bringup + deploy + ha no-outage + service-stays-up
./deploy/tests/run.sh ha soft
./deploy/tests/run.sh ha hard
```

HA blast-radius slices:

| Suite | Impact | Examples |
|-------|--------|----------|
| `no-outage` | None | healthcheck, failover `--dry-run` |
| `service-stays-up` | App stays up | stop Vault on witness or Raft leader |
| `soft` | Brief planned cutover | soft fence round-trip; auth + SQLite/Redis RPO |
| `hard` | Brief planned cutover | provider `power.sh off` + `--power-off` failover |

See `deploy/tests/README.md`, `deploy/tests/bringup/README.md`,
`deploy/tests/deploy/README.md`, and `deploy/tests/ha/README.md`.


---

## Switching hosting provider

### Which product to buy

Every one of these vendors sells two things that look interchangeable and are
not. The drivers target the API-driven one in each case; its neighbour is a
different API that the driver will not talk to.

| `PROVIDER` | Buy this | Not this | Traffic move |
|---|---|---|---|
| `netcup` | VPS / root server + failover IP | — | seconds, then **301s locked** |
| `hetzner` | **Cloud** (CCX for dedicated vCPU) | dedicated/Robot: 90–110s | seconds, no cooldown |
| `ovh` | **VPS** | dedicated, Public Cloud | ~1–2 minutes |
| `ionos` | **Cloud** (DCD, API v6) | shared-hosting VPS range | detach + attach |
| `scaleway` | **Instances** | Elastic Metal | seconds, no cooldown |
| `aws` | **EC2** + an Elastic IP | — | seconds, atomic |
| `gcp` | **Compute Engine** + a static external IP | — | release + attach |

netcup's cooldown is the one that shapes operations rather than just timing: a
cutover is one-way for five minutes, so you commit to the direction. The others
let you fail straight back, which lowers the stakes of deciding to fail over at
all.

Only AWS moves the address atomically: one call disassociates and reassociates
it, so it is never held by nobody. IONOS and GCP genuinely release it first,
leaving a window where the address is unattached and a failed second step leaves
the site dark. That window is what each driver's declared propagation time
covers.

Placement is constrained on four. OVH refuses to move an Additional IP between
services in different countries and Scaleway cannot cross a zone, so keep those
hosts together. AWS and GCP are the opposite: their addresses move freely across
availability zones within one region but never across regions, so spread the
three hosts across zones and keep them in one region.

AWS and GCP are also the two where a moving address is not what the platform
would suggest. Both answer this problem natively with a managed load balancer,
which is why those two drivers also accept `TRAFFIC_MODE=managed_lb`. If you
are building for one of them and nothing else, that is the better tool — the
balancer holds the address and the certificate, and none of the placement rules
above apply to it. Keep `floating_ip` when portability across providers matters
more. See [Traffic modes](#traffic-modes-floating-ip-or-managed-load-balancer).

### Doing the move

The shell tooling is provider-neutral, so most of a move is inventory edits:

1. `PROVIDER=<name>` and the matching `NODE*_PROVIDER_ID` values. The id format
   is whatever that provider uses — a `vXXXXXXXX` string, a numeric id, a
   service name, or the `<datacenterId>/<serverId>/<nicId>` triple IONOS needs.
   Only the driver interprets it.
2. `FAILOVER_IP`, and `FAILOVER_IP_ID` if you prefer not to resolve by address.
3. Supply that provider's credentials (see the secrets table above).
4. Re-run the bootstrap playbook. It reads `PROVIDER_REQUIRES_IP_BINDING` from
   the driver and configures — or skips — the host-side address binding.

Step 4 is not a formality. The providers split into two families:

- **Routed** — netcup, Hetzner and OVH hand the address to a host that must
  already carry it on its interface. Both app nodes bind it permanently, so the
  standby can serve the instant the route lands.
- **Delivered** — IONOS attaches the reserved IP to a NIC, Scaleway configures
  it inside the guest via `scw-net-reconfig`, and AWS and GCP never put it on
  the guest at all: they translate it to the instance's private address, so
  `ip addr` inside the machine shows only that. Binding it statically would put
  one address on two machines, and on Scaleway would fight the agent that
  removes it on detach.

That difference is the `PROVIDER_REQUIRES_IP_BINDING` fact. The four delivered
providers declare `false` and the playbook skips the `failover_ip` role for
them; the three routed ones declare `true` and get it.

### AWS and GCP: hosts with no public address

One constraint applies to both hyperscalers and to none of the VPS providers,
and it changes how the cluster is reached.

On a VPS provider a host has its own permanent public address *and* may hold the
failover address at the same time. On EC2 and Compute Engine it cannot: an
instance's primary interface gets one public IPv4, and attaching the failover
address takes that slot. A node that becomes primary would lose its own public
address, and the node that was primary would lose public reachability entirely.

The resolution is to stop wanting per-node public addresses. On these two
providers the hosts have **none**, and the only public address in the deployment
is the failover address itself, held by whichever node is currently primary.
That splits into two questions the seam now answers separately.

**How nodes reach each other.** Put all three hosts in one VPC and set
`NODE*_MESH_ENDPOINT` to their private addresses. WireGuard still carries all
node-to-node traffic — Vault Raft, Redis replication, snapshot transfer — but
peers over addresses that a failover never touches. `NODE*_PUBLIC_IP` is left
unset.

**How you reach them.** Not over the mesh: with no public endpoint to dial, a
roaming peer has nothing to connect to. Instead each provider's own identity-
aware tunnel carries SSH, and the tooling opens one per connection:

| | AWS | GCP |
| --- | --- | --- |
| Mechanism | EC2 Instance Connect Endpoint | IAP TCP forwarding |
| Authorised by | IAM | IAM |
| Agent on the host | none | none |
| Cost | free | free |
| Arrives from | the endpoint's ENI, in your VPC | `35.235.240.0/20` |

`wg-gen.sh` notices this and generates no `ci.conf` or `ops.conf` — there are no
roaming peers to generate them for. `sshd` is never reachable from the internet
on any node, which is a stronger position than the VPS providers end up in.

Set `ADMIN_SSH_SOURCES` to your subnet CIDR on AWS, so the firewall admits the
tunnel. GCP needs nothing: IAP's range is fixed and the driver declares it.
`load_provider` refuses to start on AWS without it rather than let you apply a
firewall that locks the tunnel out.

**Images do not go through the tunnel.** Both providers document theirs as
administrative rather than bulk transport. So these drivers declare
`PROVIDER_IMAGE_TRANSPORT=url`: CI stages the compressed image in object storage
and hands the host a URL that expires in fifteen minutes, which the host fetches
with `curl` and pipes into `docker load`. Set `AWS_IMAGE_BUCKET` or
`GCP_IMAGE_BUCKET`, and give the network a free private path to the bucket — an
**S3 gateway endpoint** on AWS, **Private Google Access** on GCP — since the
instances have no public address and no NAT gateway.

This keeps the property the registry-free design existed to protect: the hosts
still hold no credential. A presigned URL carries no identity of its own and is
useless once it expires, which is not true of a registry login.

The tunnels are free, the gateway endpoint and Private Google Access are free,
and nothing extra runs on the hosts. Public IPv4 is the cost: AWS bills every
public address, including Elastic IPs, at roughly $3.60 a month. Expect about
$11 a month for a three-host cluster, on top of the instances.

That is three addresses rather than one, because of a constraint worth
understanding before you design the network. **An Elastic IP only works in a
subnet whose route table points at an internet gateway** — the address is
translated there, and return traffic must leave the same way. So the app nodes
cannot sit behind a NAT gateway or NAT instance: a NAT default route and an
internet-gateway default route are the same entry in one table, and a subnet has
only one. The node *not* holding the failover address would then have no route
out at all, and it still needs to install packages and renew its own
certificates. Giving each node an auto-assigned public address solves that, and
costs the two extra addresses.

They do not conflict. Associating the failover address replaces whatever public
address the instance had, and releasing it removes public connectivity until the
instance is stopped and started — which is exactly what fencing does, so a
demoted node returns with a fresh address of its own.

#### Provisioning it

`terraform/aws/` builds all of the above: the VPC and its three subnets, both
security groups, the Instance Connect Endpoint, three instances, the Elastic IP,
the staging bucket with its gateway endpoint and expiry rule, a CI user whose
policy is scoped to exactly the calls the driver makes, and — when `dns_zone`
(or `dns_zone_id`) is set — Route 53 `app`/`api` A records plus a separate ACME
IAM user for Caddy DNS-01.

```
cd terraform/aws
cp terraform.tfvars.example terraform.tfvars    # bucket, SSH key, dns_zone=
./bring-up.sh                                   # init + apply + merge inventory
# or: terraform init && terraform apply
#     terraform output -raw inventory_fragment >> ../../deploy/inventory.env
```

Track what is done (infra through app) without needing a working UI:

```
./deploy/scripts/doctor.sh
```

See [AWS bring-up checklist](AWS_BRINGUP.md) for the full automated vs manual list.

DNS for AWS is Route 53 in this same module.
The module deliberately does not manage the Elastic IP
*association* after creation — `ignore_changes` covers it, because Terraform
and `failover.sh` both believing they decide where traffic goes would mean the
next `apply` quietly reverting a failover.

#### DNS path (every provider)

DNS is **not** behind `deploy/scripts/providers/`. Compute failover moves an
address; public names stay put. The supported path is always “this provider’s
own DNS”:

| Surface | What you change when adding a provider |
| --- | --- |
| `deploy/images/caddy/Dockerfile` | `xcaddy --with` that vendor’s `caddy-dns/*` module |
| `deploy/scripts/sync-config.sh` | `acme_dns` branch + node `.env` credentials |
| Terraform | A records for `app`/`api` → `FAILOVER_IP` (never `_acme-challenge`) |
| CI secrets | DNS API keys, separate from compute keys |

Supported DNS wiring today: **netcup** and **aws** (Route 53). Other compute
drivers still move traffic; add their DNS row before expecting public HTTPS.

Adding a **compute** provider means one new file in `deploy/scripts/providers/`
implementing the three verbs and declaring the five facts. `load_provider()`
verifies the contract at load time, so a half-implemented driver fails
immediately rather than two steps into a failover.

Three further facts have defaults, so a driver declares them only when it
differs. All three describe how the control plane reaches a host, which turned
out to vary more between providers than traffic routing does:

| Fact | Default | Non-default meaning |
| --- | --- | --- |
| `PROVIDER_ADMIN_ACCESS` | `mesh` | `tunnel`: hosts have no public address; the provider brokers the connection. Requires `provider_admin_host()` and `provider_admin_proxy_command()` |
| `PROVIDER_IMAGE_TRANSPORT` | `ssh` | `url`: stage the image and let the host fetch it. Requires `provider_publish_image()` |
| `PROVIDER_ADMIN_SSH_SOURCES` | empty | the fixed range a tunnel arrives from, where the provider publishes one |

The contract check extends to these: a driver claiming `tunnel` without the two
access verbs is rejected at load, and so is a `tunnel` driver with no SSH source
from either the driver or the inventory — that combination would produce a
firewall that locks you out of your own hosts.

Drivers may bring their own tool requirements, checked in `provider_preflight`
so a missing one is a clear error rather than a strange failure. Most need only
`curl` and `jq`; `aws` needs the AWS CLI and `gcp` needs `gcloud`, both already
present on GitHub's `ubuntu-latest` runners but not necessarily on yours.

---

## What is not automated

Deliberately, because the failure modes are worse than the toil:

- **Vault recovery keys.** Shamir unseal keys (non-AWS) and KMS recovery keys
  stay with humans; they never enter GitHub. AWS day-to-day unseal is KMS.
- **Failure detection.** Nothing decides on its own that the primary is dead.
  Prometheus alerts, a person judges, the workflow executes. Automatic failover
  on a two-node application tier is a reliable way to cause split brain during a
  network blip.
- **Failing back.** Same reason, plus the 301-second cooldown.
- **Server provisioning.** netcup has no API for ordering servers.
- **Vault Raft snapshots.** `vault operator raft snapshot save` needs a
  privileged token; take them manually or with a dedicated AppRole before risky
  changes.

Run a game-day failover before you depend on any of this. An untested failover
plan is a hypothesis.
