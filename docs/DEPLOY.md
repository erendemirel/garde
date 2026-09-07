# Deploying garde on three netcup hosts

A production layout with Vault HA, a warm application standby, and a single
control point in GitHub Actions.

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
- [Day-to-day operations](#day-to-day-operations)
- [Runbook: unsealing Vault](#runbook-unsealing-vault)
- [Runbook: failover](#runbook-failover)
- [Runbook: rebuilding after failover](#runbook-rebuilding-after-failover)
- [What is not automated](#what-is-not-automated)

---

## What this gives you

| Failure | Result |
|---------|--------|
| A Vault member restarts | Cluster keeps serving; that member needs unsealing |
| One host dies | Vault keeps quorum (2 of 3); app fails over in ~30-90s |
| The primary app node dies | Scripted cutover: Redis promoted, IP moved, standby serves |
| All three hosts reboot | Manual unseal ceremony, then everything comes back |

It does **not** give you zero downtime. Failover is a short, controlled outage,
and netcup rate-limits the failover IP to one reassignment per 301 seconds, so
the direction of a cutover is a decision you make once and live with for at
least five minutes.

---

## Topology

```
                       Internet
                          │
                 [ netcup failover IP ]  ── routed to the primary
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

Sizing: netcup **RS** (dedicated cores) suits node1 and node2, which carry TLS
termination and Argon2 password hashing. A **VPS** is enough for node3, which
runs a Vault member and monitoring.

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
would expire exactly when failover needs them. Caddy is built with the netcup
DNS module so both nodes renew independently.

**No registry.** CI builds images and streams them with `docker save` over SSH
into `docker load` on the far side. The hosts hold no registry credentials, no
source code and no compiler.

**No auto-unseal.** There is no cloud KMS in this setup, so a restarted Vault
member must be unsealed by a human. With three members that is not an outage:
the other two hold quorum. Unseal keys never enter GitHub — a workflow input is
visible in run metadata.

**The hosting provider sits behind one seam.** Everything provider-specific
reaches the outside world through three verbs — route traffic to a node, report
where traffic is, set a host's power — plus five declared facts. Drivers live in
`deploy/scripts/providers/`; `netcup`, `hetzner`, `ovh`, `ionos` and `scaleway`
ship today, selected by `PROVIDER` in the inventory. Nothing outside that
directory names a provider.

The verbs are intent rather than mechanism: "route traffic to this node", not
"assign the failover IP". A floating IP is how both current providers do it, but
that naming leaves room for a driver that swaps a DNS record or repoints a load
balancer. The facts exist because providers differ in *properties*, not only
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

**Terraform manages DNS only.** netcup cannot create servers through its API,
and letting Terraform own the failover IP would mean a plan/apply cycle in the
middle of an emergency, plus state that fights the failover script.

**SQLite stays SQLite.** `permissions.db` is around 40 KB of rarely changing
catalog. It is snapshotted with `VACUUM INTO`, which produces a consistent file
while the app runs, and shipped to the other nodes. Recovery point equals the
snapshot interval; sessions and users live in Redis and replicate continuously.

---

## Prerequisites

- Three netcup servers (Ubuntu 24.04 or similar), ordered manually
- One netcup **failover IP** with `editable: true`, ordered as an add-on
- A domain whose nameservers are netcup's (needed for DNS-01 and the DNS module)
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
the only way to reach a host — and unsealing Vault, re-running the baseline and
the initial ceremony all happen from your workstation.

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

This initialises the cluster, unseals all three members, creates the AppRole,
distributes credentials to the app nodes and seeds secrets.

It writes `vault-credentials.json` in the repository root. **Move it offline and
delete the local copy.** Losing the unseal keys means losing the Vault data
permanently, and there is no auto-unseal to fall back on.

### 6. Point DNS at the failover IP

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars && $EDITOR terraform.tfvars
terraform init && terraform apply
```

Then route traffic to the primary once:

```bash
NETCUP_SCP_REFRESH_TOKEN=... ./deploy/scripts/traffic.sh route node1
./deploy/scripts/traffic.sh status
```

The bootstrap playbook has already bound the address on both app nodes, so this
takes effect immediately. `traffic.sh route` refuses to proceed if the target
has not bound it, because a provider that routes rather than delivers the
address drops traffic for one the host does not know about.

### 7. Configure GitHub

**Secrets:**

| Secret | Contents |
|--------|----------|
| `DEPLOY_INVENTORY` | The whole `deploy/inventory.env` file |
| `DEPLOY_SSH_KEY` | Private deploy key |
| `DEPLOY_KNOWN_HOSTS` | `ssh-keyscan` output for the three mesh IPs |
| `WG_CI_CONF` | Contents of `deploy/.wg/ci.conf` |
| `REDIS_PASSWORD` | Same value as `REDIS_PASSWORD` in `prod.secrets` |
| `NETCUP_CUSTOMER_NUMBER`, `NETCUP_API_KEY`, `NETCUP_API_PASSWORD` | CCP DNS API, used by Caddy and Terraform |
| `NETCUP_SCP_REFRESH_TOKEN` | netcup driver: traffic routing and power control |
| `HCLOUD_TOKEN` | Hetzner Cloud driver, if `PROVIDER=hetzner` |
| `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY` | OVHcloud driver, if `PROVIDER=ovh` |
| `IONOS_TOKEN` | IONOS Cloud driver, if `PROVIDER=ionos` |
| `SCW_SECRET_KEY` | Scaleway driver, if `PROVIDER=scaleway` |
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin |

**Variables:** `API_DOMAIN` (used by the deploy workflow), plus `DNS_ZONE` and
`FAILOVER_IP` (used by the infra workflow).

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

Nothing to do here — the bootstrap playbook already installed it. Worth
checking once:

```bash
ssh deploy@10.10.0.1 systemctl list-timers garde-snapshot.timer
```

The timer is enabled on the primary and explicitly stopped on the other two, so
re-running the playbook after a role change moves it rather than leaving two
nodes pushing snapshots at each other.

The snapshot procedure itself lives on the host at
`/opt/garde/scripts/snapshot.sh`. Both the timer and
`deploy/scripts/sqlite-snapshot.sh` run that same script, so `VACUUM INTO` and
the integrity check exist in one place. Copies travel node to node over the
mesh using per-node keys the playbook generates and authorises; they never pass
through the CI runner.

---

## Vault secrets for this topology

Beyond the [required secrets](INSTALLATION.md#required-mandatory-secrets-in-vault),
these values are specific to running behind Caddy on the mesh:

| Secret | Value | Why |
|--------|-------|-----|
| `redis_host` | `redis` | Each node has its own local Redis under that service name |
| `use_tls` | `false` | Caddy terminates TLS at the edge |
| `cookie_secure` | `true` | Traffic is HTTPS even though garde speaks HTTP |
| `trusted_proxies` | `172.28.0.0/16` | The fixed app network subnet, so `X-Forwarded-For` is honoured |
| `domain_name` | your registrable domain | Makes `app.` and `api.` same-site for cookies |
| `cors_allow_origins` | `https://app.example.com` | The UI origin |
| `cookie_same_site` | `lax` | Subdomains of one registrable domain are same-site |

Reseed after changing `prod.secrets` by re-running `vault-cluster-init.sh`'s
seeding step, or by writing individual keys with `vault kv put`.

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
| Logs | `ssh deploy@10.10.0.1 'cd /opt/garde && docker compose -f compose/app.yml -p garde-app logs -f garde'` |
| Grafana | Tunnel to `10.10.0.3:3000` over the mesh |

Deploys update the standby app node before the primary, so a bad build is caught
on the node that serves no traffic. Vault members are updated one at a time so
quorum survives.

---

## Runbook: unsealing Vault

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

## Runbook: failover

**Before you start:** failing over is one-way for at least 301 seconds. Confirm
the primary is genuinely unhealthy rather than briefly slow.

Run the **Failover** workflow with a reason, or from a workstation:

```bash
./deploy/scripts/failover.sh --reason "node1 host failure"
./deploy/scripts/failover.sh --dry-run          # checks only, changes nothing
./deploy/scripts/failover.sh --power-off        # old primary unreachable
```

What happens, in order:

1. **Verify** the standby is warm, holds the failover IP, has Vault quorum and a
   recent snapshot
2. **Fence** the old primary so it cannot keep writing
3. **Install** the newest `permissions.db` snapshot on the new primary
4. **Promote** Redis there, permanently (`REPLICAOF NO ONE` plus `CONFIG REWRITE`)
5. **Move** the failover IP through the netcup API
6. **Verify** the public path end to end

Fencing comes before promotion deliberately. Two live primaries diverge, and
nothing merges a split brain afterwards. If the old primary is unreachable over
the mesh, the script stops rather than guessing — `--power-off` stops the server
through the netcup API, which is the only fencing left when SSH is gone.

**Immediately afterwards**, swap `PRIMARY_NODE`/`STANDBY_NODE` and the matching
`NODE*_ROLE` values in `deploy/inventory.env`, and update the
`DEPLOY_INVENTORY` secret to match. If you skip this, the next deploy renders a
`replicaof` line onto the new primary's Redis config.

Then re-run the baseline so the host-level pieces follow the roles:

```bash
cd ansible && ansible-playbook playbooks/bootstrap.yml
```

That moves the snapshot timer onto the new primary and stops it on the old one.
Until it runs, the only snapshots you get are from the scheduled workflow.

---

## Runbook: rebuilding after failover

Once the old primary is healthy again, it becomes the new standby.

1. Bring the host back, unseal its Vault member, and re-run the baseline
   playbook if the host was rebuilt from scratch.
2. Reset its Redis to replicate from the new primary:

```bash
ssh deploy@<old-primary-mesh-ip>
cd /opt/garde
docker compose --env-file .env -f compose/app.yml -p garde-app stop redis
rm config/redis/redis.conf     # sync-config will render a replica config
```

3. Confirm the inventory now lists it with `NODE*_ROLE=app-standby`.
4. Run the **Deploy** workflow with `stack: app`.
5. Verify: `./deploy/scripts/healthcheck.sh --all` should show one master, one
   replica with `link up`, and no split-brain warning.

Failing back later is a normal failover in the other direction — same script,
same cooldown.

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

netcup's cooldown is the one that shapes operations rather than just timing: a
cutover is one-way for five minutes, so you commit to the direction. The others
let you fail straight back, which lowers the stakes of deciding to fail over at
all.

Two providers constrain where the hosts live. OVH refuses to move an Additional
IP between services in different countries, and Scaleway cannot attach a
flexible IP to an Instance in another zone. On both, keep all three hosts
together.

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
- **Delivered** — IONOS attaches the reserved IP to a NIC, and Scaleway
  configures it inside the guest itself via `scw-net-reconfig`. Binding it
  statically on both nodes would put one address on two machines, and on
  Scaleway it would actively fight the agent that deconfigures the address on
  detach.

That difference is the `PROVIDER_REQUIRES_IP_BINDING` fact. The two delivered
providers declare `false` and the playbook skips the `failover_ip` role for
them; the three routed ones declare `true` and get it.

Three things are **not** behind the seam, deliberately, because they are
declarations rather than calls and a common schema for them would fit nobody:

- **Caddy's ACME DNS module**, compiled into the image in
  `deploy/images/caddy/Dockerfile` and configured by the `acme_dns` block in the
  Caddyfile. Both need editing by hand — the module path and the credential
  field names differ per provider.
- **Terraform**, in `terraform/`. Provider schemas differ enough that rewriting
  the four small files is cheaper than maintaining a generic DNS module.
- **DNS API credentials**, which are separate from the compute API credentials
  on both providers.

Adding a third provider means one new file in `deploy/scripts/providers/`
implementing the three verbs and declaring the five facts. `load_provider()`
verifies the contract at load time, so a half-implemented driver fails
immediately rather than two steps into a failover.

---

## What is not automated

Deliberately, because the failure modes are worse than the toil:

- **Vault unsealing.** No KMS, so no auto-unseal. Keys stay with humans.
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
