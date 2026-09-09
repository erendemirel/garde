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
address.

**No registry.** CI builds images and streams them with `docker save` over SSH
into `docker load` on the far side. The hosts hold no registry credentials, no
source code and no compiler.

**No auto-unseal.** There is no cloud KMS in this setup, so a restarted Vault
member must be unsealed by a human. With three members that is not an outage:
the other two hold quorum. Unseal keys never enter GitHub — a workflow input is
visible in run metadata.

**The hosting provider sits behind one seam.** Everything provider-specific
*about compute and traffic* reaches the outside world through three verbs —
route traffic to a node, report where traffic is, set a host's power — plus
five declared facts. Drivers live in `deploy/scripts/providers/`; `netcup`,
`hetzner`, `ovh`, `ionos`, `scaleway`, `aws` and `gcp` ship today, selected by
`PROVIDER` in the inventory. Nothing outside that directory names a compute
provider.

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

**DNS lives with the hosting provider, not behind the compute seam.** Failover
moves the address under stable `app.` / `api.` names; Terraform only creates
those A records (and never owns failover routing). Each provider has its own
small DNS surface — `terraform/` for netcup CCP, Route 53 inside
`terraform/aws/` — plus a matching Caddy `acme_dns` module selected by
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

DNS follows `PROVIDER`. Failover never updates these records — it only moves
the address underneath them.

**netcup** (`terraform/`):

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars && $EDITOR terraform.tfvars
terraform init && terraform apply
```

**AWS** (Route 53 inside `terraform/aws/` — set `dns_zone` or `dns_zone_id`):

```bash
cd terraform/aws
# dns_zone = "example.com"  in terraform.tfvars
terraform apply
terraform output dns_nameservers   # delegate the registrar if the zone is new
terraform output -raw acme_access_key_id
terraform output -raw acme_secret_access_key   # store as AWS_ACME_* secrets
```

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
| `DEPLOY_SSH_KEY` | Private deploy key |
| `DEPLOY_KNOWN_HOSTS` | `ssh-keyscan` output for the three mesh IPs |
| `WG_CI_CONF` | Contents of `deploy/.wg/ci.conf` |
| `REDIS_PASSWORD` | Same value as `REDIS_PASSWORD` in `prod.secrets` |
| `NETCUP_CUSTOMER_NUMBER`, `NETCUP_API_KEY`, `NETCUP_API_PASSWORD` | netcup DNS-01 + Terraform DNS (`PROVIDER=netcup`) |
| `NETCUP_SCP_REFRESH_TOKEN` | netcup driver: traffic routing and power control |
| `HCLOUD_TOKEN` | Hetzner Cloud driver, if `PROVIDER=hetzner` |
| `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY` | OVHcloud driver, if `PROVIDER=ovh` |
| `IONOS_TOKEN` | IONOS Cloud driver, if `PROVIDER=ionos` |
| `SCW_SECRET_KEY` | Scaleway driver, if `PROVIDER=scaleway` |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | AWS compute driver (EIP / fence / tunnel / S3) |
| `AWS_ACME_ACCESS_KEY_ID`, `AWS_ACME_SECRET_ACCESS_KEY` | AWS Route 53 DNS-01 for Caddy (from `terraform output acme_*`) |
| `GCP_SERVICE_ACCOUNT_KEY` | Google driver, if `PROVIDER=gcp`; the workflow writes it to a file and points `GOOGLE_APPLICATION_CREDENTIALS` at it |
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin |

**Variables:** `API_DOMAIN` (used by the deploy workflow), plus `DNS_ZONE` and
`FAILOVER_IP` (used by the infra workflow). `AWS_REGION`, `AWS_IMAGE_BUCKET` and
`GOOGLE_CLOUD_PROJECT` if you deploy to either hyperscaler.

`WG_CI_CONF` is not required on AWS or GCP: the runner does not join the mesh
there. Their credentials are set at job level rather than on the deploy step,
because on those providers even checking whether a host is reachable means
opening an authorised tunnel.

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

That moves the snapshot timer onto the new primary and stops it on the old one.
Until it runs, the only snapshots you get are from the scheduled workflow.

---

## Runbook: rebuilding after failover

Once the old primary is healthy again, it becomes the new standby.

1. Bring the host back and unseal its Vault member
   (`./deploy/scripts/unseal.sh <node>`). Re-run the baseline playbook if the
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

AWS and GCP are also the two where this architecture is not what the platform
would suggest. Both answer this problem natively with a managed load balancer in
front of an autoscaling group. The drivers exist so the same three-host design
runs there unchanged, which is worth having for portability — but if you are
building for one of them and nothing else, their own primitives are the better
tool, and this seam is not an argument against them.

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
terraform init && terraform apply
terraform output -raw inventory_fragment >> ../../deploy/inventory.env
# If you created a zone: delegate the registrar to dns_nameservers, then store
# acme_access_key_id / acme_secret_access_key as AWS_ACME_* GitHub secrets.
```

DNS for AWS is Route 53 in this same module; netcup DNS stays in `terraform/`.
They share no state. The module deliberately does not manage the Elastic IP
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
