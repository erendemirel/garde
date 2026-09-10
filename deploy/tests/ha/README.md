# HA infra test suite

Executable drills that verify the three-node failover layout (Vault Raft, Redis
primary/replica, SQLite snapshots, public traffic move). They are operator
tools, not CI unit tests: they talk to a live cluster and some of them cause a
brief outage on purpose.

For **post-deploy smoke** (no outage), see the sibling suite
`deploy/tests/deploy/` or run `./deploy/tests/run.sh deploy`.


## Layout

| Directory | Service impact | What it proves |
|-----------|----------------|----------------|
| `no-outage/` | None | Cluster is healthy; dry-run failover would succeed |
| `service-stays-up/` | App stays up | Vault member loss (witness or Raft leader) while traffic continues |
| `planned-outage/soft/` | Brief cutover | Soft fence + Redis promote + EIP/IP move; auth/RPO behaviour |
| `planned-outage/hard/` | Brief cutover | Provider power-off of the primary (hypervisor fence) |

Soft = stop the app stack (or Redis) over SSH. Hard = `power.sh off` /
`failover.sh --power-off` through the provider driver (AWS stop-instances, etc.).

## Prerequisites

```bash
export REDIS_PASSWORD=...          # same value as in prod.secrets / Vault
export ASSUME_YES=true             # skip interactive confirm on failover
# Provider compute credentials already in the environment, e.g.:
#   AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION
```

For tests that bring Vault back after a reboot/fence:

```bash
# Shamir (non-AWS): offline unseal key file
export VAULT_UNSEAL_KEYS_FILE=/path/to/offline-unseal-keys.txt

# AWS awskms: set VAULT_KMS_KEY_ID in inventory instead — drills wait for auto-unseal
```

For auth / SQLite permission drills:

```bash
export SUPERUSER_EMAIL=...
export SUPERUSER_PASSWORD=...
```

Inventory: `deploy/inventory.env` (writable — failover updates role pointers).

## How to run

```bash
# Safe to run anytime
./deploy/tests/ha/run.sh no-outage
./deploy/tests/ha/run.sh service-stays-up

# Causes a short outage; restores node1 primary / node2 standby afterwards
./deploy/tests/ha/run.sh soft
./deploy/tests/ha/run.sh hard          # provider power-off — slower
./deploy/tests/ha/run.sh all           # everything, soft before hard

# One script
./deploy/tests/ha/planned-outage/soft/01-failover-roundtrip.sh
```

Do **not** run `hard` against a provider with a long traffic cooldown (netcup
301s) unless you mean to commit to the cutover direction for that window.

## Adding a drill

1. Put it under the matching risk directory.
2. Source `../../lib.sh` (or `../lib.sh` from `no-outage` / `service-stays-up`).
3. Call `ha_boot` first; end destructive tests with `ha_restore_default_topology`
   when practical.
4. Document the risk class in the script header comment.
