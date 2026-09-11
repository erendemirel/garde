# Infra test suites

Operator drills against a live garde cluster. Not unit tests — they SSH to the
nodes and sometimes cause a brief outage on purpose.

| Suite | Path | Default impact |
|-------|------|----------------|
| **Bring-up / doctor** | `deploy/tests/bringup/` | None (offline + read-only probes) |
| **Deploy verification** | `deploy/tests/deploy/` | None (read-only / dry-run) |
| **HA / failover** | `deploy/tests/ha/` | Mixed — see that suite's README |

```bash
export REDIS_PASSWORD=... ASSUME_YES=true
# AWS: AWS_PROFILE=default (or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)

./deploy/tests/run.sh bringup         # bring-up.sh offline + doctor
./deploy/tests/run.sh deploy          # post-deploy / smoke
./deploy/tests/run.sh ha no-outage    # safe HA slice
./deploy/tests/run.sh ha soft         # planned soft cutover
./deploy/tests/run.sh all-safe        # bringup + deploy + ha no-outage + service-stays-up
```

Shared helpers live in `ha/lib.sh` (sourced by both suites for now).
