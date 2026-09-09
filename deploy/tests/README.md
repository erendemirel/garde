# Infra test suites

Operator drills against a live garde cluster. Not unit tests — they SSH to the
nodes and sometimes cause a brief outage on purpose.

| Suite | Path | Default impact |
|-------|------|----------------|
| **Deploy verification** | `deploy/tests/deploy/` | None (read-only / dry-run) |
| **HA / failover** | `deploy/tests/ha/` | Mixed — see that suite's README |

```bash
export REDIS_PASSWORD=... ASSUME_YES=true
# plus provider credentials (AWS_*, etc.) already in the environment

./deploy/tests/run.sh deploy          # post-deploy / smoke
./deploy/tests/run.sh ha no-outage    # safe HA slice
./deploy/tests/run.sh ha soft         # planned soft cutover
./deploy/tests/run.sh all-safe        # deploy + ha no-outage + service-stays-up
```

Shared helpers live in `ha/lib.sh` (sourced by both suites for now).
