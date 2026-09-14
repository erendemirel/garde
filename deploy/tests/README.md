# Infra test suites

Operator drills against a live garde cluster. Not unit tests — they SSH to the
nodes. App nodes are active-active against shared PostgreSQL and Redis.

| Suite | Path | Default impact |
|-------|------|----------------|
| **Bring-up / doctor** | `deploy/tests/bringup/` | None (offline + read-only probes) |
| **Deploy verification** | `deploy/tests/deploy/` | None (read-only) |

```bash
export REDIS_PASSWORD=... ASSUME_YES=true
# AWS: AWS_PROFILE=default (or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)

./deploy/tests/run.sh bringup         # bring-up.sh offline + doctor
./deploy/tests/run.sh deploy          # post-deploy / smoke
./deploy/tests/run.sh all-safe        # bringup + deploy
```

Shared helpers live in `deploy/tests/lib.sh`.
