# Deploy verification suite

Post-bring-up / post-deploy smoke checks. These are the checks we used while
standing up the AWS reference cluster: mesh reachability, provider preflight,
role topology, traffic location, snapshot freshness, failover dry-run, and
optional auth / public HTTPS.

**Impact: none** (no fencing, no power-off). Safe after every deploy.

```bash
export REDIS_PASSWORD=...
# AWS: prefer AWS_PROFILE=default (garde-ci). provider_preflight resolves the
# profile into AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY when those are unset.
# optional:
export SUPERUSER_EMAIL=... SUPERUSER_PASSWORD=...   # enables auth smoke + 09
export API_KEY=... \
       SERVICE_CLIENT_CERT=deploy/pki/client-ci-cert.pem \
       SERVICE_CLIENT_KEY=deploy/pki/client-ci-key.pem   # enables the positive mTLS check
./deploy/tests/deploy/run.sh
# or:
./deploy/tests/run.sh deploy
```

| Script | Checks |
|--------|--------|
| `01-mesh-and-provider.sh` | SSH/mesh to every node; `provider_preflight` |
| `02-health-and-roles.sh` | `healthcheck.sh --all`; Redis primary/replica; Vault quorum |
| `03-traffic-location.sh` | Provider traffic location matches `PRIMARY_NODE` |
| `04-snapshot-freshness.sh` | Take + distribute snapshot; age within limit |
| `05-failover-dry-run.sh` | `failover.sh --dry-run` |
| `06-auth-smoke.sh` | Login + `/users/me` (skipped if no superuser env) |
| `07-public-https.sh` | Real `API_DOMAIN`/`APP_DOMAIN` HTTPS (skipped for example.com) |
| `08-service-listener.sh` | `/validate` unpublished on the public edge (or published but closed to the shared key); mesh listener mTLS checks soft-skip when `:SERVICE_PORT` is not listening |
| `09-validate-api-keys.sh` | Shared + per-tenant API keys against in-process `/validate` (skips if SUPERUSER/API_KEY unset or image lacks the routes) |
