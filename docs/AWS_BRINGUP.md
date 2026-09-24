# AWS bring-up checklist

Track progress without needing a working app. Pair with:

```bash
./terraform/aws/bring-up.sh     # cloud infra + inventory merge
./deploy/scripts/doctor.sh      # evidence for each stage below
./deploy/scripts/doctor.sh --strict
```

Tick items as you complete them. `doctor.sh` marks many of these automatically.

## Automated (Terraform / wrapper)

- [ ] `terraform/aws/terraform.tfvars` filled (bucket, SSH public key, optional `dns_zone`; for import, `subnet_cidrs` / `node_private_ips`)
- [ ] Remote state: S3 `garde-tfstate-…` + DynamoDB `garde-terraform-locks` (see `versions.tf` backend)
- [ ] `./terraform/aws/bring-up.sh` applied successfully (or import of an existing account into that state)
- [ ] VPC, subnets, security groups, Instance Connect Endpoint present
- [ ] Key pair + 3 EC2 instances (`app` / `app` / `witness`) + Elastic IP present
- [ ] Optional: RDS Multi-AZ + ElastiCache Redis (`postgres_password` / `redis_auth_token` in tfvars)
- [ ] S3 image bucket + gateway endpoint present
- [ ] CI IAM user created (store access keys as GitHub/`AWS_*` secrets)
- [ ] Vault KMS CMK + EC2 instance profile present (`vault_kms_key_id` output)
- [ ] `deploy/inventory.env` merged from `inventory_fragment` (`PROVIDER=aws`, `TRAFFIC_MODE`, roles, instance ids, mesh endpoints, bucket, region, `VAULT_KMS_KEY_ID`)
- [ ] (Optional) Route 53 zone + `app`/`api` records

Pick the traffic mode before applying — it changes which resources exist:

- [ ] `traffic_mode = "managed_lb"` (**preferred** for active-active): ALB + ACM + multi-target attachments + alias records
- [ ] `traffic_mode = "floating_ip"`: Elastic IP + A records + ACME IAM user; Caddy issues the certificates

## Manual / human-gated

- [ ] If Terraform **created** a hosted zone: registrar NS = `terraform output dns_nameservers`
- [ ] Real `APP_DOMAIN` / `API_DOMAIN` / `COOKIE_DOMAIN` / `ACME_EMAIL` in inventory (leave placeholders until DNS is ready; `ACME_EMAIL` is unused in `managed_lb`)
- [ ] `AWS_ACME_*` in the deploy environment when using Route 53 DNS-01 (`floating_ip` only)
- [ ] Ansible bootstrap: `cd ansible && ansible-playbook playbooks/bootstrap.yml`
- [ ] WireGuard mesh configs installed (`wg-gen` / playbook)
- [ ] Vault cluster initialized with KMS auto-unseal; recovery keys stored **offline**
- [ ] Seed Vault with shared `redis_host` / `DATABASE_URL` or `POSTGRES_*` (from terraform outputs when using RDS/ElastiCache)
- [ ] Existing Shamir cluster? Run `vault-seal-migrate.sh` after sync-config ([seal-migrate runbook](DEPLOY.md#runbook-shamir--kms-seal-migrate))
- [ ] Service CA via Vault PKI: enabled by `init-vault-prod` (or `vault-pki.sh enable`); Agent auto-issues/renews server leaf to `/run/secrets/service_tls_*.pem`; client certs via `vault-pki.sh issue-client <name>`; cron `service-tls-reload.sh --remote`
- [ ] Vault holds `service_listener=true`, `service_mtls=required`, Agent PEM paths, and **`mfa_encryption_key`** (`openssl rand -base64 32` — not a dig/test key)
- [ ] Registration gates and kill switch set deliberately (`require_email_verification` default on, `require_admin_approval` default off; `public_self_service` only off when the service listener carries auth)
- [ ] Issue per-caller `/validate` keys with `POST /admin/api-keys` for each internal service
- [ ] Images built and shipped; `./deploy/scripts/deploy.sh …`
- [ ] `REDIS_PASSWORD` (and other secrets) available to sync-config / CI
- [ ] GitHub secrets/vars updated (`DEPLOY_INVENTORY`, compute keys, …)

## Verify

```bash
./deploy/scripts/doctor.sh           # stages 1–8
./deploy/tests/run.sh bringup        # bring-up offline checks + doctor --strict
./deploy/tests/run.sh deploy         # post-deploy smoke
./deploy/tests/run.sh all-safe       # bringup + deploy
```

App `/ready` is stage 8 — optional for early bring-up tracking.
