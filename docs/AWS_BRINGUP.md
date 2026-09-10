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
- [ ] Key pair + 3 EC2 instances + Elastic IP present
- [ ] S3 image bucket + gateway endpoint present
- [ ] CI IAM user created (store access keys as GitHub/`AWS_*` secrets)
- [ ] Vault KMS CMK + EC2 instance profile present (`vault_kms_key_id` output)
- [ ] `deploy/inventory.env` merged from `inventory_fragment` (`PROVIDER=aws`, instance ids, mesh endpoints, bucket, region, `VAULT_KMS_KEY_ID`)
- [ ] (Optional) Route 53 zone + `app`/`api` A records + ACME IAM user

## Manual / human-gated

- [ ] If Terraform **created** a hosted zone: registrar NS = `terraform output dns_nameservers`
- [ ] Real `APP_DOMAIN` / `API_DOMAIN` / `COOKIE_DOMAIN` / `ACME_EMAIL` in inventory (leave placeholders until DNS is ready)
- [ ] `AWS_ACME_*` in the deploy environment when using Route 53 DNS-01
- [ ] Ansible bootstrap: `cd ansible && ansible-playbook playbooks/bootstrap.yml`
- [ ] WireGuard mesh configs installed (`wg-gen` / playbook)
- [ ] Vault cluster initialized with KMS auto-unseal; recovery keys stored **offline**
- [ ] Existing Shamir cluster? Run `vault-seal-migrate.sh` after sync-config (see DEPLOY.md)
- [ ] Images built and shipped; `./deploy/scripts/deploy.sh …`
- [ ] `REDIS_PASSWORD` (and other secrets) available to sync-config / CI
- [ ] GitHub secrets/vars updated (`DEPLOY_INVENTORY`, compute keys, …)

## Verify

```bash
./deploy/scripts/doctor.sh           # stages 1–8
./deploy/tests/run.sh bringup        # bring-up offline checks + doctor --strict
./deploy/tests/run.sh deploy         # post-deploy smoke (no outage)
./deploy/tests/run.sh all-safe       # bringup + deploy + safe HA slices
```

App `/health` is stage 8 — optional for early bring-up tracking.
