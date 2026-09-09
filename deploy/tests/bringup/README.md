# Bring-up / doctor suite

Offline checks for `terraform/aws/bring-up.sh` plus a live read-only run of
`deploy/scripts/doctor.sh`. No Terraform apply and no service outage.

```bash
export ASSUME_YES=true
# provider credentials / VAULT_UNSEAL_KEYS_FILE as needed for live probes

./deploy/tests/run.sh bringup
```

| Script | What it checks |
|--------|----------------|
| `01-bring-up-offline.sh` | Missing `terraform.tfvars` → exit 1; inventory upsert merge |
| `02-doctor.sh` | `doctor.sh` and `doctor.sh --strict` against current inventory |

Requires a filled `deploy/inventory.env` and reachable nodes for the doctor
stage. Offline bring-up checks run even without AWS access.
