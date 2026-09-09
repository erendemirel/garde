#!/usr/bin/env bash
# Bring up (or refresh) the AWS cloud side of a garde cluster.
#
#   ./terraform/aws/bring-up.sh              # plan + apply
#   ./terraform/aws/bring-up.sh --plan-only
#   ./terraform/aws/bring-up.sh --yes         # skip apply confirmation
#   ./terraform/aws/bring-up.sh --no-inventory
#
# Creates/updates VPC, security groups, key pair, instances, Elastic IP, S3,
# IAM, and optional Route 53. Then merges terraform outputs into
# deploy/inventory.env. Does NOT run Ansible, Vault, or app deploy.
#
# Prerequisites:
#   - terraform.tfvars filled in (from terraform.tfvars.example)
#   - AWS credentials in the environment or ~/.aws
#   - terraform >= 1.6, aws CLI optional but useful for docto

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
INVENTORY="${INVENTORY_FILE:-$REPO_ROOT/deploy/inventory.env}"
EXAMPLE="$REPO_ROOT/deploy/inventory.example.env"
TFVARS="$ROOT/terraform.tfvars"

PLAN_ONLY=false
ASSUME_YES=false
MERGE_INVENTORY=true

while [ $# -gt 0 ]; do
  case "$1" in
    --plan-only)     PLAN_ONLY=true; shift ;;
    --yes|-y)        ASSUME_YES=true; shift ;;
    --no-inventory)  MERGE_INVENTORY=false; shift ;;
    -h|--help)       sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "required command not found: $1" >&2; exit 1; }; }

[ -f "$TFVARS" ] || {
  echo "missing $TFVARS" >&2
  echo "  cp terraform/aws/terraform.tfvars.example terraform/aws/terraform.tfvars" >&2
  echo "  # edit image_bucket_name, ssh_public_key, optional dns_zone" >&2
  exit 1
}

need terraform

if grep -q 'garde-images-CHANGEME\|AAAA\.\.\.' "$TFVARS" 2>/dev/null; then
  echo "warn: terraform.tfvars still looks like the example — edit bucket name and ssh_public_key" >&2
fi

cd "$ROOT"
echo "==> terraform init"
terraform init -input=false

echo "==> terraform plan"
terraform plan -input=false -out=tfplan

if [ "$PLAN_ONLY" = "true" ]; then
  echo "plan only — not applying"
  exit 0
fi

if [ "$ASSUME_YES" != "true" ]; then
  printf 'Apply this plan? [y/N] '
  read -r ans || true
  case "$ans" in
    y|Y|yes|YES) ;;
    *) echo "aborted"; exit 1 ;;
  esac
fi

echo "==> terraform apply"
terraform apply -input=false -auto-approve tfplan
rm -f tfplan

# --- merge inventory fragment ---------------------------------------------

upsert_inventory() {
  local inv="$1" key="$2" value="$3"
  local tmp
  tmp="$(mktemp)"
  if [ -f "$inv" ] && grep -qE "^${key}=" "$inv"; then
    # Replace existing assignment; keep the rest of the file intact.
    awk -v k="$key" -v v="$value" '
      BEGIN { done=0 }
      $0 ~ "^" k "=" {
        print k "=" v
        done=1
        next
      }
      { print }
      END { if (!done) print k "=" v }
    ' "$inv" >"$tmp"
    mv "$tmp" "$inv"
  else
    printf '%s=%s\n' "$key" "$value" >>"$inv"
    rm -f "$tmp"
  fi
}

merge_fragment() {
  local frag="$1" inv="$2" line key value
  while IFS= read -r line || [ -n "$line" ]; do
    # Trim leading spaces from heredoc indentation in the output.
    line="${line#"${line%%[![:space:]]*}"}"
    case "$line" in
      ''|\#*) continue ;;
    esac
    key="${line%%=*}"
    value="${line#*=}"
    [ "$key" = "$line" ] && continue
    upsert_inventory "$inv" "$key" "$value"
    echo "  inventory $key=$value"
  done <<<"$frag"
}

if [ "$MERGE_INVENTORY" = "true" ]; then
  echo "==> merging inventory_fragment into $INVENTORY"
  if [ ! -f "$INVENTORY" ]; then
    if [ -f "$EXAMPLE" ]; then
      cp "$EXAMPLE" "$INVENTORY"
      echo "  created inventory.env from inventory.example.env"
    else
      : >"$INVENTORY"
    fi
  fi
  frag="$(terraform output -raw inventory_fragment)"
  merge_fragment "$frag" "$INVENTORY"
  # Ensure AWS marker bits that humans often leave commented in the example.
  echo "  (review APP_DOMAIN / API_DOMAIN / COOKIE_DOMAIN / ACME_EMAIL by hand)"
fi

echo
echo "==> AWS infra is up. Next (not done by this wrapper):"
echo "  1. If a new Route 53 zone was created, delegate NS:"
if ns="$(terraform output -json dns_nameservers 2>/dev/null)"; then
  echo "$ns" | grep -q '\[\]' || echo "       terraform output dns_nameservers"
fi
echo "  2. Store compute CI keys (sensitive):"
echo "       terraform output -raw ci_access_key_id"
echo "       terraform output -raw ci_secret_access_key"
if terraform output -raw acme_access_key_id >/dev/null 2>&1; then
  acme_id="$(terraform output -raw acme_access_key_id 2>/dev/null || true)"
  if [ -n "$acme_id" ] && [ "$acme_id" != "null" ]; then
    echo "  3. Store ACME DNS-01 keys as AWS_ACME_* secrets:"
    echo "       terraform output -raw acme_access_key_id"
    echo "       terraform output -raw acme_secret_access_key"
  fi
fi
echo "  4. Ansible bootstrap:  cd ansible && ansible-playbook playbooks/bootstrap.yml"
echo "  5. Vault init, build/ship images, deploy — see docs/AWS_BRINGUP.md"
echo "  6. Track progress:     ./deploy/scripts/doctor.sh"
echo
echo "done."
