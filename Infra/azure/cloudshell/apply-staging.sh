#!/bin/bash
# Plans, policy-checks and applies the lean staging environment from Cloud Shell (ephemeral sessions included: it installs OpenTofu,
# checksum-verified, on every run). Run from the checkout: bash Infra/azure/cloudshell/apply-staging.sh
# Runs in Cloud Shell or a macOS/Linux terminal (az logged in).
# Required: SUB_ID STATE_SA SUFFIX DB_ADMINS_ID IMAGE. Optional: CRYPTO_OFFICERS_ID, GHCR_USER, STATE_RG (default rg-viadere-stg-tfstate),
# DIDIT_WORKFLOW_ID (required while app_env enables VERIFY_ENABLED; not a secret).
set -uo pipefail
source "$(dirname "$0")/common.sh"
need SUB_ID STATE_SA SUFFIX DB_ADMINS_ID IMAGE
cd "$(dirname "$0")/.." || fail "cd Infra/azure"

step "1/4 subscription and OpenTofu"
az account set --subscription "$SUB_ID" || fail "az account set"
TENANT_ID="$(az account show --query tenantId -o tsv)" || fail "tenant"
tofu_ready

step "2/4 settings"
cp terraform.tfvars.example terraform.tfvars
sed -i.bak \
  -e "s/^subscription_id *= .*/subscription_id = \"$SUB_ID\"/" \
  -e "s/^tenant_id *= .*/tenant_id       = \"$TENANT_ID\"/" \
  -e "s/^name_suffix *= .*/name_suffix     = \"$SUFFIX\"/" \
  -e "s#^github_repository = .*#github_repository = \"Gitbub0816/viadere\"#" \
  -e "s/^db_admin_group_object_id .*/db_admin_group_object_id                   = \"$DB_ADMINS_ID\"/" \
  -e "s/^key_vault_crypto_officers_group_object_id .*/key_vault_crypto_officers_group_object_id  = \"${CRYPTO_OFFICERS_ID:-}\"/" \
  -e "s#^image .*#image              = \"$IMAGE\"#" \
  -e "s/^ghcr_pull_username .*/ghcr_pull_username = \"${GHCR_USER:-}\"/" \
  -e "s/^  DIDIT_WORKFLOW_ID_IDENTITY *= .*/  DIDIT_WORKFLOW_ID_IDENTITY               = \"${DIDIT_WORKFLOW_ID:-}\"/" \
  terraform.tfvars
rm -f terraform.tfvars.bak
if grep -qE '^  VERIFY_ENABLED *= *"true"' terraform.tfvars && [ -z "${DIDIT_WORKFLOW_ID:-}" ]; then fail "set DIDIT_WORKFLOW_ID (Verify is enabled in app_env)"; fi
case "${DIDIT_WORKFLOW_ID:-}" in *[!A-Za-z0-9-]*) fail "DIDIT_WORKFLOW_ID: letters, digits and hyphens only" ;; esac
# api_min_replicas = 0 is for the first apply only (no replica before secrets and database roles exist); after the first migration the
# module default (1) applies, so a later apply does not scale the api back to zero.
if migrate_has_run; then sed -i.bak '/^api_min_replicas *=/d' terraform.tfvars && rm -f terraform.tfvars.bak; echo "first deploy done: api_min_replicas uses the default"; fi
if grep -nE "REPLACE|OWNER/|00000000-0000" terraform.tfvars; then fail "placeholder left in terraform.tfvars"; fi
grep -E "^(location|name_suffix|api_min_replicas)" terraform.tfvars

step "3/4 plan + policy check"
tofu plan -input=false -var profile=lean -out tfplan || fail "tofu plan"
tofu show -json tfplan > plan.json || fail "tofu show"
python3 -I policy_check.py plan.json || fail "policy check"
# Show every delete/replace and ask before applying (unless ASSUME_YES=1): a different machine or missing optional variable must
# never silently remove resources.
python3 -I - plan.json <<'PY' || fail "plan summary"
import json, sys
plan = json.load(open(sys.argv[1]))
counts = {"create": 0, "update": 0, "delete": 0}
risky = []
for rc in plan.get("resource_changes", []):
    actions = rc["change"]["actions"]
    for a in ("create", "update", "delete"):
        if a in actions: counts[a] += 1
    if "delete" in actions:
        risky.append(("REPLACE" if "create" in actions else "DESTROY") + "  " + rc["address"])
print(f"plan: {counts['create']} to create, {counts['update']} to update, {counts['delete']} to delete or replace")
for line in risky: print("  " + line)
PY
rm -f plan.json
if [ "${ASSUME_YES:-}" != "1" ]; then
  printf "Apply this plan? Type yes: "; read -r answer
  [ "$answer" = "yes" ] || fail "not applied (nothing changed)"
fi

step "4/4 apply (20-30 minutes the first time; press Enter now and then so Cloud Shell stays connected)"
tofu apply -input=false tfplan || fail "tofu apply"
rm -f tfplan
echo; echo "------ send these to Claude ------"
tofu output -json github_deploy
tofu output -json workload_identities
echo "DONE"
