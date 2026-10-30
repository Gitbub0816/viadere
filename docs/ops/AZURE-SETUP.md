# Azure setup: from zero to a running environment (WP-B1)

Owner guide for `Infra/azure/` (OpenTofu landing zone, plan [`../IMPLEMENTATION-PLAN-v3.md`](../IMPLEMENTATION-PLAN-v3.md) section 5, ADR-0010 to ADR-0014). Every command is meant to be copied as is; replace only the values in `<angle brackets>` or the variables set at the top of a block.

**Status (2026-10-30): code only, nothing is applied.** WP-B2/B3 (server side: managed identity, Key Vault, Blob export, Entra database authentication, process roles, queues) are implemented and tested against stubs and a local PostgreSQL 18.6; section 11 lists what the server reads. The subscriptions do not exist yet, so no `tofu plan`/`apply` has run against Azure. What was verified without credentials: `tofu fmt`, `tofu validate`, `tofu test` (both profiles, mocked providers), 64 Python unit tests (policy checker with its fixture plans, `kv_tool.py`), `actionlint` with shellcheck, and the repository's `trivy config` gate. Every step marked **(owner)** needs your Azure, GitHub or Cloudflare account.

Contents: [1 Profiles and design choices](#1-profiles-and-design-choices) · [2 Tenant, subscriptions, budget, groups](#2-tenant-subscriptions-budget-groups) · [3 State storage](#3-state-storage-bootstrap) · [4 CI identities](#4-opentofu-ci-identities-optional) · [5 GitHub](#5-github-environments-and-variables) · [6 First apply](#6-first-apply-lean) · [7 Key Vault secrets](#7-key-vault-secrets) · [8 PostgreSQL roles](#8-postgresql-roles) · [9 Cloudflare Tunnel](#9-cloudflare-tunnel) · [10 First deploy and verification](#10-first-deploy-and-verification) · [11 Server environment variables (WP-B2/B3)](#11-server-environment-variables-wp-b2b3) · [12 Switching to standard](#12-switching-to-standard-and-production) · [13 Costs](#13-monthly-cost) · [14 Troubleshooting](#14-troubleshooting)

---

## 1. Profiles and design choices

| | `lean` (default, testing) | `standard` (production-grade) |
|---|---|---|
| PostgreSQL Flexible Server 18 | Burstable B1ms, 32 GiB, VNet-integrated (delegated subnet + private DNS zone), 7-day PITR, no HA | General Purpose D2ds_v5, 128 GiB, VNet-integrated, zone-redundant HA, 35-day PITR, geo-redundant backup |
| Container Apps | Workload-profiles environment with only the Consumption profile, internal, public access disabled, peer-to-peer encryption; `ca-viadere-api` 0.25 vCPU/0.5 GiB min 1; `ca-cloudflared` 0.25/0.5 min 1; `job-viadere-migrate` | same environment type, zone-redundant; api 0.5/1 GiB min 2; cloudflared min 2 |
| Service Bus | **Basic**, local (SAS) auth disabled, public endpoint (Entra tokens only) | **Premium** 1 MU, private endpoint, public access disabled, duplicate detection |
| Key Vault | **Standard** (software keys), RBAC, purge protection, public endpoint firewalled to the Container Apps subnet (free service endpoint) | **Premium** (EC-HSM P-256 sign keys, RSA-HSM 3072 key-encryption key), private endpoint, public access disabled |
| Images | GHCR by digest | ACR Premium (private endpoint), imported by digest |
| Egress | environment's platform outbound address | NAT gateway + static IP |
| Audit-head storage | none (export stays off, as on Fly staging) | StorageV2 ZRS, version-level WORM, shared keys disabled, private endpoint |
| Monitoring | Log Analytics + App Insights, local auth off, daily cap 0.15 GB | same, no cap, 90-day retention |
| Resource locks | none | CanNotDelete on the data and security resource groups |

Common to both: region `centralus` (staging; `eastus` and `eastus2` refused PostgreSQL Flexible Server B1ms for the subscription on 2026-10-30 although `list-skus` offered it, so test a create before choosing a region; prices below are `eastus` list prices, `centralus` is within a few percent); five resource groups `rg-viadere-<stg|prd>-{net,app,data,sec,ops}`; VNet 10.40.0.0/16 (staging) or 10.50.0.0/16 (production); user-assigned identities `id-viadere-{api,worker,migrator,cloudflared}` (+ `id-viadere-acrpull` in standard) with roles only on individual keys, secrets, the namespace or the container; deploy identity `id-gh-deploy-<env>` federated to the GitHub environment; no Managed HSM; no Azure Firewall (owner decision O-8).

Design decisions taken in WP-B1 (with reasons):

- **Environment type.** Microsoft now calls the "Consumption-only" environment *legacy* and recommends a workload-profiles environment with only the built-in Consumption profile (Learn, "Consumption-only environment type", 2026-01-26). Without a dedicated profile, an environment private endpoint or a planned-maintenance window there is no management fee (Learn, "Billing", 2025-12-09; Retail Prices API meters "Environment Private Endpoint", "Environment Management Hour" and "Environment Planned Maintenance Hour", USD 0.10/h each, are therefore never triggered). Using the same type in both profiles keeps the subnet layout identical.
- **cloudflared as its own container app, not a sidecar.** A sidecar forwards to `localhost`, i.e. to its own replica, which bypasses the environment ingress, the revision traffic split and readiness gating (a starting or failing api revision would get edge traffic); the tunnel token stays with a dedicated identity that can read only that secret; api rollouts do not drop or multiply connectors. The cost is the same as a sidecar (one more 0.25 vCPU / 0.5 GiB allocation either way).
- **Single revision mode** for the api: a new revision takes traffic only after its readiness probe (`/readyz`) passes; the previous revision is kept inactive for rollback. Multiple-revision mode would keep the old replicas running and billing.
- **Key Vault keys and secret placeholders through the ARM control plane** (`azapi`): OpenTofu needs no data-plane access (works with private endpoints and firewalls), and no secret value ever enters the state (placeholders use the write-only `sensitive_body`; the PostgreSQL admin password is an ephemeral, write-only variable).
- **Policy check on every plan** (`Infra/azure/policy_check.py`, section 4/5): no public PostgreSQL in either profile; Service Bus and Key Vault public endpoints only in lean and only with Entra-only auth (printed as recorded exceptions); no subscription-scope role assignment; workload identities only at resource scope; nothing in lean that bills a fixed fee beyond the plan's lean table.

---

## 2. Tenant, subscriptions, budget, groups

**(owner)** Tools on your machine: Azure CLI **2.91.0** or later (`az version`; Python-based, no Node), OpenTofu **1.13.2**, `gh`, Python 3. Install OpenTofu checksum-verified:

```sh
TOFU_VERSION=1.13.2
curl --proto '=https' --tlsv1.2 -fsSLO "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_amd64.zip"   # macOS: _darwin_arm64.zip
curl --proto '=https' --tlsv1.2 -fsSLO "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_SHA256SUMS"
grep "tofu_${TOFU_VERSION}_linux_amd64.zip" "tofu_${TOFU_VERSION}_SHA256SUMS" | sha256sum --check   # linux/amd64 = 723bebb0...208b5
unzip tofu_${TOFU_VERSION}_linux_amd64.zip tofu && sudo install tofu /usr/local/bin/
```

### 2.1 Tenant and subscriptions (owner, portal)

1. Create (or choose) the Microsoft Entra tenant and sign in at <https://portal.azure.com> as a Global Administrator. Turn on MFA for every human account.
2. Create two **pay-as-you-go** subscriptions: `viadere-staging` and `viadere-production` (Subscriptions → Add). Nothing goes into production until the standard profile is approved.
3. Create two break-glass accounts (cloud-only, long random passwords + FIDO2 keys, excluded from conditional access, stored offline) and an alert on their sign-ins (Entra ID → Monitoring → Diagnostic settings → Log Analytics, alert rule on `SigninLogs | where UserPrincipalName in (...)`).

```sh
az login --tenant <tenant-id>
export TENANT_ID=<tenant-id> SUB_ID=<viadere-staging subscription id> OWNER_EMAIL=<your e-mail> REPO=<owner>/viadere
az account set --subscription "$SUB_ID"
```

### 2.2 Budget alert at USD 30 (owner, staging; do this first)

```sh
cat > budget.json <<EOF
{"properties": {"category": "Cost", "amount": 30, "timeGrain": "Monthly",
  "timePeriod": {"startDate": "$(date -u +%Y-%m-01)T00:00:00Z", "endDate": "2030-12-31T00:00:00Z"},
  "notifications": {
    "actual80":    {"enabled": true, "operator": "GreaterThan", "threshold": 80,  "thresholdType": "Actual",     "contactEmails": ["$OWNER_EMAIL"]},
    "actual100":   {"enabled": true, "operator": "GreaterThan", "threshold": 100, "thresholdType": "Actual",     "contactEmails": ["$OWNER_EMAIL"]},
    "forecast100": {"enabled": true, "operator": "GreaterThan", "threshold": 100, "thresholdType": "Forecasted", "contactEmails": ["$OWNER_EMAIL"]}}}}
EOF
az rest --method put --url "https://management.azure.com/subscriptions/$SUB_ID/providers/Microsoft.Consumption/budgets/viadere-staging-30usd?api-version=2024-08-01" --body @budget.json
rm budget.json
```

A budget alerts, it does not stop spending. Production gets its own budget once the standard profile is approved (section 13).

### 2.3 Resource providers (owner, once per subscription)

The module does not register providers itself (so the apply identity needs no subscription-wide register right):

```sh
for rp in Microsoft.App Microsoft.ContainerRegistry Microsoft.DBforPostgreSQL Microsoft.Insights Microsoft.KeyVault Microsoft.ManagedIdentity \
          Microsoft.Network Microsoft.OperationalInsights Microsoft.ServiceBus Microsoft.Storage Microsoft.Consumption; do
  az provider register --namespace "$rp" --wait
done
```

### 2.4 Entra groups (owner)

```sh
az ad group create --display-name grp-viadere-db-admins --mail-nickname grp-viadere-db-admins           # PostgreSQL Entra admin (no workload)
az ad group create --display-name grp-viadere-kv-crypto-officers --mail-nickname grp-viadere-kv-crypto   # create/rotate keys; never runs workloads
az ad group create --display-name grp-viadere-readers --mail-nickname grp-viadere-readers
az ad group member add --group grp-viadere-db-admins --member-id "$(az ad signed-in-user show --query id -o tsv)"
export DB_ADMINS_ID=$(az ad group show --group grp-viadere-db-admins --query id -o tsv)
export CRYPTO_OFFICERS_ID=$(az ad group show --group grp-viadere-kv-crypto-officers --query id -o tsv)
```

---

## 3. State storage bootstrap

**(owner)** One storage account per environment, Entra-only (shared keys disabled), versioning and soft delete, and a lock. It is reached by OpenTofu over its public endpoint with Entra tokens (GitHub-hosted runners have no fixed address); this is recorded with the lean exceptions in CLAUDE.md.

```sh
export STATE_RG=rg-viadere-stg-tfstate STATE_SA=stviaderestgtf$RANDOM   # 3-24 lowercase letters/digits, globally unique
az group create -n "$STATE_RG" -l eastus
az storage account create -n "$STATE_SA" -g "$STATE_RG" -l eastus --sku Standard_ZRS --kind StorageV2 \
  --min-tls-version TLS1_2 --allow-blob-public-access false --allow-shared-key-access false --https-only true
az storage account blob-service-properties update -n "$STATE_SA" -g "$STATE_RG" --enable-versioning true \
  --enable-delete-retention true --delete-retention-days 30 --enable-container-delete-retention true --container-delete-retention-days 30
STATE_SA_ID=$(az storage account show -n "$STATE_SA" -g "$STATE_RG" --query id -o tsv)
az role assignment create --assignee "$(az ad signed-in-user show --query id -o tsv)" --role "Storage Blob Data Contributor" --scope "$STATE_SA_ID"
sleep 60   # role propagation
az storage container create --name tfstate --account-name "$STATE_SA" --auth-mode login
az lock create --name lock-tfstate --resource-group "$STATE_RG" --lock-type CanNotDelete --notes "OpenTofu state for Viadere"
```

Then create `Infra/azure/backend.staging.hcl` (gitignored) from `backend.example.hcl`:

```sh
cd Infra/azure
cat > backend.staging.hcl <<EOF
use_azuread_auth     = true
subscription_id      = "$SUB_ID"
resource_group_name  = "$STATE_RG"
storage_account_name = "$STATE_SA"
container_name       = "tfstate"
key                  = "viadere/azure/staging.tfstate"
EOF
```

---

## 4. OpenTofu CI identities (optional)

Skip this section if you will always apply from your own machine. For CI plans and approved applies (`.github/workflows/azure.yml`), create two identities **outside** the module (a module must not grant rights to the identity that applies it):

```sh
az identity create -g "$STATE_RG" -n id-gh-infra-plan-stg
az identity create -g "$STATE_RG" -n id-gh-infra-apply-stg
PLAN_PID=$(az identity show -g "$STATE_RG" -n id-gh-infra-plan-stg --query principalId -o tsv)
APPLY_PID=$(az identity show -g "$STATE_RG" -n id-gh-infra-apply-stg --query principalId -o tsv)
az identity federated-credential create -g "$STATE_RG" --identity-name id-gh-infra-plan-stg --name github-azure-plan-staging \
  --issuer https://token.actions.githubusercontent.com --audiences api://AzureADTokenExchange --subject "repo:$REPO:environment:azure-plan-staging"
az identity federated-credential create -g "$STATE_RG" --identity-name id-gh-infra-apply-stg --name github-azure-infra-staging \
  --issuer https://token.actions.githubusercontent.com --audiences api://AzureADTokenExchange --subject "repo:$REPO:environment:azure-infra-staging"
```

**Plan identity** (read-only): Reader, plus a custom role for the read calls azurerm makes while refreshing (they return only keys of authentication methods this module disables: Service Bus SAS, storage shared keys, Log Analytics shared keys, ACR admin), plus read access to the state:

```sh
cat > plan-reader.json <<EOF
{"Name": "Viadere IaC plan reader", "IsCustom": true, "Description": "Refresh calls azurerm needs for a plan; no data access.",
 "Actions": ["Microsoft.App/containerApps/listSecrets/action", "Microsoft.App/jobs/listSecrets/action",
             "Microsoft.OperationalInsights/workspaces/sharedKeys/action", "Microsoft.ServiceBus/namespaces/authorizationRules/listKeys/action",
             "Microsoft.Storage/storageAccounts/listKeys/action", "Microsoft.ContainerRegistry/registries/listCredentials/action"],
 "AssignableScopes": ["/subscriptions/$SUB_ID"]}
EOF
az role definition create --role-definition @plan-reader.json && rm plan-reader.json
az role assignment create --assignee-object-id "$PLAN_PID" --assignee-principal-type ServicePrincipal --role Reader --scope "/subscriptions/$SUB_ID"
az role assignment create --assignee-object-id "$PLAN_PID" --assignee-principal-type ServicePrincipal --role "Viadere IaC plan reader" --scope "/subscriptions/$SUB_ID"
az role assignment create --assignee-object-id "$PLAN_PID" --assignee-principal-type ServicePrincipal --role "Storage Blob Data Reader" --scope "$STATE_SA_ID/blobServices/default/containers/tfstate"
```

**Apply identity** (environment-gated, required reviewers): Contributor, a lock manager role (standard creates resource locks, which Contributor cannot), and Role Based Access Control Administrator **with a condition** that allows assigning and removing only the roles this module uses:

```sh
cat > lock-manager.json <<EOF
{"Name": "Viadere IaC lock manager", "IsCustom": true, "Description": "Manage resource locks only.",
 "Actions": ["Microsoft.Authorization/locks/read", "Microsoft.Authorization/locks/write", "Microsoft.Authorization/locks/delete"],
 "AssignableScopes": ["/subscriptions/$SUB_ID"]}
EOF
az role definition create --role-definition @lock-manager.json && rm lock-manager.json
# Key Vault Crypto User, Secrets User, Crypto Officer, Secrets Officer; Service Bus Data Sender, Receiver; Storage Blob Data Contributor; AcrPull;
# Container Apps Contributor; Container Registry Data Importer and Data Reader; Managed Identity Operator; Monitoring Metrics Publisher.
ROLES="12338af0-0e69-4776-bea7-57ae8d297424, 4633458b-17de-408a-b874-0445c86b69e6, 14b46e9e-c2b7-41b4-b07b-48a6ebf60603, b86a8fe4-44ce-4948-aee5-eccb2c155cd7, 69a216fc-b8fb-44d8-bc22-1f3c2cd27a39, 4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0, ba92f5b4-2d11-453d-a403-e96b0029c9fe, 7f951dda-4ed3-4680-a7ca-43fe172d538d, 358470bc-b998-42bd-ab17-a7e34c199c0f, 577a9874-89fd-4f24-9dbd-b5034d0ad23a, f1a07417-d97a-45cb-824c-7a7467783830, 3913510d-42f4-4e42-8a64-420c390055eb"
CONDITION="((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$ROLES})) AND ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$ROLES}))"
az role assignment create --assignee-object-id "$APPLY_PID" --assignee-principal-type ServicePrincipal --role Contributor --scope "/subscriptions/$SUB_ID"
az role assignment create --assignee-object-id "$APPLY_PID" --assignee-principal-type ServicePrincipal --role "Viadere IaC lock manager" --scope "/subscriptions/$SUB_ID"
az role assignment create --assignee-object-id "$APPLY_PID" --assignee-principal-type ServicePrincipal --role "Role Based Access Control Administrator" \
  --scope "/subscriptions/$SUB_ID" --condition "$CONDITION" --condition-version 2.0
az role assignment create --assignee-object-id "$APPLY_PID" --assignee-principal-type ServicePrincipal --role "Storage Blob Data Contributor" --scope "$STATE_SA_ID/blobServices/default/containers/tfstate"
```

These two identities are the only subscription-scope assignments; the policy checker refuses any subscription-scope assignment made by the module itself.

---

## 5. GitHub environments and variables

**(owner)** Repository → Settings → Environments. None of these values is secret (client ids and subscription ids are identifiers); there are **no** Azure secrets in GitHub.

| Environment | Protection | Variables |
|---|---|---|
| `azure-plan-staging` | deployment branches: `main` | `AZURE_INFRA_CLIENT_ID` = client id of `id-gh-infra-plan-stg` |
| `azure-infra-staging` | **required reviewers** (two, not the author), branches: `main` | `AZURE_INFRA_CLIENT_ID` = client id of `id-gh-infra-apply-stg` |
| `staging` (already exists for Fly) | as today | from `tofu output -json github_deploy` after section 6: `AZURE_CLIENT_ID`, `AZURE_RESOURCE_GROUP`, `AZURE_PROFILE`, `AZURE_ACR_NAME` (empty in lean); plus `AZURE_SMOKE_HOST` (e.g. `viadere-api-az.cksites.dev`) |
| `production` | required reviewers + wait timer + tag rule `v*` (as today) | same names, production values (later) |

Repository variables (Settings → Secrets and variables → Actions → Variables): `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_PROFILE` (`lean`), `AZURE_NAME_SUFFIX`, `AZURE_DB_ADMIN_GROUP_ID`, `AZURE_KV_CRYPTO_OFFICERS_GROUP_ID`, `AZURE_BOOTSTRAP_IMAGE` (the digest used in section 6), `AZURE_GHCR_PULL_USERNAME`, `AZURE_APP_ENV_JSON` (the `app_env` map of your tfvars as one JSON object), `AZURE_TFSTATE_RESOURCE_GROUP`, `AZURE_TFSTATE_STORAGE_ACCOUNT`, and finally `AZURE_IAC_ENABLED` = `true` (until then the plan/apply jobs are skipped; `static` always runs). With the same variable names at environment level, production overrides them.

```sh
gh variable set AZURE_TENANT_ID --body "$TENANT_ID"
gh variable set AZURE_SUBSCRIPTION_ID --body "$SUB_ID"
gh variable set AZURE_PROFILE --body lean
# ... the others likewise; environment-level: gh variable set AZURE_CLIENT_ID --env staging --body <client id>
```

---

## 6. First apply (lean)

**(owner)** From your machine, as subscription Owner (CI applies come later). The PostgreSQL local administrator password is used once (password authentication must exist until WP-B2), never stored in state, and discarded.

```sh
cd Infra/azure
cp terraform.tfvars.example terraform.tfvars   # then edit: subscription/tenant ids, name_suffix, github_repository, group ids, image
# image: the newest signed release in GHCR, e.g. from the Release workflow's summary or:
#   gh api "/users/<owner>/packages/container/viadere%2Fviadere-server/versions" --jq '.[0].name'   (sha256:...)
tofu init -backend-config=backend.staging.hcl
tofu plan -var profile=lean -out tfplan   # Entra-only database: no admin password (Azure refuses one when password auth is off)
tofu show -json tfplan > plan.json && python3 -I policy_check.py plan.json && rm plan.json
tofu apply tfplan && rm tfplan
```

Expected policy-check output for lean: 0 violations and the recorded exceptions `KV-PUBLIC`, `SB-PUBLIC`, `KV-SOFTWARE-KEYS`, `PG-NO-HA`, `PG-PASSWORD-AUTH` (each has a row in CLAUDE.md's exceptions table).

Notes:
- `api_min_replicas = 0` in the example keeps the api from starting before its secrets and database roles exist; remove that line after section 10.
- Role assignments can take a few minutes to propagate. If the first apply fails creating a container app with a Key Vault 403, wait two minutes and run `tofu apply` again (with the same variables, without `postgres_set_admin_password`).
- Later plans need neither the password nor the flag.

Save the outputs you need below:

```sh
export RG_APP=$(tofu output -json resource_groups | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["app"])')
export KV_ID=$(tofu output -json key_vault | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
export PG_FQDN=$(tofu output -json postgres | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["fqdn"])')
tofu output -json key_vault_secret_map > map.json
tofu output -json github_deploy          # -> GitHub environment variables (section 5)
```

---

## 7. Key Vault secrets

**(owner)** Every secret the apps reference exists as a placeholder (`unset-placeholder`; the server refuses to start with it). Set real values through the ARM control plane with `kv_tool.py` (works for both profiles, even when the vault has no reachable public endpoint; values never appear on a command line or in the repository). Generate **fresh** values: nothing is reused from Fly or Neon (plan section 4, phase 3).

```sh
cd "$(git rev-parse --show-toplevel)"
export WORK=$(mktemp -d)   # private scratch directory for files that hold secrets; deleted at the end of section 8
# server-owned keys (fresh), written to a new mode-600 file:
python3 -I Infra/fly/generate_secrets.py --env-file "$WORK/s.env"
# append the third-party values to "$WORK/s.env" (one NAME=value per line):
#   EMAIL_API_KEY=<MailerSend API token>
#   MAILERSEND_SMS_API_TOKEN=...   MAILERSEND_SMS_INBOUND_SECRET=...   MAILERSEND_SMS_WEBHOOK_SECRET=...
python3 -I Infra/fly/generate_secrets.py --check "$WORK/s.env"
python3 -I Infra/azure/kv_tool.py put-env --vault-id "$KV_ID" --map Infra/azure/map.json --env-file "$WORK/s.env" --dry-run
python3 -I Infra/azure/kv_tool.py put-env --vault-id "$KV_ID" --map Infra/azure/map.json --env-file "$WORK/s.env"
# multi-line values go one by one from a file (stdin keeps the newlines):
python3 -I Infra/azure/kv_tool.py put --vault-id "$KV_ID" --name apns-p8 < AuthKey_NH9V2KR4LK.p8
```

`put-env` lists every mapped secret it did not find in the file (`NOT SET ...`): at this point that should be only `APNS_KEY_P8` (the command above), plus `DATABASE_URL` and `DATABASE_MIGRATION_URL` if you opted into the password fallback (section 8).

`cloudflared-tunnel-token` is set in section 9 (and `database-url` / `database-migration-url` in section 8 only with the password fallback), and (lean with a private GHCR package) the pull token:

```sh
# a classic token with read:packages only, for the user in ghcr_pull_username
python3 -I Infra/azure/kv_tool.py put --vault-id "$KV_ID" --name ghcr-pull-token     # paste, Enter (no echo)
```

**Wrapped service keys (recommended; plan 5.6).** The server accepts each of `DATA_ENCRYPTION_KEY`, `SERVER_PEPPER`, `AUDIT_CHAIN_KEY`, `SUBJECT_REF_KEY`, `CONNECT_LINK_SIGNING_KEY` (and the `*_PREVIOUS` lists) as `<NAME>_WRAPPED` = `kms1:kek-data/<version>:<base64url>`, the plain value encrypted with RSA-OAEP-256 under the Key Vault key `kek-data`, and unwraps it once at boot (SECURITY.md §2.95). A member of `grp-viadere-kv-crypto-officers` wraps the values of `"$WORK/s.env"` without any of them touching a command line or the screen:

```sh
python3 -I Infra/azure/kv_tool.py wrap-env --vault-url https://<vault>.vault.azure.net --env-file "$WORK/s.env" --out "$WORK/wrapped.env"
# then, in terraform.tfvars, map the wrapped names instead of the plain ones (e.g. SERVER_PEPPER_WRAPPED = "server-pepper"), tofu apply,
# `tofu output -json key_vault_secret_map > Infra/azure/map.json`, and store them:
python3 -I Infra/azure/kv_tool.py put-env --vault-id "$KV_ID" --map Infra/azure/map.json --env-file "$WORK/wrapped.env"
```

A plain and a wrapped value of the same variable together refuse the boot. After a `kek-data` rotation the old version must stay enabled until every wrapped value is re-wrapped under the new one.

Cloudflare must send the same `EDGE_TOKEN` value as the `edge-token` secret (section 9): read it from `"$WORK/s.env"` before that directory is deleted. Writing secrets through ARM needs `Microsoft.KeyVault/vaults/secrets/write` (Owner, Contributor or Key Vault Contributor on the vault); reading them back needs a data-plane role, which nobody but the workloads has. Container Apps picks up a new secret version within 30 minutes or on the next revision (`az containerapp revision restart`).

---

## 8. PostgreSQL roles

**(owner)** The server is private (no public endpoint), so administration runs in a one-off Container Apps Job inside the environment, as the Entra admin group. Since WP-B2 every workload connects with **its own managed identity's Entra token** (`DATABASE_AUTH=entra`, a fresh token for every new connection, TLS `verify-full`), and the module is Entra-only by default (`postgres_password_auth_enabled = false`): there is no database password anywhere. Create one Entra principal role per workload identity and give the migrator the schema:

```sh
cd Infra/azure && tofu output -json workload_identities   # principal_id of api, worker, migrator
cat > "$WORK/db-roles.sql" <<'SQL'
-- runs in database "postgres" as the Entra admin group
SELECT * FROM pgaadauth_create_principal_with_oid('viadere_migrator', '<migrator principal_id>', 'service', false, false);
SELECT * FROM pgaadauth_create_principal_with_oid('viadere_app', '<api principal_id>', 'service', false, false);
SELECT * FROM pgaadauth_create_principal_with_oid('viadere_worker', '<worker principal_id>', 'service', false, false);
ALTER DATABASE viadere OWNER TO viadere_migrator;
GRANT CONNECT ON DATABASE viadere TO viadere_app, viadere_worker;
\connect viadere
ALTER SCHEMA public OWNER TO viadere_migrator;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
# you must be signed in (az login) as a member of grp-viadere-db-admins; the job spec embeds your Entra token (valid about an hour)
CAE_ID=$(cd Infra/azure && tofu output -json container_apps_environment | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
python3 -I Infra/azure/kv_tool.py psql-job --environment-id "$CAE_ID" --host "$PG_FQDN" --sql "$WORK/db-roles.sql" --out "$WORK/dbadmin-job.json"
az containerapp job create -n job-viadere-dbadmin -g "$RG_APP" --yaml "$WORK/dbadmin-job.json"
az containerapp job start -n job-viadere-dbadmin -g "$RG_APP"
az containerapp job execution list -n job-viadere-dbadmin -g "$RG_APP" --query '[0].properties.status' -o tsv   # repeat until Succeeded
az containerapp job delete -n job-viadere-dbadmin -g "$RG_APP" --yes
rm -rf "$WORK"   # s.env, db-roles.sql, dbadmin-job.json (your token)
```

`job-viadere-migrate` (`ROLE=migrate`, identity `id-viadere-migrator`, a configuration that holds no service secret) then creates the schema and grants `viadere_app` (`DATABASE_APP_ROLE`) and `viadere_worker` (`DATABASE_WORKER_ROLE`) DML only, never DDL and never UPDATE on `audit_events`; every serving process refuses to start if its role can change the schema. If the execution fails, read its output in Log Analytics (`ContainerAppConsoleLogs`, job `job-viadere-dbadmin`). The spec uses `PGSSLMODE=verify-full` with the system trust store; if libpq reports that it cannot find a root certificate, edit the spec to `require` for this one-off job (the connection stays inside the VNet).

**Password fallback (not the default).** `postgres_password_auth_enabled = true` brings back the WP-B1 password roles (`kv_tool.py db-passwords` writes SCRAM verifiers and stores `database-url` / `database-migration-url`), `DATABASE_AUTH=password` and the two secret references. Using it needs a row in CLAUDE.md's exceptions table again (with its removal condition); turning it off again needs no server change.

## 9. Cloudflare Tunnel

The connector is `ca-cloudflared` (created in section 6, waiting for its token). Choose **one** of the two ways to create the tunnel and its hostname.

**A. With OpenTofu (zones managed by `Infra/terraform`):** set in that module's tfvars `enable_azure_tunnel = true` and `azure_test_hostname_label = "viadere-api-az"` (phase 1), apply, then read the tunnel id: `tofu output azure_tunnel_id`. Cutover later is `api_origin = "azure"` (rollback: `"fly"`). The module also adds the test host to the edge-token transform rule, the cache bypass and the edge rate limits. The API token needs **Account → Cloudflare Tunnel: Edit** in addition to its zone permissions.

**B. By hand (staging zone `cksites.dev` is hand-configured today):** Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared, name `viadere-staging-azure`; skip the install step; Public hostname: `viadere-api-az.cksites.dev`, service `HTTP` → `ca-viadere-api`, Additional application settings → HTTP Settings → HTTP Host Header `ca-viadere-api`. Then add `viadere-api-az.cksites.dev` to the expression of the existing edge-token transform rule (and to the WAF/rate-limit rules that name the API host).

Then store the tunnel token in Key Vault (never in OpenTofu state):

```sh
export CF_ACCOUNT_ID=<account id> TUNNEL_ID=<tunnel id>
read -rs CLOUDFLARE_API_TOKEN && export CLOUDFLARE_API_TOKEN   # a token with Cloudflare Tunnel: Read
curl -fsS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/cfd_tunnel/$TUNNEL_ID/token" \
  | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["result"])' \
  | python3 -I Infra/azure/kv_tool.py put --vault-id "$KV_ID" --name cloudflared-tunnel-token
az containerapp revision restart -n ca-cloudflared -g "$RG_APP" \
  --revision "$(az containerapp show -n ca-cloudflared -g "$RG_APP" --query properties.latestRevisionName -o tsv)"
```

The tunnel shows **Healthy** in the Zero Trust dashboard within a minute. The edge-token header value must equal the `edge-token` secret in Key Vault (the `EDGE_TOKEN` generated in section 7).

---

## 10. First deploy and verification

**(owner)** Via GitHub: Actions → Azure → Run workflow → environment `staging`, `deploy_digest` = the release digest (`sha256:...`). The job verifies the cosign signature (and, for production, the SLSA provenance), runs `job-viadere-migrate` with that digest under the migrator identity, waits for `Succeeded`, then updates `ca-viadere-api` to the same digest and waits until the new revision is ready (traffic stays on the old revision otherwise), and finally calls `https://$AZURE_SMOKE_HOST/healthz` and `/readyz`. Equivalent by hand:

```sh
IMG=ghcr.io/<owner>/viadere/viadere-server@sha256:<digest>
az containerapp job update -n job-viadere-migrate -g "$RG_APP" --image "$IMG"
az containerapp job start -n job-viadere-migrate -g "$RG_APP"
az containerapp job execution list -n job-viadere-migrate -g "$RG_APP" --query '[0].properties.status' -o tsv   # until Succeeded
az containerapp update -n ca-viadere-api -g "$RG_APP" --image "$IMG" --min-replicas 1
```

Then remove `api_min_replicas = 0` from `terraform.tfvars` and run `tofu apply` (the image is ignored by OpenTofu after creation; the deploy workflow owns it).

Verification checklist:

- [ ] `curl -fsS https://viadere-api-az.cksites.dev/healthz` → 200; `/readyz` → 200 (database reachable).
- [ ] A request that bypasses Cloudflare is impossible: `az containerapp show -n ca-viadere-api -g "$RG_APP" --query properties.configuration.ingress.external` → `false`; the environment has no public IP (`tofu output container_apps_environment`).
- [ ] Without the edge token the origin refuses: temporarily disable the transform rule for the test host → 421 (re-enable it).
- [ ] `az postgres flexible-server show -g rg-viadere-stg-data -n <server> --query network.publicNetworkAccess` → `Disabled`.
- [ ] `az servicebus namespace show -g "$RG_APP" -n <namespace> --query disableLocalAuth` → `true`.
- [ ] `az keyvault show -n <vault> --query "{rbac: properties.enableRbacAuthorization, purge: properties.enablePurgeProtection, acl: properties.networkAcls.defaultAction}"` → `true / true / Deny`.
- [ ] The api refuses to start with a placeholder secret (check by design, not by test: `unset-placeholder` is not valid base64url of 32 bytes).
- [ ] Budget alert e-mail address confirmed; Cost Management shows the staging subscription below USD 30 projected.
- [ ] Policy check of a fresh `tofu plan` shows only the five recorded lean exceptions.

---

## 11. Server environment variables (WP-B2/B3)

The module sets these on the processes; the server implements all of them (WP-B2/B3). `python3 -I Infra/azure/check_env_coverage.py` checks that every variable of `Server/.env.example` is set here, is a Key Vault reference, is in `app_env`, or is exempt with a reason (the Fly counterpart is `Infra/fly/check_env_coverage.py`).

| Variable | api | worker / scheduled jobs | migrate | Value | Server behaviour |
|---|---|---|---|---|---|
| `ENVIRONMENT`, `PORT`, `BIND_HOST`, `AUTO_MIGRATE=false`, `RATE_LIMIT_STORE=database` | x | x | x | | as on Fly |
| `ROLE` | `api` | `worker` | `migrate` | | api: HTTP, publishes the outbox after commits; worker: queue consumers + publisher, `/healthz` and `/readyz` only; migrate: database-only configuration, no service secret, only `ViadereServer migrate` |
| `RUN_BACKGROUND_JOBS` | `true` without a worker, else `false` | worker: `true` without scheduled jobs, else `false` | `false` | | the in-process loop (sweeps + one queue pass) |
| `QUEUE_TRANSPORT`, `AZURE_SERVICEBUS_FQDN` | x | x | | `database` without a worker, else `servicebus`; `<namespace>.servicebus.windows.net` | `ServiceBusRESTTransport` with the managed identity, or the `queue_messages` table |
| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` | id of `id-viadere-api` | `id-viadere-worker` | `id-viadere-migrator` | | the user-assigned identity (Container Apps injects `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`) |
| `AZURE_KEY_VAULT_URL` | x | x | x | `https://<vault>.vault.azure.net/` | `AzureKeyVaultKMS` |
| `AZURE_KEY_VAULT_KEK_KEY` | `kek-data` | `kek-data` | | RSA 3072 | unwraps `*_WRAPPED` secrets at boot and the Wallet keys |
| `AZURE_KEY_VAULT_KD_LOG_KEY` | `kd-log-signing` | | | EC P-256 | signs key-directory tree heads (replaces `KEY_DIRECTORY_LOG_KEY`; the worker holds a stand-in that refuses to sign) |
| `AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY` | `link-descriptor` | | | EC P-256 | signs link-session descriptors and results (WP-C1; replaces `LINK_DESCRIPTOR_SIGNING_KEY`; the worker holds a stand-in that refuses to sign) |
| `AZURE_KEY_VAULT_AUDIT_HEAD_KEY` | | `audit-head-signing` | | EC P-256 | signs exported audit heads (required in production for every role but `api`) |
| `AZURE_AUDIT_BLOB_ENDPOINT`, `AZURE_AUDIT_BLOB_CONTAINER` | | standard: `https://<account>.blob.core.windows.net/`, `audit-heads`; lean: empty | | | create-only export to the immutable container (`AUDIT_HEAD_EXPORT=azure-blob` is inferred) |
| `DATABASE_AUTH`, `DATABASE_HOST`, `DATABASE_NAME`, `DATABASE_USER` | `viadere_app` | `viadere_worker` | `viadere_migrator` | `entra` (default) or `password`; host FQDN, `viadere`, role | Entra token per new connection, `verify-full`, no fallback |
| `DATABASE_APP_ROLE` | x | x | x | `viadere_app` | runtime-role grants |
| `DATABASE_WORKER_ROLE` | | | `viadere_worker` | | worker-role grants (`GrantWorkerRolePrivileges.v1`) |
| `DATABASE_URL`, `DATABASE_MIGRATION_URL` | secret, password fallback only | secret, password fallback only | migration URL, password fallback only | | as on Fly |
| `HEALTH_PEER_NETWORKS` | x | x | | the Container Apps subnet (`10.40.0.0/23` staging) | the only peers whose `/healthz` and `/readyz` pass the origin lock without the edge token |
| `METRICS_BIND_HOST` | via `app_env` when `METRICS_PORT` is set | | | a private address | replaces `FLY_PRIVATE_IP` (still read on Fly) |
| other secrets (`EDGE_TOKEN`, the five service keys or their `*_WRAPPED` forms, `EMAIL_API_KEY`, `APNS_KEY_P8`, `MAILERSEND_SMS_*`) | Key Vault references | same | **none** | | the migrate job references no service secret |
| all other `[env]` values of `fly.staging.toml` (`PUBLIC_BASE_URL`, `RP_ID`, `TRUSTED_PROXY_COUNT`, …) | from `app_env` | same | same | | as on Fly |

Queues (lock 60 s, dead-letter on expiry): `push` (max 5 deliveries, TTL 1 h), `sms-outbound`, `channel-outbound`, `webhook-delivery`, `wallet-push`, `operator-notices` (8 each), `consumer-export` (3), `expiry` (10). The consumer dead-letters a message itself on its last allowed delivery (recorded in the database, metric `queue_dead_lettered`); alert on that metric above zero and on the broker's DLQ depth above zero (expiry). Lean (Basic) has no duplicate detection: the `processed_messages` idempotency is what makes duplicates harmless (SECURITY.md §2.91).

Resolved WP-B1 findings: (1) `migrate` has a database-only configuration (`ROLE=migrate`) and references no service secret; (2) the server never reads `Host` (cloudflared's `Host: ca-viadere-api` is irrelevant; a test scans the sources). Open: (3) re-measure `TRUSTED_PROXY_COUNT` on Azure staging (client → Cloudflare → cloudflared → ingress → app) once it runs.

## 12. Switching to standard (and production)

The profiles differ only in SKUs and networking, never in server code. Globally unique names carry the profile letter (`…l` / `…s`), so switching an existing environment **creates new** Key Vault, Service Bus namespace and PostgreSQL server (geo-redundant backup can only be set at creation) and **replaces** the Container Apps environment (zone redundancy is fixed at creation); lean has no production data by rule, so the intended path is:

1. **Production**: a separate subscription and state (`backend.production.hcl`, key `viadere/azure/production.tfstate`), `environment = "production"`, `profile = "standard"`, its own GitHub environments (`azure-plan-production`, `azure-infra-production` with reviewers) and a budget sized to section 13. Repeat sections 2 to 10 with production values; the Cloudflare zone is `viadere.com` (owner item 5).
2. **Staging on standard** (only if the owner funds it): `tofu plan -var profile=standard`, check the plan (it destroys the lean resources; Key Vault and PostgreSQL stay soft-deleted/recoverable per their retention), re-run sections 7 to 10 (new vault: new secrets and new HSM keys; new database: migrations from scratch).
3. Standard creates resource locks on the data and security groups. To replace or destroy anything in them later, remove the lock deliberately (`az lock delete --name lock-viadere-<env>-data --resource-group rg-viadere-<env>-data`), apply, and let OpenTofu recreate the lock.
4. The audit-head storage account's version-level immutability policy is created **Unlocked** (400 days). After the WP-B2 export is verified, set `audit_immutability_locked = true` and apply: this is **irreversible** (no blob version can then be deleted before 400 days, and the policy can only be extended).
5. Remove the lean rows from CLAUDE.md's exceptions table when no lean environment is in use any more.

---

## 13. Monthly cost

Prices: Azure Retail Prices API (<https://prices.azure.com/api/retail/prices>, `eastus`, USD, retail, queried **2026-10-29**; meter effective date in brackets). 730 hours per month. Excludes tax, Cloudflare (existing plan), Apple, MailerSend and outbound data beyond the free 100 GB.

### Lean (testing; default)

| Item | Basis | USD/month |
|---|---|---|
| PostgreSQL B1ms compute | `B1MS` 0.017/h (2021-12-01) × 730 | 12.41 |
| PostgreSQL storage 32 GiB | "Storage Data Stored" 0.115/GB-month (2021-06-01) | 3.68 |
| PostgreSQL backup (7-day PITR) | free up to 100 % of provisioned storage; beyond: 0.095/GB-month LRS (2021-06-01) | 0.00 |
| Private DNS zone (PostgreSQL) | "Private Zone" 0.50/zone (2019-12-01) | 0.50 |
| Container Apps: api + cloudflared, 0.25 vCPU / 0.5 GiB each, always on | vCPU idle 0.000003/s, active 0.000024/s; memory 0.000003/GiB-s (all 2022-06-01); minus the monthly free grant of 180,000 vCPU-s and 360,000 GiB-s | 10.21 (both idle) to 24.00 (api busy 24/7) |
| Container Apps requests | 0.40 per million after 2 M free (2022-06-01) | 0.00 |
| Service Bus Basic | "Basic Messaging Operations" 0.05 per million (2014-11-01) | < 0.10 |
| Key Vault Standard | operations 0.03/10k (2015-08-01), RSA-3072/EC operations 0.15/10k (2017-07-01); no per-key fee for software keys | < 1.00 |
| Log Analytics + App Insights | first 5 GB/month free, then 2.30/GB (2018-02-01); daily cap 0.15 GB keeps it inside the free allowance | 0.00 |
| State storage account | Hot ZRS ~0.026/GB-month, a few MB | < 0.05 |
| **Total** | | **≈ 27–28 idle; up to ≈ 41 if the api is busy around the clock** |

Ways to stay nearer USD 20: `api_min_replicas = 0` (scale to zero when idle: about −6/month, cold starts, and the in-process job loop pauses while idle), and a **new Azure account's 12-month free services** (750 h of B1ms and 32 GB of storage cover the PostgreSQL line, −16/month). The plan's estimate (USD 20–26, section 5.8a) counted only the api container; the separate cloudflared app adds about USD 4.30–5 at idle, the same as a sidecar would.

Fixed-fee items the lean profile deliberately does **not** create (the policy check fails if they appear): private endpoints (0.01/h = 7.30/month each, "Standard Private Endpoint", 2020-02-01), NAT gateway (0.045/h = 32.85 + 0.045/GB, 2020-06-01) and its static IP (0.005/h = 3.65, 2018-06-01), ACR (Basic 0.1666/day ≈ 5.07, 2018-01-01), Container Apps environment private endpoint / management / planned maintenance (0.10/h each, 2026-09-01), Key Vault Premium HSM keys, Service Bus Standard (10.00/month base, 2018-05-01) or Premium.

### Standard (production-grade, indicative)

| Item | Basis | USD/month |
|---|---|---|
| PostgreSQL D2ds_v5 with zone-redundant HA | "2 vCore" Ddsv5 0.178/h (2023-03-01) × 730 × 2 (primary + standby) | 259.88 |
| PostgreSQL storage 128 GiB, HA | 0.115/GB-month × 128 × 2 | 29.44 |
| PostgreSQL backup, 35-day PITR, geo-redundant | free up to 100 % of storage; geo-redundant backup storage beyond that: no `eastus` GRS meter returned by the API on 2026-10-29, confirm in the pricing calculator | not quoted |
| Container Apps: api 0.5/1 GiB × 2, cloudflared 0.25/0.5 × 2 | same meters as above | 33.86 (idle) to 89.04 (api busy) |
| (with the WP-B3 worker, 0.25/0.5 × 2) | | +11.83 to +39.42 |
| Service Bus Premium 1 MU | "Premium Messaging Unit" 0.9275/h (2018-05-01) | 677.08 |
| Key Vault Premium: 3 EC-HSM P-256 + 1 RSA-HSM 3072 | "Premium HSM-protected Advanced Key" 5.00/key-month first tier (2017-07-01) + operations | ≈ 21 |
| Private endpoints: Key Vault, Service Bus, ACR, audit blob | 0.01/h each (2020-02-01) + 0.01/GB processed | 29.20 |
| Private DNS zones (5) | 0.50 each | 2.50 |
| NAT gateway + static IP | 0.045/h + 0.005/h (+ 0.045/GB) | 36.50 |
| ACR Premium | "Premium Registry Unit" 1.6666/day (2018-01-01) | 50.70 |
| Log Analytics / App Insights, 10–25 GB | (GB − 5) × 2.30; retention beyond 31 days 0.10/GB-month | 11.50–46.00 |
| Audit storage (ZRS hot) | 0.026/GB-month (2018-07-01) | < 1 |
| **Total** | | **≈ 1,150–1,330** (+ geo-backup storage and data processing) |

Service Bus Premium is the largest line (it is the only tier with private endpoints). The cheaper production variant (Standard + Entra-only, public endpoint with an IP rule for the NAT address) saves about 665/month but would fail the standard profile's policy check by design: it is owner decision O-9 and would need its own exception row. Managed HSM (Standard B1 3.20/h ≈ 2,336/month, 2021-08-01) is not used.

---

## 14. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `tofu apply`: container app creation fails with Key Vault 403 | RBAC propagation after the first role assignments; wait two minutes and apply again. |
| api revision never becomes ready | A placeholder secret (section 7), missing database roles (section 8), or `/readyz` cannot reach PostgreSQL. Logs: Log Analytics `ContainerAppConsoleLogs` for `ca-viadere-api`. Traffic stays on the previous revision. |
| Tunnel "Down" | `cloudflared-tunnel-token` not set or stale: section 9, then restart the `ca-cloudflared` revision. |
| 421 from the origin through the tunnel | The edge-token transform rule does not cover the hostname, or its value differs from Key Vault `edge-token`. |
| 404 from the tunnel | The tunnel ingress rule lacks the hostname or the HTTP Host header `ca-viadere-api`. |
| Plan job: 403 reading the state | The plan identity lacks Storage Blob Data Reader on the `tfstate` container (section 4). |
| Plan job: 403 on `listSecrets`/`sharedKeys`/`listKeys` | The "Viadere IaC plan reader" role is missing (section 4). |
| Policy check fails | Read the `VIOLATION` lines; never weaken `policy_check.py` to pass. A deliberate exception needs a CLAUDE.md row and an owner decision first. |
| `az acr import` denied (standard) | The deploy identity's "Container Registry Data Importer and Data Reader" assignment is missing, or the registry no longer allows trusted Azure services (`network_rule_bypass_option = "AzureServices"`). |
