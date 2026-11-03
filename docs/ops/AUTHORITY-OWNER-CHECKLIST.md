# Authority owner checklist (staging)

**Status:** v1, 2026-11-02. Everything here is an action only the owner can take (GitHub settings, Azure/Entra portal or CLI, Cloudflare, Fly). Nothing in this repository assumes it is
done: until step A is complete **no authority environment exists** (condition C-5) and `authority_enabled` stays `false` (the default: the OpenTofu plan is empty and nothing bills).
Do the steps in order; tick each and record the date in `docs/reviews/IMPLEMENTATION_LEDGER.md`. Design: ADR-0019, ADR-0028, ADR-0029, ADR-0034; paths below are repository-relative.

## A. GitHub (before anything else; C-5, OQ-3)

- [ ] **A1. A distinct identity for agent sessions** (a machine user or a GitHub App) that commits and pushes instead of your own account. Add it as a collaborator with write access (not admin).
- [ ] **A2. Branch protection on `main`** (Settings > Branches, or a ruleset): require a pull request, require 1 approving review, **require review from Code Owners**, dismiss stale reviews, require status checks
  `CI` and `Azure`, no force pushes, no deletions, include administrators. `.github/CODEOWNERS` already names you for the authority paths; check the handle is yours.
- [ ] **A3. Create the environments** (Settings > Environments). For each: required reviewers = you, **Prevent self-review ON**, deployment branches = `main` only.
  `authority-staging`, `authority-admin-staging`, `authority-publish-staging`, `azure-infra-authority-staging`; and (read-only plan, no reviewer needed) `azure-plan-authority-staging`.
  Staging has one human, so each gate is a single owner approval (R-21); name a second human reviewer before production or real customer data (`docs/ops/AUTHORITY-REVIEWERS.md`, create it with the names).
- [ ] **A4. Repository OIDC subject template** (so a federated credential can pin the workflow file): `gh api -X PUT repos/<owner>/<repo>/actions/oidc/customization/sub --input - <<< '{"use_default":false,"include_claim_keys":["repo","context","job_workflow_ref"]}'`.
  This changes the subject of EVERY OIDC token of the repository: do A4 and step D5 together, otherwise `id-gh-deploy-<env>` and the infra identities stop logging in until their credentials are updated.
- [ ] **A5. Secret scanning and push protection ON.** Dependabot alerts ON.
- [ ] **A6. Remove old secrets:** Settings > Environments > `staging` and `production` > delete `FLY_API_TOKEN` (and any Neon or GCP credential: `gh secret list --env staging`, `--env production`, `gh secret list`). Delete the owner's personal `read:packages` token from every place it was stored.

## B. Retire Fly, Neon and Google Cloud (ADR-0029; owner decisions 11, 15)

Read-only checks first, with your own CLI login; record the output summary in the ledger. None of these commands changes anything.

- [ ] **B1. Fly:** `flyctl auth whoami`; `flyctl orgs list`; `flyctl apps list`; for each Viadere app: `flyctl status -a <app>`, `flyctl secrets list -a <app>` (names only), `flyctl volumes list -a <app>`.
  You reported a live app **`viadere-server-staging`**, scaled to 0: confirm with `flyctl status -a viadere-server-staging` (0 machines). Then, once Cloudflare analytics show no traffic to it for 7 days: `flyctl apps destroy viadere-server-staging`.
- [ ] **B2. Revoke the Fly tokens:** `flyctl tokens list`; revoke every token (`flyctl tokens revoke <id>`) and the org-level ones in the Fly dashboard (Account > Tokens). Confirm `FLY_API_TOKEN` is gone from GitHub (A6).
- [ ] **B3. Neon:** `neonctl me`; `neonctl projects list`; for a project `neonctl branches list --project-id <id>`. If a Viadere project exists and holds nothing to keep (staging, no production data), delete it in the Neon console; revoke API keys.
- [ ] **B4. Google Cloud:** `gcloud auth list`; `gcloud projects list`; per project `gcloud kms keyrings list --location=<loc> --project=<id>`, `gcloud kms keys list ...`, `gcloud storage buckets list --project=<id>`,
  `gcloud iam workload-identity-pools list --location=global --project=<id>`, `gcloud iam service-accounts list --project=<id>`. If resources exist: disable and schedule destruction of key versions, delete the audit bucket after confirming no required export, shut the project down.
- [ ] **B5. Old OpenTofu state** (if `Infra/terraform` was ever applied): read-only `tofu state list` against its backend. It may hold Neon passwords and the edge token: if it exists, rotate the edge token (`EDGE_TOKEN` with `EDGE_TOKEN_PREVIOUS` overlap, KEY-ROTATION.md) and delete the state after the live resources are gone.
- [ ] **B6. Cloudflare:** in the dashboard check DNS records and tunnels that still point at `*.fly.dev`; then run `Infra/cloudflare` as a **read-only** `tofu plan` (README) and import existing resources before the first apply.

## C. Azure and Entra: groups and the apply identities (once)

- [ ] **C1. Entra groups:** `grp-viadere-stg-auth-crypto-officers` (PIM-eligible members only, time-bound activation; **must not overlap** the ordinary `grp-viadere-kv-crypto-officers`) and, optionally, an authority secrets-officers group.
  Note their object ids (`AUTHORITY_CRYPTO_OFFICERS_GROUP_ID` below).
- [ ] **C2. Create `id-gh-infra-auth-apply-staging`** (user-assigned identity, in the state resource group like the ordinary apply identity, AZURE-SETUP.md section 4) and a **read-only plan identity** for the authority root. Federated credentials: subject
  `repo:<owner>/<repo>:environment:azure-infra-authority-staging` (apply) and `...:environment:azure-plan-authority-staging` (plan). Roles for the apply identity:
  Contributor on `rg-viadere-stg-auth` **after you created that resource group** (or let the first apply create it with Contributor on the subscription temporarily: preferred is to create the empty group yourself),
  constrained RBAC Administrator on that group only (allowed role-definition ids: the custom roles of `keyvault.tf`, Container Apps Contributor, Managed Identity Operator, Container Registry Data Importer, AcrPull, Key Vault Secrets User, Log Analytics Reader, Monitoring Metrics Publisher),
  **Network Contributor on the VNet resource `vnet-viadere-stg`** (it creates `snet-auth` and its NSG in `rg-viadere-stg-net`; this is a recorded residual: it could also edit other subnets of that VNet, so watch the Activity Log alert),
  and a custom role on the PostgreSQL server limited to `Microsoft.DBforPostgreSQL/flexibleServers/databases/*` (create the `viadere_authority` database object), plus Storage Blob Data Contributor on the `tfstate` container (state key `viadere/azure-authority/*`).
- [ ] **C3. Re-scope the existing `id-gh-infra-apply-staging`** (F-03): replace Contributor on the subscription by Contributor on the four resource groups `app`, `data`, `sec`, `ops` (keep `net` if it manages the VNet) and remove any role on `rg-viadere-stg-auth`.
- [ ] **C4. Set GitHub repository/environment variables** (Settings > Variables): `AZURE_AUTH_IAC_ENABLED=true`, `AZURE_AUTH_INFRA_CLIENT_ID`, `AZURE_AUTH_INFRA_PLAN_CLIENT_ID`, `AUTHORITY_ENABLED_IAC=false` (flip to `true` in step E), `AUTHORITY_ENTRA_AUDIENCE=api://viadere-authority-staging`,
  `AUTHORITY_CRYPTO_OFFICERS_GROUP_ID`, `AZURE_AUTH_BOOTSTRAP_IMAGE` (a digest in the authority registry, step E3), `OIDC_SUBJECT_WORKFLOW_REF=false` (flip with A4/D5), and the existing `AZURE_*` variables.
- [ ] **C5. Budget:** raise the staging budget alert (AZURE-SETUP.md section 2.2) from USD 30 to **USD 45** (the authority adds about USD 12 to 13 per month; `authority_min_replicas = 0` saves about 6).

## D. Ordinary tier changes (one `azure.yml` apply, reviewer approval)

- [ ] **D1. Dedicated GHCR pull credential** (decision 14): create a machine user or GitHub App for the deploy setup (not you), a fine-grained credential with **read:packages on the Viadere packages only**, 90-day expiry. Store it in `kv-vdr-stg` secret **`ghcr-pull-credential`**
  (`python3 -I Infra/azure/kv_tool.py put ...`) and set `AZURE_GHCR_PULL_USERNAME` to that account. Then **revoke your personal `read:packages` token** and delete the old Key Vault secret version `ghcr-pull-token`. Calendar reminder: rotate every 90 days.
- [ ] **D2. Enable the database path:** in the ordinary root set `authority_database_access = true` (opens 5432 from `snet-auth` in `nsg-viadere-stg-pg`) and apply through `azure.yml` (apply = true).
- [ ] **D3. Cloudflare tokens:** keep the site token without any `id.` scope; create a SEPARATE token scoped to the `id.` host's static assets only and store it as the secret `CLOUDFLARE_ID_HOST_TOKEN` of environment `authority-publish-staging` (+ variable `CLOUDFLARE_ACCOUNT_ID`).
- [ ] **D4. Entra application** (needs an Entra Application Administrator; CI deliberately has no Graph write right): run `Infra/azure-authority/bootstrap/create-entra-app.sh` with `ENV=staging`, the api and worker managed-identity object ids. Check its verification output (worker must NOT hold `Authority.Evidence.Submit`).
  Keep the printed audience and both object ids for `authority_caller_object_ids`.
- [ ] **D5. Workflow-ref pin:** after A4, set `OIDC_SUBJECT_WORKFLOW_REF=true` and apply the ordinary root (`oidc_subject_workflow_ref = true`) so `id-gh-deploy-staging` pins `azure.yml@refs/heads/main`.

## E. Enable the authority (only after A to D)

- [ ] **E1.** Set in `terraform.tfvars` / variables: `authority_enabled=true` (`AUTHORITY_ENABLED_IAC=true`), `authority_caller_object_ids`, `alert_email`. Keep `authority_flag_enabled=false`.
- [ ] **E2.** Run `Authority infrastructure` (workflow_dispatch, apply = true), approve in `azure-infra-authority-staging`. Read the plan and the policy-check output first; any `VIOLATION` stops it. The first apply fails at the container app until an image exists: do E3 right after the registry exists, then re-run.
- [ ] **E3.** Release a signed authority image (`release.yml`, needs `Server/Dockerfile.authority`), then run `Authority deploy` with the digest; it imports the image into the authority registry and updates the app. Set `AZURE_AUTH_BOOTSTRAP_IMAGE` to that registry digest.
- [ ] **E4.** Set the GitHub environment variables printed by the apply (`tofu output github_deploy_auth`, `github_authority_admin`) on `authority-staging` and `authority-admin-staging`.
- [ ] **E5. Database:** a member of `grp-viadere-db-admins` runs `Infra/azure-authority/bootstrap/authority-database.sql` once (principal creation, `REVOKE CONNECT`), then run the authority migrate job through `Authority deploy`.
- [ ] **E6. Secrets:** a secrets officer sets `oidc-pairwise-key`, `account-ref-key`, `recovery-verifier-key` and the `subject-ref-key` **copy** (same value as the api's `SUBJECT_REF_KEY`) in `kv-vdr-auth-stg` (32 random bytes, base64url).
- [ ] **E7. Keys:** PIM-activate as an authority crypto officer, read the public halves needed for the first admin run (KEK public half), then follow KEY-ROTATION.md sections 8 and 9 (inventory, publish, pin).
- [ ] **E8. Monitoring:** confirm the alert e-mail receives a test; set repository variable `JWKS_MONITOR_HOST` (the `id.` host) to enable `jwks-monitor.yml`, and add an **external dead-man heartbeat** (any uptime service that pages you when the monitor has not pinged for 45 minutes).
- [ ] **E9. Gates before any authority flag (`AUTHORITY_ENABLED`, `AUTH_LINK_SERVICE_ENABLED`, `OIDC_PROVIDER_ENABLED`, `RECOVERY_REFRESH_PROMPT_ENABLED`):** C-1 test list, C-11 reconciliation and monitor drilled, C-15 seal-key-exposed drill done (KEY-ROTATION.md section 11), rollback drill (`docs/operations/ROLLBACK.md` section 6).

- [ ] **E10. Application flags (after E9).** First pins: start the authority once with `AUTHORITY_ENABLED=true`; it prints `VIADERE-KEY-INVENTORY` lines (public keys only) and stops because nothing is pinned. Review the lines, put the `device-statement-signing` thumbprint into Core `AuthorityPinnedKeys` (an app and server release), then run `authority-admin.yml` with `key-version-pin` once per key (change file `{"name","version","thumbprint"}`). Register clients with `client-register` / `link-client-register` and import existing keys with `keylog-import` (staged; applied by the authority at its next start). For OIDC set `AUTHORITY_OIDC_ENABLED=true` on the authority and, on the api, `OIDC_PROVIDER_ENABLED=true`, `OIDC_ISSUER`, `AUTHORITY_URL` (output `authority_internal_fqdn`) and `AUTHORITY_ENTRA_AUDIENCE`. Both OIDC flags refuse `ENVIRONMENT=production`. Ledger "Stage 6 application" lists what is still open (S6-01 to S6-10).

## F. Production (not now)

Production is blocked until ADR-0034 section 9 (RSA-HSM decrypt) is implemented and tested or you sign an owner exception countersigned by A2 and A3 with a seal-key lifetime of 90 days or less (C-16, ledger L-13), a second human reviewer is named (R-21), a separate subscription
or management group for the authority is decided (spec 9.2), and the external review of spec section 13 is done.
