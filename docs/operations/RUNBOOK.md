# Runbook: operating the authentication delivery program (spec section 25)

**Status:** v1, 2026-11-02. Day-to-day operations of the two tiers. Setup steps the owner performs once: `docs/ops/AUTHORITY-OWNER-CHECKLIST.md` and `docs/ops/AZURE-SETUP.md`.

## 1. What runs where

| Tier | Resource group | Workloads | Deploy workflow | Identity | State key |
|---|---|---|---|---|---|
| Ordinary | `rg-viadere-<env>-app` | `ca-viadere-api`, `ca-cloudflared`, worker, jobs | `azure.yml` (env `staging`) | `id-gh-deploy-<env>` | `viadere/azure/<env>` |
| Authority | `rg-viadere-<env>-auth` | `ca-viadere-authority` (internal only), `job-viadere-authority-admin`, `job-viadere-authority-migrate` | `authority-deploy.yml` (env `authority-staging`) | `id-gh-deploy-auth-<env>` | `viadere/azure-authority/<env>` |
| Admin commands | authority job | `ViadereAuthority admin ...` | `authority-admin.yml` (env `authority-admin-staging`) | `id-gh-authority-admin-<env>` | — |
| Publication | Cloudflare `id.` host | static JWKS, discovery | `authority-publish.yml` (env `authority-publish-staging`) | none (Cloudflare token) | — |
| Monitor | none | `jwks-monitor.yml` (read-only) | scheduled | none | — |

## 2. Routine tasks

* **Release.** Tag `v*.*.*`: `release.yml` builds and signs the server image (and the authority image when `Server/Dockerfile.authority` exists), then deploys the ordinary image to staging through `azure.yml`.
  The authority image is deployed by the owner: `Actions > Authority deploy > digest` (shown in the release run summary); read the reviewer summary (commit, diff stat) before approving.
* **Authority admin change.** Commit a change file `Infra/azure-authority/changes/<n>.json` through a PR (CODEOWNERS), then run `Authority admin` with the command and the path; approve in the environment.
* **Key rotation / publication:** `docs/ops/KEY-ROTATION.md` sections 7 to 12 (24 h publication lead).
* **Monthly:** `swift package update` and base-image refresh (CLAUDE.md rule 5), OpenTofu/provider/Azure CLI re-check, `tofu plan` of both roots must be empty (drift), review role assignments
  in both resource groups, review Activity Log alerts, rotate the `ghcr-pull-credential` every 90 days, check seal-key `not_after` (alert fires 30 days ahead), confirm the JWKS monitor and
  the external heartbeat both reported this week.
* **Cost:** staging budget alert (Cost Management). The authority adds about USD 12 to 13 per month on top of the ordinary tier's 27 to 28 (AZURE-SETUP.md section 13): raise the budget alert to
  USD 45 before enabling it, or set `authority_min_replicas = 0` (saves about 6, cold starts, one unwrap per start).

## 3. Health checks

* Ordinary: `/healthz`, `/readyz` through the tunnel; `az containerapp revision list`.
* Authority (no public ingress): from the ordinary tier only. Probes are in the app definition (`/healthz`, `/readyz`); check `az containerapp show -n ca-viadere-authority -g rg-viadere-<env>-auth --query properties.runningStatus`
  and the authority workspace (`ContainerAppConsoleLogs_CL`). A replica that cannot unwrap/decrypt its seal key stays not-ready (fails closed).
* Reconciliation (C-11): the job's last run is within the hour; zero unmatched operations.

## 4. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Authority revision never ready | database role missing (bootstrap `authority-database.sql`), pinned key version unknown to the authority, NSG denied a service tag (check Learn "Securing a Virtual Network in Azure Container Apps" and add the tag via IaC), image not in the authority registry |
| Image pull fails | the image was not imported (`authority-deploy.yml` imports by digest), the identity lacks AcrPull, or the registry name variable is wrong |
| api cannot reach the authority | private DNS zone of the authority environment not linked to the VNet, NSG inbound from `snet-cae`, token audience/role (`Authority.Evidence.Submit`) |
| `authority-admin.yml` job succeeds but inventory step finds no lines | Log Analytics ingestion delay (wait), job logged nothing allow-listed, or the Log Analytics Reader role is missing on the authority workspace |
| `authority-publish.yml` refuses a JWK | its thumbprint is not in the attested inventory: run the admin `key-inventory` command first; never paste a key by hand |
| Policy check fails on the authority plan | read the `VIOLATION` line; never weaken `policy_check.py`; a deliberate exception needs a CLAUDE.md row and the owner's decision |
| Entra token refused by the authority | audience `api://viadere-authority-<env>`, app role assignment, `authority_caller_object_ids` allow-list |

## 5. Rollback and incidents

`ROLLBACK.md` (flags first, deploy by digest, schema forward only) and `INCIDENT_RESPONSE.md`. Operations on production are not available: production has no deploy path yet.
