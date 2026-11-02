# ADR-0029: Retire Fly.io, Google Cloud KMS and Neon from CI, IaC and code

- **Status:** proposed (2026-11-02)
- **Supersedes in effect:** ADR-0001 (Fly.io), ADR-0002 (Neon), ADR-0003 (Google Cloud KMS) — status to become "superseded by 0010/0011/0012 and retired by 0029"
- **Spec reference:** §16 (current deployment), §22 (current-stack target), §9.4; owner decision **11**; open question **O-5**; findings F-10, F-11, F-18
- **Related:** ADR-0010, ADR-0011, ADR-0012, ADR-0028
- **Review:** A5 (author role), A11, A14

## Context

Azure lean (OpenTofu `Infra/azure`) is the only staging. The repository still contains live deploy paths to Fly: `release.yml` deploys Fly staging and production on `v*.*.*` tags and `staging-deploy.yml` deploys Fly staging on every push to the working branch without cosign verification (F-10, verified by Stage 0). `Infra/terraform` defines Neon (`neon.tf`), GCP KMS and an audit bucket (`kms.tf`, `audit_bucket.tf`), and also the Cloudflare edge (`cloudflare.tf`, `cloudflare_tunnel.tf`), whose state may hold Neon passwords and the edge token if it was ever applied. `Infra/fly/` holds Fly configs and a secrets checklist; `ci.yml` checks Fly config coverage. Code and docs reference the legacy stack (F-11). Spec §22 asks A5 to propose an Azure target and a viable current-stack target; with decision 11 the current stack **is** Azure, so a single target remains.

## Decision

1. **CI.** Delete `staging-deploy.yml`. Remove the Fly deploy jobs from `release.yml` (build, scan, sign, SBOM and provenance stay; deployment moves to `azure.yml` and `authority-deploy.yml`). Replace the Fly-coverage step in `ci.yml` with the existing `Infra/azure/check_env_coverage.py`. Delete the `FLY_API_TOKEN` secrets from the `staging` and `production` GitHub environments (owner action) and revoke the tokens in Fly.
2. **IaC.** Move `cloudflare.tf` and `cloudflare_tunnel.tf` into a new OpenTofu root `Infra/cloudflare/` (fresh state in the Azure state account; import existing Cloudflare resources instead of recreating them). Delete `neon.tf`, `kms.tf`, `audit_bucket.tf` and the rest of `Infra/terraform`. Delete `Infra/fly/`. If the old `Infra/terraform` state exists, treat it as secret material: rotate the edge token (`EDGE_TOKEN` with `EDGE_TOKEN_PREVIOUS` overlap) and any credential it contains, then delete the state after the live resources are gone.
3. **Code.** Remove GCP workload-identity configuration names (`Config/OperationsConfig.swift`), the Fly-specific comment/path at `App.swift:158`, Fly assumptions in `Migrations/RuntimeRoleGrants.swift`, and the Neon PITR copy in `Dashboard/ConsoleCompliance.swift:153` (replace with the Azure value from configuration). Legacy GCS/R2 audit sinks are already refused (SECURITY §2.77).
4. **Docs.** Rewrite `docs/ops/STAGING-SETUP.md` for Azure; update ADR-0001/0002/0003 status lines; propose ADR-0010/0011/0012 for acceptance (owner decision, since they describe the running staging); update CLAUDE.md where Fly/Neon/GCP are named.
5. **Live resources (O-5, owner).** The owner checks whether these exist and, if they do, decommissions them in this order: (a) Fly apps `viadere-server-staging` (and any production app): scale to zero, confirm no traffic for 7 days via Cloudflare analytics, `flyctl apps destroy`; (b) Neon project: confirm it holds no data that must be kept (staging only, no production data), delete the project; (c) GCP: disable and schedule destruction of KMS key versions (GCP enforces a scheduled-destruction delay), delete the audit bucket after confirming no required export, shut down the project. Each step is recorded in `docs/reviews/IMPLEMENTATION_LEDGER.md` with date and actor. This ADR does not block on O-5: steps 1-4 are repository changes that are safe whether or not the resources exist.
6. **GHCR (O-4, open).** Unchanged here. If the owner makes the package public, the personal read:packages PAT (F-18) can be removed from Key Vault; the authority does not use GHCR (TRUST_BOUNDARIES §9).

## Consequences

- The only deploy paths are `azure.yml` (ordinary tier) and `authority-deploy.yml` (authority), both OIDC-federated with reviewers.
- Production has no deploy path until a production Azure environment is approved (no agent deploys to production).
- Cloudflare stays managed as code in its own root.

## Threat assumptions changed

- Removes an unreviewed deploy path on every push (F-10) and long-lived Fly tokens from GitHub (T-CP-5).

## Reviewers required

A5 (IaC moves, state handling), A11 (decommission runbook), A14 (no baseline capability lost).
