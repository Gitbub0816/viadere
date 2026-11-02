# Rollback (spec section 25; A11 must demonstrate it, spec section 27)

**Status:** v1, 2026-11-02. Every step names a control that exists in this repository. Production has no deploy path yet, so everything below is staging; a rollback drill is
recorded in `docs/reviews/IMPLEMENTATION_LEDGER.md` (date, actor, result) before any authority flag is enabled (C-11, C-15).

## 1. Principles

* **Flags first.** The fastest rollback of behaviour is a flag, not a deploy: `AUTH_DELIVERY_ENABLED`, `AUTH_LINK_SERVICE_ENABLED`, `OIDC_PROVIDER_ENABLED`,
  `RECOVERY_REFRESH_PROMPT_ENABLED` (api, `app_env`) and `AUTHORITY_ENABLED` (authority, `authority_flag_enabled`). All default off. With the authority flag off the api fails closed for
  the link service and OIDC; push MFA and delivery-only flows for existing accounts do not depend on the grant path (ADR-0019).
* **Deploy by digest.** Both tiers deploy an image by digest and keep inactive revisions (`max_inactive_revisions = 10`), so a rollback is "activate the previous revision" or
  "deploy the previous digest through the same gated workflow".
* **Schema moves forward only.** Migrations are additive (expand, then contract in a later release). A rollback never runs a down-migration; the previous image must run on the
  new schema. A migration that cannot satisfy this is not merged.
* **Authority rollbacks are reviewer-gated like deploys** (a rollback is a deploy of an older digest). During a SEV1 the owner may approve it at once; the audit trail is the workflow run.

## 2. Ordinary tier (api, worker, jobs)

1. Identify the previous good revision: `az containerapp revision list -n ca-viadere-api -g rg-viadere-<env>-app -o table`.
2. Activate it and send it all traffic (single-revision mode: `az containerapp revision activate --revision <name>` then `az containerapp ingress traffic set --revision-weight <name>=100`), or run
   `azure.yml` (workflow_dispatch, `deploy_digest`) with the previous digest. The migrate job runs again and is idempotent.
3. Verify `/healthz`, `/readyz` through the tunnel (`AZURE_SMOKE_HOST`) and the audit chain (`audit-verify`).
4. Worker and scheduled jobs: `az containerapp update -n ca-viadere-worker --image <previous digest>`; jobs take the image at their next execution.

## 3. Authority

1. Turn the flag off first when behaviour is wrong: `authority_flag_enabled = false` through `authority-infra.yml` (apply, reviewer approval), or on the running app
   `az containerapp update -n ca-viadere-authority -g rg-viadere-<env>-auth --set-env-vars AUTHORITY_ENABLED=false` by the owner (break-glass, recorded afterwards).
2. Previous image: run `authority-deploy.yml` with the previous digest (the workflow verifies signature and provenance again, imports by digest, runs the authority migrations, updates the app).
   Revision rollback without the workflow (`az containerapp revision activate`) is owner break-glass only and is recorded in the ledger.
3. **Keys are never rolled back by reverting an image.** A pinned key version is changed only by `key-version-pin` (KEY-ROTATION.md section 8). If a new pin misbehaves, pin the previous version
   (still enabled for 24 h after a switch).
4. **Published JWKS:** a bad publication is corrected by a new `authority-publish.yml` run from a commit that restores the previous documents; the old key stays published for 24 h after any switch for exactly this reason.
5. **Policy floors and clients:** raise-only rule. A policy or client change that INCREASED authority is reversed by another reviewer-gated admin command (`policy-lower` is itself an
   increase of authority and goes through the same gate); reductions (suspend a client, tighten a floor) are exposed to the api and need no gate.

## 4. Infrastructure (OpenTofu)

* `tofu apply` is not rolled back by `destroy`. Revert the commit, plan, policy-check, apply through the same gated workflow. Key Vault keys and the authority database have
  `ignore_changes`/`prevent_destroy` so a revert cannot delete key material; Key Vault purge protection keeps deleted vaults recoverable for 90 days.
* Disabling the authority tier entirely: `authority_enabled = false` plans the destruction of every authority resource **except** what `prevent_destroy` and purge protection hold; do this
  only deliberately, after exporting the audit trail, and never to "undo" a deployment.
* Cloudflare: revert the commit in `Infra/cloudflare` and apply; the tunnel is the only origin, so there is no alternative origin to fall back to (Fly is retired). The break-glass is
  the WAF "block all except /healthz" rule (KILL-SWITCHES E-13).

## 5. Data

* Database point-in-time restore: `docs/ops/RESILIENCE.md` section 3 (Flexible Server PITR to a new server, then repoint; 7 days lean, 35 days standard). The authority database is on the same server in lean: restoring
  the server restores both, so the authority's append-only key log and audit tables are restored to the same instant. Never restore only one database from a different time without checking
  the key-log head hash against the last head signed by `device-statement-signing` (a mismatch is a SEV1).

## 6. Drill (required before any authority flag)

Rollback of one ordinary deploy, one authority deploy (previous digest through `authority-deploy.yml`) and one flag-off, each timed and recorded in the ledger.
