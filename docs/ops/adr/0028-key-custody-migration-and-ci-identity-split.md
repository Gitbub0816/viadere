# ADR-0028: Key custody, migration of existing api-held keys, and the CI deploy-identity split

- **Status:** proposed (2026-11-02)
- **Spec reference:** §4.3, §9.2, §9.3, §9.4, §22, §26 (ordinary admin), §27 (exportable keys); owner decisions 5, 11, **12**; findings **F-01**, **F-02**, F-03, F-17, F-18
- **Related:** ADR-0012 (Key Vault), ADR-0019, ADR-0023, ADR-0024 §7; `Infra/azure/locals.tf` (`kv_keys`, `key_grants`), `identity.tf`, `policy_check.py`; `docs/ops/KEY-ROTATION.md`
- **Review:** A3 and A5 (author roles: custody and identities), A2, A11

## Context

`id-viadere-api` has Crypto User on `kek-data`, `kd-log-signing`, `link-descriptor`, `loop-publication`, `brand-manifest` (`locals.tf` `key_grants`, verified) and Secrets User on every service secret (F-01). One GitHub deploy identity per environment has Container Apps Contributor on the app resource group and Managed Identity Operator on all four workload identities, federated on `environment:<env>` only (`identity.tf:40,45-57`, verified) (F-02). The infra apply identity is effectively subscription Owner (F-03, carried). Decision 12: new grant/OIDC keys live only in the private signer from day one; existing keys stay with the api as a tracked exception with a migration plan.

## Decision

### 1. Key inventory and target custody

| Key | Type / purpose | Today | Target | Phase | Rationale |
|---|---|---|---|---|---|
| `grant-signing` | ES256, link-service grants | — | authority only (`kv-vdr-auth`) | Stage 6 creation | decision 12 |
| `oidc-signing-rs256`, `oidc-signing-es256` | id_tokens, access tokens | — | authority only | Stage 6 (staging flag) | decision 12, OIDC Discovery RS256 |
| `keylog-signing` | key-log heads pinned in the app | — | authority only | Stage 6 | ADR-0023 §4 |
| `kd-log-signing` | key-directory transparency log heads | api | **move to authority** with verify-before-sign: the authority keeps the last signed head, receives appended leaves, recomputes the Merkle root and signs only an append-only extension (consistency check), so a compromised api cannot sign a fork or rollback | C2 (after pilot) | a forked directory head would let a relay substitute business keys (SECURITY §2.58 residual 1) |
| `link-descriptor` | link-session descriptors | api | stays (exception) until link sessions carry grant semantics; then moves under the same verify-before-sign pattern | C3 (conditional) | descriptors are verified by the app against business-confirmed data; not an authentication grant |
| `loop-publication` | Loop manifests after the review gate | api | stays (exception) | none planned | content-integrity key; high-risk Loop actions bind through Approve v2 (business-verified) |
| `brand-manifest` | Brand Kit manifests | api | stays (exception) | none planned | content-integrity key, no authentication meaning |
| `kek-data` | RSA wrap of `*_WRAPPED` secrets | api, worker | stays (exception; required for the api to operate) | standard profile: HSM | wrapping key, not a signing key; unwrapped secrets live in api memory by necessity |
| `audit-head-signing` | exported audit heads | worker | stays with worker | — | not public-facing; export on in standard |
| `CONNECT_LINK_SIGNING_KEY` | HMAC for connect-link context | api | stays | — | marketing-link integrity |
| `AUTH_SECRET_KEY` (new) | AES-GCM for P-class fields | — | api, worker | Stage 3 | transport by design (R-01) |
| `OIDC_PAIRWISE_KEY` (new) | HMAC for pairwise `sub` and `account_ref` | — | authority only | Stage 6 | |
| `SUBJECT_REF_KEY` | HMAC for tenant `subject_ref` | api | api **and** an authority copy | Stage 6 | §3 |

**Exception row** (added to the CLAUDE.md exceptions table in this Stage 1 change): the five api-held keys `kd-log-signing`, `link-descriptor`, `loop-publication`, `brand-manifest`, `kek-data` remain with `id-viadere-api` (decision 12); no grant, OIDC, token or key-log key may ever be granted to an ordinary identity; removal condition per row above.

### 2. Authority keys: creation, policy, lifecycle

- Created in `kv-vdr-auth-<env>` through the ARM control plane by `id-gh-infra-auth-apply-<env>` (OpenTofu root `Infra/azure-authority`), `exportable = false`, key ops `sign`/`verify` only (RSA key: `sign`/`verify`, no wrap). Lean: software-protected EC/RSA keys (new CLAUDE.md exception row in Stage 6, same removal condition as the existing lean software-key row); standard: `EC-HSM` / `RSA-HSM` in Key Vault Premium.
- Crypto User (key scope) only for `id-viadere-authority`. Crypto Officer only for `grp-viadere-<env>-auth-crypto-officers` through PIM (time-bound activation, approval by a second member).
- Rotation: yearly or on suspicion; new version created, public key published in the static JWKS ≥ 24 h before activation (ADR-0024 §7), activated by an admin-job command, old version disabled after 24 h and kept (disabled, not deleted) for verification of evidence records. Emergency rollover: publish new, activate immediately, remove old from JWKS; RPs must refetch JWKS on unknown `kid` (documented).
- Backup/recovery: Key Vault soft delete and purge protection (existing settings); no key backup export (lean keys are never reused in standard, existing rule).

### 3. `SUBJECT_REF_KEY` copy

The authority needs the same HMAC key to compute a grant's `sub` as the business's `subject_ref` (ADR-0023 §5). It is copied once into `kv-vdr-auth` by a crypto officer; rotation of `SUBJECT_REF_KEY` (rare; it changes every business's references) is a coordinated change of both copies recorded in KEY-ROTATION.md. The api knowing this key does not help an attacker: the authority computes `sub` from the account that owns the verified signing key.

### 4. Recovery verifiers (moving recovery trust into the authority)

Stage 6: newly generated recovery-code sets are verified by the authority (`RECOVERY_VERIFIER_KEY` in `kv-vdr-auth`, `HMAC(key, "recovery-code\n{account_ref}\n{code}")`), so `recovery_started` in the key log carries authority-verified evidence instead of an api statement. Existing code sets stay api-verified until the person regenerates them (the app prompts after the release). Until then the authority-timed 72 h hold and the app-visible key-log head are the controls (ADR-0023 §4).

### 5. IaC policy rules (`policy_check.py`, fail in both profiles)

| Rule id | Fails when |
|---|---|
| `AUTH-KEY-SCOPE` | any role on `kv-vdr-auth` or its keys/secrets is assigned to an identity other than `id-viadere-authority` (data plane) or the authority crypto/secrets officer groups |
| `AUTH-NO-PUBLIC-INGRESS` | the authority environment is not `internal`, or any authority app has `external_enabled = true` outside the internal environment, or a Cloudflare route targets it |
| `AUTH-IDENTITY-SEPARATE` | `id-viadere-authority` is attached to any app outside `rg-viadere-<env>-auth`, or any ordinary identity is attached to an authority app |
| `AUTH-DEPLOY-SEPARATE` | any identity holds Managed Identity Operator on both an ordinary and an authority workload identity, or Container Apps Contributor on both resource groups |
| `AUTH-EGRESS` | `nsg-viadere-<env>-auth` lacks the final deny-Internet outbound rule |
| `API-NO-NEW-KEYS` | `key_grants.api` contains anything beyond the five exception keys |

### 6. CI deploy-identity split (fixes F-02)

1. **Subject hardening.** Configure the repository's OIDC subject template to include `job_workflow_ref` (GitHub's customizable OIDC subject claims); every federated credential then pins `repo:<repo>:environment:<env>:job_workflow_ref:<repo>/.github/workflows/<file>@refs/heads/main`. A workflow on another branch or file cannot obtain the identity's token.
2. `id-gh-deploy-<env>` (existing) loses nothing it needs but never gains authority rights: Container Apps Contributor on `rg-viadere-<env>-app`, Managed Identity Operator on api, worker, migrator, cloudflared only. Federated to `azure.yml` deploy job, environment `staging`.
3. `id-gh-deploy-auth-<env>` (new): Container Apps Contributor on `rg-viadere-<env>-auth`, Managed Identity Operator on the three authority identities, AcrPush on the authority registry. Federated to `authority-deploy.yml`, environment `authority-staging` with **required reviewers (≥ 1, not the change author; the owner in staging)** and deployment branch `main` only.
4. Authority images: built by `release.yml`, cosign-signed and SLSA-attested (existing pipeline); `authority-deploy.yml` verifies the signature and the expected workflow identity before pushing by digest to the authority registry and updating the app by digest. Unsigned or wrong-identity images are refused (ST-CI-05).
5. `id-gh-authority-admin-<env>`: can only start `job-viadere-authority-admin` (custom role with `Microsoft.App/jobs/start/action` on that job), federated to `authority-admin.yml`, environment `authority-admin-<env>` with **two** required reviewers.
6. Result: no single CI credential can deploy gateway and authority (spec §9.2); a compromised build credential cannot silently update all trust authorities (spec §9.4): it would need the authority environment's reviewer approval.

### 7. Control-plane identities (F-03)

- Re-scope `id-gh-infra-apply-<env>` from subscription Contributor to the four existing resource groups (`app`, `data`, `sec`, `ops`), keeping its RBAC-administrator condition, and exclude `rg-viadere-<env>-auth`.
- New `id-gh-infra-auth-apply-<env>` for the `Infra/azure-authority` root (own state container key, own GitHub environment `azure-infra-authority-<env>` with required reviewers).
- Lean exception: authority in the same subscription as the ordinary tier (recorded in Stage 6 with removal condition "standard profile: separate subscription or management group for the authority tier", spec §9.2).
- Humans: Owner on the subscription remains break-glass (AS-7); PIM for Key Vault officer roles; alert rules (Activity Log) on role assignments, Key Vault key operations (`sign` volume spikes, `create`, `update`, `delete`, access-policy/RBAC changes) in both vaults, NSG and Container Apps environment changes, and Entra application/app-role changes for `viadere-authority-<env>`.

### 8. Cloudflare

The site workflow's Cloudflare API token is scoped to Workers Static Assets for the site and `id.` host only; DNS and route changes for `id.` go through IaC (`Infra/cloudflare/`), with a drift job (Stage 6) and an audit-log alert. The tunnel token remains an api-environment secret; the authority has no tunnel.

## Consequences

- Two more GitHub environments and three new federated identities; the owner approves authority deploys in staging.
- Moving `kd-log-signing` (C2) needs the authority to hold directory leaves; scheduled after the pilot.
- Existing api-held keys remain a recorded exception, consistent with decision 12, and can never be extended to grant keys (policy rule `API-NO-NEW-KEYS`).

## Threat assumptions changed

- AS-1 no longer reaches any key that RPs or businesses trust for authentication.
- CI compromise must now defeat a second, reviewer-gated environment to touch the authority; malicious merged code remains R-11.

## Reviewers required

A3 (custody, rotation, key types), A5 (RBAC, federation, policy rules), A2 (threat deltas), A11 (rotation runbook, alerts).
