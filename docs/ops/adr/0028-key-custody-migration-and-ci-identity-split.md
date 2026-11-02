# ADR-0028: Key custody, migration of existing api-held keys, and the CI deploy-identity split

- **Status:** proposed (2026-11-02); revision 3 (2026-11-02): standby keys as separate objects without roles, `recovery-seal` keys and unwrap-only role, app-pinned reference set, KEY-ROTATION.md before Stage 4 (S1-A3-R02, S2-A2-1, S2-A2-5); revision 2 (2026-11-02): explicit key versions (S1-A3-10), custom sign-only role and backup rule (S1-A3-11), new HMAC keys (S1-A3-13), recovery moved before the pilot (ADR-0032), honest reviewer separation, CODEOWNERS and provenance (S1-A2-9), JWKS publication environment (S1-A3-01), private GHCR with a scoped pull credential (owner decision 14), residency rule (decision 13)
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
| `device-statement-signing` (was `keylog-signing`) | ES256: key-log heads, signed challenges, tenant destination-key records, pinned-key revocation lists (ADR-0033); pinned in the app as the active key | — | authority only | Stage 6 | ADR-0033 §3 |
| `device-statement-signing-standby` (revision 3) | ES256 standby, a **separate key object**, created disabled; signs statement-family revocation lists after rollover; pinned in the app as the standby | — | no role for any identity until rollover; then authority only | Stage 6 | ADR-0033 §3.2 (S1-A3-R02) |
| `recovery-seal` active + standby (revision 3) | HPKE KEM key pairs (P-256); private halves stored only wrapped, in `authority_seal_keys`; public halves pinned in the app | — | authority only (in memory after unwrap) | **before the pilot** | ADR-0034 |
| `recovery-seal-kek`, `recovery-seal-kek-standby` (revision 3) | RSA 3072, RSA-OAEP-256, key ops `wrapKey`/`unwrapKey` only; wrap the seal private keys | — | authority: unwrap on the active KEK only; standby KEK no role until rollover | **before the pilot** | ADR-0034 §5 |
| `kd-log-signing` | key-directory transparency log heads | api | **move to authority** with verify-before-sign: the authority keeps the last signed head, receives appended leaves, recomputes the Merkle root and signs only an append-only extension (consistency check), so a compromised api cannot sign a fork or rollback | C2 (after pilot) | a forked directory head would let a relay substitute business keys (SECURITY §2.58 residual 1) |
| `link-descriptor` | link-session descriptors | api | stays (exception) until link sessions carry grant semantics; then moves under the same verify-before-sign pattern | C3 (conditional) | descriptors are verified by the app against business-confirmed data; not an authentication grant |
| `loop-publication` | Loop manifests after the review gate | api | stays (exception) | none planned | content-integrity key; high-risk Loop actions bind through Approve v2 (business-verified) |
| `brand-manifest` | Brand Kit manifests | api | stays (exception) | none planned | content-integrity key, no authentication meaning |
| `kek-data` | RSA wrap of `*_WRAPPED` secrets | api, worker | stays (exception; required for the api to operate) | standard profile: HSM | wrapping key, not a signing key; unwrapped secrets live in api memory by necessity |
| `audit-head-signing` | exported audit heads | worker | stays with worker | — | not public-facing; export on in standard |
| `CONNECT_LINK_SIGNING_KEY` | HMAC for connect-link context | api | stays | — | marketing-link integrity |
| `AUTH_SECRET_KEY` (new) | AES-GCM for P-class fields | — | api, worker | Stage 3 | transport by design (R-01) |
| `OIDC_PAIRWISE_KEY` (new) | HMAC for pairwise OIDC `sub` only | — | authority only | Stage 6 | S1-A3-13 |
| `ACCOUNT_REF_KEY` (new) | HMAC for `account_ref` | — | authority only | Stage 6 | ADR-0032 §4 |
| `RECOVERY_VERIFIER_KEY` (new) | HMAC for authority recovery-code verifiers | — | authority only | **before the pilot** (ADR-0032 §3.5) | ADR-0032 §3 |
| `SUBJECT_REF_KEY` | HMAC for tenant `subject_ref` | api | api **and** an authority copy | Stage 6 | §3 |

**Exception row** (added to the CLAUDE.md exceptions table in this Stage 1 change): the five api-held keys `kd-log-signing`, `link-descriptor`, `loop-publication`, `brand-manifest`, `kek-data` remain with `id-viadere-api` (decision 12); no grant, OIDC, token or key-log key may ever be granted to an ordinary identity; removal condition per row above.

### 2. Authority keys: creation, policy, lifecycle

- Created in `kv-vdr-auth-<env>` through the ARM control plane by `id-gh-infra-auth-apply-<env>` (OpenTofu root `Infra/azure-authority`), `exportable = false`, key ops `sign`/`verify` only (RSA key: `sign`/`verify`, no wrap). Lean: software-protected EC/RSA keys (new CLAUDE.md exception row in Stage 6, same removal condition as the existing lean software-key row); standard: `EC-HSM` / `RSA-HSM` in Key Vault Premium.
- **Data-plane role (S1-A3-11).** `id-viadere-authority` gets a **custom role** "Viadere Authority Signer" with data actions `keys/read` and `keys/sign/action` only (verification is local); no backup, update, encrypt/decrypt, wrap/unwrap. The one exception (revision 3, ADR-0034 §5) is a second custom role "Viadere Authority Unwrapper" (`keys/read`, `keys/unwrapKey/action`) on the single key `recovery-seal-kek`; standby keys (`device-statement-signing-standby`, `recovery-seal-kek-standby`) carry no role for `id-viadere-authority` until a rollover grants one through `id-gh-infra-auth-apply-<env>` (ADR-0033 §3.2). The built-in Crypto User role is not used because it also grants backup and update (re-verify the built-in definition on Microsoft Learn in Stage 6). Crypto Officer only for `grp-viadere-<env>-auth-crypto-officers` through PIM (time-bound activation, approval by a second member where one exists, §6.6); officers use backup only by runbook.
- **What "non-exportable" means.** Lean (Key Vault Standard, software-protected keys): no API export and no Secure Key Release; a key backup blob is possible for a holder of `keys/backup/action` and restorable into another vault in the same subscription and geography, so backup is restricted by role and policy (`AUTH-KEY-BACKUP`, §5). Standard: HSM-protected keys (Key Vault Premium).
- **Explicit key versions (S1-A3-10).** In Key Vault a new version becomes "current" immediately, so the authority never signs with "latest": its configuration names `name/version` for every key, changed only by the admin job. At startup and on every switch the authority checks that the version's RFC 7638 thumbprint is in its configured "published `kid`s" list (from the attested inventory, ADR-0024 §7) and fails closed otherwise. For `device-statement-signing` and `recovery-seal` the reference list is the **app-pinned constants** for the environment (Core), not JWKS (S1-A3-R02 item 6). New versions are created with `nbf` set to the planned activation time as a second guard. `KeyManagementService` gains RSA (`RS256`) with the same verify-after-sign check; `AzureKeyVaultKMS`'s current-version lookup is not used by the authority.
- Rotation: yearly or on suspicion; new version created, public key published through `authority-publish` ≥ 24 h before activation (ADR-0024 §7), activated by an admin-job command that changes the pinned version, old version disabled after 24 h and kept (disabled, not deleted) for verification of evidence records. Emergency rollover: publish new, switch the pin immediately, remove old from JWKS; RPs refetch JWKS on unknown `kid` (documented maximum exposure, ADR-0024 §7.5). `device-statement-signing` and `recovery-seal` rollover and revocation follow ADR-0033 §3. Procedure documented in `docs/ops/KEY-ROTATION.md`, written **before Stage 4 pins any key** (condition C-6; ledger L-2).
- Backup/recovery: Key Vault soft delete and purge protection (existing settings); no routine key backup (lean keys are never reused in standard, existing rule).
- **Sign reconciliation.** Key Vault `AuditEvent` diagnostics on `kv-vdr-auth` go to Log Analytics (`centralus`); a job that is independent of the worker reconciles every `sign` against `authority_grants` and statement issuance records, and every `unwrapKey` against authority replica starts (exactly one per start, ADR-0034 §5), and alerts on any unmatched operation (ADR-0023 §6).

### 3. `SUBJECT_REF_KEY` copy

The authority needs the same HMAC key to compute a grant's `sub` as the business's `subject_ref` (ADR-0023 §5). It is copied once into `kv-vdr-auth` by a crypto officer; rotation of `SUBJECT_REF_KEY` (rare; it changes every business's references) is a coordinated change of both copies recorded in KEY-ROTATION.md. The api knowing this key does not help an attacker only because the authority computes `sub` from the account that owns the verified signing key, after checking any api-supplied account id against that key's `account_ref` (ADR-0032 §2, S1-A3-04), and takes the business id from its own client record.

### 4. Recovery verifiers (moving recovery trust into the authority)

Superseded by ADR-0032 §3 and ADR-0034 and moved **before** `AUTH_LINK_SERVICE_ENABLED` or `AUTHORITY_OIDC_ENABLED` is enabled for any account: code sets are generated on the device and registered with the authority only inside an HPKE envelope sealed to the pinned `recovery-seal` key (the api never sees a code or holds a hash of one), `recovery_started` needs a sealed, authority-verified code bound to the new keys, and keys recovered through a legacy (api-verified) code set are never grant-capable. The api keeps running the existing recovery flow for the account itself.

### 5. IaC policy rules (`policy_check.py`, fail in both profiles)

| Rule id | Fails when |
|---|---|
| `AUTH-KEY-SCOPE` | any role on `kv-vdr-auth` or its keys/secrets is assigned to an identity other than `id-viadere-authority` (data plane) or the authority crypto/secrets officer groups |
| `AUTH-NO-PUBLIC-INGRESS` | the authority environment is not `internal`, or any authority app has `external_enabled = true` outside the internal environment, or a Cloudflare route targets it |
| `AUTH-IDENTITY-SEPARATE` | `id-viadere-authority` is attached to any app outside `rg-viadere-<env>-auth`, or any ordinary identity is attached to an authority app |
| `AUTH-DEPLOY-SEPARATE` | any identity holds Managed Identity Operator on both an ordinary and an authority workload identity, or Container Apps Contributor on both resource groups |
| `AUTH-EGRESS` | `nsg-viadere-<env>-auth` lacks the final deny-Internet outbound rule |
| `API-NO-NEW-KEYS` | `key_grants.api` contains anything beyond the five exception keys |
| `AUTH-KEY-BACKUP` | any principal other than the authority crypto-officer group holds `keys/backup/action` (directly or through a built-in role such as Crypto User) on `kv-vdr-auth` |
| `AUTH-SIGNER-ROLE` | `id-viadere-authority` holds any data action on `kv-vdr-auth` beyond `keys/read`, `keys/sign/action`, `secrets/getSecret` on its named secrets, and `keys/unwrapKey/action` on `recovery-seal-kek` only |
| `AUTH-STANDBY-ROLE` (revision 3) | any identity other than the authority crypto-officer group holds a data role on `device-statement-signing-standby` or `recovery-seal-kek-standby` without a recorded rollover in the plan's change file |
| `AUTH-REVOCATIONS-ROLE` | `id-viadere-worker` holds the `Authority.Evidence.Submit` app role (it gets only `Authority.Revocations`) |
| `RESIDENCY-US` | any resource, backup pair, Log Analytics workspace, Service Bus namespace or Key Vault is outside Azure US regions (decision 13; ADR-0026 §3) |
| `GHCR-NO-PAT` | the Key Vault secret used for registry pulls is not the dedicated deploy-owned pull credential (§6.7) |

### 6. CI deploy-identity split (fixes F-02)

1. **Subject hardening.** Configure the repository's OIDC subject template to include `job_workflow_ref` (GitHub's customizable OIDC subject claims); every federated credential then pins `repo:<repo>:environment:<env>:job_workflow_ref:<repo>/.github/workflows/<file>@refs/heads/main`. A workflow on another branch or file cannot obtain the identity's token.
2. `id-gh-deploy-<env>` (existing) loses nothing it needs but never gains authority rights: Container Apps Contributor on `rg-viadere-<env>-app`, Managed Identity Operator on api, worker, migrator, cloudflared only. Federated to `azure.yml` deploy job, environment `staging`.
3. `id-gh-deploy-auth-<env>` (new): Container Apps Contributor on `rg-viadere-<env>-auth`, Managed Identity Operator on the three authority identities, AcrPush on the authority registry. Federated to `authority-deploy.yml`, environment `authority-staging` with required reviewers (§6.6) and deployment branch `main` only.
4. Authority images: built by `release.yml`, cosign-signed and SLSA-attested (existing pipeline); `authority-deploy.yml` verifies the signature, the expected workflow identity **and the SLSA provenance tying the digest to a commit on protected `main`**, shows that commit and its diff summary to the reviewer, then pushes by digest to the authority registry and updates the app by digest. Unsigned, wrong-identity or off-`main` images are refused (ST-CI-05). A correctly signed image built from a malicious merged commit remains R-11; branch protection and CODEOWNERS (§6.6) are the control on what reaches `main`.
5. `id-gh-authority-admin-<env>`: can only start `job-viadere-authority-admin` (custom role with `Microsoft.App/jobs/start/action` on that job), federated to `authority-admin.yml`, environment `authority-admin-<env>` with required reviewers (§6.6). `authority-publish.yml` (ADR-0024 §7) runs in environment `authority-publish-<env>` with the same reviewers and its own Cloudflare token; it holds no Azure credential.
6. **Reviewer separation, stated honestly (S1-A2-9).**
   1. Named reviewers per environment are recorded in `docs/ops/AUTHORITY-REVIEWERS.md` (Stage 6): staging = the owner.
   2. Agent sessions commit and push through a GitHub identity **distinct from the owner's** (a machine user or GitHub App), and every authority environment enables "Prevent self-review", so a run triggered by an identity cannot be approved by it. This needs an owner action (OQ-3).
   3. `main` has branch protection with required review, and CODEOWNERS (owner) on `.github/workflows/authority-*.yml`, `.github/CODEOWNERS`, `Server/Sources/ViadereAuthority*`, `Infra/azure-authority/` and `Site/content/id/**`, with code-owner review required.
   4. Staging has one human. The admin, deploy and publish paths are therefore **a single owner approval** in staging; revision 1's "two reviewers, neither the requester" is withdrawn for staging. This is residual **R-21** (owner A2), removal condition: a second human reviewer is named before production or before any real customer data. Production requires two human reviewers, neither the requester.
   5. Test ST-CI-08: a workflow run triggered by the reviewer's own identity cannot approve itself; CODEOWNERS exists and code-owner review is enforced on the listed paths.
7. **Registry credential (owner decision 14).** GHCR images stay private. The owner's personal `read:packages` token (F-18) is replaced by a dedicated pull credential owned by the deploy setup: a GitHub App installation token or fine-grained token scoped to `packages:read` on the Viadere packages only, created and rotated by the deploy workflow (not a person), stored in `kv-vdr-<env>` and readable only by the ordinary tier's registry configuration. The authority never pulls from GHCR (it uses its own registry, TRUST_BOUNDARIES §9). Policy rule `GHCR-NO-PAT`; rotation at least every 90 days and on any suspicion.
8. Result: no single CI credential can deploy gateway and authority (spec §9.2); a compromised build credential cannot silently update all trust authorities (spec §9.4): it would need the authority environment's reviewer approval, and JWKS publication needs the same.

### 7. Control-plane identities (F-03)

- Re-scope `id-gh-infra-apply-<env>` from subscription Contributor to the four existing resource groups (`app`, `data`, `sec`, `ops`), keeping its RBAC-administrator condition, and exclude `rg-viadere-<env>-auth`.
- New `id-gh-infra-auth-apply-<env>` for the `Infra/azure-authority` root (own state container key, own GitHub environment `azure-infra-authority-<env>` with required reviewers).
- Lean exception: authority in the same subscription as the ordinary tier (recorded in Stage 6 with removal condition "standard profile: separate subscription or management group for the authority tier", spec §9.2).
- Humans: Owner on the subscription remains break-glass (AS-7); PIM for Key Vault officer roles; alert rules (Activity Log) on role assignments, Key Vault key operations (`sign` volume spikes, `create`, `update`, `delete`, access-policy/RBAC changes) in both vaults, NSG and Container Apps environment changes, and Entra application/app-role changes for `viadere-authority-<env>`.

### 8. Cloudflare

The site workflow's Cloudflare API token is scoped to the site's Workers Static Assets and has **no** `id.` scope; `authority-publish.yml` has its own token scoped to the `id.` host's static assets only (ADR-0024 §7). DNS and route changes for `id.` go through IaC (`Infra/cloudflare/`), with a drift job (Stage 6) and an audit-log alert. The tunnel token remains an api-environment secret; the authority has no tunnel. Cloudflare Logpush and analytics for `id.` and the link-service host exclude query strings (ADR-0026 §3).

### 9. Worker scope at the authority (S1-A2-8)

The worker gets a separate app role `Authority.Revocations` that reaches only `POST revocations`; `Authority.Evidence.Submit` is assigned to `id-viadere-api` only. Test ST-AUTH-18: a worker token on `evidence` → `403`.

## Consequences

- Two more GitHub environments and three new federated identities; the owner approves authority deploys in staging.
- Moving `kd-log-signing` (C2) needs the authority to hold directory leaves; scheduled after the pilot.
- Existing api-held keys remain a recorded exception, consistent with decision 12, and can never be extended to grant keys (policy rule `API-NO-NEW-KEYS`).

## Threat assumptions changed

- AS-1 no longer reaches any key that RPs or businesses trust for authentication.
- CI compromise must now defeat a second, reviewer-gated environment to touch the authority; malicious merged code remains R-11.

## Reviewers required

A3 (custody, rotation, key types), A5 (RBAC, federation, policy rules), A2 (threat deltas), A11 (rotation runbook, alerts).
