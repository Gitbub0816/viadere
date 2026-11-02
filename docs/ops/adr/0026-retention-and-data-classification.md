# ADR-0026: Retention and data classification for authentication delivery

- **Status:** proposed (2026-11-02); revision 2 (2026-11-02): E split into E-high and E-routine (S1-A10-1), Role column (S1-A10-8), log allow-list (S1-A10-2), residency per decision 13 (S1-A10-3), variables (S1-A10-9), backups and key retirement (S1-A10-10), data-subject rights (S1-A10-7), MailerSend (S1-A10-6), phone hashes (S1-A10-5)
- **Spec reference:** §11, §11.1, §12.1, §13 (privacy test), §19.1, §23; owner decisions 7 and 10; post-Stage-0 ruling **O-3**; findings F-07
- **Related:** `docs/ops/DATA-INVENTORY.md` §7 (retention classes), SECURITY §2.20, §2.22, §2.55, §2.77; ADR-0020, ADR-0023
- **Review:** A10 (author role, privacy), A2, A11 (operability of sweeps)

## Context

Decision 7: US-only residency (Azure US regions); pending delivery secrets live minutes; security transaction metadata 30 days; high-value audit evidence longer and access-restricted per the existing audit policy. Decision 10: align existing retention to 30 days (approval-request and link-token metadata) while tamper-evident audit events keep longer, access-restricted retention. **O-3 (owner ruling after Stage 0): signed device decisions and approval-result JWS are high-value audit evidence** — longer, access-restricted retention, no secrets. **Decision 13 (2026-11-02):** all Viadere data at rest stays in US Azure regions; Cloudflare and named processors are listed honestly with their regions; nothing authentication-related is stored outside the US. Today approval requests are purged after 400 days and the result JWS is kept for disputes (SECURITY §2.55); `signed_decisions` 730 days (365-2555); `audit_events` 2555 days (730-3650) (DATA-INVENTORY §7).

## Decision

### 1. Classes

| Class | Definition | Default | Access |
|---|---|---|---|
| **P** pending secret | bearer URLs, OTP/partner codes, email-fallback addresses, business `variables`, link-code hashes, number-match codes, authority challenges' nonces | deleted at open, terminal state or expiry; sweep every 60 s; never longer than `expires_at + 2 min` | api/worker runtime only, through the owning service; never in console, export, logs |
| **T** security transaction metadata | ids, states, timestamps, tenant, pseudonymous refs, method, purpose, channel outcomes, policy version, reason codes, digests; no secrets, no content | **30 days** after terminal state (decisions 7, 10) | runtime, business (its own), operators with support role |
| **E-high** high-value audit evidence | payment and step-up decisions; recovery and key-log entries; admin, operator and crypto-officer actions; **all device-signed decisions and approval-result JWS (owner ruling O-3)** until the owner rules on OQ-1; no secrets, minimal personal data | existing audit policy (below); access-restricted | §4 |
| **E-routine** routine security evidence | authority-signed issuance records for low-risk sign-ins (link-service grants and OIDC tokens for `purpose: sign_in`: jti, kid, aud, acr, amr, sub hash, `ach`, policy version); fatigue, pause and report bookkeeping (minimal fields: ids, reason code, time) | **30 days** (the T period) | as E-high |
| **C** content | message bodies, interaction payload text | unchanged (existing classes) | unchanged |

E-high periods (O-3, "per the existing audit policy"): `signed_decisions` and the new `approval_results` keep the existing `signed_decisions` class (default 730 days, bounds 365-2555, holdable, not tenant-adjustable); `audit_events` and `authority_audit_events` keep 2555 days (730-3650) with the existing export-before-purge rule, but report events ("This wasn't me") carry only ids, reason code and time; key-log entries live for the account's lifetime plus the `signed_decisions` period after deletion (they prove which keys could sign). These numbers need privacy/legal approval before production (spec §11.1); no new long period is invented here.

**Why low-risk approval-result JWS are not yet E-routine (S1-A10-1).** O-3 classifies signed device decisions and approval-result JWS as high-value evidence without a risk qualifier. Moving routine sign-in JWS to 30 days would change that ruling, so it is put to the owner as **OQ-1** ("May device-signed results of low-risk sign-ins move to E-routine, 30 days?"). Until the owner rules, they stay E-high; everything else A10 named as routine is E-routine at 30 days now.

### 2. Per store

Role: **Pr** = Viadere as processor for the business; **Co** = Viadere as controller (its own purposes); **J?** = joint or separate, for counsel (S1-A10-8). The column links to the DPA template and the sub-processor list.

| Store (table / system) | Class | Role | Retention | Change from today |
|---|---|---|---|---|
| `auth_delivery_secrets` (new; includes `variables`) | P | Pr | until open/terminal/expiry, ≤ expiry + 2 min | new |
| `auth_deliveries` (new; `variables` only as a digest) | T | Pr | 30 days after terminal | new |
| `auth_delivery_events` (new) | T | Pr | 30 days | new |
| `approve_requests` | T (displayed details and challenge already cleared at terminal state) | Pr | **30 days** after terminal (was 400); one-time purge migration for rows older than 30 days (§3) | decision 10 |
| `approval_results` (new table: `result_ref`, `kid`, JWS) | E-high (O-3; OQ-1 open for low-risk sign-ins) | J? | `signed_decisions` class (730 d default) | O-3 |
| `decisions` (signed interaction decisions) | E-high | J? | `signed_decisions` class, unchanged; free-text `reply` erasure on account deletion unchanged (SECURITY §2.20) | none |
| `interactions` content | C | Pr | `interaction_content` unchanged (400) | none |
| `link_tokens` (SMS `/l/`, `/h/`) | T | Co | 7 days; table emptied when SMS link minting is removed (ADR-0027) | then dropped |
| `phone_link_mo_challenges` (new, ADR-0027) | P (nonce hash, keyed number hash) | Co | **whole row deleted at use or expiry** (unverified begins keep nothing); audit event only | new |
| `rate_limit_buckets`, `replay_nonces` | T | Co | until expiry (existing) | none |
| `webhook_deliveries` | T | Pr | 30 days (existing) | none |
| `outbox`, `processed_messages` | T | Co | 30 days | align if longer |
| `authority_challenges` | P (nonce) / T | Co | nonce cleared at use; row 30 days | new |
| `authority_link_codes`, `authority_oidc_codes` | P | Co | expiry + 2 min | new |
| `authority_grants` (issuance records) | E-routine for `purpose: sign_in`; E-high for `step_up` | Co | 30 days / `signed_decisions` class | new |
| `authority_keylog_entries`, `authority_keylog_heads`, `authority_accounts` | E-high | Co | account lifetime + `signed_decisions` period | new |
| `authority_tenant_keys` (ADR-0031) | T (business public keys) | Co | while active + 30 days | new |
| `authority_recovery_verifiers` (ADR-0032) | E-high (keyed verifiers, no codes) | Co | until the set is replaced or the account is deleted | new |
| `authority_audit_events` | E-high (reports: minimal fields) | Co | 2555 d, export-before-purge | new |
| `authority_oidc_consents` | T while active | Co | deleted on revoke or account deletion | new |
| fatigue, pause and report bookkeeping | E-routine | Co | 30 days | new |
| App Insights / Log Analytics (`centralus`) | T (allow-listed fields only) | Co | 30 days (existing lean setting) | **allow-list**, not regex redaction (§3) |
| Cloudflare logs and analytics | T | Co | Logpush for `id.` and link hosts excludes query strings and bodies; Cloudflare-side retention per plan, documented in DATA-INVENTORY | new rule |
| Service Bus messages | T (ids only) | Co | message TTL ≤ 1 day | none |
| PostgreSQL backups (PITR) | all classes | — | 7 days lean / 35 days standard, US region pairs only | restore runbook (§3) |
| APNs / FCM | provider | Pr/Co | ids only, no control over provider logs | payload minimization is the control |
| MailerSend (email fallback) | provider | Pr | content retention off or minimum, activity retention shortest; location verified before enabling (ADR-0020 §7 gate) | new use, gated |
| SMS provider inbound messages (phone MO) | provider | Co | shortest available retention configured and documented (S1-A10-5) | new |

### 3. Mechanics

- Add `auth_delivery_metadata` (30, bounds 7-90, tenant may shorten, holdable), `auth_evidence_routine` (30, not tenant-adjustable, holdable) and `auth_secrets` (minutes, not adjustable, not holdable: a legal hold never preserves bearer secrets) to `RetentionClass`; extend `approval_results` into the existing `signed_decisions` class.
- P sweeps run in the job loop every minute and on every state transition (delete in the same transaction); a test asserts no P row outlives `expires_at + 2 min` (ST-PRIV-04).
- **Logs (S1-A10-2).** Auth-delivery, phone-link, recovery and OIDC routes log an **allow-list** of fields (route template, status, ids, latency, error code), implemented in the logger and in the App Insights telemetry initializer; query strings, bodies and non-id headers are never logged. Regex redaction stays only as a second layer. Cloudflare Logpush and analytics for the `id.` and link-service hosts exclude query strings.
- **Phone numbers (S1-A10-5).** Wherever a number is compared or stored outside the existing encrypted columns, it is `HMAC-SHA256(SERVER_PEPPER, "phone\n" ‖ e164)`; never a plain hash.
- **Backups and key retirement (S1-A10-10).** `AUTH_SECRET_KEY` versions are retired (disabled, then deleted) only after the longest backup window (35 days in standard) has passed since their last use, so P-class ciphertext in a backup becomes undecryptable then; the restore runbook re-runs every retention sweep and replays deletion tombstones (account deletions, revocations) **before** the restored database serves traffic (ST-PRIV-04b). The move of `approve_requests` from 400 to 30 days ships with a one-time purge migration and a release note for existing retention settings.
- **Inherited gaps (S1-A10-10), listed with owners:** `channel_endpoints` and `rcs_postbacks` have no purge (owner A10, Stage 2); `sms_consent_events` kept indefinitely pending counsel (owner A10 with counsel, before production).
- **Residency (decision 13, S1-A10-3).** Residency means: **all Viadere data at rest is stored in Azure US regions** (`centralus` in staging; geo-redundant backup pairs in the standard profile must be US pairs). Enforced by an Azure Policy "allowed locations" assignment limited to US regions on every Viadere resource group and by a `policy_check.py` rule `RESIDENCY-US` that fails any resource, backup pair, Log Analytics workspace, Service Bus namespace or Key Vault outside US regions (ADR-0028 §5). Transit and processors are disclosed, not claimed as US-only: Cloudflare (global edge and tunnel: TLS termination and transit processing worldwide; logs per Cloudflare plan), Apple APNs and Google FCM (ids only), Microsoft Entra ID (global identity service for workload tokens; no customer data), MailerSend (location to be verified; fallback gated, ADR-0020 §7), Didit (EU by default; identity verification only, outside the authentication-delivery claim), the SMS provider (inbound phone-link texts). The exact list with regions lives in `docs/ops/DATA-INVENTORY.md` §3 and the public sub-processor list. Nothing authentication-related is stored outside the US: this is why the email fallback is gated. Destination countries for email/SMS are a separate setting (SCOPE_LEDGER C-7).

### 4. Access restriction for class E (E-high and E-routine)

- Database: E tables live in schema `evidence`; `viadere_app` and `viadere_worker` have `INSERT` and `SELECT` on id and timestamp columns only, no `SELECT` on payload columns (`jws`, `signed_payload`, `public_key`, `proof`) except through the security-definer function used by verification paths that need them; UPDATE/DELETE refused except via the retention gate (SECURITY §2.77 pattern).
- People: only the operator role `security_auditor` (new; separate from support and operator admin, `docs/ops/CONSOLE-ROLES.md`) can export evidence, through the audited `export-dispute`-style job with a fresh passkey step-up and a reason of ≥ 20 characters; audit event `evidence.accessed` (actor, subject ids, reason). Tenants never read raw evidence other than their own business-verified JWS (which they already receive).
- Authority E data (which holds the cross-business view per `account_ref`, S1-A10-11) is reachable only by authority roles; its export is an admin-job command under the reviewer rules of ADR-0019 §5 and needs the same `security_auditor` reason and step-up.

### 5. Data subject rights (S1-A10-7)

Account deletion (SECURITY §2.20) additionally: deletes P, T and E-routine auth rows for the account, deletes OIDC consents, appends `account_deleted` to the authority key log (revoking every key), and keeps E-high rows that contain no free text for their period (they hold keys, ids and signatures, needed to prove what a device signed; the legal basis under applicable US state law, e.g. security-and-integrity and legal-claims exceptions, is for counsel). The privacy notice says which evidence survives deletion, for how long and why. The consumer export (SECURITY §2.78) lists, by category with counts, businesses and times (never secrets or signatures): auth deliveries, `approval_results`, authority grants, OIDC consents, key-log entries (devices and dates), pause and fatigue state, reports, phone-link records. Consent list and revoke are in the app (ADR-0024 §8). Each new table has a deletion test (ST-PRIV-06).

## Consequences

- `approve_requests` purge moves from 400 to 30 days; dispute evidence survives in `approval_results`.
- Backups are the longest-lived copy of T data; the restore runbook re-applies sweeps and tombstones, and `AUTH_SECRET_KEY` retirement bounds P ciphertext in backups.
- Low-risk sign-in JWS stay E-high until the owner answers OQ-1.
- Privacy/legal approval of the E periods is a production prerequisite (spec §11.1).

## Threat assumptions changed

- A database read (AS-2c) exposes no P secret after its minutes window and only ciphertext within it.
- Evidence is no longer readable by every operator role.

## Reviewers required

A10 (classification, periods, rights), A2 (evidence access), A11 (sweep operability).
