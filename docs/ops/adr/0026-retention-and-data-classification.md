# ADR-0026: Retention and data classification for authentication delivery

- **Status:** proposed (2026-11-02)
- **Spec reference:** §11, §11.1, §12.1, §13 (privacy test), §19.1, §23; owner decisions 7 and 10; post-Stage-0 ruling **O-3**; findings F-07
- **Related:** `docs/ops/DATA-INVENTORY.md` §7 (retention classes), SECURITY §2.20, §2.22, §2.55, §2.77; ADR-0020, ADR-0023
- **Review:** A10 (author role, privacy), A2, A11 (operability of sweeps)

## Context

Decision 7: US-only residency (Azure US regions); pending delivery secrets live minutes; security transaction metadata 30 days; high-value audit evidence longer and access-restricted per the existing audit policy. Decision 10: align existing retention to 30 days (approval-request and link-token metadata) while tamper-evident audit events keep longer, access-restricted retention. **O-3 (owner ruling after Stage 0): signed device decisions and approval-result JWS are high-value audit evidence** — longer, access-restricted retention, no secrets. Today approval requests are purged after 400 days and the result JWS is kept for disputes (SECURITY §2.55); `signed_decisions` 730 days (365-2555); `audit_events` 2555 days (730-3650) (DATA-INVENTORY §7).

## Decision

### 1. Classes

| Class | Definition | Default | Access |
|---|---|---|---|
| **P** pending secret | bearer URLs, OTP/partner codes, email-fallback addresses, link-code hashes, number-match codes, authority challenges' nonces | deleted at open, terminal state or expiry; sweep every 60 s; never longer than `expires_at + 2 min` | api/worker runtime only, through the owning service; never in console, export, logs |
| **T** security transaction metadata | ids, states, timestamps, tenant, pseudonymous refs, method, purpose, channel outcomes, policy version, reason codes; no secrets, no content | **30 days** after terminal state (decision 7, 10) | runtime, business (its own), operators with support role |
| **E** high-value audit evidence | device-signed decisions, `ApprovalResult` JWS, authority key-log entries, grant/token issuance records, audit events; **no secrets**, minimal personal data | existing audit policy (below); access-restricted | §4 |
| **C** content | message bodies, interaction payload text | unchanged (existing classes) | unchanged |

Evidence periods (O-3, "per the existing audit policy"): `signed_decisions` and the new `approval_results` keep the existing `signed_decisions` class (default 730 days, bounds 365-2555, holdable, not tenant-adjustable); `audit_events` and `authority_audit_events` keep 2555 days (730-3650) with the existing export-before-purge rule; key-log entries live for the account's lifetime plus the `signed_decisions` period after deletion (they prove which keys could sign). These numbers need privacy/legal approval before production (spec §11.1); no new period is invented here.

### 2. Per store

| Store (table / system) | Class | Retention | Change from today |
|---|---|---|---|
| `auth_delivery_secrets` (new) | P | until open/terminal/expiry, ≤ expiry + 2 min | new |
| `auth_deliveries` (new) | T | 30 days after terminal | new |
| `auth_delivery_events` (new) | T | 30 days | new |
| `approve_requests` | T (displayed details and challenge already cleared at terminal state) | **30 days** after terminal (was 400) | decision 10 |
| `approval_results` (new table split out of `approve_requests`: `result_ref`, `kid`, JWS) | E | `signed_decisions` class (730 d default) | O-3; the JWS was previously kept implicitly |
| `decisions` (signed interaction decisions) | E | `signed_decisions` class, unchanged; free-text `reply` erasure on account deletion unchanged (SECURITY §2.20) | none |
| `interactions` content | C | `interaction_content` unchanged (400) | none (not auth-delivery metadata) |
| `link_tokens` (SMS `/l/`, `/h/`) | T | 7 days (already ≤ 30); table emptied when SMS link minting is removed (ADR-0027) | then dropped |
| `phone_link_mo_challenges` (new, ADR-0027) | P (nonce hash) / T (row) | nonce hash deleted at use/expiry; row 30 days | new |
| `rate_limit_buckets`, `replay_nonces` | T | until expiry (existing) | none |
| `webhook_deliveries` | T | 30 days (existing) | none |
| `outbox`, `processed_messages` | T | 30 days | align if longer |
| `authority_challenges` | P (nonce) / T | nonce cleared at use; row 30 days | new |
| `authority_link_codes`, `authority_oidc_codes` | P | expiry + 2 min | new |
| `authority_grants` (issuance records: jti, kid, aud, acr, amr, sub hash, `ach`, policy version) | E | `signed_decisions` class | new |
| `authority_keylog_entries`, `authority_keylog_heads` | E | account lifetime + `signed_decisions` period | new |
| `authority_audit_events` | E | 2555 d, export-before-purge | new |
| `authority_oidc_consents` | T while active | deleted on revoke or account deletion | new |
| App Insights / Log Analytics | T (redacted) | 30 days (existing lean setting) | add redaction patterns for `adl_`, codes, URLs on auth routes |
| Service Bus messages | T (ids only) | message TTL ≤ 1 day | none |
| PostgreSQL backups (PITR) | all classes | 7 days lean / 35 days standard | documented: deleted P/T rows can persist in backups for that window; restores re-run sweeps before serving |
| APNs / FCM | provider | ids only, no control over provider logs | payload minimization is the control |
| MailerSend (email fallback) | provider | content retained per provider settings; configure the shortest content retention the account allows; listed as sub-processor | new use |

### 3. Mechanics

- Add `auth_delivery_metadata` (30, bounds 7-90, tenant may shorten, holdable) and `auth_secrets` (minutes, not adjustable, not holdable: a legal hold never preserves bearer secrets) to `RetentionClass`; extend `approval_results` into the existing `signed_decisions` class.
- P sweeps run in the job loop every minute and on every state transition (delete in the same transaction); a test asserts no P row outlives `expires_at + 2 min` (ST-PRIV-04).
- Residency: every store above is in the Azure US region of the deployment (`centralus` in staging); providers process outside Viadere's control and are disclosed. Destination countries for email/SMS are a separate setting from residency (SCOPE_LEDGER C-7).

### 4. Access restriction for class E

- Database: E tables live in schema `evidence`; `viadere_app` and `viadere_worker` have `INSERT` and `SELECT` on id and timestamp columns only, no `SELECT` on payload columns (`jws`, `signed_payload`, `public_key`, `proof`) except through the security-definer function used by verification paths that need them; UPDATE/DELETE refused except via the retention gate (SECURITY §2.77 pattern).
- People: only the operator role `security_auditor` (new; separate from support and operator admin, `docs/ops/CONSOLE-ROLES.md`) can export evidence, through the audited `export-dispute`-style job with a fresh passkey step-up and a reason of ≥ 20 characters; audit event `evidence.accessed` (actor, subject ids, reason). Tenants never read raw evidence other than their own business-verified JWS (which they already receive).
- Authority E data is reachable only by authority roles; its export is an admin-job command with two reviewers.

### 5. Data subject rights

Account deletion (SECURITY §2.20) additionally: deletes P and T auth rows for the account, deletes OIDC consents, appends `account_deleted` to the authority key log (revoking every key), and keeps E rows that contain no free text (they hold keys, ids and signatures, needed to prove what a device signed during the dispute period: legitimate-interest basis already documented in §2.20). The consumer export (SECURITY §2.78) includes a summary of auth deliveries (business, purpose, state, time), never secrets or signatures.

## Consequences

- `approve_requests` purge moves from 400 to 30 days; dispute evidence survives in `approval_results`.
- Backups are the longest-lived copy of T data; documented rather than solved in lean.
- Privacy/legal approval of the E periods is a production prerequisite (spec §11.1).

## Threat assumptions changed

- A database read (AS-2c) exposes no P secret after its minutes window and only ciphertext within it.
- Evidence is no longer readable by every operator role.

## Reviewers required

A10 (classification, periods, rights), A2 (evidence access), A11 (sweep operability).
