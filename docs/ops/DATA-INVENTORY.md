# Data inventory and retention (LEG-PR-002, LEG-PR-006; spec §13)

**Status:** draft v1, 2026-10-27, derived from the Server migrations (`Server/Sources/ViadereServerKit/Migrations`) and purge jobs. Owner: Privacy
lead. **Counsel review pending** for every lawful-basis, retention-period and cross-border cell marked `[counsel]`. Retention periods must be
established through this inventory and applicable law (spec §13), not hardcoded: the "current purge" column states what the code does today.

Classes follow the spec §13 table: **PUB** Public, **OPS** Operational, **SEC** Security metadata, **IDA** Identity assertions,
**RIE** Raw identity evidence, **PKP** Passkey private keys, **SMP** Sensitive message payloads. **P** = personal data of an identifiable
person (or a pseudonym derivable by Viadere); **E** = encrypted at rest at field level (AES-256-GCM, row-bound, `DATA_ENCRYPTION_KEY`); **H** = peppered hash only
(`SERVER_PEPPER`). Custody is "Viadere" (Neon, ADR-02) unless stated. All rows sit in Neon PostgreSQL 18 with provider-level encryption at rest on top of the field encryption shown.

Not stored by Viadere today (by design, confirm on each change): raw ID images, birthdates, selfies (RIE: issuer/device/Didit, ADR-05), passkey private
keys (PKP: device / E2EE vault), plaintext phone numbers, plaintext message bodies, API keys and tokens (hashes only).

## 1. Table inventory

| Table | Data | Class | P | Protection | Retention (current purge job) | Notes / gaps |
|---|---|---|---|---|---|---|
| `consumers` | optional display name (none for device-first accounts), passkey user handle (only once a passkey exists), status, policy version, how it was created | OPS | P | none beyond DB | Until account deletion (`DELETE /v1/account`, docs/SECURITY.md §2.20) | display name is user-chosen and never required (§2.5a) |
| `account_enroll_ceremonies` | reserved account id, challenge hash, state, times | SEC | none | hash only | Purged a day after expiry (`IdentityMaintenance`) | |
| `passkey_credentials` | WebAuthn public keys, sign count | SEC | P | public keys | Deleted with the account | public keys only; private keys on device |
| `passkey_ceremonies` | challenges, state | SEC | | | Purged 1 h after expiry (job loop) | |
| `devices` | name, platform, kind, notice window, expiry, replacement state, trust tier and why, integrity format, key algorithm | SEC | P | none | Revoked/expired devices are revoked by `DeviceLifecycle.revokeExpired`; rows kept (cool-down proof, `docs/SECURITY.md` §2.5); names blanked on account deletion | rows of deleted accounts: confirm deletion scope `[counsel]` |
| `device_keys` | device public keys per purpose, attested flag | SEC | P | public keys | With device / account | |
| `app_attest_keys` | App Attest key id, public key, counter | SEC | P | public key | With device / account | |
| `device_enroll_challenges` | hashed challenges | SEC | | H | expires with challenge (no explicit purge) | gap: add purge |
| `token_families`, `access_tokens`, `refresh_tokens` | session families, token **hashes**, sealed refresh successor | SEC | P | H; successor sealed | Successor nulled after the grace window (retention job); rows not purged | gap: purge expired/revoked token rows |
| `recovery_profiles`, `recovery_codes`, `account_recoveries` | peppered hashes of recovery id/codes, pending passkey, state | SEC | P | H | Swept by `RecoveryService.sweep`; deleted with account | recovery codes are bearer secrets (residual risk) |
| `phone_links` | phone **ciphertext**, hash, masked form, last4, OTP hash, state | OPS | P | E + H | Erased on account deletion | last4 and masked number are readable |
| `link_tokens` | token hash, phone ciphertext/hash, purpose | OPS | P | E + H | Deleted `LINK_TOKEN_RETENTION_DAYS` (7) after expiry | |
| `sms_contexts` | SMS conversation state ciphertext | SMP | P | E | Reset on account deletion; opt-out kept as suppression only | state can hold business names and menu context |
| `sms_consent_events` | phone hash, opt-out keyword, time | OPS | P | H | **Kept** (suppression/consent evidence) | retention `[counsel]` (TCPA/CTIA evidence period) |
| `sms_outbound` | phone ciphertext, **body ciphertext**, status | SMP | P | E | Finished rows deleted after `OUTBOUND_RETENTION_DAYS` (30) | |
| `channel_endpoints` | RCS/SMS capability per phone hash | OPS | P | H | no purge | gap: purge for deleted accounts |
| `channel_outbound` | phone ciphertext, channel, status, provider id | OPS | P | E + H | Finished rows deleted after `OUTBOUND_RETENTION_DAYS` | |
| `rcs_postbacks` | postback token hash, phone hash, target | OPS | P | H | no purge after consume/expiry | gap |
| `processed_provider_messages` | provider message ids (dedup) | OPS | | | no purge | gap: bound growth |
| `conversation_sessions` | business/consumer pair, channel, state | OPS | P | none | Until account deletion | |
| `conversation_messages` | message **body ciphertext**, direction, timestamps | SMP | P | E | Erased on account deletion; no age-based purge | retention period for messages `[counsel]`; E2EE (ADR-07) will move bodies off the server |
| `businesses`, `business_handles`, `business_codes`, `retired_business_codes` | directory listing, legal name, website, brand | PUB | (P if sole trader) | none | Kept (handles/codes are never reassigned) | |
| `business_applications` | requested handle, legal name, description, reviewer note | OPS | P | none | no purge | operator decision notes: retention `[counsel]` |
| `business_controls` | throttle, ceiling, suspension reason | SEC | | | Kept | |
| `business_api_keys` | key **hash**, prefix, last4, scopes, revoked | SEC | | H | Kept after revocation (audit) | |
| `business_idempotency` | idempotency key, request hash, **sealed** result | OPS | | E | `BusinessIdempotency.purge` (job loop) | |
| `relationships` | consumer-business link, status | OPS | P | none | Until account deletion | |
| `consent_grants` | per-purpose consent with version, source, channels | SEC | P | none | Until account deletion | consent receipts are evidence: retention `[counsel]` |
| `interactions` | request payload JSON (kind, purpose, display text), status, outcome JSON | SMP | P | payload erased on deletion | Payload/outcome erased on account deletion; no age-based purge | payload can contain business text; classify per kind `[counsel]` |
| `interaction_challenges` | challenge nonce hash | SEC | | H | no purge | gap |
| `decisions` | **signed decision** (device-signed canonical JSON), signature, assurance | SEC | P | integrity | **Append-only.** Kept pseudonymous for disputes; free-text `reply` payload erased on deletion (§2.20) | dispute-retention period `[counsel]` |
| `audit_events` | actor, actor pseudonym (`actor_ref`, HMAC of the account id), policy version, action, outcome, ids, redacted metadata, hash chain | SEC | P (ids) | HMAC chain (`AUDIT_CHAIN_KEY`) | **Append-only, no purge** | retention/erasure policy `[counsel]`; chain head exported to write-once storage Verify detail (attempts, reasons, methods, consent) is in the platform-only trail (no `business_id`); the business-facing views and export are a projection (`BusinessAuditProjection`): consumer actors shown as the business's `subject_ref` |
| `replay_nonces` | replay-guard nonces | SEC | | | Purged at expiry (job loop) | |
| `rate_limit_buckets` | limiter keys (IP /64, hashes), tokens | OPS | P (IP) | | Purged when refilled/expired (job loop) | keys hold client IPs |
| `security_notices` | in-app security notices | SEC | P | none | Until account deletion | |
| `apns_tokens` | APNs device tokens | OPS | P | none | Dropped when APNs reports invalid; with account | tokens are personal data |
| `live_activity_tokens`, `live_activity_starts` | Live Activity push tokens, activity keys | OPS | P | none | Dropped when APNs invalidates | |
| `webhook_subscriptions` | business URL, **secret ciphertext** (+ previous) | SEC | | E | Until deleted by the business | |
| `webhook_deliveries` | event body (**ciphertext**), status, attempts | SMP | P | E | Succeeded/dead rows deleted after `WEBHOOK_RETENTION_DAYS` (30); bodies mentioning a deleted consumer scrubbed | |
| `webhook_delivery_attempts` | per-attempt status/duration/error | OPS | | | Deleted with their delivery | |
| `loyalty_programs`, `loyalty_accounts`, `loyalty_ledger` | program rules, points balance, **member reference ciphertext**, ledger | OPS | P | member ref E | Until account deletion; ledger kept for accounting `[counsel]` | |
| `rewards`, `reward_claims`, `reward_redemptions` | offers, claims, redemption code **hash**, slot | OPS | P | H | Until account deletion; codes valid ~2 min | |
| `wallet_passes`, `wallet_registrations` | pass serial, auth token hash, device library id, push token | OPS | P | H | Until voided/deleted | pass content carries no phone/name |
| `wallet_push_outbox`, `wallet_logs` | pass-update queue, device logs | OPS | | | Purged after 7 days (job loop) | |
| `delegation_grants`, `delegation_invitations` | household grants, **label ciphertext**, code hash | SEC | P | E + H | Until revoked/expired and account deletion | labels erased on deletion |
| `dashboard_users` | email **ciphertext** + hash, display name | OPS | P | E + H | Unverified sign-ups purged after 24 h; verified kept while a member | removal of a business user: retention `[counsel]` |
| `dashboard_passkeys` | WebAuthn public keys | SEC | P | public keys | With user | |
| `dashboard_sessions` | session token hash, realm, timestamps | SEC | P | H | Deleted 24 h after expiry | |
| `dashboard_ceremonies`, `dashboard_email_codes` | challenges, email-code hashes, sealed payload | SEC | P | H / sealed | Ceremonies purged 1 h after expiry; codes after 24 h | |
| `org_memberships`, `org_invites`, `operator_enrollments` | roles, invite email **ciphertext**, token hash | SEC | P | E + H | Kept (membership history); enrollment tokens expire | |
| `abuse_signals`, `usage_events` | per-business complaint/opt-out counters, metering | OPS | | | Abuse buckets older than 90 days purged; usage kept (billing) | usage retention `[counsel]` |
| `disclosure_receipts` (WP2, used by Verify) | customer's consent to **one** disclosure: business, subject_ref, capability, purpose, field names, request id, times | IDA | P | none (no evidence) | **Kept** as consent evidence; `consumed_at`/`revoked_at` set once | retention `[counsel]`; contains no attribute values |
| `verification_requests` (WP3) | a business's request for one customer: ids, `subject_ref`, capability, parameters (e.g. `{"years":21}`), purpose, status, label, **names** of disclosed fields, idempotency and request hashes | IDA | P | H (idempotency); **no evidence, no values** | Closed requests deleted after 400 days (`VerifyService.runMaintenance`); with the account otherwise | 400 days is a placeholder `[counsel]` |
| `verification_attempts` (WP3) | one try: method, status, **single-use Wallet nonce** (erased when consumed), Didit session id, internal failure reason, purge status | SEC | P | nonce deleted on use; session id is an opaque provider id | Deleted with the request (400 days); a row whose provider purge is pending is kept until the purge succeeds; the purge retries with exponential backoff (`purge_next_at`, 30 s to 24 h) and has no attempt cap; an overdue purge (> 1 h) raises `viadere_verify_provider_purge_overdue` | `vendor_data` at Didit is this row's id, not a person |
| `verification_results` (WP3) | outcome, **payload ciphertext** (the capability's output fields: for `age.minimum` only the boolean and validity fields), provenance JSON (method, verifier, issuer id, assurance dimensions, expiry, revocation state, policy version; **no personal data**) | IDA | P | payload E (row-bound); provenance plain | **Payload erased at the business's one retrieval or after 15 min**, whichever is first; provenance deleted with the request | identity names/addresses are payload until retrieved `[counsel]` |
| `verification_provider_events` (WP3) | Didit webhook `event_id` (deduplication) | OPS | | | Deleted after 7 days | |

## 2. Data outside the Server database

| Data | Where | Class | Custody and treatment |
|---|---|---|---|
| Secrets: `DATA_ENCRYPTION_KEY`, `SERVER_PEPPER`, `AUDIT_CHAIN_KEY`, `CONNECT_LINK_SIGNING_KEY` | Fly secrets, offline escrow | SEC | Never in the database or git; target: KMS (ADR-03). Loss makes encrypted columns / hashes unrecoverable |
| Audit chain heads | write-once storage (to be provisioned: object-lock bucket) | SEC | Output of `audit-head`; integrity anchor |
| Raw identity evidence (ID image, selfie, birthdate) | Didit (processor), Apple Wallet / issuer, device | RIE | Not collected centrally (ADR-05); Viadere keeps the minimized result; Didit sessions are purged after reading, with unbounded retry and an alert `[counsel: DPA, residency]`; Didit's own data-retention window is configured to the shortest the account allows (backstop if our purge cannot run) |
| Passkey private keys, approval keys | Secure Enclave / iCloud Keychain / E2EE vault | PKP | Never server plaintext (ADR-06/08) |
| Logs | Fly logs, Cloudflare, GCP audit logs | OPS/SEC | Server redacts tokens, secrets and phone numbers (`LogRedaction`); log retention: Fly 7 days (default, verify), GCP KMS audit 400 days (Terraform) `[counsel]` |
| Backups | Neon PITR (7 days) + daily snapshots (30 days) | all | Erased data persists in backups until they age out: stated in the privacy notice `[counsel]` |
| Email (verification codes, invitations) | transactional email provider | OPS | Address and code in transit; provider is a sub-processor |
| Didit session data (WP3): ID images, selfie, liveness video, document fields, face embedding and scores | Didit (processor, EU by default), only for the duration of one verification | RIE | Captured on the device and sent **directly to Didit**; Viadere never receives images or biometrics. After reading the decision in memory and deriving the one claim, the server deletes the session with `privacy_erasure` and deletes the vendor user (`POST /v3/users/delete/`), and records the deletion; failures are retried. Configure the shortest retention in the Didit console as a backstop and keep biometric-template retention **off**. No biometric template is retained at Didit. `[counsel: BIPA / GDPR Art. 9, DPA, residency]` |
| Apple Wallet presentment (WP3): the encrypted DeviceResponse | transient, in server memory | RIE | Decrypted with the merchant key (KMS-wrapped, ADR-03), verified, reduced to the requested elements, **never persisted or logged**. Apple and the issuing authority do not learn where the ID was shared (Apple's design). IACA trust anchors are public certificates on disk |
| SMS/RCS content | MailerSend or Twilio / RCS provider | SMP | Provider retains per its terms: sub-processor `[counsel]` |

## 3. Sub-processors (to publish; LEG-PR-006)

Fly.io (hosting), Cloudflare (edge, site), Neon (database), Google Cloud (KMS), MailerSend (SMS and transactional email; Twilio as the alternative SMS provider), RCS provider (TBD), Apple (APNs, Wallet, App Attest),
Didit (identity verification). Each needs a DPA, a transfer mechanism and a breach-notification
clause `[counsel]`; the public sub-processor list must match this table (Site, WP7).

## 4. Lawful basis, purpose and rights (placeholders for counsel)

| Processing purpose | Data | Lawful basis `[counsel]` | Rights / notes |
|---|---|---|---|
| Account and authentication | consumers, passkeys, devices, tokens | `[contract / legitimate interest]` | access, deletion (`DELETE /v1/account`) |
| Delivering business interactions and SMS/RCS | phone link, outbound, messages, interactions | `[contract; consent for marketing channels]` | opt-out (STOP keywords), consent receipts |
| Security, fraud and abuse prevention | audit, decisions, rate limits, abuse signals | `[legitimate interest]` | retention balanced against erasure |
| Business onboarding and verification | applications, dashboard users | `[contract / legitimate interest]` | |
| Billing and metering | usage_events, ledger | `[contract / legal obligation]` | |
| Identity assertions (Verify) | assertion metadata, minimized results | `[consent / explicit consent for biometrics]` | jurisdiction-specific (BIPA, GDPR Art. 9) |

## 5. Gaps found while building this inventory

1. No age-based purge for: `interactions`, `conversation_messages`, `decisions`, `consent_grants`, `audit_events`, `business_applications`, `channel_endpoints`, `rcs_postbacks`, `processed_provider_messages`, `interaction_challenges`, `device_enroll_challenges`, expired `access_tokens`/`refresh_tokens`. Retention must be set per data class (spec §13) and implemented as configurable class-based jobs (WP8 part 2 / Server owner).
2. `RetentionService` covers only outbound rows, link tokens, webhook deliveries and device expiry. A `RETENTION_*` setting exists for three of these only.
3. Export of data for a subject-access request exists only as `export-dispute` (per interaction); there is no subject-access export (LEG-PR gap).
4. Backups retain erased data until Neon retention expires; the privacy notice must say so.

## 6. Addendum (2026-10-28, WP6): tables added by WP1, WP2, WP5 and WP6, and the retention that now exists

Sections 1 to 5 are unchanged (they were written before these tables existed). Same legend. Retention periods marked **[class]** are the per-data-class values of
`RetentionClass` (section 7): platform default, hard bounds, operator-adjustable inside the bounds, legal hold where noted.

### 6.1 Approve v2, key directory and E2EE (WP1)

| Table | Data | Class | P | Protection | Retention | Notes |
|---|---|---|---|---|---|---|
| `kd_log_entries`, `kd_tree_heads` | the business key directory: signed root/key/revoke statements (public keys only), Merkle leaf hashes, signed tree heads | PUB | | integrity (database triggers refuse UPDATE and DELETE; the log is signed by `KEY_DIRECTORY_LOG_KEY`) | **Kept** (a transparency log that forgets is not one) | public keys and key ids only; no customer data |
| `approve_enrollments` | business, relationship, consumer, `subject_ref`, capability, code **hash**, the device's signed statement, the business confirmation | SEC | P | code H | Rows of cancelled/expired enrollments: with the relationship or account; statements are public keys and signatures | the 8-character code is a short-lived bearer secret (bounded by 10-minute life, rate limits) |
| `approve_keys` | pairwise approval public key and HPKE public key per relationship, `kid`s, assurance, status | SEC | P | public keys | Revoked with the relationship, the device or the account; rows kept for verification of old results | no private key ever leaves the device |
| `approve_requests` | request metadata, `subject_ref`, protection mode, hash, **sealed** details (server-visible mode only), decision, `amr`, the compact JWS result | SEC | P | `details_sealed` E; end-to-end requests hold only an opaque envelope | Deleted after **400 days** with their deliveries (`ApproveRequestService` maintenance; the capability's maximum result retention) | 400 days is a placeholder `[counsel]`; the JWS is the business's dispute evidence |
| `approve_deliveries` | which device was offered which request | OPS | P | none | With the request | |
| `approve_freezes` | customer-set freeze of approvals (reason code, times) | SEC | P | none | Deleted with the account | |

### 6.2 Capability policy (WP2)

| Table | Data | Class | P | Protection | Retention | Notes |
|---|---|---|---|---|---|---|
| `business_entitlements` | tier and capability grants/revocations with actor, justification and review reference | SEC | | none | **Kept** (who allowed what, when) | no customer data |
| `capability_switches` | operator kill switches per capability (global or business), reason | SEC | | none | Kept | |
| `policy_rules` | jurisdiction rules per capability, reason | SEC | | none | Kept | |
| `relationships.subject_ref` (column) | pairwise pseudonym of a customer for one business | IDA | P | H (`SUBJECT_REF_KEY`) | With the relationship | re-derived after a key change |

### 6.3 Credential vault (WP5, behind `VAULT_SYNC_ENABLED`)

| Table | Data | Class | P | Protection | Retention | Notes |
|---|---|---|---|---|---|---|
| `vault_vaults`, `vault_members`, `vault_manifests`, `vault_blobs`, `vault_joins`, `vault_recovery_releases` | **end-to-end encrypted** blobs and manifests of a person's credentials, member device keys, join tokens | PKP/SMP | P | the server holds ciphertext only (keys never leave the devices) | Deleted with the vault or the account; expired joins removed by the vault job | anti-rollback counters are plaintext integers; `vault_recovery_releases` holds account/device ids and times of recovery-envelope release requests (72 h hold, 24 h window); `vault_members.former_device_id` remembers the account device of a removed member |

### 6.4 Business platform (WP6)

| Table | Data | Class | P | Protection | Retention | Notes |
|---|---|---|---|---|---|---|
| `business_onboarding` | one row per business: stage facts (domain verified, legal-entity review, sensitive-category review, sandbox milestones, go-live request and decision), legal registry **number and name, jurisdiction and references to evidence** (a URL or record id; **no documents are stored**) | OPS | (P if sole trader) | none | Kept while the business exists; free text of decided applications is erased per **[applications]** | the references are what an operator checked, not the evidence |
| `business_domains` | domain, verification token, method, result, next check | OPS | | none | Deleted with the organization | the token is public (it is published in DNS) |
| `contract_acceptances` | which document slug and version, who accepted, when, **hash** of IP (versioned pepper) and of the user agent | SEC | P (user id) | H | **Kept** (contract evidence) `[counsel]` | the raw address and agent are never stored |
| `business_mtls_certs` | tenant-bound client certificate fingerprints / CA key ids, label, subject, expiry | SEC | | none | Deleted with the organization | public certificate data |
| `business_security_settings` | console IP allow-list, privileged-inactivity timeout, two-person flag, mTLS requirement, alert subscriptions, **security contacts (sealed)** | SEC | P (contacts) | contacts E | Deleted with the organization | |
| `business_api_keys` (columns added) | non-secret key id `kid`, IP allow-list, expiry, last-used time and **hash** of the caller's address, certificate binding, rotation links, revoker and reason | SEC | | H | Kept after revocation | last-used address is a versioned-pepper hash |
| `dashboard_sessions` (columns added) | **hash** and masked form of the address, hash and label of the user agent, country | SEC | P | H | Deleted 24 h after expiry | shown to the user in Security > Sessions |
| `dashboard_known_contexts` | hash of the sign-in context (network, agent) per user, for suspicious-login alerts | SEC | P | H | Deleted after **400 days** unseen **[support_records]** | |
| `pending_changes` | two-person approval requests: kind, **sealed** payload (no secret), requester, approver, status | SEC | P | payload E | Decided requests deleted per **[support_records]** (730 days) | |
| `platform_flags` | operator switches: flag, scope, value, reason, who | SEC | | none | Kept while set; the audit trail keeps the history | the audit-export mark is stored here too |
| `operator_notices` | operator announcements: audience, scope, text, delivery progress | OPS | | none | Finished notices deleted per **[support_records]** | no personal data in the text by policy |
| `support_tickets` | tickets and appeals: subject, **sealed body**, status, operator note | OPS | P | body E | Closed tickets deleted per **[support_records]** | |
| `data_requests` | tenant export / deletion requests, status, decisions; the export artifact is **sealed** and erased after 24 hours | OPS | | artifact E | Decided requests per **[support_records]**; artifact 24 h | export contains no secret and no customer-level data |
| `consumer_exports` | consumer data export jobs: device, status, **ciphertext chunks sealed to the requesting device's key** | OPS | P | E2EE (the server cannot read it) | Bundle erased at expiry (7 days); row deleted a week later | |
| `account_freezes` | operator freeze of a consumer account: reason (internal), operator, times | SEC | P | none | Released freezes deleted per **[support_records]** | the person is shown a generic notice, not the reason |
| `retention_settings`, `legal_holds` | per-class retention days (platform and tenant), legal holds (scope, reason, who) | SEC | | none | Kept; holds kept after release | |
| `audit_checkpoints` | the sequence number and hash of the last purged audit event | SEC | | | Kept | lets the remaining chain verify |
| `interactions.content_erased`, `conversation_messages.content_erased` (columns) | marks rows whose content the retention job replaced | OPS | | | | |

## 7. Retention by data class (WP6): what the code purges now

Implemented in `Operations/Retention.swift` (`RetentionClass`, `RetentionPurger`), run by the job loop at most once a minute per instance, idempotent and batched. An operator moves a
**platform** value inside the bounds (`/operator/retention`, reason required, audited `retention.platform_set`); a business may **shorten** (never lengthen) the classes
marked tenant-adjustable for its own data (Compliance > Retention, audited `retention.tenant_set`). A **legal hold** (`/operator/holds`: global, one business or one consumer, reason
required) suspends every holdable class for its scope until released. The deployment's `WEBHOOK_RETENTION_DAYS`, `OUTBOUND_RETENTION_DAYS` and `LINK_TOKEN_RETENTION_DAYS` remain the defaults of their classes.

| Class | What is purged | Default (min-max) days | Tenant may shorten | Holdable |
|---|---|---|---|---|
| `interaction_content` | payload text, reply and signed decision of **finished** interactions are erased; the row, ids and status stay | 400 (30-1095) | yes | yes |
| `conversation_content` | message bodies replaced by `[expired]` | 730 (30-3650) | yes | yes |
| `signed_decisions` | device-signed decisions deleted | 730 (365-2555) | no | yes |
| `consent_history` | **superseded** consent versions deleted; the current consent of a relationship never | 1095 (365-3650) | no | yes |
| `audit_events` | events older than the period **and** already covered by an exported head; a checkpoint keeps the chain verifiable; nothing is purged without an export target | 2555 (730-3650) | no | yes |
| `business_applications` | free-text description and reviewer note of decided applications | 730 (90-3650) | no | yes |
| `usage_records` | metering rows | 2555 (365-3650) | no | yes |
| `webhook_deliveries` | deliveries with their attempts, including never-sent (paused) ones | 30 (1-365) | yes | yes |
| `outbound_messages` | finished SMS and channel sends | 30 (1-365) | no | yes |
| `link_tokens` | used or expired link tokens | 7 (1-90) | no | no |
| `security_tokens` | expired session tokens, enrollment and interaction challenges | 30 (7-180) | no | no |
| `channel_capability` | RCS capability cache, consumed postbacks, provider message de-duplication markers | 180 (14-730) | no | no |
| `security_notices` | in-app notices (dismissed ones after 90 days) | 365 (30-1095) | no | no |
| `support_records` | closed tickets and appeals, finished notices, decided approvals and data requests, released freezes, expired export bundles, old dashboard contexts | 730 (90-3650) | no | yes |

**Append-only tables and the retention gate.** `audit_events`, `decisions` and `consent_grants` refuse UPDATE and DELETE at the database. The retention job deletes through
`RetentionDeleteGate.perform`, a transaction that opens a narrow exception for DELETE on those three tables only (a transaction-local setting in PostgreSQL, a one-row gate that the
same transaction closes in SQLite); UPDATE stays refused. A process that can run arbitrary SQL as the runtime role can open the gate too: what protects the audit log from that is the
write-once export of signed heads, not the trigger (SECURITY.md section 2.77).

**Status of the section 5 gaps.** Gap 1 (no age-based purge) closed for every table listed there, with these exceptions that stay by design: `sms_consent_events` (suppression evidence),
`businesses`/handles/codes (never reassigned), `passkey_credentials`, `devices` and `relationships` (until account deletion), `kd_*` (public log). Gap 2 closed (14 classes). Gap 3 closed:
`POST /v1/account/exports` is the subject-access export (section 6.4, `consumer_exports`; SECURITY.md section 2.78). Gap 4 (backups) is unchanged.

## 8. Addendum (2026-10-30, feature expansion v4 Phase 1: Organization)

Migrations `Organization.v1` and `Surfaces.v1`. No Loops or Brand Kit table exists in this release.

| Table | Data | Class | P | Protection | Retention (current purge job) | Notes / gaps |
|---|---|---|---|---|---|---|
| `business_preferences` | per (customer, business): favorite, mute level and end, `blocked_at` | OPS | P | none | Deleted with the account (`PreferenceService.wipe`); a block outlives the connection it ended, by design | never shown to the business |
| `conversation_state` | per (customer, conversation): archived time, muted | OPS | P | none | Deleted with the account | never shown to the business |
| `alert_seen` | per viewer: alert id (`{source}:{id}`) and when it was marked seen | OPS | P | none | Deleted with the account | gap: no age-based purge yet (bounded by the alerts the account opened); add a 400-day class with the next retention change |
| `business_surfaces` | a business's module layout versions (module ids and order only), who published | OPS | | none | Deleted with the tenant (`TenantRights`) | no customer data |

The Alerts and Benefits lists are read models over existing tables; they store nothing beyond the rows above.

## 9. Addendum (2026-10-31, customer profiles; `docs/PROFILES.md`, SECURITY.md §2.97)

Migration `Profiles.v1`.

| Table | Data | Class | P | Protection | Retention (current purge job) | Notes / gaps |
|---|---|---|---|---|---|---|
| `consumer_profiles` | the custom public name | PII | P | field cipher (row-bound) | Deleted with the account (`ProfileService.wipe`) | the public name is shared with every connected business by design |
| `profile_values` | profile values (contact, personal, birth date, travel, memberships, vehicle, home, work) | PII | P | field cipher (row-bound, `profile_values.value#{rowId}`) | Deleted with the account | no operator or support view; closed catalog |
| `profile_grants` | per (customer, business, field key): granted and revoked times, reason | OPS | P | none (keys only) | Kept without values after the account is deleted (grant history) | gap: no age-based purge yet; propose 400 days after revocation |
| `profile_receipts` | customer-visible disclosure receipts: business name, action, keys, purpose, request id | OPS | P | none (no values) | Kept like consent history | gap as above |
| `profile_requests` | a business's request: keys, purpose (business text), status, approved keys | OPS | P | none | Deleted with the account | gap: no age-based purge of answered requests yet |
| `profile_verified_facts` | booleans established with an ID, method, assurance, policy version, time | PII (derived) | P | none | Deleted with the account or when the customer removes them | never a document number, image, name or birth date |
| `profile_verification_attempts` | nonce (until used), provider session id, purge state | OPS | P | none | Abandoned attempts fail after their lifetime; rows without a pending purge are deleted after 30 days and with the account | provider sessions are purged with the Verify backoff |
| `profile_category_requests` | a business's request to be allowed a profile category, justification, operator decision | OPS | | none | Deleted with the tenant | no customer data |

