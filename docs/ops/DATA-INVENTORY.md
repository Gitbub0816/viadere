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
| `consumers` | display name, passkey user handle, status | OPS | P | none beyond DB | Until account deletion (`DELETE /v1/account`, docs/SECURITY.md §2.20) | display name is user-chosen |
| `passkey_credentials` | WebAuthn public keys, sign count | SEC | P | public keys | Deleted with the account | public keys only; private keys on device |
| `passkey_ceremonies` | challenges, state | SEC | | | Purged 1 h after expiry (job loop) | |
| `devices` | name, platform, kind, cool-down, expiry, replacement state | SEC | P | none | Revoked/expired devices are revoked by `DeviceLifecycle.revokeExpired`; rows kept (cool-down proof, `docs/SECURITY.md` §2.5); names blanked on account deletion | rows of deleted accounts: confirm deletion scope `[counsel]` |
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
| `audit_events` | actor, action, outcome, ids, redacted metadata, hash chain | SEC | P (ids) | HMAC chain (`AUDIT_CHAIN_KEY`) | **Append-only, no purge** | retention/erasure policy `[counsel]`; chain head exported to write-once storage |
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
| `verification_attempts` (WP3) | one try: method, status, **single-use Wallet nonce** (erased when consumed), Didit session id, internal failure reason, purge status | SEC | P | nonce deleted on use; session id is an opaque provider id | Deleted with the request (400 days); a row whose provider purge is pending is kept until the purge succeeds | `vendor_data` at Didit is this row's id, not a person |
| `verification_results` (WP3) | outcome, **payload ciphertext** (the capability's output fields: for `age.minimum` only the boolean and validity fields), provenance JSON (method, verifier, issuer id, assurance dimensions, expiry, revocation state, policy version; **no personal data**) | IDA | P | payload E (row-bound); provenance plain | **Payload erased at the business's one retrieval or after 15 min**, whichever is first; provenance deleted with the request | identity names/addresses are payload until retrieved `[counsel]` |
| `verification_provider_events` (WP3) | Didit webhook `event_id` (deduplication) | OPS | | | Deleted after 7 days | |

## 2. Data outside the Server database

| Data | Where | Class | Custody and treatment |
|---|---|---|---|
| Secrets: `DATA_ENCRYPTION_KEY`, `SERVER_PEPPER`, `AUDIT_CHAIN_KEY`, `CONNECT_LINK_SIGNING_KEY` | Fly secrets, offline escrow | SEC | Never in the database or git; target: KMS (ADR-03). Loss makes encrypted columns / hashes unrecoverable |
| Audit chain heads | write-once storage (to be provisioned: object-lock bucket) | SEC | Output of `audit-head`; integrity anchor |
| Raw identity evidence (ID image, selfie, birthdate) | Didit (processor), Apple Wallet / issuer, device | RIE | Not collected centrally (ADR-05); Viadere keeps the minimized result; Didit sessions are purged after reading `[counsel: DPA, residency]` |
| Passkey private keys, approval keys | Secure Enclave / iCloud Keychain / E2EE vault | PKP | Never server plaintext (ADR-06/08) |
| Logs | Fly logs, Cloudflare, GCP audit logs | OPS/SEC | Server redacts tokens, secrets and phone numbers (`LogRedaction`); log retention: Fly 7 days (default, verify), GCP KMS audit 400 days (Terraform) `[counsel]` |
| Backups | Neon PITR (7 days) + daily snapshots (30 days) | all | Erased data persists in backups until they age out: stated in the privacy notice `[counsel]` |
| Email (verification codes, invitations) | transactional email provider | OPS | Address and code in transit; provider is a sub-processor |
| Didit session data (WP3): ID images, selfie, liveness video, document fields, face embedding and scores | Didit (processor, EU by default), only for the duration of one verification | RIE | Captured on the device and sent **directly to Didit**; Viadere never receives images or biometrics. After reading the decision in memory and deriving the one claim, the server deletes the session with `privacy_erasure` and deletes the vendor user (`POST /v3/users/delete/`), and records the deletion; failures are retried. Configure the shortest retention in the Didit console as a backstop and keep biometric-template retention **off**. No biometric template is retained at Didit. `[counsel: BIPA / GDPR Art. 9, DPA, residency]` |
| Apple Wallet presentment (WP3): the encrypted DeviceResponse | transient, in server memory | RIE | Decrypted with the merchant key (KMS-wrapped, ADR-03), verified, reduced to the requested elements, **never persisted or logged**. Apple and the issuing authority do not learn where the ID was shared (Apple's design). IACA trust anchors are public certificates on disk |
| SMS/RCS content | Twilio / RCS provider | SMP | Provider retains per its terms: sub-processor `[counsel]` |

## 3. Sub-processors (to publish; LEG-PR-006)

Fly.io (hosting), Cloudflare (edge, site), Neon (database), Google Cloud (KMS), Twilio (SMS), RCS provider (TBD), Apple (APNs, Wallet, App Attest),
Didit (identity verification), email provider (Resend or other). Each needs a DPA, a transfer mechanism and a breach-notification
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
