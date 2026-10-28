# Detection and response runbooks (OPS-005)

**Status:** v1, 2026-10-27. Every step below names a control that exists today (see `KILL-SWITCHES.md` E-numbers) or is marked **[GAP Gn]**
where the tool is missing and the interim manual step is given. Review after every incident and tabletop (`TABLETOP-EXERCISES.md`).
Roles are placeholders until named: **IC** incident commander, **SEC** security lead, **ENG** on-call engineer, **OPS** operator-console user, **COMMS** communications, **LEGAL** counsel/privacy lead.

## RB-0 Common procedure

**Severity.** SEV1 active compromise of keys/identity evidence/tenant isolation, or full outage of sign-in approval; SEV2 contained compromise of one business or one capability down; SEV3 degraded or suspected. SEV1/2 page IC + SEC immediately.

**First 15 minutes (all runbooks).**
1. Open an incident record (time-stamped log; paste every command and result). Move to the contact path independent of Viadere (spec OPS-009): a separate chat/bridge and the status page host (`status.<apex>`, not on our stack).
2. Preserve evidence before changing state: `fly logs --app viadere-server > incident-<id>-logs.txt` (server logs are redacted), Cloudflare firewall/analytics export for the window, GCP KMS audit log export, and the audit head: `fly ssh console --app viadere-server -C "/app/ViadereServer audit-head --env production" > head-<id>.json`.
3. Check chain integrity: `fly ssh console --app viadere-server -C "/app/ViadereServer audit-verify --env production"`, and against the last exported head: copy the stored `head.json` to the machine and run `audit-verify --head head.json`. A mismatch is a SEV1 (see RB-5).
4. Contain using the narrowest control that works (KILL-SWITCHES.md section 3), then eradicate, recover, notify, review.
5. Notification clocks: counsel decides legal notification (GDPR 72 h to the authority, state breach laws, contractual customer notice) the moment personal data exposure is plausible; the IC records the decision time.

Running a Server command in production: `fly ssh console --app viadere-server -C "/app/ViadereServer <command> --env production"`. The machine already holds the production secrets; do not copy them elsewhere. Commands that write (`reencrypt-fields`) are idempotent. `export-dispute` and operator actions are themselves audited.

Useful audit queries (run with the `viadere_readonly` role, from the Neon SQL editor or `psql` against the Neon host; never with the application role): `SELECT seq, occurred_at, actor_kind, action, outcome, business_id, consumer_id, subject_id FROM audit_events WHERE occurred_at > now() - interval '24 hours' AND action IN (...) ORDER BY seq;` Audit `metadata_json` is redacted by design.

---

## RB-1 API-key compromise (business API key leaked or misused)

**Detect.** Operator abuse signals (`/operator/abuse`), `abuse.auto_throttled`, unusual `interaction.issued` / `message.business_sent` volume or origin, business report, secret-scanning alert (gitleaks, GitHub), Cloudflare spike on `/v1/business/*`.
1. Confirm the key and business: key prefix/last4 from the business (dashboard `/dashboard/api-keys`); in the audit log find `apikey.created` / `interaction.issued` by `business_id`.
2. **Contain.** If a business admin is reachable: have them **Revoke** the key (`/dashboard/api-keys`, audited `apikey.revoked`, immediate) and create a replacement (needs passkey re-auth). If not reachable or the dashboard account is also suspect: OPS **suspends** the business (`/operator/businesses/{id}` -> Suspend, reason; blocks keys, cancels pending interactions) **[GAP G3: no operator revoke-all-keys]**.
3. Limit blast radius while investigating: throttle (E-2) and lower priority ceiling (E-3) instead of suspending when the business is legitimate and the key is already revoked.
4. **Assess impact.** Which interactions were sent with the key (`interactions` by `business_id` and time; `webhook_deliveries` for leaked event data; scope list of the key from the dashboard). A test key (`vdk_test_`) only reached sandbox relationships.
5. **Recover.** New key with minimum scopes; rotate webhook secrets if the key had `webhooks:manage` (`POST /v1/business/webhooks/{id}/rotate-secret`); business rotates secrets in their systems.
6. **Notify.** The business (what, when, which scopes); affected consumers if they received fraudulent interactions (in-app notices **[GAP G9]**: manual comms through the business until the operator notice tool exists). LEGAL decides regulatory notice.
7. **Follow-up.** Add secret-scanning pattern for the `vdk_live_` prefix at the host (GitHub secret scanning partner pattern), expiry/rotation policy for keys (WP6).

## RB-2 Business impersonation (look-alike business, hijacked verified business, phishing through a verified business)

**Detect.** User/business report, `interaction.reported_suspicious`, complaint-rate throttle, handle/code confusable report, brand-protection monitoring.
1. Identify the business id and handle (`/operator/businesses`); read its application and verification history (`/operator/applications/{id}`).
2. **Contain.** Suspend (E-1) with a reason; this removes it from discovery and routing (`only verified businesses appear`). Pending interactions are cancelled.
3. If the real business account was taken over (dashboard compromise): suspend, then follow RB-1 for keys and RB-3 for webhooks; list `dashboard.login` and `team.*` audit events for the organization; remove unknown members (business admin, or support-assisted); passkey recovery for business users does not exist **[known gap in Server/README: no operator-assisted recovery]**, so re-onboard the owner through a fresh verified invitation after identity checks.
4. For a look-alike: handle/code are never reassigned (`retired_business_codes`); reject the application (`/operator/applications/{id}/reject`), and file takedowns for the domain/brand outside Viadere.
5. **Consumers.** Query `relationships` for the business; consumers connected through it should get a notice **[GAP G9]**; disconnect relationships by suspending (they cannot be messaged). SMS threads connected to the business receive a content-free notice from the gateway.
6. Review domain verification and re-verification cadence (WP6).

## RB-3 Webhook takeover (attacker controls a business webhook URL or secret)

**Detect.** Business reports unexpected events, deliveries to a changed URL (`webhook.created`/`webhook.deleted` audit), `webhook.dead_lettered` spikes, SSRF alerts.
1. Identify subscriptions: dashboard `/dashboard/webhooks` or `webhook_subscriptions` by `business_id`.
2. **Contain.** Business deletes the endpoint (`webhook.deleted`) or rotates its secret (`webhook.rotated`; the previous secret is accepted only for the overlap window). Operator cannot pause an endpoint **[GAP G5]**; if the business cannot act, suspend the business (E-1) so no new events are produced.
3. Stop leaking queued data: delivery bodies are encrypted at rest and contain redacted decisions (no `signedDecision`); delete queued deliveries for the endpoint only through the business action or accept they will expire (retention 30 days).
4. **Assess.** Which events were delivered to the attacker's URL: `webhook_delivery_attempts` joined to deliveries by subscription and time; event types determine exposed data (message text, interaction outcomes, pseudonymous ids).
5. **Recover.** New endpoint (verification of ownership **[WP6]**), new secret via the dashboard (passkey re-auth, shown once), business updates its verifier. Inform affected consumers if message text was exposed.

## RB-4 Relay compromise (the Viadere server, edge or a provider account is attacker-controlled)

**Detect.** Audit chain mismatch, unexplained deploys (`fly releases`), image digest not in the release log, Cloudflare/Fly/GCP/Neon login or token anomalies, unexpected KMS key use (alert "unexpected_use"), origin reachable outside Cloudflare.
1. **Declare SEV1.** IC + SEC. Move to an out-of-band channel.
2. **Contain** (choose by evidence): block at the edge (E-13: WAF rule to block everything except `/healthz`), or stop machines (E-14: `fly scale count 0 --app viadere-server`). An outage is preferable to an attacker relaying approvals. Revoke the CI deploy token (Fly: `fly tokens list` / revoke), the Cloudflare API token, the Neon API key, and GitHub environment secrets.
3. **Preserve.** Do not delete machines before copying logs/volumes if any; export audit head and the Neon branch state (create a Neon branch from now for forensics).
4. **Establish trust.** Rebuild from a known-good commit: verify the image signature and provenance (`cosign verify ...` and `gh attestation verify oci://<image>@<digest> --repo <repo>`); redeploy only a digest that verifies and was produced by `release.yml` from a reviewed tag.
5. **Rotate everything the relay could read** (assume all secrets in Fly): `CONNECT_LINK_SIGNING_KEY` (links die, acceptable), `DATABASE_URL` (reset the Neon roles: `neon_role` password rotation), APNs key (revoke in the Apple Developer account, issue new), Twilio token, RCS secrets, email key, Pass Type ID certificate if signed passes may be forged. `DATA_ENCRYPTION_KEY`, `SERVER_PEPPER` and `AUDIT_CHAIN_KEY` cannot be rotated safely today **[GAP G8]**: if they were exposed, treat all encrypted fields as disclosed, notify per LEGAL, and prioritize G8 and the KMS migration (ADR-03).
6. **Recover trust anchors.** Compare the chain with the last exported head; events after it are unverified. Re-sign a fresh head after recovery.
7. **E2EE note.** Once HPKE (ADR-07) ships, a relay compromise cannot read sensitive payloads and cannot substitute pinned business keys undetected; check the transparency-log head against the last exported one.

## RB-5 Signing-key compromise (KMS rotation and secret rotation)

Covers the KMS-held keys (`Infra/terraform/kms.tf`: `audit-head`, `connect-link`, `webhook` signing keys; `data-kek`, `hpke-kek` wrapping keys) and today's environment keys.

**Detect.** KMS alert "unexpected_use" (key used by a principal other than `viadere-server-kms-*`), "admin_change" alert, signature verification failures in the wild, audit-chain mismatch, leaked secret.
1. **Contain in KMS.** In the GCP project: disable the affected key *version* (`gcloud kms keys versions disable <N> --key <key> --keyring viadere-production --location <loc>`). For a suspected service-account takeover, disable the service account `viadere-server-kms-production` and revoke its workload-identity binding first; this stops all signing (degraded mode: RESILIENCE.md).
2. **Rotate an asymmetric signing key (no auto-rotation exists).** Create a new key version (`gcloud kms keys versions create --key <key> --keyring viadere-production --location <loc>`); asymmetric keys have no primary version, so the server must be configured with the new version's full resource name. Publish the new public key id (key directory / JWKS / audit-head verification doc), keep the old version enabled for verification only until outstanding artifacts expire (connect links minutes, audit heads: forever: keep the old public key, disable signing by revoking `cloudkms.signer` on that key and retire after export of final heads), then schedule destruction (30-day recoverable) only when nothing references it.
3. **Rotate a wrapping key (`data-kek`, `hpke-kek`).** Symmetric keys rotate by creating a new primary version (automatic every 90 days). After a compromise: new version, then re-wrap every wrapped key with the job (re-encryption tooling, **[GAP G8]**), then disable the old version.
4. **Rotate today's environment secrets** (until KMS is live):
   - `CONNECT_LINK_SIGNING_KEY`: set a new value (`fly secrets set CONNECT_LINK_SIGNING_KEY=...`); all outstanding connect links/QR codes stop verifying, new ones work. Acceptable; reprint printed QR codes.
   - `AUDIT_CHAIN_KEY`: **no rotation path** **[GAP G8]**. Changing it breaks verification of every existing event. Interim: do not change it; compromise response is to export and escrow the head, treat events after the compromise window as untrusted, and add a chain version with a new key id in Server. Keep the old key in escrow.
   - `DATA_ENCRYPTION_KEY`, `SERVER_PEPPER`: **no rotation path** [GAP G8]. The pepper keys OTP hashes, phone lookup hashes and pseudonyms; changing it orphans them. Interim: contain, assess exposure, plan engineered rotation (multi-key read, `rotate-data-key` command) before declaring recovery.
5. **Verify.** `audit-verify` after rotation; sign a fresh head with the new key; run a staging end-to-end test.
6. **Notify** per LEGAL when integrity of evidence (signed heads) or confidentiality of data was affected.

## RB-6 Fraudulent verification (fake age/identity assertion, vendor liveness bypass)

Phase 3 capability; use this runbook as the design target. **Detect.** Business or user report, anomalous pass rate for a verification method, Didit/Apple advisories, repeated failures followed by a pass.
1. Identify the verification result refs and the method/issuer/assurance level (`decisions.assurance`, evidence ref). Use `export-dispute --interaction <id>` for approvals; verification results will have an equivalent (WP3).
2. Contain: raise the required assurance for the capability (policy engine, WP2 **[GAP G2 flag]**), disable the method (Wallet or Didit) at the capability level **[GAP G2/G14]**, throttle/suspend the requesting business if it is the abuser.
3. Invalidate affected assertions (expiry is short by design; revoke result refs [WP3]); tell relying businesses to re-verify.
4. Vendor escalation: Didit security contact; Apple for Wallet issuer questions. Preserve vendor session ids, not images (Viadere does not hold them).
5. Review the threat model entry (spec §15 fake age assertion) and add the adversarial test (CLAUDE.md: every fix starts with a reproducing test).

## RB-7 Credential issuer revocation (a Wallet ID issuer or IACA root is untrusted)

1. Trigger: issuer advisory (state DMV, AAMVA), Apple notice, or our own finding that an issuer signs fraudulent credentials.
2. Contain: remove the IACA root from the trusted list **[GAP G14]** (until then: emergency deploy removing the root from the bundled list and a release through `release.yml`; target is a database allow-list with audit).
3. Existing results from that issuer: query by issuer id in the result metadata (WP3), expire them, notify relying businesses, require re-verification through another method.
4. Communicate to users who used that issuer (in-app notice **[GAP G9]**).
5. Document trust-list changes as audited operator actions; revisit annually.

## RB-8 Device theft or loss (consumer)

**User path (works today).** From another trusted device or after recovery: revoke the lost device (`DELETE /v1/devices/{id}`, audited `device.revoked`); revoking others is allowed only from a trusted device; see the cool-down rules in `docs/SECURITY.md` §2.5. If there is no other device: **account recovery** with the recovery ID and one recovery code (`/v1/recovery/begin`): a new passkey takes effect after 72 h, all existing devices are notified and any trusted device can cancel; afterwards old devices, sessions, passkeys and codes are revoked. Remove phone links from a trusted device (`phone_link.removed`).
**Support path.** Support cannot freeze or revoke on the user's behalf **[GAP G7]**. Interim: if fraud is in progress, the user may delete the account (`DELETE /v1/account`, which revokes every session and device) or the operator suspends the business being abused.
**Detect.** `device.enrolled` shortly after `auth.login` from a new place, `device.replacement_pending`, notices not dismissed, `auth.refresh_reuse_detected`, `interaction.reported_suspicious`.
**Expectations.** A thief's new device cannot approve high/critical requests for 24 h (72 h when unattested); a stolen bearer token alone cannot enroll a device; delegates can never approve sign-ins or payments.

## RB-9 Vendor outages

General: confirm on the vendor status page and our own probes, declare SEV by user impact, post to `status.<apex>`, apply the degraded mode in `RESILIENCE.md` section 4, do not weaken a security control to "stay up" (CLAUDE.md).

| Vendor | Symptoms | Immediate actions | Do not |
|---|---|---|---|
| **APNs** | push `5xx`/timeouts, approvals not arriving | Interactions still land in the app on open; SMS/RCS handoff link for non-security kinds is automatic; extend expiries only per policy (security kinds <= 15 min); status banner | send approval decisions over SMS (never allowed) |
| **Twilio (SMS)** | `gateway.sms_failed` rising, `sms_outbound` backlog | Outbox retries; switch `TWILIO_MESSAGING_SERVICE_SID`/`TWILIO_FROM_NUMBER` to a standby account/sender with `fly secrets set` (second provider adapter does not exist; standby is a second Twilio sender); keep OTP allowlist unchanged | widen `OTP_ALLOWED_COUNTRIES` to compensate |
| **RCS provider** | `channel.*` failures | Router falls back to SMS automatically; unset RCS config to disable if the provider is flapping | |
| **Didit** | verification sessions failing | Disable the non-Wallet method [GAP G2]; Wallet path continues; message users | collect ID images ourselves |
| **Apple Wallet / pass signing** | pass issuing fails, PassKit callbacks fail | Pass endpoints may answer 501/retry; pass update pushes queue in `wallet_push_outbox` (7-day purge); renew the Pass Type ID certificate before expiry (calendar it) | |
| **Neon** | `/readyz` 503, `RATE_LIMIT_STORE` fail-closed | Machines leave rotation (readiness check); security-critical limiters refuse requests (by design), others run per instance; check Neon status; if the project/branch is damaged restore per `RESILIENCE.md` section 3 (PITR branch, repoint `DATABASE_URL` with `fly secrets set`) | switch the limiter to `memory` in production |
| **Fly.io** | machines unhealthy, deploys fail, region outage | `fly status`; `fly machine restart`; scale in another region (`fly scale count 2 --region ewr`) once multi-region is approved; Cloudflare serves a branded error page; if Fly is down for > RTO, stand up the image on a standby (documented DR drill) | |
| **Cloudflare** | edge errors, DNS or WAF outage | Status page is on a different provider; if only the proxy fails, a documented break-glass is DNS to Fly directly (loses WAF/rate limits and TLS policy: SEC-approved for <= 1 h, with `EDGE_TOKEN`/mTLS gaps noted) | leave the origin open longer than the approval |
| **GCP KMS** | signing/unwrap errors | Cached unwrapped keys keep verification and field decryption working until process restart (avoid restarts); new signatures (audit heads, connect links) queue or fail closed; regional alternatives (multi-region key ring) are a design decision; do not fall back to software keys in production | create exportable keys as a workaround |

## RB-10 Routine procedures referenced elsewhere

**Audit head export (schedule: at least hourly in production, plus before every deploy).** `fly ssh console --app viadere-server -C "/app/ViadereServer audit-head --env production"`; write the JSON to the write-once bucket (object lock, retention >= 1 year) from a scheduled job in the same account that holds no database access; alert when the newest head is older than 2 h. The target is KMS-signed heads (`audit-head` key, ADR-03). **[Scheduling job is not built; owner: ENG.]**

**Database role bootstrap (after Terraform creates the roles).** Two roles, two secrets. `viadere_migrator` owns the schema; its URL is the Fly secret `DATABASE_MIGRATION_URL`, read only by `ViadereServer migrate` (the release command). `viadere_app` is `DATABASE_URL` for every serving machine and `DATABASE_APP_ROLE=viadere_app` (plain `[env]`) names it for the grants. Once, as `viadere_migrator`: `GRANT CONNECT ON DATABASE viadere TO viadere_app; GRANT SELECT ON ALL TABLES IN SCHEMA public TO viadere_readonly;`. Every `migrate` then runs the `RuntimeRoleGrants` migration step: DML and sequence usage on all tables, default privileges for later tables, `REVOKE CREATE ON SCHEMA public` and `REVOKE UPDATE ON audit_events` from `viadere_app` (the audit table is never updated; its only delete is the retention purge after the head export). With `DATABASE_MIGRATION_URL` set, a staging/production machine whose runtime role can create objects or owns tables refuses to start, so a mistaken single-role deployment is caught at deploy time. Residual: Fly secrets are app-wide, so the migration URL is present in the runtime machine environment; the server does not read it outside `migrate`, but rotate it after any host compromise (Neon: `neon_role` password reset) and prefer a CI-held secret passed to a one-off release machine when Fly supports per-command secrets.

**Certificate and SPKI pin rotation.** The app pins the API SPKI (`Packages/ViadereKit`). Before any change of CA, key type or Cloudflare certificate pipeline: ship an app release containing the next pin (backup pin) and wait for adoption, then change; a forced change without adoption bricks old app versions. Keep two pins at all times.

**Operator access review (monthly).** List operators and dashboard owners; remove leavers; check `operator.created` events; rotate Cloudflare/Neon/Fly tokens quarterly.
