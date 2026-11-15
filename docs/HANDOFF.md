# Handoff — state of the build and what's next

**Branch:** `claude/inspiring-cannon-t5hxfw` · **Last updated:** 2026-10-29

Read [`../CLAUDE.md`](../CLAUDE.md) first (versioning policy, no Node/PHP, working rules), then this file.

## Where things stand

**Wallet credential status lists (2026-11-15, G24).** Verify (and profile verification) now checks an mdoc's issuer status list when the MSO names
one (IETF Token Status List, draft-ietf-oauth-status-list-21, CWT form): fetched only from a host listed for that IACA
(`WALLET_STATUS_LIST_HOSTS`) through the SSRF guard with address pinning and no redirects, signature verified to the **same** IACA, `lst`
inflated strictly with a 4 MiB cap, cached at most an hour. Revoked and suspended are refused; an unobtainable list fails closed for high-assurance
capabilities (every Verify capability). Only stricter settings exist (`WALLET_STATUS_FAIL_MODE=all`, `WALLET_STATUS_REQUIRED=true`, a shorter
`WALLET_STATUS_LIST_MAX_CACHE_SECONDS`). Normative: [`SECURITY.md`](SECURITY.md) §2.60 "Wallet credential status". Open: the operator must list
each issuer's status host before Wallet credentials that carry a reference can verify; no real Apple Wallet credential with a status reference has
been tested (synthetic fixtures only); JWT-form lists and `identifier_list` are not supported.

**Email fallback for one-time codes (2026-11-15, G23).** A business may ask, per `otp` auth delivery, for the code to be mailed to an address it
supplies (`channels` with `email` and `fallback.email.address`), only while `AUTH_EMAIL_FALLBACK_ENABLED` is on (default off; **the server refuses it
in staging and production** until the owner closes ledger L-8: MailerSend's storage location and retention recorded in `docs/ops/DATA-INVENTORY.md`)
and the tenant turned on Security → Email fallback (`allow_email_fallback`, default off, passkey, audited; migration `AuthEmailFallback.v1`). Fixed
Viadere template (C-OTP-01 + C-OTP-03, new row C-OTP-05), no link, no code in the subject, MailerSend tracking off, sent at most once (the address
leaves the sealed secret by compare-and-swap before the send), budgets per tenant, customer and address that suppress the email but never the
delivery (`authdl-email-*`, fail closed). Normative: [`SECURITY.md`](SECURITY.md) §2.101 "Email fallback"; ADR-0020 implementation note (G23).
Open: the `auth.delivery.fallback_used` webhook event (contract + SDK change); L-8 (owner); magic links by email are deliberately not built.

**Link service completed: same-device hand-off, cross-device creates, registration-nonce relay (2026-11-15).** A same-device link-service approval
now finishes: after the authority **accepted** it, the phone opens the authority-signed `return_url` byte for byte with `#vdr_code=<32-byte code>`
once through the system opener (checked before signing and again before opening; never on deny, report, refusal, timeout or expiry; a failure drops
the code and shows LS-10). The business can create cross-device deliveries (`destination.cross_device: true`): it shows the `match_code` from the
view's `cross_device {ach, match_code}`, the phone types it and opens nothing, and the initiating session redeems with `ach` and its PKCE verifier;
the api and the authority refuse an answer in the other mode's shape. Businesses read a destination-key registration nonce with a live key at
`POST /v1/business/destination-keys/registration-nonce` (own tenant only, fail-closed per-tenant limit, audited). Everything stays behind
`AUTH_LINK_SERVICE_ENABLED` / `AUTH_DESTINATION_RECORDS_ENABLED` / `AUTHORITY_TENANT_KEYS_ENABLED` (off). Normative: [`SECURITY.md`](SECURITY.md)
§2.110; ADR-0021 and ADR-0031 implementation notes; copy LS-09, LS-10. Not verified: the app build (syntax-parsed only), the PostgreSQL run.

**Message attachments (2026-11-15, C4.3b).** Customers and businesses can send images in a conversation: app (device-signed raw upload, PhotosPicker
composer, image bubbles), business API (`POST`/`GET /v1/business/conversations/{sessionId}/attachments[/{id}]`, `attachmentIds` on
`sendMessage`) and console (thumbnails through `/dashboard/conversations/{id}/attachments/{aid}`, "Add an image" before a reply). Every upload is
size-capped from `Content-Length` before the body is read, decoded by the Brand Kit front end and pure-Swift codecs, dimension-capped,
re-encoded without metadata (JPEG when opaque, PNG with transparency), sealed with the field cipher bound to tenant and row, and stored in a
private attachment store; it is bound to one conversation, one tenant and one side and claimed by compare-and-swap when sent; unsent uploads expire
after an hour. Webhooks carry ids and metadata only; SMS threads get SMS-09/SMS-10 with no link; MMS media are ignored. Retention, account and
tenant deletion mark rows and the maintenance sweep deletes the objects. Normative: [`SECURITY.md`](SECURITY.md) §2.113 (and §2.108 item 7); copy
UX_COPY SMS-09, SMS-10, MSG-ATT-01..08; data inventory §11. Open: the Azure container (`AZURE_ATTACHMENT_BLOB_*`) is not in `Infra/azure` yet;
Node and Swift SDK helpers for the two routes; the app build (syntax-parsed only) and the PostgreSQL run.

**Link-service screen, Lock Screen names, pairing QR, SQLite contention (2026-11-15).** A `link_mode: "viadere"` delivery now opens
`LinkServiceScreen` (Kit `LinkServiceViewModel`): the relayed `link_open` challenge is verified against the pinned statement keys, the screen
shows only the signed tenant, client and return host, a number is typed when the challenge asks for one, and the answer is a factor signed with
the biometric approval key, sent to `link-evidence`. (Superseded the same day: the same-device hand-off of ADR-0021 §5.3 now opens the signed
return URL after acceptance; see the entry above.) "Show business names on the Lock Screen" exists (off by default:
notifications say "Viadere", no logo), read by the notification service extension from the app group. The pairing code is also shown as a QR of
`https://{link domain}/p/{code}`; only a new device's pairing entry reads it (scanner or universal link), an enrolled device refuses it everywhere,
the server lists `/p/*` in the AASA with a fallback page that reads nothing, and log lines mask the code. SQLite (development and tests) runs on
one connection per process: two connections deadlocked in deferred transactions and SQLite returned BUSY at once, which no busy timeout prevents
(`SQLiteContentionTests`). Normative: [`SECURITY.md`](SECURITY.md) §2.104 (gate step 5), §2.107, §2.110 (device side); copy: UX_COPY §0 rule 5,
N-02a/N-03a/N-05a/N-06a, N-SET-01, LS-01..08, S-PAIR-09/10, WEB-07. Not verified: the app build (syntax-parsed only), the PostgreSQL run.

**RFC 9421 request signatures and the `push_approval` view (2026-11-15, G9/G22).** A live API key can now send sign-in prompts with an HTTP
Message Signature instead of mutual TLS: `AUTH_LIVE_KEY_ASSURANCE=mtls_or_signature` is the staging and production default (`mtls` keeps the
certificate-only rule). Profile (`ecdsa-p256-sha256` raw `r||s` low S; exactly `@method @authority @path @query content-digest content-type`;
`created`/`expires`/`keyid`/`nonce`/`tag="viadere-api-v1"`; 300 s windows; single-use nonce in the replay store) lives in Core and is verified by
`BusinessAPIKeyMiddleware` before any handler; `@authority` comes from `REQUEST_SIGNATURE_AUTHORITIES` (default the host of `PUBLIC_BASE_URL`), never
`Host`. Keys are registered under Security > Request signing (Owner or Security Admin, passkey step-up, proof of possession over a single-use
challenge; bound to one API key and carried through rotation; audited, Owners mailed). Swift (`requestSigner:`) and TypeScript (`requestSigner`)
SDKs sign opt-in with KMS-capable signers; vectors `docs/protocol/vectors/http-signatures-v1.json` come from an independent Python generator and
are checked by Core, server, Swift SDK and Node tests. The `push_approval` record is readable through `GET /v1/business/auth-deliveries/{id}`
(`ViewMethod`) and emits `auth.delivery.*` events. Normative: [`SECURITY.md`](SECURITY.md) §2.112, §2.103 (`push_approval` record); ADR-0020
implementation note. Not done: Kotlin SDK signing (and the Kotlin `ViewMethod` change is unbuilt), two-person approval for signing-key
registration, a business-wide "signatures on every route" switch. Verified 2026-11-15: Core 647 + 44, Business SDK 90 + 8, Server 1248 (9 skipped) + 109 on SQLite, Node 336. Not verified: the PostgreSQL run.

**Profile changes, console recovery, analytics rollups and branded passes (2026-11-15).** A verified business can ask to change its public name,
handle or website from Organization; the change waits in `business_profile_changes` (customers never see it) until two different operators approve
it under `/operator/profile-changes`, with the impersonation checks of verification re-run at each approval (Viadere look-alikes, names confusable
with other verified businesses' names or any handle they ever held, retired handles never reused, website on a verified domain). A console user
who lost every passkey is re-enrolled by an Owner or Organization Admin from Team (preferred) or, only when no other admin has a passkey, through
`/operator/recoveries`: two operators, a recorded identity-proof checklist whose evidence rules are an **owner/legal decision**, a 72-hour waiting
period with notice to every member and security contact, then a one-hour link to the member's own address; old passkeys are deleted when the new one
is enrolled. Analytics read a daily rollup plus today's live rows; the consumer export gains `historyByBusiness`. Signed Wallet passes carry the
business's approved Brand Kit colors (contrast-checked, else Viadere's) and icon, logo and strip images. Normative: [`SECURITY.md`](SECURITY.md)
§2.111, [`WALLET.md`](WALLET.md). Not verified: the PostgreSQL run; screenshots of the new pages were checked in light and dark at 1280 px.

**Business-link destinations and the link service (2026-11-15, G4/G11).** The pieces that let the app open a business's sign-in link safely now
exist, all behind flags that ship off. Core verifies the authority's tenant record (`viadere-tenant-keys+jws`), the pinned-key revocation list and
the destination-key registration proof, with independent vectors. The authority stores tenant destination keys (admin job only: nonce, proof of
possession, attested DNS/well-known evidence, 13-month limit; reduce-only revocation with or without the api) and signs records with the existing
`device-statement-signing` key (`AUTHORITY_TENANT_KEYS_ENABLED`). The api relays records unchanged (`GET /v1/auth-tenants/{id}/destination-keys`,
`AUTH_DESTINATION_RECORDS_ENABLED`). The app's `AuthorityDestinationVerifier` replaces the fail-closed verifier only with
`AuthDeliveryFlags.destinationVerification` and pinned keys, and checks the opened URL bytes against `url_sha256`. The link service
(`link_mode: "viadere"`, `AUTH_LINK_SERVICE_ENABLED`, refused in production) creates deliveries with a business-bound authority challenge,
relays the device's evidence and completes the delivery on redemption. Normative: [`SECURITY.md`](SECURITY.md) §2.110; owner steps:
[`ops/AUTHORITY-OWNER-CHECKLIST.md`](ops/AUTHORITY-OWNER-CHECKLIST.md) section E2. Cross-device creates, the business-facing nonce relay and the
same-device hand-off were built later the same day (entry above). Not verified: the PostgreSQL run, live DNS evidence fetching.

**Console conversations, benefits and RCS rich cards (2026-11-15).** A business without an integration can now read and answer customer messages in
the console (`Dashboard/ConsoleConversations.swift`: list, thread, reply through `ConversationService.businessSend`, assign, close, reopen; reads
audited, bodies decrypted only for the owning tenant, customers shown as `subject_ref`), and run its loyalty program, revoke rewards, void Wallet
passes and check codes at the counter (`Dashboard/ConsoleBenefits.swift`, calling the business API's own service functions; revoke, void and check
need a fresh passkey; live only after go-live approval). New permissions `viewConversations`, `replyConversations`, `viewBenefits`,
`manageBenefits` (matrix in `docs/ops/CONSOLE-ROLES.md`); `BusinessPrincipal.consoleUserId` attributes console actions to the person in the audit
chain. The RCS sender now sends the rich cards Core renders (`richCard` standalone or carousel, one token per target shared by chip and card,
no links or media, plain resend on a 4xx). Normative: [`SECURITY.md`](SECURITY.md) §2.11, §2.108, §2.109. Not verified: the PostgreSQL run and a
real RBM provider; screenshots of the new pages were checked in light and dark at 1280 px.

**CKey and app polish (2026-11-14, branch `claude/tender-ritchie-c8ox1c`, which continues `claude/inspiring-cannon-t5hxfw`).** The app path of
"Sign in with Viadere" draws its link as a CKey in the concept style (pure-Swift port in `ViadereCore/OpticalCode`, verified against the
reference build), with the QR code one link away; the app has one scanner for the Viadere code and QR codes (`Features/Scan`), gated by
`ScannedCodePolicy`; sheets end in a drawn outcome with a haptic. Normative text and residual risks: [`SECURITY.md`](SECURITY.md) §2.104.
Verified here: Core 574, Kit 715, Server on SQLite (see the commit). **Not verified:** the app does not compile on Linux, so the scanner, the
CKey package integration and the new components are syntax-parsed only; nothing has been scanned with a real phone. First device jobs:
build in Xcode, scan the staging sign-in page from a laptop screen in bright and dim rooms, and keep the QR link until that passes.
**CKey Safe Actions built (2026-11-14, owner decision).** With the authority's ES256 key `ckey-safe-action-signing` pinned and
`CKEY_SAFE_ACTION_ISSUER` set on the authority, the Viadere code is a signed `signin.request` Safe Action for the challenge (the authority
signs it with the challenge; the api only stores, draws and publishes it: `/.well-known/ckey-safe-actions.json`, `/ckey/requests/{id}`), and
the app verifies it with its own Swift reader against pinned keys (`VIADERE_CKEY_SAFE_ACTION_KEYS`, `keyId:ES256:<SEC 1 hex>`) before
opening the unchanged sign-in review. Off (plain link) until the owner pins the key. [`SECURITY.md`](SECURITY.md) §2.104 "Safe Actions" maps
every spec rule to code and test. Owner follow-ups: (1) ES256 Safe Actions need CKey 0.1.0-build.118 or later, which is on CKey's scratch
branch only: when the owner publishes the first Stable-Release build ≥ 118 (the earlier plan named build 115; ES256 needs 118), re-pin `App/project.yml` (`CKeyScanner`
revision) to it, regenerate `docs/protocol/vectors/ckey-profile0-v1.json`, `ckey-safe-actions-v1.json` and `ckey-safe-actions-es256-v1.json`
from that build, re-run the Core port tests, and update the CLAUDE.md CKey rows. Viadere's reader does not depend on the CKey build; other
CKey readers do. (2) Before enabling: create the key (OpenTofu), pin its version with the admin job, set `CKEY_SAFE_ACTION_ISSUER` in
`authority_env`, put the key file's entry into the app build, and only then turn it on. (3) Whether the Verify, Connect and dashboard codes
should offer a CKey beside the QR.

**Business code styles and campaigns (2026-11-15).** Businesses style their own connect and Loop install codes in Brand Studio ("Your code": the
Viadere code by default, black on white, a custom CKey, or QR colours), always with a plain QR beside the styled code; security surfaces keep
`ViadereCodeStyle`. Campaign links are stored, listed, archived and counted (connections credited only from a server-verified context of a live
campaign of the same business), and a campaign's follow-up action (closed list in Core) is offered by the app only after connecting. The decode
proof found the reference's 3:1 floor too lax on a contrasting surround, so business marks must also be near white or near black (luma 216 / 56).
Normative: [`SECURITY.md`](SECURITY.md) §2.105, §2.106. Not verified: Postgres run, real phones and print; the app changes are syntax-parsed only.

Built: the Swift stack in [`../README.md`](../README.md) — Core, Kit, BusinessSDK, Server (Vapor, Postgres 18), App (XcodeGen, iOS 17), Site (Swift static site), Infra (Fly.io, Cloudflare, Neon, Google Cloud KMS) — implementing [`COMPLETE-PRODUCT-SPEC.md`](COMPLETE-PRODUCT-SPEC.md), [`MESSAGING-GATEWAY-SPEC.md`](MESSAGING-GATEWAY-SPEC.md) and [`SECURITY-TRUST-PLATFORM-SPEC.md`](SECURITY-TRUST-PLATFORM-SPEC.md) per [`IMPLEMENTATION-PLAN-v2.md`](IMPLEMENTATION-PLAN-v2.md).

**Security Architecture Expansion ([`IMPLEMENTATION-PLAN-v3.md`](IMPLEMENTATION-PLAN-v3.md)), WP-A2, B4, B5 built (2026-10-29):** accounts are created **device-first and pseudonymous** (`POST /v1/accounts/enroll/begin` + `POST /v1/accounts`; no name, email, phone or passkey), the protocol is platform-neutral (`IntegrityEvidence` with formats, Android verifier stub that never attests, `algorithm` on key registrations, `PushRegistration`), and device trust is a **server-decided tier D0/D1/D2 with no time-based elevation** (owner decision: a device becomes D1 only as a new account's attested first device or by approval from another D1 device; a business can re-enroll a D0 device of an account with no D1 device for its own Approve v2 requests). Passkeys and recovery codes are optional ("Protect your account", proven by the device's own user-verified key). Audit events carry `actor_ref` and `policy_version` (chain version 4). Normative text: [`SECURITY.md`](SECURITY.md) §2.5a; vectors: [`protocol/vectors/`](protocol/vectors/); migration `DeviceFirstAccounts.v1`. The app's onboarding is consent → set up this iPhone → notifications → protect (optional) → phone (optional); the App Clip creates a request-key-only D0 account. Not yet built from v3: everything else (A1, B1–B3, C*, D*, E*, F*); the App has not been built in Xcode with these changes (`swiftc -parse` only). Known consequence: a clip-created account is not taken over by the full app (no passkey to sign in with); the full app creates its own account.

Independent release-gate reviews were run for Approve (Phase 2), Verify (Phase 3), the Authenticator (Phase 4) and the platform (Phases 0/1 and enterprise). **Every finding has been fixed and pushed** (commits prefixed `fix(approve-gate)`, `fix(verify-gate)`, `fix(vault-gate)`, `fix(platform-gate)`), each with targeted tests. Release flags stay off in production: `APPROVE_V2_ENABLED`, `VERIFY_ENABLED`, `VAULT_SYNC_ENABLED` (sync), Tier E connectivity.

The previous session ran out of its disk allowance (the container restarted five times), so the **full** verification after the gate fixes has **not** been run. That is the first job.

## Next steps (in order)

1. **Full verification** (one at a time; the server suite needs ~8 GB of free disk for build + Postgres):
   ```sh
   export PATH=/opt/swift/usr/bin:$PATH        # Swift 6.4.1 (install per CLAUDE.md if missing)
   (cd Packages/ViadereCore && swift test)
   (cd Packages/ViadereBusinessSDK && swift test)
   (cd Packages/ViadereKit && swift test)
   (cd Server && swift test)                                                    # SQLite
   (cd Server && TEST_DATABASE_URL="postgres://postgres:…@127.0.0.1:5432/viaderetest?sslmode=disable" \
                 TEST_RATE_LIMIT_STORE=database swift test)                     # PostgreSQL 18
   (cd Site && swift test && swift run viadere-site build --out dist && swift run viadere-site lint --dist dist)
   Design/tools/.venv/bin/python Server/Tests/browser/test_connect_button.py    # browser test (Playwright)
   python3 -I Infra/fly/check_env_coverage.py
   ```
   Last full results before the gate fixes: Server 683/683 SQLite, 679/683 Postgres (the 4 retention failures were fixed in `4e70510`), Core 248+39, SDK 57, Kit 407. Fix anything red at the root cause; never weaken a control.
2. **Re-review the critical/high gate fixes** with an independent reviewer (read-only), against the findings they close:
   - Approve F1 (business-authenticated enrollment: fragment secret `es`, binding tag, SAS), F2 (legacy approval path behind an expiring operator entitlement), condition 4 (root key authorization).
   - Verify F1 (business audit projection; underage indistinguishable), F2 (no global consumer ID in business views), F3 (Didit purge backoff + switch).
   - Vault M2 (72 h recovery-envelope release hold), M3 (rotation always fits; 2 MiB cap / 4 MiB ceiling).
   - Platform M1–M4 (security purpose gating, step-up on team changes, two-person approval, Tier E CA binding).
   Several gate fixes did not record a failing test before the fix (Verify fixer); the re-review should confirm the new tests actually catch the exploit.
3. **Open engineering items:** make `ViadereCore.domain` configurable so staging SMS/QR links point at staging; separate Fly release app for migrations (`Infra/fly/README.md` §1a) so serving machines don't hold `DATABASE_MIGRATION_URL`; Secure-Enclave-backed vault agreement key (`TODO(vault-se-dhkem)`); system Credential Exchange import (iOS 26); the Wallet KMS key unwrapper (Verify Wallet method is unavailable in production until assigned).

## Needs the product owner / real infrastructure

- **Staging:** follow [`ops/STAGING-SETUP.md`](ops/STAGING-SETUP.md) (accounts: Apple Developer, Cloudflare, Neon, Twilio, Resend, Fly.io). Staging API: `api-staging.viadere.com`.
- **First Xcode build** of the app (never compiled — Linux only); real-device testing (Secure Enclave, App Attest, passkeys, Wallet IDs, credential provider).
- **Apple:** in-app identity presentment entitlement, merchant ID + encryption certificate, APNs key, App Attest.
- **Didit:** account, workflow (document + liveness + face match), webhook secret, White Label theme, shortest retention.
- **Counsel:** every legal page (`Site/content/legal/*`, all `counsel_review: pending`), Verify per market (AGE-006), biometrics (BIPA/GDPR Art. 9), Didit DPA, Apple relay terms, retention schedule, export compliance.
- **Gate evidence:** incident drill, assistive-technology accessibility testing, end-to-end delivery/opt-out with real carriers/APNs/Twilio, enterprise connectivity failover.
- **Release pins:** real SPKI pins and team ID (Release and Staging archives fail until set).

## Where to look

| Topic | File |
|---|---|
| Normative wire formats, threat model, residual risks | [`SECURITY.md`](SECURITY.md) |
| Risk register, runbooks, kill switches, data inventory | [`ops/`](ops/) |
| Business API | [`openapi.yaml`](openapi.yaml), [`BUSINESS-INTEGRATION.md`](BUSINESS-INTEGRATION.md) |
| Architecture decisions | [`ops/adr/`](ops/adr/), [`IMPLEMENTATION-PLAN-v2.md`](IMPLEMENTATION-PLAN-v2.md) |
| Loops, Brand Kits, Organization (spec and plan) | [`FEATURE-EXPANSION-v4.md`](FEATURE-EXPANSION-v4.md), [`FEATURE-EXPANSION-PLAN-v4.md`](FEATURE-EXPANSION-PLAN-v4.md) |
