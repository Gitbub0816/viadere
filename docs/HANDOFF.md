# Handoff — state of the build and what's next

**Branch:** `claude/inspiring-cannon-t5hxfw` · **Last updated:** 2026-10-29

Read [`../CLAUDE.md`](../CLAUDE.md) first (versioning policy, no Node/PHP, working rules), then this file.

## Where things stand

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
