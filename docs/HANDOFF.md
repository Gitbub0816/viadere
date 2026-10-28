# Handoff — state of the build and what's next

**Branch:** `claude/inspiring-cannon-t5hxfw` · **Last updated:** 2026-10-28

Read [`../CLAUDE.md`](../CLAUDE.md) first (versioning policy, no Node/PHP, working rules), then this file.

## Where things stand

Built: the Swift stack in [`../README.md`](../README.md) — Core, Kit, BusinessSDK, Server (Vapor, Postgres 18), App (XcodeGen, iOS 17), Site (Swift static site), Infra (Fly.io, Cloudflare, Neon, Google Cloud KMS) — implementing [`COMPLETE-PRODUCT-SPEC.md`](COMPLETE-PRODUCT-SPEC.md), [`MESSAGING-GATEWAY-SPEC.md`](MESSAGING-GATEWAY-SPEC.md) and [`SECURITY-TRUST-PLATFORM-SPEC.md`](SECURITY-TRUST-PLATFORM-SPEC.md) per [`IMPLEMENTATION-PLAN-v2.md`](IMPLEMENTATION-PLAN-v2.md).

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
