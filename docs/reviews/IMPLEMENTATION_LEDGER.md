# Implementation ledger (A0)

Required by `docs/product/AUTH-DELIVERY-SPEC-v2.md` §15.1: A0 records artifact links and commit identifiers. Stages and owners follow §24. Review rules follow §15 and §15.1: every security-sensitive change has one author and at least one different specialist reviewer; cryptography, recovery, token issuance and grant authorization need A2 plus A3; no agent deploys to production; A0 coordinates and may not waive a security gate.

Branch for Stage 0: the working branch `worktree-agent-aef563e35efb70f43`, started from `claude/inspiring-cannon-t5hxfw` at `a4b1e31`. Nothing is pushed.

## Stages

| Stage | Name | Artifacts | Authoring roles | Reviewer roles | Commit | Status |
|---|---|---|---|---|---|---|
| 0 | Discovery | `docs/architecture/CURRENT_STATE.md`, `docs/architecture/GAP_ANALYSIS.md`, `docs/product/SCOPE_LEDGER.md`, `docs/reviews/IMPLEMENTATION_LEDGER.md`; evidence reports A4, A5, A6, A8, A14 (kept outside the repository in `/tmp/claude-0/auth/stage0/`, not committed) | A0 (reconciliation, spot-checks), A4, A5, A6, A8, A14 (evidence reports) | Pending: A2 and A5 on security findings F-01 to F-03; A14 on scope; A7 on Android notes (Kotlin package not yet merged); owner approval of the current-state inventory (gate: "Current-state inventory approved") | 59bc991 | Written, awaiting review |
| 1 | Threat model + ADRs | `docs/architecture/THREAT_MODEL.md`, `docs/architecture/TRUST_BOUNDARIES.md`, ADR-0019 to ADR-0033 in `docs/ops/adr/` (the spec's `docs/architecture/ADR/` and "ADR-0001" map to this existing series; ADR-0019 is the implementation strategy; ADR-0031-0033 added in revision 2), `docs/product/UX_COPY.md`, `docs/product/FLOW_MATRIX.md`, CLAUDE.md exception row for api-held keys (decision 12), `docs/reviews/STAGE1_REVIEW_REQUEST.md`, reviews `STAGE1_A2_SECURITY_REVIEW.md`, `STAGE1_A3_CRYPTO_REVIEW.md`, `STAGE1_A6A7_PLATFORM_REVIEW.md`, `STAGE1_A9A10_UX_PRIVACY_REVIEW.md`, author response `STAGE1_RESPONSE.md`, `docs/ops/DATA-INVENTORY.md` update | One Stage 1 author acting as A1, A2, A3, A5, A10 | Reviewed once (A2 BLOCK; A3, A6/A7, A9/A10 approve with conditions). Revision 2 awaits delta re-review by the same reviewers; A5 peer or A4 (network) and A4 (contracts) still pending; A0 consistency. Author may not approve. | recorded by A0 after commit | Revision 2 written, awaiting delta re-review |
| 2 | API + data contracts | `contracts/openapi/auth-delivery-v1.yaml`, event and webhook schemas, migrations, retention sweeps, webhook signature v2 in Core | A4, A8, A10 | A10 (privacy), A2, A13 (contract tests); Core change reviewed by A3 | | Implemented on branch (contract aligned with ADR-0020 revision 3.1). Contract `contracts/openapi/auth-delivery-v1.yaml` + `contracts/schemas/`, Core `AuthDelivery/` and webhook v2, migration `AuthDelivery.v1`, vectors `docs/protocol/vectors/webhook-v2.json`, SECURITY section 2.101. Awaiting A10, A2, A13, A3 review |
| 3 | Delivery engine | Delivery aggregate and state machine, magic-link and OTP transport, code delivery, queue handlers, SDKs (Swift, TypeScript), harness, `tests/security/` | A4, A8 | A2, A9 (copy), A13 | | Engine, device routes, queue handlers, webhook v2 and the Swift SDK verifier implemented behind `AUTH_DELIVERY_ENABLED` (off by default in staging and production); ST- tests listed in SECURITY 2.101. Revision 3.1 allocation engine (`AuthMatchGroups`) ready for the Stage 5 `auth-approvals` route. Not yet: RFC 9421 request signatures, TypeScript SDK and harness, email fallback, link service. Awaiting A2, A9, A13 review |
| 4 | Native handoffs | iOS confirm-gated handoff, number-matching UI, equal Deny, Live Activity policy, notification routing fixes, watch classification, Android handoff from the Kotlin branch, UX copy | A6, A7, A9 | A9 (UX), A13 (real-device checks), A2 | | Not started |
| 5 | Viadere MFA proofs | Number matching protocol, signed factor assertions, replay tests, grant evaluation interface | A1, A2, A3, A4 | A12 (cannot implement), A3 for proof semantics | | Not started |
| 6 | Cloud hardening | Signer environment, identity and vault, split deploy identity, legacy platform retirement, alerts, drift job, docs and ADR cleanup, CLAUDE.md exception rows | A5, A11 | A3, A4, A12 | | Not started |
| 7 | Red team + QA | Red-team scenarios (spec §26), compromise tests, tenant breakout, full suites on SQLite and PostgreSQL | A12, A13 | A0 (gate check; may not waive), A2 | | Not started |
| 8 | Controlled pilot | Feature flags, rollback plan, owner approval record (staging only) | A0, A11, A14 | Owner | | Not started |
| 9 | Optional IdP discovery | Business case, OIDC architecture review (staging-only flag per decision 6); SAML design note | A0, A1, A2, A3 | Owner approval required | | Not started |

## Stage 0 evidence trail

| Item | Source | A0 handling |
|---|---|---|
| A4 backend report | `/tmp/claude-0/auth/stage0/A4-backend.md` | Spot-checked webhook signature, retention values, SMS OTP and link minting, signed-decision stripping, approve push, Live Activity attributes; reclassified the signed-decision finding as an intentional privacy design (CURRENT_STATE section 11). |
| A5 cloud report | `/tmp/claude-0/auth/stage0/A5-cloud.md` | Spot-checked key grants, deploy identity roles and federation subject, Fly deploy workflows, ingress settings. Live Azure, GitHub and Cloudflare settings are unverified. |
| A6 iOS report | `/tmp/claude-0/auth/stage0/A6-ios.md` | Spot-checked `/h/` redemption, approve routing, notification action policy. Downgraded `/h/` from High to Medium. Device behavior unverified. |
| A8 SDK report | `/tmp/claude-0/auth/stage0/A8-sdk.md` | Spot-checked absence of TypeScript/Android code on the branch. Kotlin package not inspected (separate branch). |
| A14 scope draft | `/tmp/claude-0/auth/stage0/A14-scope.md` | Updated for decisions 9-12, which A14 predates; several of its "owner ruling needed" items are now resolved (conflicts C-1, C-6, C-13). |
| Repository base | `a4b1e31` | The agent worktree started from a stale `main` (`41242da`) without the spec; A0 reset the worktree branch to `claude/inspiring-cannon-t5hxfw` before writing. |

## Gate status (spec §24)

| Gate | Condition | State |
|---|---|---|
| Stage 0 exit | Current-state inventory approved | Not yet approved; documents written |
| Stage 1 entry | Stage 0 outputs reviewed | Stage 1 drafted in parallel at the orchestrator's direction; Stage 0 review still pending |
| Stage 1 exit | Threat model, trust boundaries, ADRs signed by reviewers (spec §24) | Not yet. Reviews received (A2 BLOCK; A3, A6/A7, A9/A10 approve with conditions); revision 2 and `STAGE1_RESPONSE.md` written; delta re-review requested |
| Production | Owner approval after release gates | Not applicable; no agent deploys to production |

## Open items carried to Stage 1

1. Findings F-01 to F-03 need A2 and A5 sign-off on severity and the signer design.
2. Owner questions O-1 to O-6 (see `GAP_ANALYSIS.md` section 8 and `SCOPE_LEDGER.md` section 5).
3. Unverified live settings listed in `CURRENT_STATE.md` section 12 need an operator with Azure, GitHub and Cloudflare access.
4. THREAT_MODEL.md and ADR-0001 are spec §16 discovery outputs that belong to Stage 1 and are not written yet.

## Stage 1 revision 2 (2026-11-02)

All Critical, High and Medium findings of the four reviews are fixed or replaced by an argued alternative; Medium/Low deferrals carry an owner and a stage. Full table: `docs/reviews/STAGE1_RESPONSE.md`. Owner decisions 13 (residency), 14 (private GHCR, scoped pull credential) and 15 (read-only checks before deleting legacy resources) were applied (ADR-0026 §3, ADR-0028 §6.7, ADR-0029 §5). Structural changes: authority-minted account identity and authority-verified recovery (ADR-0032), authority-built and signed displays and device statements (ADR-0033), business-signed destinations verified on the device against authority tenant keys (ADR-0031), JWKS publication behind its own reviewer-gated environment, budgets that limit alerts instead of availability, field-level trust table (TRUST_BOUNDARIES §4.3a).

### Owner questions raised by revision 2 (no owner decision was changed)

| Id | Question | Why it is a question | Default until answered |
|---|---|---|---|
| OQ-1 | May device-signed results of **low-risk sign-ins** (approval-result JWS, factor JWS) move to E-routine (30 days), as A10 proposes? | O-3 names all signed device decisions and approval-result JWS as high-value evidence | They stay E-high (O-3 as written) |
| OQ-2 | Pilot start needs the app to ask people to make new recovery codes; people who recover with old codes lose Viadere sign-in (link service, OIDC) until they do. Accept this UX cost? | Product impact of ADR-0032 §3 (security requirement from A2/A3) | Design as written |
| OQ-3 | Create a GitHub identity for agents distinct from the owner's (machine user or GitHub App), enable "Prevent self-review", branch protection and CODEOWNERS; accept that staging admin/deploy/publish is a single owner approval (R-21) until a second human reviewer exists | Owner action and residual acceptance (S1-A2-9) | Authority environments not created until answered |
| OQ-4 | Accounts created while the authority is down are permanently without Viadere sign-in features; acceptable for the pilot (an upgrade path is ledger item L-1)? | Product impact of ADR-0032 §1.5 | Design as written |
| OQ-5 | Phone numbers linked by customer-originated text receive only on-ramp text and SMS-04 (no interaction content by SMS) until carrier verification exists. This narrows SMS-thread continuity for app users; decision 9 is unchanged | Feature scope (S1-A10-4) | Design as written |
| OQ-6 | Spanish as the first additional locale for the US launch? | Product choice (S1-A9-12) | English only in the pilot |
| OQ-7 | Business-mode magic links in the pilot require each tenant to register a destination-signing key through the reviewed admin path (ADR-0031); slower onboarding | Decision 2 kept; adds an onboarding requirement | Design as written |

### Tracked follow-ups from revision 2

| Id | Item | Owner | Stage |
|---|---|---|---|
| L-1 | Upgrade path for outage-created accounts (must rest on authority-verified evidence) | A2 | 6 |
| L-2 | `docs/ops/KEY-ROTATION.md`: explicit versions, standby device-statement key, emergency rollover | A3, A11 | 6 |
| L-3 | Purge for `channel_endpoints`, `rcs_postbacks` | A10 | 2 |
| L-4 | `sms_consent_events` retention and TCPA/CTIA review | A10 with counsel | before production |
| L-5 | `login_hint` by signed request object or PAR | A1 | 9 |
| L-6 | Review of the unmerged Kotlin package against ADR-0030 | A7 | 4 (before Android merge) |
| L-7 | Device checks marked **verify** (watch action routing, `sms_body` on OEM apps, RCS inbound, Android clipboard flag) | A6, A7, A13 | 4, 5, 7 |
| L-8 | MailerSend and SMS-provider storage locations verified and recorded (email fallback gate) | A10, owner | before enabling email fallback |
| L-9 | Counsel list from the A10 review §4 (E periods, state privacy law, COPPA, TCPA/CTIA, residency wording, controller/processor, lawful requests, OIDC consent terms, claims language) | A10 with counsel | before production |

## Stage 1 record

Owner rulings applied after Stage 0: O-1 (Kotlin allowed; CLAUDE.md rule 4), O-3 (signed device decisions and approval-result JWS are high-value audit evidence; ADR-0026), O-6 (household delegation and customer profiles are baseline; "first-party actions" = existing first-party surfaces; THREAT_MODEL §1.4), decision 9 phone proof (ADR-0027). Still open at revision 1: O-4 (GHCR visibility) and O-5 (live Fly/Neon/GCP resources), both answered by owner decisions 14 and 15 on 2026-11-02; O-2 narrowed to carrier behavior for customer-originated texts (still open).

| Item | Stage 1 resolution |
|---|---|
| F-01 | Exception recorded (CLAUDE.md row, ADR-0028 §1 migration plan); authority keys never on ordinary identities |
| F-02, F-03 | Design in ADR-0028 §6-§7; implemented in Stage 6 |
| F-04, F-22 | ADR-0025 |
| F-05 | ADR-0022 §2-§3 |
| F-06 | ADR-0027 |
| F-07 | ADR-0026 |
| F-08 | ADR-0021 §4 |
| F-10, F-11 | ADR-0029 |
| F-12 | ADR-0022 §1, ADR-0023 §1 (push MFA stays business-verified; privacy rule kept) |
| F-14, F-15, F-16, F-25 | ADR-0022 §2.5, §5.5, §8 (UI work in Stage 4) |
| F-19 | ADR-0020 §3 (RFC 9421 for live keys) |
| F-23 | ADR-0023 §2 (JOSE profile; standard primitives only), for A3 review |

Code claims re-verified by the Stage 1 author before relying on them: `Infra/azure/locals.tf` (`kv_keys`, `key_grants`, subnets), `identity.tf` (deploy identity roles and federated subject), `containerapps.tf` (internal ingress, `allow_insecure_connections`), `Services/PhoneLinkService.swift` (SMS OTP body), `Security/WebhookSignature.swift` (v1 MAC), `Approve/ApproveSupport.swift` (generic approve push, no request id), `docs/SECURITY.md` §2.26, §2.54-§2.58, §2.77, §2.95, `docs/ops/DATA-INVENTORY.md` §7.
