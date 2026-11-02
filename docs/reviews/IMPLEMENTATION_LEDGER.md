# Implementation ledger (A0)

Required by `docs/product/AUTH-DELIVERY-SPEC-v2.md` §15.1: A0 records artifact links and commit identifiers. Stages and owners follow §24. Review rules follow §15 and §15.1: every security-sensitive change has one author and at least one different specialist reviewer; cryptography, recovery, token issuance and grant authorization need A2 plus A3; no agent deploys to production; A0 coordinates and may not waive a security gate.

Branch for Stage 0: the working branch `worktree-agent-aef563e35efb70f43`, started from `claude/inspiring-cannon-t5hxfw` at `a4b1e31`. Nothing is pushed.

## Stages

| Stage | Name | Artifacts | Authoring roles | Reviewer roles | Commit | Status |
|---|---|---|---|---|---|---|
| 0 | Discovery | `docs/architecture/CURRENT_STATE.md`, `docs/architecture/GAP_ANALYSIS.md`, `docs/product/SCOPE_LEDGER.md`, `docs/reviews/IMPLEMENTATION_LEDGER.md`; evidence reports A4, A5, A6, A8, A14 (kept outside the repository in `/tmp/claude-0/auth/stage0/`, not committed) | A0 (reconciliation, spot-checks), A4, A5, A6, A8, A14 (evidence reports) | Pending: A2 and A5 on security findings F-01 to F-03; A14 on scope; A7 on Android notes (Kotlin package not yet merged); owner approval of the current-state inventory (gate: "Current-state inventory approved") | 59bc991 | Written, awaiting review |
| 1 | Threat model + ADRs | `docs/architecture/THREAT_MODEL.md`, `TRUST_BOUNDARIES.md`, `docs/architecture/ADR/*` (ADR-0001 implementation strategy; phase table; retention table; in-app phone-ownership proof; number matching; link service; webhook signature v2; evidence model for decisions; exception for api-held keys) | A1, A2, A3, A5, A10 | A2 and A3 for crypto/key/token/grant ADRs; A10 for retention; A0 for consistency | | Not started |
| 2 | API + data contracts | `contracts/openapi/auth-delivery-v1.yaml`, event and webhook schemas, migrations, retention sweeps, webhook signature v2 in Core | A4, A8, A10 | A10 (privacy), A2, A13 (contract tests); Core change reviewed by A3 | | Not started |
| 3 | Delivery engine | Delivery aggregate and state machine, magic-link and OTP transport, code delivery, queue handlers, SDKs (Swift, TypeScript), harness, `tests/security/` | A4, A8 | A2, A9 (copy), A13 | | Not started |
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
| Stage 1 entry | Stage 0 outputs reviewed | Blocked on the line above |
| Production | Owner approval after release gates | Not applicable; no agent deploys to production |

## Open items carried to Stage 1

1. Findings F-01 to F-03 need A2 and A5 sign-off on severity and the signer design.
2. Owner questions O-1 to O-6 (see `GAP_ANALYSIS.md` section 8 and `SCOPE_LEDGER.md` section 5).
3. Unverified live settings listed in `CURRENT_STATE.md` section 12 need an operator with Azure, GitHub and Cloudflare access.
4. THREAT_MODEL.md and ADR-0001 are spec §16 discovery outputs that belong to Stage 1 and are not written yet.
