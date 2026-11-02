# Implementation ledger (A0)

Required by `docs/product/AUTH-DELIVERY-SPEC-v2.md` §15.1: A0 records artifact links and commit identifiers. Stages and owners follow §24. Review rules follow §15 and §15.1: every security-sensitive change has one author and at least one different specialist reviewer; cryptography, recovery, token issuance and grant authorization need A2 plus A3; no agent deploys to production; A0 coordinates and may not waive a security gate.

Branch for Stage 0: the working branch `worktree-agent-aef563e35efb70f43`, started from `claude/inspiring-cannon-t5hxfw` at `a4b1e31`. Nothing is pushed.

## Stages

| Stage | Name | Artifacts | Authoring roles | Reviewer roles | Commit | Status |
|---|---|---|---|---|---|---|
| 0 | Discovery | `docs/architecture/CURRENT_STATE.md`, `docs/architecture/GAP_ANALYSIS.md`, `docs/product/SCOPE_LEDGER.md`, `docs/reviews/IMPLEMENTATION_LEDGER.md`; evidence reports A4, A5, A6, A8, A14 (kept outside the repository in `/tmp/claude-0/auth/stage0/`, not committed) | A0 (reconciliation, spot-checks), A4, A5, A6, A8, A14 (evidence reports) | Pending: A2 and A5 on security findings F-01 to F-03; A14 on scope; A7 on Android notes (Kotlin package not yet merged); owner approval of the current-state inventory (gate: "Current-state inventory approved") | 59bc991 | Written, awaiting review |
| 1 | Threat model + ADRs | `docs/architecture/THREAT_MODEL.md`, `docs/architecture/TRUST_BOUNDARIES.md`, ADR-0019 to ADR-0034 in `docs/ops/adr/` (the spec's `docs/architecture/ADR/` and "ADR-0001" map to this existing series; ADR-0019 is the implementation strategy; ADR-0031-0033 added in revision 2, ADR-0034 in revision 3), `docs/product/UX_COPY.md`, `docs/product/FLOW_MATRIX.md`, CLAUDE.md exception row for api-held keys (decision 12), `docs/reviews/STAGE1_REVIEW_REQUEST.md`, reviews `STAGE1_A2_SECURITY_REVIEW.md`, `STAGE1_A3_CRYPTO_REVIEW.md`, `STAGE1_A6A7_PLATFORM_REVIEW.md`, `STAGE1_A9A10_UX_PRIVACY_REVIEW.md`, author response `STAGE1_RESPONSE.md`, `docs/ops/DATA-INVENTORY.md` update | One Stage 1 author acting as A1, A2, A3, A5, A10 | Reviewed once (A2 BLOCK; A3, A6/A7, A9/A10 approve with conditions). Revision 2 re-reviewed: A2 BLOCK (narrow), A3 approve with conditions (`STAGE1_A2_SECURITY_REREVIEW.md`, `STAGE1_A3_CRYPTO_REREVIEW.md`). Revision 3 checked: A2 and A3 **approve with conditions** (`STAGE1_A2_REV3_CHECK.md`, `STAGE1_A3_REV3_CHECK.md`). Revision 3.1 answers those conditions (C-13 is a hard gate before the Stage 2 authority contract freezes; A2 checks the documents, no new round; A3 re-checks only the S3-A3-01/-02 deltas before Stage 6). A9 copy review (C-12); A5 peer or A4 (network) and A4 (contracts) still pending; A0 consistency. Author may not approve. | recorded by A0 after commit | Revision 3.1 written, awaiting the C-13 document check |
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
| Stage 1 entry | Stage 0 outputs reviewed | Stage 1 drafted in parallel at the orchestrator's direction; Stage 0 review still pending |
| Stage 1 exit | Threat model, trust boundaries, ADRs signed by reviewers (spec §24) | Not yet. Revision 2 re-reviewed (A2 BLOCK narrow; A3 approve with conditions); revision 3 and the "Revision 3" table in `STAGE1_RESPONSE.md` written; A2 and A3 approved revision 3 with conditions; revision 3.1 written ("Revision 3.1" table); C-13 document check by A2 pending before the Stage 2 authority contract freezes |
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
| L-1 | ~~Upgrade path for outage-created accounts~~ **Closed in revision 3**: no account is created without genesis (ADR-0032 §1.5, S2-A2-8 option (a)) | A2 | — |
| L-2 | `docs/ops/KEY-ROTATION.md`: explicit versions, standby keys as separate objects, revocation rules for both pinned families, compromise and loss-of-both runbooks, routine rotation, seal-key creation (two separate runs, attested KEK public halves) and destruction, seal-key lifetime (≤ 6 months), and the **"seal key exposed"** procedure (ADR-0033 §3, ADR-0034 §5, §8; revision 3.1) | A3, A11 | **before Stage 4 pins any key** (moved from 6; condition C-6); the exposure procedure is **drilled once in staging** before any authority flag in the pilot (C-15) |
| L-3 | Purge for `channel_endpoints`, `rcs_postbacks` | A10 | 2 |
| L-4 | `sms_consent_events` retention and TCPA/CTIA review | A10 with counsel | before production |
| L-5 | `login_hint` by signed request object or PAR | A1 | 9 |
| L-6 | Review of the unmerged Kotlin package against ADR-0030 | A7 | 4 (before Android merge) |
| L-7 | Device checks marked **verify** (watch action routing, `sms_body` on OEM apps, RCS inbound, Android clipboard flag) | A6, A7, A13 | 4, 5, 7 |
| L-8 | MailerSend and SMS-provider storage locations verified and recorded (email fallback gate) | A10, owner | before enabling email fallback |
| L-9 | Counsel list from the A10 review §4 (E periods, state privacy law, COPPA, TCPA/CTIA, residency wording, controller/processor, lawful requests, OIDC consent terms, claims language) | A10 with counsel | before production |
| L-10 | Optional device-side `subject_ref` statement to narrow R-07' (S2-A2-11 item 5, S1-A3-R04 item 3) | A2 | 5 |
| L-11 | Format vectors from the A3 re-review Lows (R04-R06) in `docs/protocol/vectors/` (`keylog-v1.json` incl. comparison code, `auth-destination-v1.json`, device-statement vectors incl. cross-`typ` and revocation, `recovery-seal-v1.json`, RFC 7638 `kid` agreement) | A3 with the implementing stage | 2-6 |
| L-12 | Re-check on Microsoft Learn whether Key Vault or Managed HSM offers a key-agreement (ECDH) operation (and the built-in Crypto User role definition). If one exists, HPKE with an HSM-resident KEM key becomes an alternative to ADR-0034 §9 (A3 re-check); if not, §9 stands. Either way it feeds L-13 | A3 | 6 |

## Stage 1 revision 3 (2026-11-02)

Answers the A2 re-review (BLOCK, narrow) and the A3 re-review (approve with conditions); full table in `STAGE1_RESPONSE.md` "Revision 3". Structural changes: **ADR-0034** (new): recovery codes generated on the device, sealed with HPKE (`DHKEM(P-256, HKDF-SHA256)` / `HKDF-SHA256` / `AES-256-GCM`, the ADR-0007 suite) to a pinned `recovery-seal` key, never seen or hashed by the api, and bound to the new keys at recovery start; passkey assertions accepted only for `oidc_login` and `recovery_cancel` (ADR-0023 §3a); device-add comparison code typed on the existing device (ADR-0033 §4.1); defined, role-restricted, sticky revocation of pinned keys with standbys as separate key objects (ADR-0033 §3); tenant destination keys need a PoP and their thumbprint in the domain evidence (ADR-0031 §1); request grouping with number selection and `session_handle`-only supersession (ADR-0022 §5.2); no account without genesis (ADR-0032 §1.5).

**Additive changes to ADRs that Stages 2-3 code against** (for forwarding): ADR-0020 §2 optional `session_handle`; §8 supersession only with a matching `session_handle`; §1/§5 `destination_unverified` denials not counted toward fatigue. ADR-0027 §1.3 one clarifying sentence (dormant owner: transfer waits indefinitely), no behavior change. ADR-0025 and ADR-0026 unchanged.

### Owner questions raised by revision 3

| Id | Question | Why | Default until answered |
|---|---|---|---|
| OQ-8 | Decision 16 OQ-4 said outage-created accounts "stay limited until re-bound". Revision 3 (A2 S2-A2-8 option (a)) instead creates **no** account while the authority is down: sign-up waits and retries. Replace the OQ-4 wording? | Changes the product behavior the owner accepted provisionally | Design as revision 3 (no limited accounts) |
| OQ-2 (restated) | The "Make new recovery codes" offer of decision 16 is kept, but it is **not shown** until sealed recovery (ADR-0034) ships and its tests pass (condition C-4). Registering a new set retires the old codes, including the api's legacy set | Timing and UX of an owner-accepted feature | Offer after ADR-0034 ships |
| OQ-9 | Device add needs typing a 6-digit code from the new device on an existing device; passkey-only people add a device through an existing device or recovery, not with the passkey alone | Product friction from S2-A2-2/-3 | Design as revision 3 |
| OQ-10 | Business-mode tenants must publish a DNS TXT (or well-known) key thumbprint and renew destination keys at least every 13 months | Onboarding friction from S1-A3-R03 (extends OQ-7) | Design as revision 3 |

## Stage 1 revision 3.1 (2026-11-02)

Answers the A2 and A3 checks of revision 3 (both **approve with conditions**); full table in `STAGE1_RESPONSE.md` "Revision 3.1". Docs only. Changes: device-add caps and comparison-nonce timing (ADR-0033 §4.1, ADR-0023 §4, DF-5; S3-A2-1, S3-A3-01; **C-13**); collision-free, prefix-free number allocation in approval groups (ADR-0022 §5.2 item 6, ADR-0020 §2a, §8; S3-A2-2; C-14); seal-key custody, `seal_kid`, exposure procedure, lifetime, lean-pilot mitigations and the production HSM construction (ADR-0034 §5, §8-§10, ADR-0028, TRUST_BOUNDARIES §3, §4.2; S3-A2-3, S3-A3-02; C-15, C-16); Lows S3-A2-4..-6 and S3-A3-03..-05 fixed in the design (C-17); S3-A3-06 recorded.

**Changes to ADRs that Stages 2-3 code against (ADR-0020, additive only; forward to the agent implementing ADR-0020):**
- §2 `session_handle`: derivation is now a MUST (`HMAC-SHA256(K_sh, "viadere-session-handle-v1\n" ‖ initiating_session_id)`); documentation and SDK only, **no schema change**.
- New §2a on `POST /v1/business/auth-approvals`: two members `match_tag` and `match_prefix_tag` (present iff `number_match`), and three new `409` answers on that route: `match_code_in_use`, `match_digits_required {digits: 3}`, `match_code_space_exhausted`.
- §8: the `session_handle` abuse rule (more than 3 request ids per (tenant, subject) in 10 minutes → treated as absent for supersession; alert above 20 per hour per tenant); group rules (distinct and prefix-free codes, 3 digits from 30 open, group-pressure alert above 10). `authdl-tenant` remains the only `429` budget.
- §9: new audit event `auth_delivery.group_pressure`.
- No member, state, route or answer is removed or changed.

**Authority contract (Stage 2), gate C-13:** the authority OpenAPI encodes `POST challenges` purpose `keylog_pop` (PoP nonce), one `keylog_device_added` challenge per entry (`409 challenge_exists`), one pending `device_added` entry per account, `429 device_add_limit` (5 per account per 24 h), `409 key_in_use`, the `set_id` member on `recovery_codes_set` challenges, the head member `recovery_set`, and the admin commands `seal-key create --role`, `seal-key exposed`.

### Conditions from the revision 3 checks

| Condition | Where it is met | Gate | State |
|---|---|---|---|
| C-1 … C-12 (A2, earlier) | unchanged; C-1 test list now also includes ST-REC-22, ST-REC-23, ST-MFA-11, ST-AUTH-25 | as before | carried |
| C-13 S3-A2-1 | ADR-0033 §4.1, ADR-0023 §4, DF-5, THREAT_MODEL T-REC-10, ST-REC-22 | before the Stage 2 authority contract freezes | design done; A2 document check pending; OpenAPI in Stage 2 |
| C-14 S3-A2-2 | ADR-0022 §5.2 item 6, ADR-0020 §2a, §8, R-20, ST-MFA-11 | Stage 2 contract; ST-MFA-11 before the pilot | design done |
| C-15 R-23 lean mitigations | ADR-0034 §8, §10; L-2; L-14 | before `RECOVERY_REFRESH_PROMPT_ENABLED` or any authority flag in the pilot | design done; drill and container hardening open |
| C-16 R-23 production | ADR-0034 §9 (JWE `RSA-OAEP-256` + `A256GCM`, RSA-HSM, one `decrypt` per envelope); L-13 | before any production authority | **production blocked** until §9 ships or an owner exception is signed |
| C-17 S3-A2-4..-6 | ADR-0032 §1.8; ADR-0031 §4; ADR-0022 §5.2 item 1, ADR-0020 §8 | before Stage 7 | design done |
| C-18 OQ-8 | owner | pilot | open (owner) |
| A3 Stage 4 conditions | S3-A3-01 amended (ADR-0033 §4.1); revocation storage and whole-list refusal (ADR-0033 §3.3); KEY-ROTATION.md with the seal-key incident procedure and lifetime (L-2) | Stage 4 | design done; L-2 open |
| A3 "before Stage 6 starts" | R-23 restated; `seal_kid`; lifetime; production option chosen (§9) | before Stage 6 | design done; A3 delta re-check pending |

### Tracked follow-ups from revision 3.1

| Id | Item | Owner | Stage |
|---|---|---|---|
| L-13 | Implement ADR-0034 §9 (JWE `RSA-OAEP-256` + `A256GCM`, `recovery-seal-rsa` RSA-HSM 3072, Decrypter role, per-challenge decrypt record and reconciliation, iOS and Android OAEP parameters, vectors), or obtain an owner exception countersigned by A2 and A3 (seal-key lifetime ≤ 90 days, review date). **No production authority and no real-customer recovery set until one of the two exists.** Recommended: adopt §9 in lean staging too, after an A3 delta check | A3, A5, A6/A7 | 6 (before production) |
| L-14 | Authority container hardening for C-15: `RLIMIT_CORE` 0, `PR_SET_DUMPABLE` 0, route-list test (no debug endpoints), shell-less runtime image test, no `CAP_SYS_PTRACE`, no exec permission on the authority app (policy check), release-build test refusing staging thumbprints in production builds | A5, A11 | 6 (before any authority flag in the pilot) |
| L-15 | `docs/protocol/vectors/`: `keylog-v1.json` cap cases and filtering-bound vector; `recovery-seal-v1.json` additions of ADR-0034 §7; `auth-destination-v1.json` PoP nonce and window cases; SDK vectors for `session_handle`, `match_tag` and `match_prefix_tag` | A3 with the implementing stage | 2-6 |
| L-16 | UX and platform follow-ups: A9 checks S-DEV-05 for failed and expired adds, S-REC-05 as a required step after an exposure, S-REC-04's support path for people with no device after an invalidation, and S3-A3-06 copy ("set up Face ID / Touch ID to make recovery codes") in FLOW_MATRIX and UX_COPY; A6/A7 confirm the Android `AUTH_BIOMETRIC_STRONG` equivalent for `approvalBiometric` and name the reinstall-surviving revocation store on Android | A9, A6, A7 | 4 |
| L-17 | S3-A2-6 RP integration guide sentence and SDK helper `sessionHandle(for:)`; S3-A2-4 closure task for unconfirmed accounts | A8, A4 | 2-3 |

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
