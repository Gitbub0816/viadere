# Stage 1 response to the four reviews (author revision 2)

| | |
|---|---|
| Author | Stage 1 design author (roles A1, A2-author, A3-author, A5, A10); not a reviewer of this response |
| Date | 2026-11-02 |
| Base | `claude/inspiring-cannon-t5hxfw` at `30b7008`, plus owner decisions 13-15 (`a500fdb`) |
| Reviews answered | `STAGE1_A2_SECURITY_REVIEW.md` (BLOCK), `STAGE1_A3_CRYPTO_REVIEW.md`, `STAGE1_A6A7_PLATFORM_REVIEW.md`, `STAGE1_A9A10_UX_PRIVACY_REVIEW.md` |
| Owner decisions | All of 1-15 kept. Where a fix touched one, it is an owner question (OQ-n, `IMPLEMENTATION_LEDGER.md`), not a change |
| New ADRs | ADR-0031 (tenant destination keys, business-signed destinations), ADR-0032 (authority-minted accounts, account binding, authority-verified recovery), ADR-0033 (authority-built displays, signed device statements, pinned-key rollover) |

No severity was changed by the author. Dispositions: **fixed** (design changed as required), **alternative** (different design, argued at least as strong), **deferred** (Medium/Low only, with owner and stage), **disputed** (for the reviewer to rule). Where two reviews conflicted, the stricter option was taken and the row says so, for the reviewers to confirm.

## A2 (security) — verdict BLOCK

| Finding | Sev. | Disposition | Where |
|---|---|---|---|
| R-07 ruling | — | **Fixed.** A2's required design adopted as normative (items 1-8); revision 1's §27 interpretation withdrawn. Key choice: `device-statement-signing` with `typ viadere-tenant-keys+jws` (A3 to confirm) | ADR-0031; ADR-0021 §3.4-§3.5; TRUST_BOUNDARIES B11/B11b, §8; THREAT_MODEL T-GW-6, T-ML-7, AT-2, §7, R-07'; UX_COPY S-LINK-09 |
| S1-A2-1 | Critical | **Fixed.** Authority mints the account id at genesis (no caller-chosen id); import covers every id incl. keyless (`imported_keyless`, never grant-capable); synchronous genesis; outage-created accounts permanently refused; enrollment complete only after the device verifies its head; ST-AUTH-15 | ADR-0032 §1; ADR-0023 §4; TRUST_BOUNDARIES §4.3, §4.3a, DF-5; THREAT_MODEL T-GW-3, AT-1 1.3.2 |
| S1-A2-2 | Critical | **Fixed.** Authority-verified recovery codes (registered by factor JWS, keyed verifiers, authority attempt limits); legacy-code recovery never grant-capable; S-SEC-01 state; moved before any authority-backed flag; ST-REC-07..09, -11; AT-1 1.3.3 marked [R → C] | ADR-0032 §3; ADR-0023 §4; ADR-0028 §4; THREAT_MODEL T-REC-2, T-GW-14; UX_COPY S-REC-04, S-REC-05, S-SEC-01 |
| S1-A2-3 | High | **Fixed** (R-07 ruling design); §7 row 3 cites ST-ML-10..13 | as R-07 ruling |
| S1-A2-4 | High | **Fixed**, including the optional item 3: authority builds every display; signed `viadere-challenge+jws` verified by the device before the person acts; factor JWS carries `return_url`; device opens only the signed URL after acceptance; ST-LS-07, -08, ST-REC-10; ST-GW-07 rewritten | ADR-0033 §1, §2, §4; ADR-0021 §5; ADR-0023 §3; ADR-0024 §4; TRUST_BOUNDARIES §4.3a |
| S1-A2-5 | High | **Fixed.** Confidential clients only; assertion `aud` = issuer only (stricter than A3's staging allowance); RFC 9207 `iss`; R-17 as named §13 exception; `login_hint` pushes fatigue-counted; ST-OIDC-11..14, -16 | ADR-0024 §2, §4, §6; THREAT_MODEL T-OIDC-11..13, AT-1 1.7, R-17 |
| S1-A2-6 | High | **Fixed.** Budgets limit alerting, not availability; over budget = silent inbox delivery; `429` only per-tenant; ST-MFA-05 rewritten, ST-MFA-10, ST-DLV-09; business throttling guidance; residual R-20 recorded for the business-side trigger rate | ADR-0020 §8; ADR-0022 §5.1-§5.2; THREAT_MODEL T-DO-8, T-MFA-6, AT-6, RT-9; UX_COPY INB-01 |
| S1-A2-7 | Medium | **Fixed.** No displacement before cool-down + in-app no-objection; UNLINK notified in app, churn limited and alerted; spoof indicator mandatory; ST-PH-08, -09 | ADR-0027 §1.3, §1.5; UX_COPY S-PH-07, S-PH-08 |
| S1-A2-8 | Medium | **Fixed.** Field-level trust table; `audience` removed (grant `aud`/`tid` from client record); worker role `Authority.Revocations`; ST-AUTH-17, -18 | TRUST_BOUNDARIES §4.3a, §4.2; ADR-0020 §2; ADR-0019 §4.2; ADR-0028 §9 |
| S1-A2-9 | Medium | **Fixed** with honest staging statement: named reviewers file; agent identity distinct from owner + Prevent self-review (owner action, OQ-3); branch protection + CODEOWNERS; SLSA provenance tied to protected `main`; staging = single owner approval as residual R-21; ST-CI-08 | ADR-0028 §6.4-§6.6; ADR-0019 §5; TRUST_BOUNDARIES B13; THREAT_MODEL T-CP-4, R-21 |
| S1-A2-10 | Medium | **Fixed.** All named tests added; ST-GW-07 and ST-MFA-05 rewritten; ST-AUTH-19 added; ST-MFA-06 counts toward no row; §5/§7 mapping per A2's table | THREAT_MODEL §5, §6, §7 |
| S1-A2-11 | Medium | **Fixed.** Dedup = retry horizon + 300 s from first receipt (≥ 72 h), derived from the Core backoff table; `auth.*`/new `approve.*` v2-only from M0; ST-WH-06 | ADR-0025 §2.4, §3 |
| S1-A2-12 | Low | **Fixed.** R-03 restated; R-07' replaces R-07; R-17, R-18, R-19 added; AT-1 1.3.2/1.3.3 marked open until ADR-0032 ships | THREAT_MODEL §4, §8 |
| S1-A2-13 | Low | **Fixed.** Separate `ACCOUNT_REF_KEY`; request-signing key registration needs passkey step-up + Owner notice | ADR-0032 §4; ADR-0028 §1; ADR-0020 §3 |

## A3 (cryptography) — approve with conditions

| Finding | Sev. | Disposition | Where |
|---|---|---|---|
| S1-A3-01 | High | **Fixed.** Dedicated `authority-publish.yml` + reviewer environment + `id.`-only Cloudflare token (site token loses `id.`); CODEOWNERS; admission only by thumbprint against an attested admin-job inventory; independent read-only monitor; tests renumbered **ST-OIDC-15** and ST-GR-07 because A2 already used ST-OIDC-11..14 | ADR-0024 §7; ADR-0028 §6.5, §8; TRUST_BOUNDARIES §2, B10, §4.2; THREAT_MODEL T-OIDC-2, T-CP-8 |
| S1-A3-02 | High | **Fixed** with option (b) plus A2's authority-verified codes. Option (a) (import api verifiers and a pepper copy) not adopted: it imports possibly api-rewritten code sets on trust and puts `SERVER_PEPPER` in the authority vault. ST-REC-07/-08 cover A3's ST-REC-05 intent (ST-REC-05 id was unused; kept free) | ADR-0032 §3; ADR-0028 §4 |
| S1-A3-03 | High | **Fixed.** Head lists active keys, `env`, `aud`, `kid`; app requires its own key ids and monotonic `seq`; enrollment complete only after head check; App Attest at genesis; import runs once with snapshot digest; synchronous genesis. The race residual A3 asked to state no longer exists for new accounts (authority-minted ids) | ADR-0032 §1; ADR-0033 §2; ADR-0023 §4; THREAT_MODEL T-GW-3, T-REC-3 |
| S1-A3-04 | High | **Fixed.** Step 3a constant-time binding of `accountId` to the signing key's `account_ref` before any `sub`; business id/`tid` from client record; ST-AUTH-05a | ADR-0032 §2; ADR-0023 §3, §5; ADR-0024 §6; ADR-0028 §3 |
| S1-A3-05 | Medium | **Fixed.** Authority `match_failures`, fail at 3, counts toward pause; SDK advisory rule; rejection sampling; ST-AUTH-20 | ADR-0023 §3 step 6; ADR-0022 §2.1, §2.4 |
| S1-A3-06 | Medium | **Fixed** (same design as S1-A2-4) | ADR-0033 §1 |
| S1-A3-07 | Medium | **Fixed.** `v2=<kid>:<mac>`, one `t=`, duplicate `kid` malformed, field charsets, digest compared not copied, vectors; ST-WH-07 | ADR-0025 §1, §2 |
| S1-A3-08 | Medium | **Fixed.** Non-optional `numberMatch` in all three SDKs; refusal vectors | ADR-0022 §3; ADR-0030 §2 |
| S1-A3-09 | Medium | **Fixed.** Exact v2 member set with formats and presence rules; `invalid_match_attempts` kept as advisory 0-3 | ADR-0022 §3 |
| S1-A3-10 | Medium | **Fixed.** Explicit version pin, thumbprint check against published inventory, `nbf`, RSA in `KeyManagementService`; KEY-ROTATION.md written in Stage 6 (deferred doc, owner A3/A11, Stage 6); ST-AUTH-22 | ADR-0028 §2 |
| S1-A3-11 | Medium | **Fixed.** Custom sign-only role; `AUTH-KEY-BACKUP` and `AUTH-SIGNER-ROLE` rules; `VerifiedEvidence` builders + module scan; `AuditEvent` reconciliation; "non-exportable" in lean stated | ADR-0028 §2, §5; ADR-0023 §6; TRUST_BOUNDARIES §4.1, §4.2; THREAT_MODEL T-AUTH-12 |
| S1-A3-12 | Low | **Fixed.** Device keys: SPKI SHA-256 `KeyIdentifier`; authority keys: RFC 7638 | ADR-0023 §2 |
| S1-A3-13 | Low | **Fixed** (`ACCOUNT_REF_KEY`) | ADR-0032 §4 |
| S1-A3-14 | Low | **Fixed.** Exact encoding, no truncation, input normalization, LF refused, vector | ADR-0024 §3, §6 |
| S1-A3-15 | Low | **Fixed**, stricter: `lcl_`/`ocl_` prefixes; assertion `aud` = issuer only (token endpoint URL **not** accepted even in staging, per A2); alg from registered JWK; `iat` required; `jti` single use | ADR-0024 §2, §3, §6 |
| S1-A3-16 | Low | **Fixed** | ADR-0024 §7.5 |
| S1-A3-17 | Low | **Fixed.** Active + standby pinned; `kid` in headers; standby-signed revocation list; residual R-22 for apps that never fetch it | ADR-0033 §3; THREAT_MODEL R-22 |
| S1-A3-18 | Low | **Fixed** (with S1-A2-11) | ADR-0025 §2.4 |
| S1-A3-19 | Low | **Fixed** | ADR-0020 §3 |
| S1-A3-20 | Low | **Fixed.** Hash-chain definition, env in PoP, PoP by new key, thumbprint check, cached head signing | ADR-0033 §4, §5; ADR-0023 §4 |
| S1-A3-21 | Info | **Fixed.** `uv = user_presence` → `amr ["hwk","mfa"]` (no `pin`); `hwk` only for attested keys; A1 confirms in Stage 5. Conflicts with A6/A7 finding 16's "`amr: pin`" note: A3's more conservative reading taken | ADR-0023 §3, §5; ADR-0024 §5 |
| S1-A3-22 | Info | **Fixed.** Not called JCS; vector cases listed | ADR-0023 §2 |

## A6/A7 (platform) — approve with conditions

| Finding | Sev. | Disposition | Where |
|---|---|---|---|
| 1 Deny/Report need unlock | High | **Fixed.** Deny/This wasn't me: no `.authenticationRequired`, no `.foreground`; Review/Open `.foreground`; Android no `setAuthenticationRequired`; Core test ST-MFA-11 | ADR-0022 §5.5; ADR-0021 §4.5; FLOW_MATRIX F1, F7, F9, §4.3; UX_COPY §1 |
| 2 Offline deny mechanism | High | **Fixed** with option (b): claim dropped; one attempt, then local N-09 and inbox; business sees `pending`; Approve never queued (F7/F8 offline cells changed). Option (a) (pre-signed deny valid for the request lifetime) not chosen because it would need a longer signature freshness window than SECURITY §2.3 allows | ADR-0022 §5.6; FLOW_MATRIX F7-F9; UX_COPY N-09, S-MFA-11 |
| 3 Android FCM pipeline | High | **Fixed.** Data-only high priority, render N-01 then update same id, permission priming, HIGH channel, `VISIBILITY_PRIVATE`, OEM fallback and help item; force-stopped and Doze conditions added as FLOW_MATRIX §3a (separate table instead of two more columns) | ADR-0022 §9; ADR-0020 §6.2; FLOW_MATRIX §3a; UX_COPY E-08 |
| 4 PendingIntent rules | High | **Fixed.** Per-action rules, `startActivity(ACTION_VIEW)` only from the foreground activity, CI lint | ADR-0022 §9.3; ADR-0021 §4.3, §4.5 |
| 5 ADR-0027 victim-induced text | Medium-High | **Fixed.** R-13b; SMS-02 states the effect (merged with A10's opt-out wording); per-number verified-link caps; S-PH-01/02 say who it is for | ADR-0027 §1.4, §1.5, §3.1b; THREAT_MODEL AT-5, R-13b; UX_COPY S-PH-01, S-PH-02, SMS-02 |
| 6 Compose sheet | Medium | **Fixed.** `MFMessageComposeViewController` only; RCS/MMS/long-text inbound in Stage 5 test; poll until expiry; `<queries>`/exception fallback; no `SEND_SMS` | ADR-0027 §1.2, §1.3, §1.6; UX_COPY S-PH-06 |
| 7 watchOS routing and copy | Medium | **Fixed** in design; delivery target of mirrored actions marked **verify** for Stage 4 device test (owner A6); watch Report action, phone relay, W-05; N-03 reworded for the wrist; `WatchSync` refusal test | ADR-0022 §8; UX_COPY N-03, W-02, W-05, §11 |
| 8 Wear OS | Low | **Fixed** | ADR-0022 §8 table |
| 9 Lock Screen privacy | Medium | **Fixed.** Rule rewritten; Android `VISIBILITY_PRIVATE` + public version. Interruption level: A6/A7 proposed `timeSensitive` for approvals and payments, A9 (S1-A9-8) required never; **A9's stricter rule taken** (`active` everywhere) — A6/A7 to confirm | UX_COPY §0 rule 5; ADR-0022 §5.5; ADR-0020 §6.2 |
| 10 Live Activities | Medium | **Fixed** (rule + Core test ST-UX-05) | ADR-0022 §5.7 |
| 11 Cold launch / NSE | Low-Medium | **Fixed** (matrix notes; `alert` push type and `mutable-content`; no silent-push dependency); Stage 4 test cases | FLOW_MATRIX §4.4; ADR-0020 §6.2 |
| 12 Universal links, fragment | Low-Medium | **Fixed.** `#vdr_code=` fragment; "no longer used" screen never redeems (ST-ML-14); `open(url:)` never redeems | ADR-0021 §4.4, §5.3; ADR-0033 §4; UX_COPY S-LINK-10 |
| 13 Android App Links, Credential Manager, keys | Medium | **Fixed.** Business guidance on verified App Links; Credential Manager not required for push MFA; API 30 minimum, key attestation, invalidation, Play Integrity | ADR-0022 §9.4; ADR-0030 §2; ADR-0021 §4.3; FLOW_MATRIX §4.5 |
| 14 ADR-0030 packaging; Kotlin review | Low-Medium | Manifest rules and ConnectKit rules **fixed**. Kotlin package review **deferred**: no Kotlin source exists at this commit (owner A7, Stage 4 before the Android merge; ledger L-6) | ADR-0030 §2, Consequences |
| 15 Number entry | Low-Medium | **Fixed** (acceptance list items in design) | ADR-0022 §2.3; FLOW_MATRIX §5; ST-MFA-13 |
| 16 Biometric prompts | Low | **Fixed.** `localizedReason` on the signing context; `uv` vocabulary per S1-A3-21 (no `pin` claim) | UX_COPY S-MFA-04; ADR-0023 §3 |
| 17 Head verification | Low | **Fixed.** Deny/Report never wait for a head check; Android network security config is a Stage 4 item (owner A7) | ADR-0032 §3.4; FLOW_MATRIX §4.12 |
| F13 matrix note (QR in app) | — | **Fixed** | ADR-0024 §4; FLOW_MATRIX F13 |

## A9 (UX writing and behavioral security) — approve with conditions

| Finding | Sev. | Disposition | Where |
|---|---|---|---|
| S1-A9-1 | High | **Fixed** (A9 text; `{date}` removed; rule 4 "no time-based trust claims") | UX_COPY S-PAY-02, S-PAY-02b, §0 rule 4 |
| S1-A9-2 | High | **Fixed** for S-MFA-05, S-PAY-01b, S-MFA-12 and "Approved only after the relay accepted". **Alternative** for S-MFA-11: A6/A7 finding 2 removes queued approvals, so A9's "Saved on this phone. We'll send it …" would describe behavior that no longer exists; S-MFA-11 now says the answer was not sent. At least as strong: nothing is claimed, nothing stale is submitted later. A9 to confirm | UX_COPY S-MFA-05, -11, -12, S-PAY-01b; ADR-0022 §5.6 |
| S1-A9-3 | High | **Fixed** (copy and field behavior) | UX_COPY S-MFA-01, -02, -10, S-PAY-01, S-LINK-03; ADR-0022 §2.3 |
| S1-A9-4 | High | **Fixed.** One vocabulary table; testable equal-prominence definition; Deny first; footer button; explanatory line; no slide-to-approve; notification actions Review/Deny and Open/This wasn't me; F9 locked cell corrected | UX_COPY §0.1, §0.2; ADR-0022 §2.5; FLOW_MATRIX §5; THREAT_MODEL ST-UX-02 |
| S1-A9-5 | High | **Fixed** (A9 replacement texts, plus a variant for "no other trusted device") | UX_COPY S-REC-01..03 |
| S1-A9-6 | Medium | **Fixed**; deviation from Part II recorded for A0 | UX_COPY S-MFA-06, S-PAY-01c, S-MFA-07, §11 |
| S1-A9-7 | Medium | **Fixed** (OIDC-02..05, -07, phone screen OIDC-08, consent list/revoke OIDC-09/-10, display name reviewed and shown with host) | UX_COPY §8; ADR-0024 §3, §4, §8 |
| S1-A9-8 | Medium | **Fixed** (rule rewritten, placeholder, `active` only, Settings option, ST-PRIV-05 extended) | UX_COPY §0 rule 5, §1; ADR-0022 §5.5 |
| S1-A9-9 | Medium | **Fixed** | UX_COPY S-DEV-01 |
| S1-A9-10 | Medium | **Fixed** (S-MFA-08 wording + acknowledgement gate kept; S-MFA-13; WEB-05 non-enumerating) | UX_COPY S-MFA-08, -13, WEB-05; ADR-0022 §5.1 |
| S1-A9-11 | Medium | **Fixed** (host display rules; absolute times) | UX_COPY S-LINK-01, §0 rule 10; ADR-0021 §3.5 |
| S1-A9-12 | Medium | **Fixed** (localization section). Spanish as first locale is a product choice: owner question OQ-6 | UX_COPY §10 |
| S1-A9-13 | Medium | **Fixed** | FLOW_MATRIX §5; UX_COPY §0 rule 10 |
| S1-A9-14 | Low | **Fixed** (C-TOTP-01, W-02, S-LINK-05, N-06 fixed template, E-07, S-PH-06, S-PH-08, S-PH-01 wording) | UX_COPY; ADR-0020 §9 |

## A10 (privacy and compliance) — approve with conditions

| Finding | Sev. | Disposition | Where |
|---|---|---|---|
| S1-A10-1 | High | **Fixed** for the split: E-high / E-routine (30 days) with authority sign-in issuance records, fatigue/pause/report bookkeeping in E-routine; reports carry minimal fields. Device-signed low-risk sign-in JWS stay E-high **because owner ruling O-3 names all approval-result JWS high-value**; moving them is owner question **OQ-1** (not changed by the author) | ADR-0026 §1, §2 |
| S1-A10-2 | High | **Fixed.** Allow-list logging in logger and telemetry initializer; Cloudflare Logpush excludes query strings; `login_hint` optional with documented exposure (PAR/request object deferred, owner A1, Stage 9); ST-PRIV-01 extended | ADR-0026 §3; ADR-0020 §9; ADR-0024 §4.3; THREAT_MODEL T-DO-1 |
| S1-A10-3 | High | **Fixed** per owner decision 13: residency = data at rest in Azure US regions; Azure Policy + `RESIDENCY-US`; processors listed with regions (unknowns marked **verify**); email fallback gated until MailerSend storage is verified US or content storage is off; DATA-INVENTORY updated for retired Fly/Neon/GCP. Cloudflare Data Localization is not required by decision 13 (transit is disclosed) | ADR-0026 §3; ADR-0020 §7; ADR-0028 §5; DATA-INVENTORY header, §2, §3; ADR-0029 §7 |
| S1-A10-4 | High | **Fixed.** Spoof indicator hard fail; MO-linked numbers get only on-ramp text and SMS-04 (OQ-5 informs the owner); SMS-02 rewritten with UNLINK and STOP; trusted-device proof no longer shortens cool-down; counsel item added | ADR-0027 §1.3, §1.4, §2, §3.7; UX_COPY SMS-02 |
| S1-A10-5 | Medium | **Fixed** (keyed hashes, whole-row deletion, provider retention, allow-list, webhook-path enumeration) | ADR-0027 §1.1, §1.6, §3.5; ADR-0026 §2, §3 |
| S1-A10-6 | Medium | **Fixed** (provider settings, suppression/delete path, bounce ids only, TTL ≤ 15 min, sub-processor listing, default off with console warning) | ADR-0020 §7; ADR-0026 §2 |
| S1-A10-7 | Medium | **Fixed** (export by category for every store, privacy-notice statement, consent list/revoke, deletion tests ST-PRIV-06) | ADR-0026 §5; ADR-0024 §8 |
| S1-A10-8 | Medium | **Fixed** (Role column; joint/separate for business-verified decisions left to counsel) | ADR-0026 §2 |
| S1-A10-9 | Medium | **Fixed** (variables P class, digest only in T rows, excluded from audit/webhooks/console, guide) | ADR-0020 §2, §9; ADR-0026 §1, §2 |
| S1-A10-10 | Medium | **Fixed** (key retirement after backup window; restore runbook ST-PRIV-04b; purge migration). Inherited gaps listed with owners: `channel_endpoints`/`rcs_postbacks` purge **deferred** (owner A10, Stage 2); `sms_consent_events` retention **deferred** to counsel (owner A10, before production) | ADR-0026 §3 |
| S1-A10-11 | Low | **Fixed** (authority cross-business view under `security_auditor` controls; sector common-ownership review) | ADR-0026 §4; ADR-0024 §3 |
| §4 counsel list | — | Carried unchanged into the ledger as production prerequisites | IMPLEMENTATION_LEDGER |

## Disputed findings

None. Three inter-review conflicts were resolved toward the stricter option and are flagged for confirmation: interruption level (A6/A7 finding 9 vs S1-A9-8), `private_key_jwt` audience in staging (S1-A3-15 vs S1-A2-5), and the `pin` amr claim (A6/A7 finding 16 vs S1-A3-21). One alternative needs A9's ruling (S-MFA-11, row S1-A9-2).

## Re-review scope

A2 asked to re-review only the deltas: ADR-0020 §2, §8; ADR-0021 §3.4, §5; ADR-0023 §3, §4; ADR-0024 §2, §4, §6, §7; ADR-0031-0033; THREAT_MODEL §3-§8; TRUST_BOUNDARIES §4.3/§4.3a. A3: ADR-0023, 0024 §6-§7, 0025, 0028 §2, §5, §6, 0031-0033. A6/A7: ADR-0021 §4, ADR-0022 §5, §8, §9, ADR-0027 §1, FLOW_MATRIX. A9/A10: UX_COPY, ADR-0026, ADR-0027, DATA-INVENTORY.

---

# Revision 3 (2026-11-02): response to the A2 and A3 re-reviews

| | |
|---|---|
| Reviews answered | `STAGE1_A2_SECURITY_REREVIEW.md` (BLOCK, narrow), `STAGE1_A3_CRYPTO_REREVIEW.md` (APPROVE WITH CONDITIONS), both at `bfa9ff6` |
| Base | `claude/inspiring-cannon-t5hxfw` at `4a84bde` |
| New ADR | **ADR-0034** sealed recovery envelopes (`recovery-seal`, HPKE RFC 9180, suite `DHKEM(P-256, HKDF-SHA256)` 0x0010 / `HKDF-SHA256` 0x0001 / `AES-256-GCM` 0x0002, mode_base) |
| ADRs changed | 0023, 0024, 0028, 0031, 0032, 0033 (main deltas); 0019, 0021, 0022 (small); **0020 and 0027 additive only**; 0025 and 0026 unchanged |
| Owner decisions | None changed. New owner questions OQ-8 to OQ-10, OQ-2 restated (`IMPLEMENTATION_LEDGER.md`) |

No severity was changed by the author. Dispositions as in revision 2.

## A2 re-review

| Finding | Sev. | Disposition | Where |
|---|---|---|---|
| **S2-A2-1** recovery codes and recovery key through the api in clear | Critical | **Fixed** as required, items 1-5. (1) `recovery-seal` HPKE key pair, active + standby, both pinned in the app next to the statement keys; the authority holds only the active private key. Key Vault has no ECDH operation, so the private key is stored wrapped under a non-exportable RSA KEK with an unwrap-only role, reconciled per unwrap (residual R-23 stated). (2) Registration: device-generated codes sealed with `info = "VIADERE-RECOVERY-SET-V1\n{env}"`, `aad = ach‖nonce`; the factor JWS commits to `envelope_digest`; **`approvalBiometric` D1-equivalent key required**; a new set invalidates the previous authority set and the app retires the api's legacy set. (3) Start: `{recovery_id, nonce, code, new_kids}` sealed; every new key's PoP commits to the envelope digest; activation adds exactly `new_kids`; the head's `pending_recoveries[]` carries `kids` and the recovering device checks them. (4) AT-1 1.3.3 stays [R] and the refresh prompt is off until ST-REC-14..16, -21 pass (C-4). (5) ST-REC-14, -15, -16 (plus A3's ST-REC-21). Additionally, a legacy start is refused for accounts that have an authority set | ADR-0034; ADR-0032 §3; ADR-0023 §4; ADR-0028 §1, §2, §5; TRUST_BOUNDARIES §4.1, §4.2, §4.3a, DF-6; THREAT_MODEL T-REC-8, T-GW-14, AT-1 1.3.3, R-23; UX_COPY S-REC-05, -06 |
| **S2-A2-2** passkey assertions accepted for key additions | High | **Fixed** as required, items 1-5: assertions only for `oidc_login` and reduce-only `recovery_cancel`; per-purpose `clientDataJSON.origin` allow-list; `passkey_added` only from the app on the device that created the passkey, by factor JWS; R-17 restated as single-session only; FLOW_MATRIX F10 says how a passkey-only person adds a device; ST-REC-17 | ADR-0023 §3a, §4; ADR-0024 §4; THREAT_MODEL T-REC-9, T-OIDC-11, AT-1 1.3.4, R-17; TRUST_BOUNDARIES §4.3a, DF-4, DF-5; FLOW_MATRIX F10 |
| **S2-A2-3** device add not bound to the device held | High | **Fixed**, items 1-4: B refuses a challenge whose `kids` are not exactly its own and shows a 6-digit code over `env`, nonce and sorted `kids` (derivation and vectors specified); A asks for B's code (typed, into `match`); the authority recomputes it from the stored entry; reported name labelled "Name chosen on the new device"; ST-REC-18. **Clarification for A2:** the required text says A's display "shows the same code"; A **never shows** it (showing it would let the person copy A's own screen); the authority computes the expected value. We read that as A2's intent; please confirm | ADR-0033 §1, §4.1; ADR-0023 §4; TRUST_BOUNDARIES DF-5; THREAT_MODEL T-REC-10, AT-1 1.3.5; UX_COPY S-DEV-03..05 |
| S2-A2-4 enrollment confirmation does not commit to the head | Medium | **Fixed**: factor JWS carries `head_hash` and `seq`; every key of the entry confirms the same head before any becomes grant-capable; imported accounts confirm per device and list other devices (S-SEC-05); "exactly" (enrollment) versus "contains" (steady state) made explicit; ST-AUTH-23 | ADR-0032 §1.4; ADR-0023 §3, §4; ADR-0033 §2; THREAT_MODEL T-REC-12 |
| S2-A2-5 revocation list usable against the standby | Medium | **Fixed**: only the standby signs statement-family revocations and only of the active key; a list naming the standby or signed by the active key is ignored; sticky; routine rotation by app release + `AUTHORITY_MIN_APP_VERSION`; same rules for `recovery-seal` (seal-family lists may name only the active seal key); KEY-ROTATION.md before Stage 4 (C-6); ST-REC-19 | ADR-0033 §3; ADR-0034 §5; ADR-0028 §2; ledger L-2; THREAT_MODEL T-AUTH-17, R-22 |
| S2-A2-6 unauthenticated authorize drives challenges and signing | Medium | **Fixed**: no challenge on page load (a neutral, sign-free client check instead); challenge only after a method is chosen, behind `oidc-authorize-ip`/`-client` edge limits; per-tenant challenge-signing bulkhead separate from heads, tenant records, revocation lists and grants; OIDC-11 page; ST-OIDC-17, ST-AUTH-24 | ADR-0024 §4; ADR-0033 §2; TRUST_BOUNDARIES §4.3, §4.3a, DF-4; THREAT_MODEL T-AUTH-16 |
| S2-A2-7 S-REC-04 promises a forbidden self-service path | Medium | **Fixed**: S-REC-04 rewritten (no "make new codes" path; recover with an earlier authority set or support); ADR-0032 §3.3 states the two paths; ST-REC-20 | UX_COPY S-REC-04; ADR-0032 §3.3; THREAT_MODEL T-REC-11 |
| S2-A2-8 permanently limited accounts | Medium | **Fixed with option (a)** (A2's recommendation): no consumer is created when genesis fails; the app retries (S-SEC-04); L-1 closed; decision 16 wording raised as owner question OQ-8 | ADR-0032 §1.5; ADR-0019 Consequences; UX_COPY S-SEC-03 (retired), S-SEC-04; ledger OQ-8 |
| S2-A2-9 collapse supersedes the victim's prompt | Medium | **Fixed with both of A2's options combined**: supersession only with a matching business `session_handle`; otherwise requests stay open as a group, the typed number selects the request, the rest are cancelled only after an approval; collisions sign nothing (S-MFA-15); Deny/Report answer the group as one count; no lockout lever is created (nothing is refused or cancelled by count). R-20 narrowed to "retry on collision"; ST-MFA-10 extended | ADR-0022 §5.1-§5.2; **ADR-0020 §2, §8 (additive)**; THREAT_MODEL T-DO-8, T-MFA-6, AT-6, R-20; UX_COPY S-MFA-14, -15; FLOW_MATRIX F7 |
| S2-A2-10 verification failures reported as denials | Medium | **Fixed**: integrity class (`destination_mismatch`, sent on the wire as the existing `destination_unverified`, high-priority alert) versus availability class (`destination_unverifiable`: no server call, item stays open, retry; clock-skew copy); neither counts toward the pause; T-AUTH-8 and F1/F2 state the tenant-record dependency; tenant-key hardening (13-month `not_after`, admin-job revocation without the api, automatic host removal on a failed weekly re-check); ST-ML-15. The wire value was kept so that Stage 2-3 code is unaffected | ADR-0031 §1, §4; **ADR-0020 §1, §5 (additive)**; ADR-0022 §5.4; ADR-0021 §2; THREAT_MODEL T-ML-10, T-AUTH-8; FLOW_MATRIX F1/F2; UX_COPY S-LINK-11, -12 |
| S2-A2-11.1 "two reviewers" leftovers | Low | **Fixed** | THREAT_MODEL T-GW-5, T-AUTH-7 |
| S2-A2-11.2 "at most" vs "at least" refresh | Low | **Fixed**: a cached statement is re-signed when older than 5 min at serving time | ADR-0033 §2; ADR-0031 §2 |
| S2-A2-11.3 `amr` for unattested keys | Low | **Fixed**: `swk` replaces `hwk` (`["swk","mfa"]` / `["swk","user","mfa"]`) | ADR-0023 §5; ADR-0024 §5 |
| S2-A2-11.4 `account_ref` checks on device add | Low | **Fixed**: approving device checks the challenge's `account_ref`; authority checks the approving key's account; in ST-REC-10 | ADR-0033 §2, §4.1; ADR-0023 §4 |
| S2-A2-11.5 remove R-07' with a subject statement | Low (optional) | **Deferred** (optional by A2): ledger L-10, owner A2, Stage 5; `sub` kept in the destination statement for it | ADR-0031 §3, §7; ledger L-10 |
| S1-A2-2 remainder | Critical | Closed by S2-A2-1 and S2-A2-7 above | as above |
| S1-A2-6 remainder | High | Closed by S2-A2-9 above | as above |
| S1-A2-7 note (dormant owner) | — | **Written down**: the transfer waits indefinitely while the existing account never fetches the notice (no behavior change) | **ADR-0027 §1.3 (one sentence)** |
| S1-A2-8 remainder (missing §4.3a rows) | — | **Fixed**: rows for new-device name, recovery codes, recovery start keys, recovery id, enrollment `head_hash`, comparison code, WebAuthn purposes, OIDC challenge creation, `tenant-keys` path parameter, delivery id | TRUST_BOUNDARIES §4.3a |
| S1-A2-12 remainder | — | R-17 narrowed; AT-1 1.3.3 stays [R] until ADR-0034 ships | THREAT_MODEL AT-1, R-17 |
| §5 ruling 1 option (`timeSensitive` for security-change notices) | — | **Not adopted** (optional): `active` stays the only level; revisit with A6/A9 in Stage 4 together with ST-PRIV-05 | — |
| Conditions C-1 … C-12 | — | **Accepted** and reflected: C-1 test list now includes ST-AUTH-23, ST-REC-14..21 (THREAT_MODEL §6); C-3 in ADR-0032 §1.5; C-4 in ADR-0032 §3.5 and UX_COPY S-REC-05; C-6 in ADR-0033 §3.8 and ledger L-2; C-9 (no plaintext recovery code member) is satisfied by design (ADR-0034); C-10 in ADR-0024 §4; C-12 in UX_COPY status. C-2, C-5, C-7, C-8, C-11 unchanged and still binding | as listed |

## A3 re-review

| Finding | Sev. | Disposition | Where |
|---|---|---|---|
| **S1-A3-R01** codes visible to the api, same set the api hashes, start not bound | High | **Fixed** (same design as S2-A2-1): item 1 separate set generated on the device, api holds no hash, legacy set retired; item 2 HPKE (the option A3 named first, ADR-0007 construction) with purpose `info`, challenge `aad`, `account_ref`, set id and nonce inside, digest committed by the factor JWS; item 3 code sealed with every new key's `kid`, PoP over `VIADERE-KEYLOG-V1\n{env}\nrecovery_started\n{kid}\n{nonce}\n{envelope_digest}`; item 4 CSPRNG, 50 bits, Crockford normalization stated, keyed HMAC verifier with lookup by value and CAS in the attempt transaction; item 5 ST-REC-14, ST-REC-21 (A3's ST-REC-15 is numbered ST-REC-21 because A2 used ST-REC-15); item 6 not needed (no owner exception requested). RSA-OAEP-256 alternative not taken: HPKE reuses one Core implementation on both sides; the custody gap it would close is stated as R-23 and tracked (L-12) | ADR-0034; ADR-0032 §3; TRUST_BOUNDARIES §4.3a; THREAT_MODEL T-REC-2, T-REC-8, T-GW-14, T-AUTH-15, R-23 |
| **S1-A3-R02** revocation statement and authority undefined | Medium | **Fixed** with every listed item: payload defined (with `key_family`); index roles; only the standby revokes, only the active key; sticky, no expiry; standby-only after revocation; standby as a separate key object without a role until a reviewer-gated grant; loss-of-both and routine rotation stated; app-pinned reference set for the startup check; ST-REC-13 extended, ST-REC-19, vectors | ADR-0033 §2, §3; ADR-0023 §1; ADR-0028 §1, §2, §5; THREAT_MODEL T-AUTH-17, R-22 |
| **S1-A3-R03** tenant keys without PoP or domain binding | Medium | **Fixed**: `viadere-destination-key-registration+jws` PoP with admin-job nonce; thumbprint in DNS TXT `_viadere-destkey.<host>` or the well-known file, fetched by the reviewer-gated workflow (the authority job keeps its egress deny) and re-checked by the job; `not_after` ≤ 13 months; P-256 only, both S forms accepted; ST-AUTH-16 extended | ADR-0031 §1, §6; ADR-0023 §1; THREAT_MODEL T-ML-9, AT-1 1.8 |
| S1-A3-R04 destination statement details | Low | **Fixed**: items 1 (`url_sha256` encoding), 2 (check 4 is against api data; in R-07'), 4 (third `kid` definition), 5 (tenant record `seq`, replay window stated), 6 (exact members, ≤ 4096 bytes). Item 3 (`sub`): kept and marked unchecked; subject statement **deferred** (L-10) | ADR-0031 §2-§4, §7; ADR-0023 §2; THREAT_MODEL R-07' |
| S1-A3-R05 device statement checks and cadence | Low | **Fixed**: `iss` and `env` in every check; `kid_header` removed; re-sign rule at serving time; `reported_name`; `enrollment_confirmed` (and `recovery_started`) display rows | ADR-0033 §1, §2 |
| S1-A3-R06 encodings and loose ends | Low | **Fixed**: `account_ref` truncation stated; normalization (ADR-0034 §2); `swk` for unattested keys; builders emit RFC 7638 `kid`s, agreement vector; key-inventory channel named (job log → read-only Log Analytics → attested inventory, bound to `name/version`) | ADR-0032 §1.1; ADR-0034 §2; ADR-0023 §2, §5; ADR-0024 §7.3; TRUST_BOUNDARIES §4.2 |
| S1-A3-R07 one key, several `typ`s | Info | **Adopted**: one Core verifier with non-optional expected `typ`, exact member set, cross-`typ` vector over all four statement types (challenge, head, tenant record, revocation list) | ADR-0033 §2 |
| S1-A3-R08 monitor scope | Info | **Adopted**: discovery fields compared, unreachable documents alert, dead-man check | ADR-0024 §7.4 |
| S1-A3-02 remainder | High | Closed by S1-A3-R01 | as above |
| S1-A3-17 remainder | Low | Closed by S1-A3-R02 | as above |
| S1-A3-10 note (app-pinned set) | — | **Fixed** | ADR-0028 §2 |
| S1-A3-12 note (third `kid`, SPKI vs RFC 7638 in builders) | — | **Fixed** | ADR-0023 §2 |
| S1-A3-06 note (device name) | — | **Fixed** (`reported_name`) | ADR-0033 §1 |
| Ruling on `amr` (`user` optional on the `user_presence` row) | — | Left to A1 in Stage 5 as A3 allows; `face`/`fpt` never emitted (stated) | ADR-0023 §5 |
| A3 conditions (Stages 2-6) | — | **Accepted**. Low/Info vectors tracked as ledger L-11; Key Vault key-agreement re-check as L-12 | ledger |

## Disputes and clarifications

No finding is disputed. One clarification is flagged for A2 (S2-A2-3: the existing device never displays the comparison code). One reviewer option was not taken, with reasons (S1-A3-R01: HPKE rather than RSA-OAEP-256; the gap is R-23).

## Changes to ADRs that Stages 2-3 code against

- **ADR-0020 (additive):** §2 new optional create member `session_handle` (also on `auth-approvals`); §8 supersession only when both requests carry the same `session_handle`; §1/§5 a `deny` with `reason: destination_unverified` is sent only for integrity failures and is not counted toward fatigue. No member, state or route removed.
- **ADR-0027:** one clarifying sentence in §1.3 (dormant owner), no behavior change.
- **ADR-0025, ADR-0026:** unchanged.

## Revision 3 re-review scope

A2: ADR-0032 §1.4, §1.5, §3; ADR-0034; ADR-0023 §3a, §4; ADR-0033 §1, §2, §3, §4.1; ADR-0022 §5.1-§5.2, §5.4; ADR-0024 §4; ADR-0031 §1, §4; ADR-0020 §2, §5, §8 deltas; TRUST_BOUNDARIES §4.3a, DF-5, DF-6; THREAT_MODEL T-REC-8..12, T-AUTH-15..17, T-ML-9/-10, AT-1, AT-6, §6 new tests, R-17, R-20, R-22, R-23. A3: ADR-0034; ADR-0032 §1.1, §3; ADR-0033 §2, §3, §4.1 (code derivation); ADR-0031 §1-§3; ADR-0023 §1, §2, §5; ADR-0028 §1, §2, §5; ADR-0024 §7.3. A9: UX_COPY revision 3 strings (C-12).
