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
