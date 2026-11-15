# Stage 1 review request (threat model, trust boundaries, ADRs, UX copy, flow matrix)

| | |
|---|---|
| Spec | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §15.1 (one author, at least one different specialist reviewer; cryptography, recovery, token issuance and grant authorization need A2 **and** A3), §24 Stage 1 exit gate ("threat model, trust boundaries, ADRs signed by reviewers") |
| Author | Stage 1 author acting as A1, A2, A3, A5, A10. **The author may not approve.** A2 and A3 reviewers must be different agents from the author. |
| Date | 2026-11-02 |
| How to record a review | Append a section "Review by <role>, <date>" to this file (or a sibling `STAGE1_REVIEW_<role>.md`) with: verdict (approve / approve with changes / block), findings with ids `S1-<role>-<n>`, severity, and the exact file and section. A0 links the result in `IMPLEMENTATION_LEDGER.md`. |

## Artifacts under review

| Artifact | Path |
|---|---|
| Threat model | `docs/architecture/THREAT_MODEL.md` |
| Trust boundaries | `docs/architecture/TRUST_BOUNDARIES.md` |
| ADR-0019 implementation strategy (spec "ADR-0001") | `docs/ops/adr/0019-auth-delivery-implementation-strategy.md` |
| ADR-0020 API and state machine | `docs/ops/adr/0020-auth-delivery-api-and-state-machine.md` |
| ADR-0021 magic links and link service | `docs/ops/adr/0021-magic-links-and-link-service.md` |
| ADR-0022 push MFA | `docs/ops/adr/0022-push-mfa-number-matching.md` |
| ADR-0023 factor assertions, key log, grants | `docs/ops/adr/0023-signed-factor-assertions-and-grants.md` |
| ADR-0024 OIDC provider (staging) | `docs/ops/adr/0024-oidc-provider-staging.md` |
| ADR-0025 webhook signature v2 | `docs/ops/adr/0025-webhook-signature-v2.md` |
| ADR-0026 retention and classification | `docs/ops/adr/0026-retention-and-data-classification.md` |
| ADR-0027 phone ownership without SMS auth | `docs/ops/adr/0027-phone-ownership-without-sms-auth.md` |
| ADR-0028 key custody and CI split | `docs/ops/adr/0028-key-custody-migration-and-ci-identity-split.md` |
| ADR-0029 retire Fly/GCP/Neon | `docs/ops/adr/0029-retire-fly-gcp-neon.md` |
| ADR-0030 SDK packaging | `docs/ops/adr/0030-sdk-packaging-and-versioning.md` |
| UX copy | `docs/product/UX_COPY.md` |
| Flow matrix | `docs/product/FLOW_MATRIX.md` |
| CLAUDE.md exception row (api-held keys) | `CLAUDE.md`, exceptions table |
| ADR index | `docs/ops/adr/README.md` |

## Decisions the author made that need explicit acceptance or rejection

1. **R-07 / stop-ship interpretation** (ADR-0021 §3.4): under gateway compromise the api can rewrite a business-supplied URL; the pilot treats §27 "verified domain bypass" as "without compromising the api". A2 must accept or block until business-signed destinations ship.
2. **Watch is never an authenticator** (ADR-0022 §8): stricter than spec §8 permits.
3. **RS256 alongside ES256** for id_tokens (ADR-0024 §2): OIDC Discovery requires RS256.
4. **Business API paths** under `/v1/business/…` instead of the spec's illustrative `/v1/auth-deliveries`; no new `POST /v1/devices/link` (ADR-0020 §1).
5. **RFC 9421 request signatures required for live keys** on auth routes (ADR-0020 §3).
6. **Push MFA stays business-verified** (device pairwise JWS); the authority does not countersign MFA results (ADR-0022 §1, ADR-0023 §1). The authority signs only link-service grants, OIDC tokens and key-log heads.
7. **Authority key log** as the independent source of device/passkey keys, with a one-time trusted import of existing keys (R-16) (ADR-0023 §4).
8. **Legacy interaction approvals frozen** for the pilot (ADR-0022 §7).
9. **No SSO session and no refresh tokens** at the staging OP (ADR-0024 §4, §2).
10. **Phone ownership by customer-originated nonce** (`phone_control_mo`, never a factor); SMS OTP and `/l/`, `/h/` links removed (ADR-0027).

## A2 — security (threat model owner role; reviews A1, A3, A5 work)

- [ ] Every attacker assumption of spec §4.2 appears in THREAT_MODEL §2 with a "must still hold" statement and tests; none is weakened.
- [ ] Every §26 red-team scenario maps to a control and at least one test in THREAT_MODEL §5/§6; check that each cited test would **fail if its control were removed**.
- [ ] Attack tree AT-1: no leaf leads to a valid grant/id_token from AS-1 alone; verify the monotone api rule (TRUST_BOUNDARIES §5) against every authority route in §4.3.
- [ ] T-GW-3/T-GW-4: the key log and authority-computed `sub` close the "insert key" and "remap subject" paths; look for any other api-controlled input the authority trusts (display object, tenant id, return URL, `login_hint`).
- [ ] Decision list items 1, 5, 6, 7, 8 above.
- [ ] Residual risks R-01 to R-16: each is real, owned, and not hiding a stop-ship condition (§27 table in THREAT_MODEL §7).
- [ ] ADR-0021 destination validator rules (§3) against an open-redirect and host-confusion corpus; the 24 h hold and notices for new hosts.
- [ ] ADR-0022 fatigue limits: no attacker-controlled indefinite lockout; collapse semantics.
- [ ] ADR-0027 spoofing analysis and the `UNLINK` path; that `phone_control_mo` cannot reach any assurance decision.
- [ ] ADR-0028 CI split: confirm no single identity can deploy both tiers or assign the authority identity; check `job_workflow_ref` subject pinning is achievable.

## A3 — cryptography and key management (required together with A2 for ADR-0023, ADR-0024, ADR-0025, ADR-0028)

- [ ] JOSE profile (ADR-0023 §2): header allow-list, `alg` per `typ`, explicit typing, RFC 7638 `kid`, canonical JSON, low-S; compare against RFC 7515/7519/8725.
- [ ] Factor JWS verification order (ADR-0023 §3): challenge consumed after all checks; constant-time comparisons; skew bounds; `display_digest` domain separation string.
- [ ] Key-log proofs (ADR-0023 §4): genesis cannot be replayed onto an existing account; `account_ref` derivation and use of `OIDC_PAIRWISE_KEY` for two purposes (domain-separated) — accept or require a separate key.
- [ ] Grant claims (ADR-0023 §5) and OIDC tokens (ADR-0024 §6): lifetimes, `jti` replay, pairwise `sub` derivation and truncation, `cch` binding.
- [ ] `ApprovalResult` v2 (ADR-0022 §3): additive version, `match` and `match_digits` in the digest; verifier behavior for v1 vs v2.
- [ ] Webhook v2 MAC construction (ADR-0025 §1): string-to-sign ambiguity (field separators, host normalization), dual-sign migration.
- [ ] Key custody (ADR-0028 §1-§4): every key has owner, use restriction, rotation, revocation, emergency rollover, backup; `SUBJECT_REF_KEY` copy reasoning; `kd-log-signing` verify-before-sign plan; Key Vault key types (Ed25519 absence claim in ADR-0024 §2).
- [ ] F-23: new formats compose only standard primitives; no bespoke cryptography.

## A6 / A7 — platform feasibility (iOS/watchOS; Android/Wear OS)

- [ ] FLOW_MATRIX every cell for iOS, watchOS, Android: feasible with public APIs (UserNotifications categories and actions, notification response on cold launch, `UIApplication.open` and universal links, `MFMessageComposeViewController`; FCM, immutable `PendingIntent`, App Links, `ACTION_SENDTO`, Keystore `setUserAuthenticationParameters`, StrongBox).
- [ ] Number entry UX on the approval screen; same-device app switching (S-MFA-10); Approve always foreground (F-14), category registration and request id in payload (F-15).
- [ ] Confirm-before-open (ADR-0021 §4) and the `/h/` fix (F-08).
- [ ] Watch tier (ADR-0022 §8) and its copy (UX_COPY §7).
- [ ] Key-log head verification in the app (ADR-0023 §4): pinned keys build setting, 15-minute freshness on real networks.
- [ ] ADR-0030 packaging: SwiftPM mirror approach; Android artifact split; review of the unmerged Kotlin package against ADR-0030 (A7).

## A9 — UX writing and behavioral security

- [ ] UX_COPY rules §0 and every string: plain, no urgency, business attribution, no success claims, Lock Screen minimal disclosure, consistency with existing app wording.
- [ ] Equal prominence of Deny vs Approve/Continue (ADR-0022 §2.5, UX_COPY §3); "This wasn't me" placement.
- [ ] Spec §7 vs §20 differences resolved toward §20; the §7 SMS fallback string removed (decisions 1, 9).
- [ ] Recovery downgrade and trade-off statements (S-REC-01, S-REC-03) match actual behavior (SECURITY §2.26).
- [ ] OIDC consent and QR instructions (OIDC-04, OIDC-05) resist QR phishing as far as copy can.
- [ ] Accessibility notes in FLOW_MATRIX §5.

## A10 — privacy

- [ ] ADR-0026 classification of every store, the 30-day alignment (decisions 7, 10), and the O-3 evidence classification; backups and provider retention disclosed.
- [ ] Evidence access restriction (`security_auditor`, step-up, reason, audit) and DB column privileges (ADR-0026 §4).
- [ ] Email-fallback address handling (ADR-0020 §7): purpose limitation, deletion after send, sub-processor listing.
- [ ] Phone-number processing in ADR-0027 (MO messages, MT notice, `UNLINK`), enumeration resistance.
- [ ] Pairwise identifiers: OIDC `sub` per sector; grant `sub` = existing per-tenant `subject_ref`; no cross-tenant correlation introduced.
- [ ] Push payload minimization (ADR-0020 §6) and F-20 thread id.

## A5 — cloud/network (peer review of the author's A5 work by a different A5 agent, or by A4 per §15 table "A4 reviews A3/A5 deployment boundaries")

- [ ] TRUST_BOUNDARIES §9: `snet-auth` sizing/overlap, internal environment DNS, NSG outbound tag list (validate against Microsoft's documented requirements before enabling deny), ACR Basic reachability by service tag, cost.
- [ ] Entra application + app role approach for B5; token validation details.
- [ ] Policy-check rules in ADR-0028 §5 are implementable in `policy_check.py`.
- [ ] ADR-0029 state handling for `Infra/terraform` and the Cloudflare root move.

## A4 — backend (contract feasibility; reviews integration contracts)

- [ ] ADR-0020 state machine transitions, CAS, outbox messages, idempotency, rate-limit namespaces; collapse/supersede semantics with Approve v2 counters.
- [ ] Authority synchronous calls from enrollment (ADR-0023 consequences) and outbox retry.

## Owner (for information; open questions, not blocking Stage 1 review)

- **O-4** GHCR package visibility (drops the personal PAT for the ordinary tier).
- **O-5** Whether Fly apps, Neon and GCP resources exist in live accounts (ADR-0029 §5 decommission steps).
- **O-2** (narrowed) carrier behavior for customer-originated texts to the staging number (ADR-0027 §3.4).
- New: acceptance of the E-class periods by privacy/legal before production (ADR-0026 §1).
