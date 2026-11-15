# Stage 1 review by A2 (application security / threat model), 2026-11-02

| | |
|---|---|
| Reviewer role | A2, independent of the Stage 1 author (did not write any reviewed artifact) |
| Request | `docs/reviews/STAGE1_REVIEW_REQUEST.md` (A2 checklist and decision list) |
| Baseline | `claude/inspiring-cannon-t5hxfw` at `0fab4ce` |
| Read | Spec v2 §4, §5, §6.4, §9.3, §10, §13, §18, §19, §22, §23, §26, §27, Part II; `AUTH-OWNER-DECISIONS.md` (binding); `THREAT_MODEL.md`; `TRUST_BOUNDARIES.md`; ADR-0019 to ADR-0030; `FLOW_MATRIX.md`; CLAUDE.md exception row for decision 12 |
| Code checked | `Server/.../Services/PhoneLinkService.swift` (`makeVerified`), `Services/RecoveryService.swift`, `Packages/ViadereCore/.../API/RecoveryDTOs.swift`, `APIRoutes.swift` (recovery routes), `Policy/SubjectRefs.swift`, `Services/WebhookService.swift` (retry table), `BusinessSDK/ApprovalVerifier.swift` (replay guard), `App.swift` (`EdgeLockMiddleware`), `Infra/azure/locals.tf`; `docs/SECURITY.md` §2.30, §2.51-§2.59 |

## Verdict: **BLOCK**

The design is careful and most of it holds: monotone api rule, no raw-sign route, keys only in `kv-vdr-auth`, authority-computed `sub`, business-verified push MFA, static JWKS, separate deploy identity. But two paths let a compromised api (AS-1) obtain a valid link-service grant or id_token for a victim **without the victim's authenticator** (S1-A2-1, S1-A2-2). That is spec §27 stop-ship 1 ("any single ordinary public service can independently issue a successful authentication grant"), and it breaks the §13 formal metric. In both cases the authority trusts evidence that the api supplies and the authority does not verify itself. In addition I **do not accept** the R-07 interpretation (ruling below). Findings S1-A2-4, -5 and -6 are High and must also be fixed before the Stage 1 exit gate.

Stage 1 can be re-reviewed against the deltas only, once ADR-0020, -0021, -0023, -0024, THREAT_MODEL (§3, §4, §5, §6, §7, §8) and TRUST_BOUNDARIES §4.3 carry the required changes. A2 does not need to re-read the unchanged parts.

## R-07 ruling: author's reading rejected; design change required before the pilot

**Ruling.** I do not accept the reading that §27 "a verified business domain can be bypassed" applies only to "a tenant or external attacker without compromising the api". Three reasons:

1. §26 states the scenario without that qualifier: "Swap business destination domain or follow open redirects: **blocked** before magic-link handoff". §4.3 says one compromised ordinary workload must not defeat the invariants, and §4.2 lists gateway compromise as the first attacker assumption. Showing the true host only lets the person *notice*; it does not *block*. A phishing host that looks plausible (for example `signin-example.co` for `example.com`) gets through.
2. The impact is account takeover at the business. The URL is a bearer sign-in token, and a rewrite can (a) send the real token to an attacker host, or (b) send the person to a credential-phishing page. Both are what §27 is meant to stop.
3. The mitigation the author proposed ("Phase B `destination_signature` … with a directory key") is not sufficient as written. Key-directory tree heads are signed by `kd-log-signing`, and the api holds that key (decision 12 exception; ADR-0028 §1 moves it only "after the pilot"). Under AS-1 the api can sign a complete fabricated log for a device that has no pinned head yet (a fresh install), and that log can carry a fake root for the business (SECURITY §2.58 residuals 1 and 10).

**Required design (normative for ADR-0021 §3.4; replaces "Phase B"; must ship before any `link_mode: "business"` delivery in the pilot):**

1. **Authority-attested tenant destination keys.** A tenant that uses business-mode magic links registers one or more P-256 public keys with purpose `auth-destination-signing`. They go into a new authority table `authority_tenant_keys {tenant_id, kid (RFC 7638), public_key, purpose, allowed_hosts[], display_name, status, not_after}` **through the authority admin job only** (adding a key or a host increases authority, so it follows the ADR-0019 §5 path with reviewed change file and reviewers). The api may call `revocations` for these keys (reduce-only), and nothing else. `allowed_hosts` is copied from the tenant's verified `auth_links` hosts at registration, and the reviewer checks the domain-control evidence.
2. **Signed tenant record for devices.** The authority signs `viadere-tenant-keys+jws` (new `typ`, ES256, the JOSE profile of ADR-0023 §2). Key: `keylog-signing` with this distinct `typ`, or a dedicated `tenant-keys-signing` key (A3 to choose). Payload: `{v, iss, tenant_id, display_name, allowed_hosts[], keys[{kid, public_key, not_after}], issued_at}`. The device fetches it through the api and verifies it against the authority keys already pinned in the app (`VIADERE_AUTHORITY_KEYLOG_KEYS`). It refuses a record older than 15 minutes, the same freshness rule as key-log heads, so a revocation reaches devices within 15 minutes.
3. **Business-signed destination statement.** On create, the business sends `destination.signature`, a compact JWS with `typ: viadere-destination+jws`, header `alg, kid, typ` only, ES256. Canonical payload:
   `{v:1, iss:<tenant id>, aud:"urn:viadere:device", sub:<subject_ref>, brq:<the create request's request_id>, purpose:<sign_in|step_up|verify_contact>, url_sha256:<base64url SHA-256 of the exact URL bytes>, host:<lowercase A-label host>, iat, exp, jti}`
   with `exp − iat ≤ 600`, `exp ≤ expires_at` of the delivery and `jti` of 128 random bits. The statement carries a digest of the URL, not the URL itself, so it is not a bearer value and may be stored as class T.
4. **Device verification before Continue is enabled.** On the link screen the app verifies all of the following:
   - the signature, with a key from the authority-signed record of the tenant that the delivery names;
   - `typ`, `aud` and `iss`;
   - `brq` and `purpose` against the display object;
   - `exp` against the device clock with ±60 s skew;
   - `host ∈ allowed_hosts` from the authority record;
   - that `jti` has not been seen before. The device keeps seen `jti` values until `exp` plus skew.

   The **business name and host on the link screen come from the authority record and the signed statement**, never from the api's display fields. After `open`, the device computes SHA-256 of the exact URL it received and requires it to equal `url_sha256`. It also requires the parsed host to equal `host`, and it re-runs `AuthDestinationValidator`. Only then does it call the system open API. Any failure means the URL is not opened. The device shows "We couldn't confirm this link came from {authority display_name}" (new UX_COPY string, A9) and sends `POST …/deny` with reason `destination_unverified`, which is audited and alerted.
5. **Fail closed in the pilot.** Set `AUTH_DESTINATION_SIGNATURE_REQUIRED=true`, with no off switch in staging pilot configuration. If a tenant has no registered destination key, business-mode create returns `422 destination_signature_required`. The tenant can use the link service instead, once S1-A2-4 is fixed.
6. **SDKs.** Swift, TypeScript and Kotlin backend SDKs gain `signAuthDestination(url, …)`. Vectors go in `docs/protocol/vectors/auth-destination-v1.json`.
7. **Stated residual.** The api still sees the URL during its minutes-long life (R-01, unchanged). Under AS-1 it can also deliver a *genuine* signed URL that the business issued for the attacker's own account to the victim's device (login-CSRF style, the victim lands in the attacker's account). `sub` binding narrows this only to the degree that the device knows its own `subject_ref` from a source other than the api. Record it as R-07' (Low, A2). This replaces R-07.
8. **Tests (Stage 7, all A/K/S/V):**
   - ST-ML-10: AS-1 rewrites any byte of the stored URL after create, and the device refuses to open it.
   - ST-ML-11: the device refuses each of these: a missing signature; a key not in the authority record; a key revoked within the last 15 minutes; an expired statement; a statement older than its `iat` window; a wrong `brq` or `purpose`; a replayed `jti`; a host not in `allowed_hosts`.
   - ST-ML-12: the device refuses an api-fabricated `viadere-tenant-keys+jws` signed by any key other than the pinned authority key, and refuses a stale one (> 15 min).
   - ST-ML-13: create without a signature gets `422` while the flag is on.
   - ST-AUTH-16: the api's identity cannot add an `authority_tenant_keys` row (no route; `404`).

   Each of these tests fails if its control is removed.

The orchestrator's alternative, "links are issued only via the authority-signed link service", also satisfies §27, but only after S1-A2-4. It conflicts with decision 2 ("both … business-supplied URLs (default)"), so the signed-destination design above is the one that keeps decision 2 intact.

## Findings

Severity: **Critical** = stop-ship path (§27) open in the design; **High** = §26/§4.3 requirement not met or materially overstated; **Medium** = must be fixed before the pilot gate; **Low** = fix or record before Stage 7.

### S1-A2-1 — Critical — `genesis` lets the api choose which account a new key belongs to

- **Location:** ADR-0023 §4 (entry table, `genesis` row: "refused if the authority has ever seen the account … a forged genesis only creates an attacker's own account"); TRUST_BOUNDARIES §4.3 `POST keylog/entries`; THREAT_MODEL AT-1 1.3.2 (marked [C]); consequences paragraph of ADR-0023 (append "retried by the outbox").
- **Issue:** The authority receives the consumer id from the api and derives `account_ref = HMAC(OIDC_PAIRWISE_KEY, accountId)`. It has no independent knowledge of which consumer ids already exist. An AS-1 attacker posts a `genesis` with its own device keys and a **victim's** consumer id. This works for any account the authority has not yet seen:
  - accounts created after the R-16 import snapshot and before cutover;
  - accounts whose genesis is still in outbox retry because the authority was down at enrollment (ADR-0023 consequences explicitly allow this);
  - existing accounts that have no keys and so were not imported.

  The attacker's key then signs factor evidence. The grant `sub` is computed from that consumer id with `SUBJECT_REF_KEY`, which yields the victim's `subject_ref` at every tenant, and the OIDC pairwise `sub` is the victim's as well. The attacker gets a valid login for the victim with no authenticator of the victim's. The statement "a forged genesis only creates an attacker's own account" is false. ST-GW-03 does not cover this path.
- **Required change:**
  1. The authority **allocates** the account identity at genesis. Either it returns the new consumer id (UUIDv4 from its own CSPRNG) and the api must create the consumer row with it, or it records which consumer id it minted for each `account_ref`. `genesis` takes no caller-chosen consumer id. Any request that names a consumer id the authority neither minted nor imported is refused.
  2. The one-time import (R-16) covers **every** consumer id that exists at cutover, keyless ones included (`imported_keyless`, never grant-capable until an authority-verified recovery or enrollment). From cutover, account creation in the api calls authority genesis synchronously. If the authority is unavailable, the account is created with no grant capability **permanently**: it can use messaging and business-verified approvals, but no later genesis for that id is accepted. Any later path to grant capability needs authority-verified evidence.
  3. ADR-0023 §4: replace the `genesis` text and add an explicit statement of where the authority gets the account binding it trusts.
  4. Tests:
     - ST-AUTH-15: genesis naming an existing (imported) consumer id → refused;
     - ST-AUTH-15: genesis naming an id the authority did not mint → refused;
     - ST-AUTH-15: an account created during a simulated authority outage never yields a grant, even after the outbox retries;
     - ST-AUTH-15: concurrent api-forged genesis versus the real enrollment → the forged one has no effect.

### S1-A2-2 — Critical — recovery start is an api statement, so AS-1 takes over any dormant account after 72 h

- **Location:** ADR-0023 §4 (`recovery_started`: "the api's statement"; `recovery_activated`: "adds the recovery passkey, revokes all earlier keys"); ADR-0028 §4 (authority-verified codes only in Stage 6 and only for newly generated sets; "existing code sets stay api-verified until the person regenerates them"); THREAT_MODEL T-REC-2, AT-1 1.3.3 (marked [C]), R-02; spec §4.3 invariant 5, §13, §23, §27.
- **Verified:** recovery codes are verified only in the api (`RecoveryService`, `POST /v1/recovery/begin` public, `RecoveryPolicy.holdSeconds = 72 h`). Under AS-1 the api can also write a new code set for any account.
- **Issue:** AS-1 posts `recovery_started` for a victim, suppresses every push (R-02), and waits 72 h. If the victim does not open the app in that time, `recovery_activated` installs the attacker's passkey as grant-capable and revokes the victim's keys. The only control left is "the victim opens the app within 72 h and sees the key-log head". That is detection that depends on user behavior, not a cryptographic control, and many accounts are dormant for three days. AS-1 can also keep relaying a stale or missing head. The app "refuses heads older than 15 min" but is not required to tell the person that it could not check. This is a grant without the victim's authenticator, so it is stop-ship 1 and stop-ship 6.
- **Required change (before `AUTH_LINK_SERVICE_ENABLED` or `AUTHORITY_OIDC_ENABLED` is turned on for any account, so Stage 6's plan moves before the pilot):**
  1. Authority-verified recovery codes. When a trusted device creates a code set, it submits a `viadere-factor+jws` from a logged key (new purpose `recovery_codes_set`; the display includes the set id and count). The device generates the codes, the authority stores only `HMAC(RECOVERY_VERIFIER_KEY, "recovery-code\n" ‖ account_ref ‖ "\n" ‖ code)`, and the api keeps its own hashes for the existing flow. `recovery_started` is accepted only with a code that the authority verifies itself, single use, with its own attempt limits.
  2. Keys added by `recovery_activated` on an api-verified (legacy) code set are **never grant-capable** at the authority. Link service and OIDC refuse that account. The account regains grant capability only through a later authority-verified path (a new recovery against an authority-registered code set, or an admin-job decision with reason, recorded as a controlled downgrade per §4.3). The app copy says so (A9).
  3. The app must show a persistent "We couldn't check your account's security" state (A9, A6) when it cannot obtain a valid head fresher than 15 minutes for more than one hour while online, and it must never treat an absent head as "no pending recovery".
  4. Fix THREAT_MODEL AT-1 1.3.3 to [R] until (1) and (2) ship, then [C].
  5. Tests:
     - ST-REC-07: simulated AS-1 starts a recovery with no authority-verified code; after 72 h with no cancel, the authority still issues no grant and no id_token for the account;
     - ST-REC-08: a legacy-code recovery yields keys that the authority marks non-grant-capable;
     - ST-REC-09: the app shows the warning state when heads are withheld.

### S1-A2-3 — High — business-supplied URL not bound end to end (R-07)

- **Location:** ADR-0021 §3.4, THREAT_MODEL T-GW-6, T-ML-7, AT-2 2.1, §7 row 3, R-07; TRUST_BOUNDARIES §8.
- **Required change:** the design in the R-07 ruling above, items 1-8. THREAT_MODEL §7 row 3 must then cite ST-ML-10..13 and drop the interpretation.

### S1-A2-4 — High — link-service `return_url` and display objects come from the api, so a code can be stolen on the same-device path

- **Location:** TRUST_BOUNDARIES §4.3 `POST challenges` ("display object, return URL … neutral") and DF-3; ADR-0023 §3 (`display_digest` is checked "equals the digest of the display object stored with the challenge", and the stored object is api-supplied); ADR-0021 §5.3 (the device "opens `return_url`", which it received from the api); ADR-0024 §4, §8 (OIDC display and consent).
- **Issue:**
  1. Step 5 of the verification order proves only that the device saw what the api told the authority it would show. Under AS-1 the api writes both values, so the check is empty, which is why ST-GW-07 would pass without any real control.
  2. Same-device link service (F3) has **no number matching**, and the factor JWS does not commit to `return_url`. The attack runs like this:
     - the attacker starts a sign-in at business B as the victim in its own browser, which holds the PKCE verifier;
     - the victim gets a prompt they did not ask for and taps "Continue on this phone" (user presence only);
     - AS-1 gives the device an attacker host as `return_url`;
     - the device sends `vdr_code` there;
     - the attacker pastes the code into its own session at B's real return URL, B redeems it with the attacker's verifier, and B receives a grant for the victim.

     Without AS-1 the code would reach the victim's browser and fail PKCE. So AS-1 turns one mistaken tap into account takeover and bypasses the number matching that R-03 claims "narrows" this case.
- **Required change:**
  1. The authority **builds the display object itself** from its own records:
     - for `link_open`: the tenant display name and link client display name stored at client registration, the exact `return_url` and its host, the purpose, and the match digits;
     - for `oidc_login`: the client display name, the exact `redirect_uri` and its host;
     - for `keylog_device_added`: the new device name and the thumbprint of every key in the entry, checked equal to the entry's keys.

     The authority never accepts display text from the api. `POST challenges` returns the display, and the api relays it unchanged.
  2. The factor JWS for `link_open` carries `return_url` (exact string) in addition to `display_digest`. The authority checks it byte for byte against the client registration. The device opens **only** the URL it signed, and only after the evidence round trip. If AS-1 fakes the "accepted" answer, no code hash is registered, so the opened code is useless.
  3. Optional but recommended: the authority signs the challenge (`viadere-challenge+jws`) so the device can detect tampering before the person acts, instead of failing after.
  4. Tests:
     - ST-LS-07: a substituted `return_url` → evidence refused and no code registered;
     - ST-LS-08: an api-modified display (business name, host) → evidence refused;
     - ST-REC-10: a `device_added` display whose thumbprints differ from the entry → refused;
     - rewrite ST-GW-07 so that it fails without the control.

### S1-A2-5 — High — OIDC under AS-1: the api controls the authorize front end; public clients; client-auth audience

- **Location:** ADR-0024 §2 (`token_endpoint_auth_methods_supported` includes `none`), §4 (the api renders the authorize page and relays `redirect_uri`, `code_challenge`, `nonce`, and the passkey origin is `https://id.<domain>`, served by the api), §6 (`private_key_jwt` `aud` = token endpoint URL); THREAT_MODEL §3.11 and §8 (no residual recorded).
- **Issue:**
  1. **Session swap / code injection.** The authorize parameters reach the authority only through the api, and the WebAuthn origin is an api-served page. AS-1 can therefore create the authority challenge for a victim's *genuine* login using the **attacker's** RP session's `code_challenge` and `state`, run the victim's real passkey or app ceremony against it, and deliver the code to the attacker's browser. The RP then logs the attacker in as the victim. Passkey origin binding does not help, because the origin itself is the compromised component. The victim did initiate a login, so the "unsolicited prompt" defenses do not apply. This is outside the §13 metric only because the victim must be actively logging in, and THREAT_MODEL does not say so.
  2. **Public clients (`none`).** AS-1 swaps in its own `code_challenge` and redeems the code itself. For SPA and native clients, the resulting tokens are the RP's whole session proof.
  3. **`private_key_jwt` audience.** With `aud` = the token endpoint URL, the scheme is open to the 2025 audience-injection class of attacks. Current guidance (OpenID Foundation errata, draft RFC 7523bis) is that `aud` must be the issuer identifier only, as a single string.
  4. Mix-up defense. There is no `iss` authorization-response parameter (RFC 9207).
- **Required change:**
  1. The staging OP accepts **confidential clients only** (`private_key_jwt`) until a separate A2 and A3 review. Remove `none` from metadata.
  2. Client assertions must have `aud` exactly equal to the issuer string. Arrays and the token endpoint URL are refused.
  3. Return `iss` in every authorization response and advertise `authorization_response_iss_parameter_supported: true`.
  4. Add residual **R-17**: "A compromised api, which hosts the authorize endpoint and the WebAuthn origin, can bind a victim's genuine authentication to an attacker-initiated RP session." Owner A2. Removal condition: before any production IdP, the browser-facing authorization endpoint and passkey origin run in a component outside the ordinary tier with its own identity and deploy path, plus external review (spec §13 "External review"). Record it as a named exception to the §13 metric.
  5. `login_hint` pushes count against the ADR-0022 §5 fatigue counters per (client, account).
  6. Tests:
     - ST-OIDC-11: `none` is refused;
     - ST-OIDC-12: an assertion with `aud` = token endpoint or an array → `invalid_client`;
     - ST-OIDC-13: `iss` is present in success and error responses;
     - ST-OIDC-14: `login_hint` prompts above the budget are suppressed.

### S1-A2-6 — High — rate budgets give an external attacker a rolling lockout

- **Location:** ADR-0020 §8 (`authdl-subject` 5 per 10 min and 20 per day; refusal); ADR-0022 §5.1 (`429` above 6/h), §5.2 (collapse); THREAT_MODEL T-MFA-6, AT-6, RT-9, ST-MFA-05 (which *asserts* the refusal).
- **Issue:** Anyone who knows a victim's identifier at a business can trigger that business's sign-in about 7 times per hour or 20 times per day. That exhausts the per-subject budget, so the victim's own sign-in delivery is refused (`429` / not deliverable) for the rest of the window, and the attacker can repeat this indefinitely. Collapse also lets the attacker keep cancelling the victim's pending prompt. The pause rule is covered (the user can lift it), but the budgets are not. This fails §23 ("avoid permanent lockout as an attacker-controlled DoS") and RT-9 ("without creating indefinite attacker-controlled lockout").
- **Required change:**
  1. Per-subject and per-relationship budgets limit **alerting**, not availability. Over budget, the newest request is still created and collapsed, and is delivered silently (no alert push, inbox only, marked "You have a pending sign-in from {Business}"), so a person who is actively signing in opens the app and finds it. `429` is reserved for per-tenant aggregate floods and for the existing "at most 3 pending" structure, applied with collapse rather than refusal.
  2. Superseding by collapse also does not alert while over budget.
  3. Business guidance and SDK: throttle unauthenticated sign-in triggers per client IP and per account on the business side.
  4. Rewrite ST-MFA-05 and add ST-MFA-10: after an attacker exhausts every per-subject budget, a sign-in the victim initiates is still completable from the inbox; ST-DLV-09 is the same check for magic links.

### S1-A2-7 — Medium — phone MO proof immediately displaces the existing owner's link

- **Location:** ADR-0027 §1.3, §3.1; `PhoneLinkService.makeVerified` (`Server/Sources/ViadereServerKit/Services/PhoneLinkService.swift:136-143`, verified: "proving control of it moves the link", which revokes other accounts' links in the same transaction).
- **Issue:** With a spoofed MO (R-13), an attacker does not only link a fresh number. It **revokes the victim's established link at once**, and its own link becomes the SMS-gateway routing identity after cool-down. The victim's inbound texts to businesses are then attributed to the attacker's account context. A spoofed `UNLINK` likewise revokes anyone's link. `phone_control_mo` does not reach any assurance decision (checked: `RecoveryService` only cools phone links down; no `AssurancePolicy` path reads phone links), so this is a privacy and integrity issue, not an authentication one.
- **Required change:**
  1. A number already verified to another account moves only when (a) the new link's cool-down ends and (b) the existing account was notified **in app**, through the key-log-head-style pull and not by push alone, and did not choose "Keep my number". Until then the existing link stays the routing identity.
  2. `UNLINK` is honored, but the account is notified in app, and repeated `UNLINK` / re-link cycles on a number are rate-limited and alerted.
  3. Where the provider exposes an aggregator spoof or "unverified sender" indicator, it is mandatory to evaluate it, not optional.
  4. Tests: ST-PH-08 (spoofed MO against a linked number leaves the existing link in place until cool-down and no-objection); ST-PH-09 (UNLINK churn is limited and notified).

### S1-A2-8 — Medium — the monotone rule needs a field-level trust table; worker scope too wide

- **Location:** TRUST_BOUNDARIES §4.3, §5; ADR-0021 §5.4 ("the client's tenant equals the caller's tenant (passed by the api …)"); ADR-0020 §2 `audience` ("`aud` of any grant"); ADR-0019 §4.2 (one app role for api and worker).
- **Issue:** The rule is stated per route, but several values the authority uses come from the api inside "neutral" or "increasing" routes: tenant, `audience`, `code_challenge`, `return_url`, display, consumer id, `login_hint` resolution. Some are safe (the authority re-derives `sub`), and some were not (S1-A2-1, -4, -5). A per-field table is the reviewable control.
- **Required change:**
  1. Add a table to TRUST_BOUNDARIES §4.3. For each route and request field, record: the source, whether the authority trusts it, the check it applies, and the consequence if AS-1 lies. A field that ends up in a signed artifact must be either authority-derived or covered by device or business evidence.
  2. The grant `aud` and `tid` come from the authority's link-client record, never from the request. Remove "`aud` of any grant" from ADR-0020 §2 `audience`, or make it an equality check only.
  3. Give the worker a separate app role `Authority.Revocations` that reaches only `revocations`.
  4. Tests: ST-AUTH-17 (api-supplied `audience`/`tenant` differing from the client record → refused, or ignored with the client-record value used); ST-AUTH-18 (a worker token on `evidence` → `403`).

### S1-A2-9 — Medium — reviewer separation is not achievable as written

- **Location:** ADR-0019 §5 ("two required reviewers, neither of whom is the requester"); ADR-0028 §6.3 ("required reviewers (≥ 1, not the change author; the owner in staging)"), §6.4; ADR-0021 (proposed tenant-key registration uses the same path).
- **Issue:** Staging has one human (the owner), and agent sessions commit and push through the owner's GitHub identity. "Not the change author" and "two reviewers, neither the requester" then either cannot be met, which deadlocks the admin path, or will be weakened in practice, which turns the control into a single approval. Nothing in the design requires branch protection or CODEOWNERS. Whoever can push to `main` changes `authority-deploy.yml`, and the federated subject is pinned only to `@refs/heads/main`. A cosign check of "release.yml identity" does not stop a malicious but correctly signed image built from a malicious commit.
- **Required change:**
  1. Name the reviewer identities per environment.
  2. Agents use a GitHub identity distinct from the owner's, and environments enable "Prevent self-review".
  3. `main` has branch protection with required review, plus CODEOWNERS on `.github/workflows/authority-*.yml`, `Server/Sources/ViadereAuthority*`, `Infra/azure-authority/` and `Site/content/id/` (JWKS).
  4. `authority-deploy.yml` verifies SLSA provenance that ties the digest to a commit on protected `main`, and shows that commit to the reviewer.
  5. If only one human can review in staging, record honestly that the admin path is a single owner approval, as a residual with a removal condition. Do not claim "two reviewers".
  6. ST-CI-08: a workflow run triggered by the reviewer's own identity cannot approve itself; a CODEOWNERS file exists and is enforced.

### S1-A2-10 — Medium — test catalogue: missing tests and tests that pass without their control

- **Location:** THREAT_MODEL §5, §6, §7.
- **Issue:**
  1. §7 stop-ship row 3 has no AS-1 test (fixed by ST-ML-10..13).
  2. ST-REC-02 tests the hold but not "no grant from an api-only recovery" (ST-REC-07).
  3. Nothing tests genesis (ST-AUTH-15).
  4. ST-GW-07 passes without a meaningful control (S1-A2-4).
  5. ST-MFA-05 encodes the lockout (S1-A2-6).
  6. RT-1 "read other tenants' data" has no test at the authority boundary. Add ST-AUTH-19: an api token cannot read another tenant's link clients, consents, grants or audit through any authority route. Only `keylog/{account_ref}/head` reads, and it returns only the head.
  7. ST-MFA-06 "documents pass-through". Keep it, but it must not count toward any §26 row.
- **Required change:** add the tests named in S1-A2-1 to -9, and map each §26 and §27 row to at least one test that fails without its control. My mapping for the revised §5/§7:

| §26 / §27 | Control (after changes) | Test that fails without it |
|---|---|---|
| RT-1 gateway compromise | no key; no raw sign; authority-minted account binding; authority-built display; authority-verified recovery | ST-GW-01, ST-AUTH-02, -15, ST-LS-07, ST-REC-07, ST-AUTH-19 |
| RT-2 stolen webhook secret | ids-only webhooks; fetch and verify | ST-WH-04 |
| RT-3 replay | `ach` single use; business replay guard | ST-AUTH-09, ST-MFA-03 |
| RT-4 destination swap / open redirect | validator + signed destination + authority tenant record | ST-ML-03..05, ST-ML-10..13 |
| RT-5 push interception | ids-only payload | ST-PRIV-02 |
| RT-6 one tenant compromised | tenant from credential; authority client binding | ST-TEN-01..05, ST-AUTH-17 |
| RT-7 ordinary admin | no console path; admin job; CODEOWNERS / reviewers | ST-CON-02, ST-AUTH-07, ST-CI-08 |
| RT-8 email/SMS recovery | no such route; authority-verified codes | ST-REC-01, ST-REC-07, -08 |
| RT-9 MFA flood | budgets limit alerts, not availability; pause liftable | ST-MFA-07, ST-MFA-10, ST-DLV-09 |
| RT-10 crash | outbox, CAS, bounded retries, dedup | ST-DLV-01, -02, ST-WH-05 |
| §27 grant from one ordinary service | as RT-1, plus legacy freeze | as RT-1, ST-GW-08 |
| §27 link token in push/logs | ids-only push, P-class ciphertext, redaction | ST-PRIV-01..03, ST-ML-06 |
| §27 verified domain bypass | R-07 design | ST-ML-10..13 |
| §27 cross-tenant | ST-TEN-*, ST-AUTH-17, -19 | same |
| §27 exportable critical keys | non-exportable KV keys; no api role on `kv-vdr-auth` | ST-AUTH-01, -10, ST-GW-02 |
| §27 recovery bypasses assurance | authority-verified recovery; `phone_control_mo` never a factor | ST-REC-07, -08, ST-PH-06 |

### S1-A2-11 — Medium — webhook v2 migration and dedup window

- **Location:** ADR-0025 §2.4, §3; `Server/Sources/ViadereServerKit/Services/WebhookService.swift:11-13` (verified: 8 attempts, backoff 30 s … 24 h, about 43 h total).
- **Issue:**
  1. Receivers keep event ids until `t + 24 h`, but retries continue for about 43 h. A delivery the receiver processed but answered late (timeout) is retried after its dedup row has expired and is processed again.
  2. Phase M2 makes `auth.*` v2-only only after M1. These event types do not exist yet, so there is no reason ever to sign them with v1, and the dual-sign window would put v1 MACs on auth events.
- **Required change:**
  1. Keep dedup until the last possible retry plus 300 s (state it as ≥ 72 h, and tie it to the backoff table in Core so it cannot drift).
  2. `auth.*` and new `approve.*` events are v2-only from M0, with no `v1=` entry on them.
  3. ST-WH-06: an event re-delivered at the final retry offset is deduplicated.

### S1-A2-12 — Low — residual risk register needs correcting

- **Location:** THREAT_MODEL §8 and §4.
- **Issue and required change:**
  1. R-03 overstates its narrowing (see S1-A2-4); restate it after the fix.
  2. Replace R-07 with R-07' (ruling item 7).
  3. Add R-17 (S1-A2-5).
  4. Add R-18: "`kd-log-signing` held by the api (decision 12) lets AS-1 present a fabricated key directory to a device with no pinned head. That device then accepts forged E2EE `ApprovalRequest` signers and display, which yields no authorization because the business checks `txn_digest`, but can mislead the person." Removal: ADR-0028 C2.
  5. Add R-19: under AS-1, a revoke and freeze flood (R-14) can also be aimed at authority key-log entries through `revocations`. It is reduce-only, but a mass revocation must alert.
  6. Mark AT-1 1.3.2 and 1.3.3 as open until S1-A2-1 and -2 are fixed.

  None of R-01..R-16 hides a stop-ship condition after S1-A2-1, -2 and -3 are fixed. R-11 and R-15 are correctly kept as separate classes.

### S1-A2-13 — Low — key-purpose hygiene

- **Location:** ADR-0023 §4 (`account_ref` under `OIDC_PAIRWISE_KEY`); TRUST_BOUNDARIES §4.1.
- **Issue:** One secret serves two purposes. It is domain-separated, but rotating the OIDC pairwise key would re-key the whole key log.
- **Required change:** use a separate `ACCOUNT_REF_KEY`. The final say belongs to A3. Also, business request-signing key registration (ADR-0020 §3) must require the same fresh passkey step-up and Owner notice as destination hosts (AS-3/AS-4).

## Decision list (STAGE1_REVIEW_REQUEST "Decisions … need explicit acceptance")

| # | Decision | A2 ruling |
|---|---|---|
| 1 | R-07 interpretation | **Rejected**; design change above (S1-A2-3) |
| 2 | Watch never an authenticator | **Accepted.** Stricter than §8 and consistent with the absence of watch keys; Deny/report are reduce-only |
| 3 | RS256 alongside ES256 | **Accepted.** Discovery requires RS256 support; separate key per algorithm; `alg` fixed by registration |
| 4 | `/v1/business/…` paths; no `POST /v1/devices/link` | **Accepted.** Device association is covered by existing ceremonies plus key-log proofs |
| 5 | RFC 9421 required for live keys | **Accepted**, with the S1-A2-13 condition on key registration |
| 6 | Push MFA stays business-verified | **Accepted.** Verified against SECURITY §2.53/§2.54: the business binds the key with `es` (binding tag or SAS) the relay never sees, and verifies against its own record, so AS-1 cannot mint MFA success. The relay status never suffices |
| 7 | Authority key log with one-time import | **Accepted only with S1-A2-1 and S1-A2-2**; the import must include keyless accounts |
| 8 | Legacy approvals frozen | **Accepted.** ST-GW-08 (zero active legacy entitlements) is a pilot release gate |
| 9 | No SSO, no refresh tokens | **Accepted** |
| 10 | Phone ownership by customer-originated nonce | **Accepted with S1-A2-7.** `phone_control_mo` cannot reach an assurance decision (checked) |

## Checklist outcome (A2 section of the request)

- §4.2 assumptions: all seven are present in THREAT_MODEL §2, and none is weakened in wording. AS-1's "must still hold" was not met by the design (S1-A2-1, -2, -4).
- §26 and §27 mapping: complete after S1-A2-10.
- AT-1: leaves 1.3.2 and 1.3.3 are open (S1-A2-1, -2). 1.6 is open for the link service (S1-A2-4) and for OIDC under AS-1 (S1-A2-5, residual).
- Other api-controlled inputs the authority trusts: display, `return_url`, consumer id at genesis, recovery start, tenant/`audience`, authorize parameters (S1-A2-1, -2, -4, -5, -8).
- ADR-0021 validator rules: sound for create-time checks (strict parse, A-labels, exact host, no userinfo, port, IP literal or backslash, query-value redirect check). The 24 h hold and notices are adequate for AS-3/AS-4. Server-side redirects stay R-06.
- ADR-0022 fatigue: see S1-A2-6. Pause semantics are correct (per business and customer, ≤ 1 h, liftable).
- ADR-0027: S1-A2-7.
- ADR-0028 CI split: the role separation (`AUTH-DEPLOY-SEPARATE`, Managed Identity Operator split, separate apply identity) is correct. `job_workflow_ref` is available in GitHub's OIDC token and can be included through the repository's custom subject template, and Azure federated credentials match the resulting subject string exactly, so subject pinning is achievable. Human and branch controls are S1-A2-9.
- Tenant isolation: data (per-query tenant filter, separate authority DB), key (pairwise approval keys, per-tenant clients), authorization (tenant from credential, strict decoding refuses `tenant_id`) and routing (pairwise `subject_ref`, webhook v2 tenant binding) hold for requests through the API. Under AS-1 the api DB is exposed, as stated honestly in RT-1. S1-A2-8 and ST-AUTH-19 close the authority side.
- Replay, nonce, audience and expiry: correct on factor JWS (`ach` consumed after all checks), grants (`jti`, `cch`, 60 s), OIDC codes (60 s, single use, PKCE), webhooks (300 s plus dedup, except S1-A2-11), and RFC 9421 nonces (600 s).

## Sign-off

A2 security review of Stage 1. Verdict: **BLOCK** pending S1-A2-1 through S1-A2-6. Medium findings are due before the pilot gate, and Low findings before Stage 7. Reviewer: A2 agent, 2026-11-02.

This is an agent review record produced for the Viadere multi-agent build process (spec §15, §27). It is **not a third-party certification**, penetration test or independent external security assessment, and it does not replace the external review that spec §13 requires before any production IdP.
