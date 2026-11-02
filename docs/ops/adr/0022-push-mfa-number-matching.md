# ADR-0022: Push MFA — number matching, transaction binding, fatigue controls, passkey bias and the watch tier

- **Status:** proposed (2026-11-02)
- **Spec reference:** §3, §5.2, §7, §7.2, §8 (watchOS, Wear OS), §14.1 (watch tier), §18, §20, §26 (replay, flooding); owner decision 4
- **Related:** ADR-0006 (pairwise keys), ADR-0007 (E2EE), SECURITY §2.53-§2.58 (Approve v2), ADR-0020, ADR-0023; findings F-05, F-12, F-14, F-15, F-16, F-25
- **Review:** A1, A2, A3 (JWS change), A6/A7 (feasibility), A9 (copy and layout)

## Context

Approve v2 already gives a device-signed, transaction-bound, pairwise `ApprovalResult` JWS that the business verifies against a key it enrolled (SECURITY §2.54), plus fatigue counters, freeze and report (§2.57). It is gated off in staging. There is no number matching (F-05). The legacy `authenticate`/`authorize` interaction path is decided on relay status and is not independently verifiable (SECURITY §2.58 residual 9). The approve push uses an unregistered category and no request id (F-15); the low-assurance approve action can dead-end (F-14); Deny is visually weaker (F-16). Decision 4: pilot is passkey-biased, with transaction-bound push MFA with number matching and payment step-up.

## Decision

### 1. Push MFA is Approve v2

`POST /v1/business/auth-approvals` creates an Approve v2 request (existing semantics, SECURITY §2.55) and an auth-delivery record of method `push_approval` for unified status and events. The business verifies the `ApprovalResult` JWS itself; the relay's status never suffices. This keeps F-12's privacy rule (the business never receives the global device id) because pairwise keys are per business (ADR-0006).

### 2. Number matching

1. **Code.** The business generates `match_code`: 2 decimal digits (`10`-`99`) for `capability = auth.challenge` at risk `low`/`medium`; 3 digits (`100`-`999`) for `transaction.approve` and any `high`/`critical` request. CSPRNG; never `00`-`09`-style leading zero to avoid entry ambiguity.
2. **Carriage.** In E2EE requests, `number_match: {digits, code}` is a member of the business-signed `ApprovalRequest` (inside the envelope; the relay cannot read or change it). In server-visible requests it is a request field; the relay can read it, which is acceptable because number matching defends against fatigue, not against the relay (THREAT_MODEL T-MFA-1, R-12).
3. **Display.** The business shows the code on the screen where the sign-in or payment started (its web page or app). The phone **never displays the code**: the approval screen asks "Enter the number shown on {Business}" with a numeric field. Approve is disabled until the field has the right length.
4. **Check.** The device compares the entry with the code in constant time. Up to 3 wrong entries per request (local counter, also reported as `invalid_match_attempts` in the result); the third makes the device submit a signed `decision: "deny"` with `deny_reason: "number_mismatch"`, which counts toward the pause rule (§5). The JWS carries `match` (the entered string) so the business verifies it against its own record. Lock Screen and notification never show the code, amount or payee.
5. **Equal-prominence Deny.** Approve and Deny are the same component size, weight and contrast; Approve is never the filled default when context is missing (server-visible label) (spec §7.2, §20; fixes F-16). Brand kits cannot restyle either (existing rule: no partner styling on security surfaces).
6. **Same-device sign-in** (business app on the same phone): the person switches apps to read the number. This is a known usability cost; the SDK recommends passkeys for same-device flows (§6).

### 3. Transaction binding: `ApprovalResult` v2

Additive version bump of SECURITY §2.54 (Core change with the SDK verifier updated in the same change):

- Payload `v: 2` adds `match` (string, present iff the request carried `number_match`) and `deny_reason` (`number_mismatch`, `not_me`, optional). All other members, canonicalization, header allow-list and `exp − iat ≤ 600` (devices sign 300) are unchanged.
- `authentication` details gain `match_digits` (2 or 3) so `txn_digest` covers that a number match was required (a relay cannot strip the requirement in server-visible mode without breaking the business's digest check).
- `ApprovalVerifier` (Swift), and the TypeScript and Kotlin verifiers (ADR-0030), check: `v ∈ {1,2}`; if the business's pending request has `number_match`, then `v == 2` and `match == code` (constant time), else `match` absent. v1 results remain valid only for requests created without number matching.
- Replay: unchanged (`aud‖kid‖challenge` consumed once by the business; relay CAS).

### 4. Payment and high-value step-up

1. `capability = transaction.approve`, displayed `transaction {currency, amount_minor, payee_display, transaction_reference}` (existing), 3-digit number matching, `amr = biometric` (key `approvalBiometric`, `.biometryCurrentSet`), D1 device not in cool-down (existing).
2. `txn_digest` binds amount, currency, payee and reference (existing); any change fails the business's check.
3. **High and critical requests must be E2EE** (business-signed, ADR-0007) in the pilot configuration; server-visible high/critical requests are refused with `422 e2ee_required`. This removes relay prompt injection for payments (SECURITY §2.58 residual 6).
4. Secure Payment Confirmation (W3C) is not adopted in the pilot; recorded as a Phase B option for businesses with WebAuthn.

### 5. Fatigue and bombing controls

1. Existing per-relationship counters (window 1 h): warn from 3 requests, refuse above 6 (`429`), pause the business's requests for that customer after 3 denials, reports or number-mismatch denials, at most 3 pending (SECURITY §2.57).
2. **Collapse:** a new sign-in approval for the same (tenant, subject) cancels the pending one (`superseded`), so the person never sees a stack of prompts; the app shows only the newest and says how many were replaced ("2 earlier requests were replaced").
3. **"This wasn't me"** = signed `decision: report` with `deny_reason: not_me`: counts as a denial, creates a security notice, an operator-visible event, and the business sees `report` in the verified result.
4. **No indefinite attacker-controlled lockout:** a pause applies only to that business and that customer, lasts at most 1 h, and the customer can lift it at once in the app with a biometric proof (existing `ApproveFreezeProof` pattern, action `unpause`). Other businesses and the customer's own app sign-in are never affected.
5. Push: category `viadere.approve` registered in the app with actions **Deny** (no foreground needed) and **Review** (`.foreground`); the payload carries the request id `req` (fixes F-15); approve always foregrounds the app (fixes F-14); `apns-collapse-id` = request id.

### 6. Passkey bias

- Viadere does not replace the business's passkeys. The business SDKs' `recommendStepUp(context)` helper returns, in order: (1) the business's own WebAuthn passkey when the customer has one on this device or via hybrid transport (origin-bound, phishing resistant); (2) Viadere push with number matching; (3) delivery-only methods (link, code) only when the business's policy allows, with the downgrade recorded in the business's own audit and in `auth.delivery.fallback_used`.
- For Viadere's own OIDC provider, passkey is offered first and is the only method that yields `urn:viadere:acr:passkey` (ADR-0024 §5).
- Copy and docs never call push approval phishing resistant (spec §6.5, §18).

### 7. Legacy interaction path

From pilot start: no new legacy approval entitlements (SECURITY §2.58 residual 9) may be granted; existing ones keep their expiry (sunset 2027-06-30). The pilot release gate requires zero active legacy entitlements in staging (THREAT_MODEL ST-GW-08) so no ordinary workload can produce an authentication success that a business accepts on relay status alone (§27).

### 8. Watch tier (spec §14.1 open question, decided here)

| Surface | Allowed for auth/payment items | Why |
|---|---|---|
| watchOS (phone-mediated, no keys on the watch; existing `WatchSync`) | view business and purpose; **Deny**; **This wasn't me** (report). No Approve. Shows "Approve on your iPhone". | The watch holds no key; any watch approve would be signed by the phone's `request` key without user verification (assurance `none`), below every auth requirement; number entry and Face ID live on the phone. Fixes F-25 (watch sends deny where report is meant). |
| Wear OS (future) | same rule | Device capabilities and biometric policies vary (spec §8) |
| Non-security items (confirm/choose, low) | unchanged existing behavior | not in scope |

Classification: watch = **W0 "notification surface"**, never an authenticator; it can only reduce (deny/report). This is stricter than spec §8's "low- to medium-risk with paired-device trust" (allowed, not required) and is recorded as a deliberate choice; revisiting it needs a new ADR with a watch-resident key design.

## Consequences

- Businesses must display the code on their own screen; the SDKs return it from the create call.
- `ApprovalResult` v2 is a Core wire change; old devices that cannot do number matching get requests without it only if the business did not require it; `AUTH_NUMBER_MATCHING_REQUIRED` makes the server refuse approvals without `number_match` for auth capabilities.
- Opening Approve v2 in staging still needs the Phase 2 gate evidence in SECURITY §2.58.

## Threat assumptions changed

- Fatigue approvals of attacker-initiated prompts now need the attacker's number to reach the victim (T-MFA-1); real-time phishing relay remains (R-12).
- Relay prompt injection is removed for payments (E2EE required) and remains a labelled residual for low/medium server-visible requests.
- The watch can no longer be argued to be an authenticator.

## Reviewers required

A1 (assurance semantics), A2 (fatigue and lockout), A3 (`ApprovalResult` v2), A6 and A7 (number entry, categories, watch), A9 (equal prominence, copy).
