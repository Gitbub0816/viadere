# Stage 5 code review: push MFA with number matching (A2 security + A3 wire), 2026-11-02

| | |
|---|---|
| Reviewer roles | A2 (application security) and A3 (`ApprovalResult` v2 wire). Independent of the author: did not write any reviewed code |
| Change reviewed | Merge `8b0708b` (second parent `f51661e`; commits `e1a0ba2`, `56235bb`, `ba02a7a`, `4f2563c`, `f51661e`); `git diff 8b0708b^1 8b0708b` plus the follow-ups `10bb09e`, `0ffc82d` on `claude/inspiring-cannon-t5hxfw` |
| Binding design | ADR-0022 (revision 3.1 and the Stage 5 `jti` amendment) above all; ADR-0020 §2a, §8; ADR-0023 §2, §7; SECURITY §2.54-§2.58 and §2.102; THREAT_MODEL T-MFA-1, R-12, R-20, ST-MFA-01..13; AUTH-DELIVERY-SPEC-v2 |
| Ran (scratch worktree `/tmp/claude-0/s5review`, removed afterwards) | `Packages/ViadereKit` `swift test --filter "NumberMatch\|ApproveV2\|AuthDelivery"` (94 tests, 11 suites, pass); `Packages/ViadereCore` `--filter "ApprovalResultV2\|Approve"` (11 tests, pass); `Packages/ViadereBusinessSDK` full suite (90 tests, 18 suites, pass); two proof tests written for this review (below), both reproduce their finding |
| Not run here | `Server` suite (SQLite and PostgreSQL; disk and time). Server findings are from reading, cross-checked against the existing `AuthApprovalTests` |
| Not possible here | App targets in Xcode 27.1, locked-phone notification Deny, Face ID |

## Verdict: **APPROVE WITH CONDITIONS**

Both feature flags (`AUTH_DELIVERY_ENABLED`, `APPROVE_V2_ENABLED`) are off in staging and production, and the device Deny action ships off in production. The wire and verifier work is sound:

- `ApprovalResult` v2 has the exact member set, plus the required `jti`.
- `NumberMatchExpectation` cannot be omitted, so a verifier cannot skip number matching by default.
- A v1 result, or a v2 result without `match`, is refused when the request asked for a number.
- `match` is compared in constant time.
- The business and the relay both consume `aud‖kid‖challenge` and `aud‖jti`.
- The tag reservation is re-checked under the customer row lock.

Two findings are **blocking before either flag is turned on in any environment, and before ST-MFA-10/11 are reported as passing**:

- **S5-01 (High).** A group that mixes a 2-digit and a 3-digit request cannot be approved on the phone. One attacker request scored as high risk, or the api's own escalation once 30 requests are open, locks the victim out of their own sign-in. The server test that claims ST-MFA-11 builds exactly such a group, but it signs the result directly and never goes through the device screen.
- **S5-02 (Medium).** A Deny on a group screen counts as N denials toward the pause, not one. Three attacker requests plus one honest Deny pause the victim's sign-ins for an hour.

The other conditions are listed per finding.

## Findings

Severity scale: Critical / High / Medium / Low / Info. Nothing is fixed in this review (read-only). "Verified" means reproduced with a test or traced line by line.

### S5-01 — High — OPEN (blocking) — a mixed 2-/3-digit group cannot be approved: cheap lockout of the victim's sign-in

- **Where:**
  - `Packages/ViadereKit/Sources/ViadereKit/AuthDelivery/NumberMatchApproval.swift:346` (the group requirement takes `digits = max(...)` over every request);
  - `:164` (the field length is that one `digits`);
  - `:212`, `:224` (`canApprove` needs `requirementUsable`);
  - `Packages/ViadereKit/Sources/ViadereKit/AuthDelivery/NumberMatch.swift:26-29` (`isWellFormed` requires **every** candidate to have exactly `digits` characters);
  - `Packages/ViadereKit/Sources/ViadereKit/Stores/ApproveController.swift:106` (the group is every number-matched prompt of the business).
- **Issue:** ADR-0022 §5.2 item 6 is built so that 2-digit and 3-digit codes **coexist** in one group: the allocation is prefix-free, and the api escalates new requests to 3 digits from 30 open requests. The device collapses the group to one length, though. With one 3-digit and one 2-digit candidate:
  - `isWellFormed` is false, so Approve is disabled for the whole group;
  - even if it were true, the field would accept only 3 digits, so a 2-digit code could never be typed.

  The person can only Deny, and that Deny also denies their own request (§5.2 item 2), which feeds S5-02.
- **Exploit paths:**
  1. **One request.** The business scores sign-ins from an unknown device or network as `high` risk, which is common risk-based practice, so it gets 3 digits (`ApprovalNumberMatch.requiredDigits`). The attacker starts one sign-in for the victim's account from a fresh network. The victim then starts their own sign-in at `medium` risk (2 digits). Both requests land in one group, and the victim cannot approve their own sign-in until the attacker's request expires. Repeating every expiry window (120 s by default) keeps the victim out indefinitely. The per-requester throttle allows 3 per network prefix, so one network is enough.
  2. **Escalation.** The attacker keeps 30 2-digit requests open: 10 /24 networks within the 120 s expiry, against the SDK's default throttle. Every new request, the victim's included, is then forced to 3 digits (`409 match_digits_required`, SDK redraw), and the group is mixed again. ADR-0022 §5.2 items 4, 5 and 7 (ST-MFA-10, ST-MFA-11) require that the victim's request stays completable under exactly this load.
- **Verified:** The proof test `aMixedLengthGroupCannotApproveTheVictimsRequest` (text below) loads two business-signed end-to-end requests, `470` and `52`, through the real `ApproveRequestHandler`. It builds the group the way `numberMatchGroup` does and types `52`. The result: `requirement.digits == 3`, `isWellFormed == false`, and `canApprove == false` (also with 3 digits typed). The test passes, so the defect is confirmed. The server test `AuthApprovalTests.testCollisionsArePreventedAndTheVictimsRequestIsCompletable` (`Server/Tests/ViadereServerKitTests/AuthApprovalTests.swift:131`) creates 20 3-digit attacker requests plus the victim's `47`. It signs the result in the harness, so it bypasses the screen, and SECURITY §2.102 cites it as ST-MFA-10/11 evidence.
- **Required change:**
  - Give each candidate its own length. `NumberMatchRequirement.isWellFormed` should check each code against its own length (2 or 3).
  - Size the field to the longest candidate. Evaluate when the entry reaches a candidate's length: an exact 2-digit hit selects that request (prefix-freedom makes this unambiguous); otherwise wait for the third digit. Count a wrong entry only on a complete entry that matches nothing.
  - Add a Kit test with a mixed group, an approve of each length, and a wrong entry of each length.
  - Add an end-to-end ST-MFA-11 test that goes through `NumberMatchApprovalViewModel`, not only through the harness signer.
  - Correct the ST-MFA-10/11 claim in SECURITY §2.102 until both tests exist.

### S5-02 — Medium — OPEN (blocking) — a group Deny counts as N denials toward the pause

- **Where:**
  - `NumberMatchApproval.swift:407` (`ApproveControllerAnswering.answer` signs and submits one result per request in the group);
  - `Server/Sources/ViadereServerKit/Approve/ApproveRequestService.swift:244` (`promptVerdict` turns every decided row into a refusal);
  - `Packages/ViadereCore/Sources/ViadereCore/Approve/ApprovePrompt.swift:58` (pause at 3 refusals in the window).
- **Issue:** ADR-0022 §5.2 item 2 says a group Deny, This wasn't me, or automatic `number_mismatch` deny "answers every open request in the group and counts as **one** denial or report toward the pause". In the code, every request in the group becomes its own `denied` or `reported` row, and the pause counts rows.
- **Exploit path:** The attacker triggers 3 sign-ins for the victim; that is within the SDK throttle, from one network. The victim sees "3 open requests from {Business}" and taps Deny, which is the honest answer. The relay records 3 refusals, `promptVerdict` returns `.autoDeny`, and every request for the next hour is auto-denied without a prompt, the victim's own included (S-MFA-13 inbox item only). The victim can lift the pause with a biometric proof, but the attacker re-arms it with 3 more requests after each lift. One deliberate Deny, or three wrong entries on a group, equals three denials.
- **Verified:** The proof test `aGroupDenySendsOneAnswerPerRequest` shows that the screen hands all three ids to the answering layer, and `:407` loops over them. `AuthApprovalTests.testTheNotificationDenyIsReduceOnlyAndCountsTowardThePause` shows that three denied rows pause the relationship.
- **Required change:**
  - Mark the group answer so the relay counts it once. For example, the device sends the group's request ids together, or the relay counts distinct `(decided_at, decided_kid)` batches, or a per-submission `group_answer` id that is bound into the signed result or the device-signed request.
  - Add a server test: 3 open requests, one group Deny, and the next request is **not** auto-denied.
  - Also exclude `deny_reason = destination_unverified` from the refusal count (ADR-0022 §5.4). The api does not count it today: `promptVerdict` ignores `deny_reason`. It is not reachable for approvals yet, because `LiveAuthDeliveryAPI.reduce` refuses it, but the v2 wire allows it.

### S5-03 — Medium — OPEN — `AUTH_NUMBER_MATCHING_REQUIRED` does not exist: the legacy route still creates push approvals without a number

- **Where:** `ApproveRequestService.create` (the legacy `POST /v1/business/approve/requests` path); no `authNumberMatchingRequired` in `ServerConfig`. ADR-0022 Consequences and ADR-0019 §6 call for the flag ("default on when approvals are on").
- **Issue:** With `auth-approvals` live, any API key with `approvals:manage` can still create `auth.challenge` approvals through the legacy route with no `number_match`. A fatigue attacker who triggers sign-ins at a business that has not migrated gets prompts with no number at all, so T-MFA-1 holds only by convention. The business-side verifier stays downgrade-proof only if the business passes `.required`. The relay has no policy to refuse a number-less authentication approval.
- **Required change:** Add the flag (default on whenever `APPROVE_V2_ENABLED` is on). When it is on, the legacy create refuses `auth.challenge` (and `transaction.approve`) without number matching with `422 number_match_required`. Test both settings. Separately, a legacy v1 payment request is now unapprovable on the device, because `requiresNumber` is true for every transaction. That is fail-closed and acceptable, but the legacy route should refuse such a request at create time instead of delivering a prompt that can only be denied.

### S5-04 — Low — OPEN — silence starts at 4 open requests, not "above 6 per hour", and the inbox line is missing

- **Where:** `ApproveRequestService.swift:117-118`, `:180`; `ApprovePrompt.swift:63` (`maxPending = 3`).
- **Issue:**
  - ADR-0022 §5.1 delivers silently only above 6 per hour or over a per-subject budget. Because `maxPending` is 3, three attacker requests already make the victim's genuine request silent (`testOverBudgetRequestsAreCreatedSilently...` asserts 3 pushes for 8 creates).
  - The ADR's inbox line ("You have a pending sign-in from {Business}") is not written.
  - `silent` is decided only on the pre-transaction verdict. A concurrent create that is over budget inside the transaction (`:180`) still pushes.
- **Required change:** Use the ADR threshold for auth approvals, or record the stricter rule in the ADR. Write the inbox item for silent requests. Re-derive `silent` from the in-transaction verdict.

### S5-05 — Low — OPEN — the reduce-only Deny endpoint is gated on `AUTH_DELIVERY_ENABLED`

- **Where:** `Server/Sources/ViadereServerKit/Approve/AuthApprovalService.swift:43-46`, used by the `approveRequestDeny` route; `ApproveSupport.pushRequest` puts `req` on **every** Approve v2 push, legacy route included.
- **Issue:** In an environment with `APPROVE_V2_ENABLED` on and `AUTH_DELIVERY_ENABLED` off, staging builds show Deny on every approval notification (`AuthDeliveryFlags.staging`), but the endpoint answers `404`. Every Lock Screen Deny then fails, and only N-09 is shown. This is the R4-03 failure mode again, in that configuration.
- **Required change:** Gate the deny endpoint on `ApproveGate` alone, or drop the Deny action unless both flags are on.

### S5-06 — Low — OPEN — wrong-entry counter: keyed by business-chosen `request_id`, pruned by any listing that omits the request, restored asynchronously

- **Where:**
  - `ApproveRequestHandler.swift:95` and `:225` (keys `ApproveLocalState.matchAttempts` by `request_id`);
  - `App/Viadere/Features/Approve/ApproveRequestSheet.swift:79-81` (count restored in `.task`, after the sheet is live);
  - `NumberMatchApproval.swift` `ApproveControllerAnswering.answer` (signs an approve even when the stored count is 3).
- **Issue:**
  - `request_id` is unique only per business, so two businesses using the same id share a counter.
  - Any `load()` in which the request is missing or fails verification once (for example, a directory or log fetch error) prunes the count to 0. An end-to-end relay, which the threat model treats as untrusted, can therefore reset the three-strikes rule by omitting the request from one listing.
  - The sheet starts at 0 until the `.task` completes. After an automatic `number_mismatch` deny that failed (R4-01 path) and a reopen, Approve is briefly enabled, and nothing below the view model refuses an approve when the persisted count is 3.
  - Impact is bounded: the business treats `invalid_match_attempts` as advisory, and the relay still locks after 5 invalid submissions on server-visible requests.
- **Required change:**
  - Key by `businessId|requestId`, or by the relay delivery id.
  - Prune only requests whose terminal state was observed (a `410` or `409` from the relay, or expiry), not those merely absent from one listing.
  - Load the count before presenting, and make `ApproveControllerAnswering` / `ApproveRequestHandler.answer` refuse `.approve` when the stored count is at least 3.

### S5-07 — Low — OPEN — missing tests for the claimed controls

None of the following is covered by a test today:

1. **Concurrent creates.** Nothing exercises the reservation lock (`AuthMatchGroups.reserve`, `AuthGrouping.swift:49-51`) with two parallel creates of the same tag on PostgreSQL. The code is correct by reading: the lock on the customer row, then a re-check inside the transaction, closes the TOCTOU between `check` and `reserve`. But the claim "two concurrent requests cannot both take the same code" has no test.
2. **The relay's `relayRequired`.** No server test creates an end-to-end `auth-approvals` request. The relay's `relayRequired` path (`ApprovalResult.swift:383`) has no test in any package.
3. **The relay's `jti` store.** `ApproveRequestService.swift` (the `approval-jti:{business}` registration) is never reached by a test, because the second submission is already refused by the status CAS. Removing it fails nothing, despite the mutation claim in SECURITY §2.102.
4. **The deny endpoint's rate limit.** `authdl-deny` is untested.
5. **Positive vectors.** `approval-result-v2.json` has no positive case for `.notRequested` (a v1 result accepted, and a v2 result without `match` accepted). These pin the compatible side of the downgrade rule.
6. **S5-01 and S5-02.** Both have no test (see above).

### S5-08 — Info — confirmed controls

These were confirmed by reading the code and by the passing suites:

- **Replay.** `verifyAndConsume` consumes `aud‖kid‖challenge`, then `aud‖jti`, and only after every check passed, so a forged result cannot burn a challenge. The relay refuses a result for a non-pending request (status CAS) and records the `jti` per business.
- **Downgrade to v1.** `ApprovalExpectation` and `PendingApproval` take `NumberMatchExpectation` with no default. `.required` refuses v1 (`numberMatchRequired`) and v2 without `match` (`numberMismatch`). The SDK's `createAuthApproval` always returns `.required(code:)`. The end-to-end request v2 carries `number_match` inside the business-signed body. A v1 request whose details name `match_digits` is refused by the device, and server-visible `match_digits` sits in `txn_digest`, so a relay that strips the requirement breaks the business's digest check. v3 and unknown members are refused (vectors).
- **Constant time.** `ConstantTime.equals` (verifier `match`, challenge, digest, idempotency hash) and `NumberMatcher.constantTimeEqual` (device) compare the whole length with no early exit. Tag equality in `MatchGroupPolicy.evaluate` is not constant time. That is fine: the tags are the business's own HMACs, compared only within the business's own group.
- **Match-code oracle and enumeration.** The api never sees a code for end-to-end requests, only HMAC tags under a key the business holds. The `409` answers are scoped to (business, customer) and reveal only that business's own open requests. On server-visible requests a modified device could probe the relay's sealed code, but each wrong `match` counts as `binding_mismatch`, and the request locks after 5. That device already receives the code in its request view by design (T-MFA-1).
- **Tenant crossover.**
  - The business `GET` is scoped by `businessId` and sandbox mode, and answers `404` for non-auth-approval rows.
  - Deny and submit check that the delivery's device and customer match the principal.
  - Tags, supersession, `closeGroup` and pressure are all filtered on (business, consumer).
  - The relay's `jti` scope includes the business.
- **Result forgery.**
  - The header allow-list is unchanged; there is no `jwk`, `jku` or `crit`.
  - The member set is exact, and the presence rules are enforced (`deny_reason` never on an approve; `not_me` only on a report).
  - `jti` must be exactly 16 bytes.
  - The device factory refuses to sign an approve of a number-matched request without `match`.
- **TOCTOU between the tag check and the reservation.** `check` runs before the transaction, with alerting. `reserve` repeats it inside the transaction after `SELECT … FOR UPDATE` on the consumer row. On SQLite, writers are serialized. Every terminal path (`finish`, submit, reduce-only deny) releases tags inside its own transaction. Lock order is relationship then consumer; no other path takes them in the opposite order.
- **Reduce-only Deny.** The endpoint moves only `pending → denied/reported` by CAS, records no `result_jws` or `result_ref`, and a later approve gets `409`. The body is strict, and the endpoint is rate limited per device.
- **Notification privacy.** The Approve push has a generic title and body, a constant `thread-id`, `req` = this device's delivery UUID, `apns-collapse-id` = the same value, and interruption level `active`. It carries no business name, amount or code. The server test checks the push the server sent (`push.interruptionLevel`, `approveRequestId`, `collapseID`, no business text). `ApprovePushPayloadPolicy` itself is tested only on hand-built dictionaries, not on `APNSwiftSender`'s encoded payload. That is a small gap to close with S5-07. Over-budget requests send no push.
- **Code sampler and keys.** The sampler draws 16-bit values with rejection (`limit = ⌊65536/span⌋·span`), never yields a leading zero, and matches the independent Python vectors. HKDF labels and session-handle derivation also match the vectors.

### S5-09 — Info — smaller notes

- **The "iff" rule.** ADR-0022 §3 says `match` is present "**iff** the request carried `number_match`". The device omits `match` on a deny, and the verifier accepts that. Either amend the ADR to "on an approve", or require `match` on every v2 result of a number-matched request.
- **Report without a reason.** `report` without `deny_reason` is accepted. The ADR's model is `report` = `not_me`. Consider requiring the reason on v2.
- **Reduce-only report.** `report: true` on the reduce-only Deny yields `reported` without a signed result, whereas ADR-0022 §5.3 says "the business sees `report` in the verified result". There is no Report action on approval notifications, so this is reachable only from the watch forward or a direct call. Document that the business gets status only.
- **Signing inside the handler.** `ApproveRequestHandler.answer` will sign an approve of a payment without a number (only the view model enforces `requiresNumber`). Add the same guard in the handler, as R4-01 did for the screen.
- **Network work inside the submit transaction.** `closeGroup` calls `finish`, and therefore the webhook outbox, inside the submit transaction. That is correct, but it holds the row locks longer.
- **Legacy route with an end-to-end v2 request.** An end-to-end v2 request (`ApprovalRequestBuilder.endToEnd(numberMatch:)`) sent through the legacy route gets `matchDigits = nil`. The relay then expects `.notRequested` and refuses every approve as `unexpectedMatch`, which counts toward the lock. Refuse `numberMatch` on the legacy builder path, or document that it is for `createAuthApproval` only.

## Proof tests (scratch only, not committed)

`Packages/ViadereKit/Tests/ViadereKitTests/ReviewS5ProofTests.swift` in the scratch worktree (a copy is kept at `/tmp/claude-0/-home-user-viadere/3b41d0e0-5b55-55a1-acf8-7590519ad1f4/scratchpad/ReviewS5ProofTests.swift`). Both pass, which demonstrates the defects:

```swift
@Test func aMixedLengthGroupCannotApproveTheVictimsRequest() async throws {
    let relay = try await makeRelay()
    let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
    let key = try await phone.enrolled()
    _ = try await relay.deliverNumberMatched(to: key, code: "470", requestId: "req_attacker_3d")
    _ = try await relay.deliverNumberMatched(to: key, code: "52", requestId: "req_victim_2d")
    let prompts = try await phone.handler.load().prompts
    let victim = try #require(prompts.first { $0.request.requestId == "req_victim_2d" })
    let context = NumberMatchApprovalContext(group: [victim] + prompts.filter { $0.id != victim.id })
    #expect(context.requirement?.digits == 3)
    #expect(context.requirement?.isWellFormed == false)
    let vm = NumberMatchApprovalViewModel(context: context, answering: RecordingAnswering(), clock: { relay.now })
    vm.edit("5"); vm.edit("52")
    #expect(!vm.canApprove)          // the victim typed their own number
}

@Test func aGroupDenySendsOneAnswerPerRequest() async throws {
    let answering = RecordingAnswering()
    let requirement = NumberMatchRequirement(digits: 2, candidates: [.init(requestId: "a", code: "21"), .init(requestId: "b", code: "22"), .init(requestId: "c", code: "23")])
    let context = NumberMatchApprovalContext(business: "Northwind", expiresAt: Date().addingTimeInterval(300), requirement: requirement, groupRequestIds: ["a", "b", "c"])
    let vm = NumberMatchApprovalViewModel(context: context, answering: answering)
    await vm.deny()
    #expect(try #require(await answering.answers.last).1 == ["a", "b", "c"])   // then one signed deny per id (NumberMatchApproval.swift:407)
}
```

## Conditions

| # | Condition | Before |
|---|---|---|
| C-1 | S5-01: per-candidate code lengths and variable-length entry on the device; Kit and end-to-end ST-MFA-10/11 tests through the view model; correct the SECURITY §2.102 claim | Either flag on in any environment |
| C-2 | S5-02: a group answer counts as one refusal at the relay; `destination_unverified` is never counted; server test | Either flag on in any environment |
| C-3 | S5-03: `AUTH_NUMBER_MATCHING_REQUIRED` (default on with approvals), with legacy-route refusal and tests | Pilot |
| C-4 | S5-04, S5-05, S5-06 | Pilot |
| C-5 | S5-07 missing tests (concurrent reservation on PostgreSQL, the relay's `relayRequired` and `jti`, deny rate limit, `.notRequested` positive vectors) | Pilot |
