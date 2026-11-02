# Stage 4 code review: authentication delivery on the device (A2 security + A6 iOS), 2026-11-02

| | |
|---|---|
| Reviewer roles | A2 (application security) and A6 (iOS). Independent of the author: did not write any reviewed code |
| Change reviewed | Merge `ca7601d` (`git log 3295db8..ca7601d`: `6204044`, `6bd864d`, `9f94812`, `f8c60b9`); `git diff 3295db8 ca7601d -- Packages App docs` |
| Binding design | ADR-0021 §3-§4, ADR-0022 §2-§5, §8, ADR-0031 §4, ADR-0033 §4.1 (revision 3.1 caps), UX_COPY, FLOW_MATRIX, THREAT_MODEL ST- tests, STAGE1_A2_REV3_CHECK, STAGE1_A3_REV3_CHECK (Stage 4 rows) |
| Ran | `Packages/ViadereKit` `swift test` (672 tests, 102 suites, all pass after the fixes below, no warnings); `Packages/ViadereCore` rendering suite (9 pass); `swiftc -parse` on every touched App file (pass). `Server` not built (out of scope, disk) |
| Not possible here | Compiling the App targets (Xcode 27.1 / iOS SDK), notification and watch delivery, Face ID, Keychain accessibility while locked |

## Verdict: **APPROVE WITH CONDITIONS**

The core controls are present and tested.

- **Approve.** It runs only in the app. It needs Face ID: the approval key is biometric-bound, and `ApproveRequestHandler.answer` signs through `PromptBoundKey`. No auth category has an approve action. A legacy security approve from a notification returns `.requiresApp`. The watch is refused on both paths.
- **Links and hand-offs.** No path auto-redeems a `/h/` hand-off. `redeemHandoff` has exactly one caller, `HandoffConfirmationViewModel.open()`. No path opens a link destination: `openLink` and `UIApplication.open` are reachable only through `LinkConfirmationViewModel.proceed()`. That call is gated on a verified host, re-checks the returned URL, and ships with `FailClosedDestinationVerifier`.
- **Lock Screen and logs.** No code, link, amount or business name is drawn on the Lock Screen by default. Nothing in the new code logs a code or a URL.

I found one **High** bypass of the three-strikes rule and fixed it with a test. Two smaller bugs were also fixed with tests. The open items below are conditions, not blockers. Number matching is inert until the Core v2 wire lands. The wrong-entry counter does not survive a dismissal or a relaunch. Notification Deny cannot succeed until the auth-delivery client and the server's `req` key exist. One Live Activity construct is likely to fail strict-concurrency checking in Xcode.

## Findings

Severity scale: Critical / High / Medium / Low / Info. "Fixed" means fixed in this review's commit, with a test that fails without the fix (checked by reverting it).

### R4-01 — High — FIXED — three wrong entries could be followed by an approve

- **Where:** `Packages/ViadereKit/Sources/ViadereKit/AuthDelivery/NumberMatchApproval.swift` (`canApprove`, `approve()`, `submit`).
- **Issue:** The third wrong entry submits the automatic `number_mismatch` deny. If that submission failed, `submit` put the screen back to `.entering`, for example because Face ID was cancelled on the "Decline the request" prompt (which the in-app deny needs) or because the phone was offline. `canApprove` did not look at `wrongEntries`, so a fourth entry with the right number signed an **approve**. The person, or someone coaching them, got unlimited further guesses on a 2-digit code. This breaks ADR-0022 §2 item 4 and §5.2 item 2 ("the third makes the device submit a signed deny"). Reproduced with the new test before the fix: the approve was sent.
- **Change made:** `wrongEntryLimitReached` (`wrongEntries >= 3`) now disables Approve for good. `deny()` resends the `number_mismatch` denial of the whole group, ending in `.autoDenied`. Test: `aFailedAutomaticDenialNeverReopensApprove`.

### R4-02 — Medium — CLOSED (Stage 5) — the three-strikes counter is per screen, not per request

- **Where:** `NumberMatchApproval.swift:103` (`wrongEntries`, in memory only); `App/Viadere/Features/Approve/ApproveRequestSheet.swift:45`, `:73`.
- **Issue:** ADR-0022 §2 item 4 says "up to 3 wrong entries **per request** (local counter)", and §5.2 item 2 says "3 per group". The counter lives in the view model, which is built anew each time the sheet opens. Two wrong entries, then a dismissal (swipe-down is allowed; only the handle asks "Leave this request?"), then a reopen, give three fresh tries. So does a relaunch. The counter is not reported either (`invalid_match_attempts`, see R4-04), so nothing upstream sees the attempts.
- **Required change:** Persist the wrong-entry count per request id (or per group key) in the approval store, alongside `LocalDecision`. Keep it until the request leaves the open set. Seed the view model from it, and add a test that a new view model for the same request starts at the stored count. Also make swipe-dismiss go through the same "Leave this request?" confirmation once `wrongEntries > 0`.

### R4-03 — Medium — CLOSED (Stage 5; production flag stays off until the pilot) — notification Deny on `viadere.approve` cannot succeed in the shipping build

- **Where:** `NotificationActionHandler.handleAuthDelivery`; `ViadereServices.swift:35` (`authDelivery = UnavailableAuthDeliveryAPI()`); `NotificationModel.swift:61`; server `ApproveSupport.pushRequest` (sends `category: "viadere.approve"` with no `req`, and `interruption-level: time-sensitive`).
- **Issue:** Stage 4 registers the `viadere.approve` category, so every Approve v2 push the server sends today now shows **Deny** on the Lock Screen. In the shipping build that Deny cannot work, for two reasons:
  1. The server's push carries no `req`. The handler therefore returned `.openRequests` from a background action (`opensApp: false`). The app is never brought forward, so nothing was shown and nothing was sent, and the person believed they had denied. **Fixed:** that path now also posts N-09 ("Deny not sent yet. Open Viadere."). The test `aDenyWithoutAUsableIdOpensTheRequestListInsteadOfGuessing` is extended and fails without the fix.
  2. With a `req`, `reduce` goes to `UnavailableAuthDeliveryAPI` and always fails. N-09 is posted, which is honest, but the action never denies.
- **Required change (before release):** Do one of the following before a build that registers `viadere.approve` ships:
  - wire `AuthDeliveryAPI.reduce` to a server endpoint that accepts a request-key-signed reduce-only deny, and have the server put `req` in the Approve v2 push; or
  - drop the Deny action from `approveCategory` behind `AuthDeliveryFlags` until both exist.

  Separately, the server still marks these pushes `time-sensitive`. That contradicts ADR-0022 §5.5, which Core's `ChannelRenderer` now follows. This is a server item, so it is logged here for the Stage 5/server owner. F-14 and F-15 routing (`req`) is inert until the server sends `req`.

### R4-04 — Medium — CLOSED (Stage 5) — number matching is inert on the shipping path

- **Where:** `NumberMatchApproval.swift` `NumberMatchApprovalContext.init(prompt:numberMatch:)` (`requiresNumber: numberMatch != nil`, and `ApproveRequestSheet` always passes `nil`); `ApproveControllerAnswering.answer` (drops `match` and `deny_reason`).
- **Issue:** The code says, and the comment admits, that `number_match` is not yet in the business-signed request. So today every Approve v2 request is approved **without** a number. The signed result carries no `match`, no `deny_reason: number_mismatch` and no `invalid_match_attempts`. The device logic is correct and well tested, but it protects nothing in production until the Core `ApprovalResult` v2 wire lands. The fail-closed switch (`requiresNumber`) depends on whether the requirement is present. It does not depend on a policy that says "this business or request kind must be number-matched". A relay that strips `number_match` would therefore silently downgrade a request.
- **Required change (before the pilot, with the Core and server work):** Add `number_match` to the signed request content, so the relay cannot strip it, and `match`, `deny_reason` and `invalid_match_attempts` to the signed result. Derive `requiresNumber` from signed policy (payments and high or critical risk always; ADR-0022 §2.1), not from whether a requirement is present. Do not mark the ST-MFA number-matching tests as passing before then.

### R4-05 — Medium — OPEN (needs Xcode) — Live Activity disclosure property is probably main-actor isolated

- **Where:** `App/ViadereWidgets/ViadereLiveActivityWidget.swift:27`.
- **Issue:** `private static var disclosure` is declared on a type that conforms to `Widget`, a `@MainActor` protocol in current SDKs, so the property is inferred to be main-actor isolated. It is read inside the `ActivityConfiguration` content and Dynamic Island closures. The author's own commit `6204044` established that those builders are **not** main-actor isolated (it made `viadereProtectedSurface()` and `viadereNightSurface()` `nonisolated` for that reason). Under `SWIFT_VERSION 6.0` this is very likely the error "main actor-isolated static property 'disclosure' can not be referenced from a nonisolated context".
- **Required change:** Mark it `nonisolated private static var disclosure` (`UserDefaultsPreferences` and `LiveActivityDisclosure` are both nonisolated and `Sendable`), then build in Xcode 27.1. I did not change it, because the change cannot be verified on Linux.

### R4-06 — Low — FIXED — the constant-time compare could equate lengths that differ by 256

- **Where:** `Packages/ViadereKit/Sources/ViadereKit/AuthDelivery/NumberMatch.swift` `constantTimeEqual`.
- **Issue:** `UInt8(truncatingIfNeeded: a.count ^ b.count)` is 0 when the lengths differ by a multiple of 256, and the missing bytes compare against 0. As a result, `evaluate(entry: "47" + 256 × NUL)` returned `.match`. The UI cannot reach it, because `applyEdit` admits only digits and caps the length, but `evaluate` is public.
- **Change made:** The length mismatch is now a separate whole bit. Test: `lengthDifferencesAreNeverTruncatedAway`.
- **Timing (confirmed):** The loop has no early exit, every candidate is compared, and the only data-dependent branch is the `hits.append`, which follows the comparison. That is adequate for a 2-3 digit local compare whose result is shown to the person anyway.

### R4-07 — Low — OPEN — a `viadere.auth.code` tap opens the link confirm screen

- **Where:** `NotificationModel.swift:103` and `NotificationActionHandler.swift:109`. Both the `link` and `code` categories map to `.authDelivery(id)`, which leads to `PendingAuthDelivery` and then `LinkConfirmationSheet`.
- **Issue:** A code delivery is shown through the link flow: it fetches `linkDisplay` and then fails closed (`notYetSupported`, S-LINK-09 wording). That is safe, but it is the wrong screen, and the wording says "we didn't open it" about a code.
- **Required change:** Carry the category in the target (or a `kind`), and route code deliveries to the code screen (shown after unlock, never on the Lock Screen) when it is built. Until then, show E-03 or N-08 instead of the link failure copy.

### R4-08 — Low — OPEN — the neutral Live Activity still draws the business's Brand Kit accent

- **Where:** `ViadereLiveActivityWidget.swift:39`, `:46` (`accent: context.attributes.accent` on the decision views and the island keyline).
- **Issue:** In `.neutral` mode the text is Viadere's own, but the keyline, the stage dot and the trailing text use the business's accent for non-security decisions. A recognisable brand colour on the Lock Screen is a weak "which business" hint, which F-09 means to remove.
- **Required change:** Pass `ViadereColor.accent` whenever `disclosure == .neutral`.

### R4-09 — Low — OPEN — "the system declined to open" is reported as a wrong destination

- **Where:** `LinkConfirmation.swift:235`.
- **Issue:** When `UIApplication.open` returns false, the screen says S-LINK-08, "not the business's site". That accuses a verified host. Nothing is re-sent, so this is copy only.
- **Required change:** Use its own phase or E-02 wording.

### R4-10 — Info — confirmed controls

These were confirmed by reading the code and by **reverting each control and re-running its test**. Every test failed without its control:

- Paste, AutoFill and replace refusal in `applyEdit` (`theFieldRefusesPasteAutoFillAndNonDigits`).
- The on-device re-check of the returned URL's host (`theUrlTheServiceReturnsIsCheckedAgainOnTheDevice`).
- Watch refusal of a security approve on the legacy path (`theWatchNeverApprovesASecurityItem`).
- Neutral Live Activity by default (`theDefaultLockScreenIsNeutral`).
- Deny without unlock on `viadere.approve` (`approveCategoryIsReviewAndDenyOnly`).
- The threshold of three (`aWrongNumberIsAnnouncedAndThreeWrongEntriesDenyTheGroup`).

Also confirmed:

- **Routing ids.** `req` is a bounded `[A-Za-z0-9_-]{1,64}` and `adl` is a UUID. The category decides which key is read. `presentRequest(key:)` only selects among prompts that were already verified, so a wrong or replayed `req` can at worst deny, and only via the reduce-only path. Stale or expired requests are refused by the relay. Nothing is queued.
- **Deep links.** `DeepLinkRouter` never produces `.authDelivery` or `.approveRequest` from a URL. The neutral Live Activity opens `viadere://i/{id}` only.
- **App lock.** While the app lock is on, routing is queued, and the queue is capped at 5.
- **Watch.** Mirrored categories register Deny and Report only. The phone refuses every other decision for auth categories before calling the handler.
- **Device-add screens.** They sit behind `AuthDeliveryFlags.deviceAddComparison`, which is off and presented nowhere. The new device shows the code only when the challenge's `kids` equal its own exactly. The existing device has no API that returns the code. ADR-0033 §4.1 was amended with the S3-A3-01 / S3-A2-1 caps before these screens were built, so the A3 Stage 4 row is met. No authority key is pinned yet (L-2 / C-6 is not triggered).
- **Copy and logging.** No new `print`, `Logger` or `os_log` call. Codes and URLs are not written anywhere except the system open.

### R4-11 — Info — the `HostPresentation` registrable-domain heuristic

Without the Public Suffix List, the "strong" part is a heuristic: for example `evil.blogspot.com` emboldens `blogspot.com`. The full host is always shown, so this is acceptable for the stage. Ship the PSL, or make the bold span cover the full host, when Stage 6 turns verification on.

## Swift 6 / `#if canImport` notes (A6)

- **Kit view models.** They are `@MainActor`, and `@Observable` sits under `#if canImport(Observation) && !os(Linux)`, which is correct and builds on Linux. `ApproveControllerAnswering` (`@MainActor`) satisfies a `Sendable` protocol whose single requirement is `async`, so the isolated witness is legal.
- **App files.** They parse. Watch: `WatchModel` is `@MainActor`, and its `UNUserNotificationCenterDelegate` methods are `nonisolated async` and hop with `MainActor.run`. That is fine. `NumberEntryField.Coordinator` inherits main-actor isolation from `UITextFieldDelegate`, which is fine.
- **Probable compile error:** R4-05 only.

## Needs a real device (Stage 4 device checklist)

1. **Locked-phone actions.** Deny (`viadere.approve`) and This wasn't me (`viadere.auth.link`, legacy `viadere.authenticate` and `viadere.authorize`) run on a locked phone after first unlock. Check the request-key Keychain accessibility, check the background window, and check that N-09 appears when offline.
2. **Number field.** On iOS 27 it offers no QuickType or "From Messages" code suggestion, no paste (edit menu, hardware ⌘V, drag, Universal Clipboard), and no dictation of more than one digit. VoiceOver announces a wrong entry.
3. **Failed automatic denial (R4-01).** Cancel Face ID on the automatic `number_mismatch` denial: Approve stays disabled and Deny retries it.
4. **Mirrored actions on the watch.** Check whether they are delivered to the watch app's delegate (with the watch app installed) or to the iPhone app, and that in either case only Deny and Report exist and an unreachable phone shows W-05.
5. **Lock Screen and Dynamic Island.** With `liveActivityLockScreenDetails` off they show "Decision needed / Open Viadere to see it." with no business text, both for a locally started activity and for a remote APNs content-state update.
6. **Hand-off and link sheets.** A universal link `/h/{token}` opened from Mail or Messages shows the confirm sheet and redeems only on Open. A link push's Open shows the confirm sheet, and Continue stays disabled (fail closed).
7. **Build (R4-05).** Build all targets in Xcode 27.1 with Swift 6 language mode and fix the widget isolation if it fails.

## Sign-off

Agent review record: Stage 4 code review by A2 (security) and A6 (iOS), independent reviewer agent, 2026-11-02, at `ca7601d` plus this review's fixes (R4-01, R4-03 item 1, R4-06).

- **Verdict:** **APPROVE WITH CONDITIONS.**
- **Before release of a build that registers `viadere.approve`:** R4-03. *Closed in Stage 5:* the server sends `req` with `interruption-level: active` and `apns-collapse-id`, and accepts the request-key reduce-only deny (`POST /v1/approve/requests/{id}/deny`, `AuthApprovalTests.testTheNotificationDenyIsReduceOnlyAndCountsTowardThePause`); `LiveAuthDeliveryAPI.reduce` is wired; `AuthDeliveryFlags.forConfiguration` turns the Deny action on for staging and local builds only.
- **Before the pilot:** R4-02 and R4-04. *Closed in Stage 5:* R4-02 — wrong entries persist per request id in `ApproveLocalState.matchAttempts`, the sheet seeds from it and cannot be swiped away after a wrong entry (`NumberMatchStage5Tests.theWrongEntryCountSurvivesANewScreenForTheSameRequest`); R4-04 — `number_match` is inside the business-signed request (v2), `match`/`deny_reason`/`invalid_match_attempts` inside the signed result, `requiresNumber` comes from signed or digest-bound policy (payments always), and `ApproveRequestSheet` builds its context from the verified group (SECURITY 2.102).
- **Before the first device build:** R4-05.
- **Before Stage 6 closes:** R4-07 to R4-09 and R4-11.
