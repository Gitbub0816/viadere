# Code review: no SMS authentication (ADR-0027) and 30-day auth retention (ADR-0026)

- **Roles:** A2 (security), A10 (privacy). Independent reviewer; did not write the change.
- **Scope:** merge `b85033d` (`git log 4a84bde..b85033d -- Server Packages App docs`): `PhoneLinkMO` (Core), `PhoneLinkService`, `phone_link_mo_challenges` / `PhoneLinkMO.v1`, `AuthRetention.v1`, `SMS/GatewayService`, `ChannelRouter` / `ChannelRenderer` / `RCSInbound`, retired `/l/` `/h/` and OTP/link-token routes (410), Kit `PhoneLinkViewModel` and `DeepLink.retiredLink`, `RetentionClass` additions.
- **Binding:** AUTH-OWNER-DECISIONS 1, 9, 10, 16; ADR-0026; ADR-0027 (rev 3); UX_COPY S-PH-01..08, SMS-01..04; STAGE1_A2_REV3_CHECK (S1-A2-7 note: dormant owner); STAGE1_A9A10 (S1-A10-4 spoof indicator mandatory, S1-A10-5).
- **Date:** 2026-11-02

## Verdict

**Superseded by the Re-check below (APPROVE WITH CONDITIONS).** Original verdict: **BLOCK** until F-1 is fixed. F-2 is fixed in this review. Everything else may ship as conditions with owners.

The removal itself holds. No Viadere-sent SMS carries a code, a link with a token or an approval, and the old routes are dead. The new customer-originated proof is built correctly: the nonce is random, keyed-hashed, bound to the sending number, single-use and time-limited. One binding control from the design review is missing in code. ADR-0027 §1.3 (rev 3) says a pending transfer never completes while the current owner has not **fetched** the in-app notice. The implementation completes the transfer when the waiting period ends, whatever the owner saw. A test asserts that behaviour.

## Verification

| What | Result |
|---|---|
| Server (SQLite): `PhoneLinkMOTests`, `AuthRetentionTests`, `SMSGatewayTests`, `RCSTests`, `HardeningTests`, `Round3Tests`, `LinkDomainTests`, `NotificationSettingsTests`, `WP6RetentionTests` | 150 tests, 0 failures |
| Server after the F-2 fix: `PhoneLinkMOTests`, `AzurePlatformTests`, `AppAttestTests`, `WP6EdgeTests`, `WalletTests` | 54 tests, 0 failures (2 skipped, environment-dependent) |
| `Packages/ViadereCore` | 484 tests, pass |
| `Packages/ViadereKit` | 673 tests, pass |
| PostgreSQL run | not run in this review (no database in this container); required before merge per CLAUDE.md rule 6 |

**Each security test fails without its control.** All mutations below were applied together, the two suites were run, and the originals were restored.

| Control removed (temporary) | Test that failed |
|---|---|
| Candidate challenges not filtered by the sender's keyed hash, and the decrypted claimed number not compared with `From` | `testATextFromAnotherNumberNeverBindsAndLeavesTheRealChallengeAlive` (the stranger's text bound the number) |
| `suspectedSpoof` / `notProvided` accepted | `testTheSenderIndicatorIsAHardFail` |
| Expiry guard removed | `testALateTextCannotBindAndANonceIsNotReusable` |
| "Keep my number" no longer revokes the pending transfer | `testAVictimInducedTextCannotTakeALinkedNumberOver` (the number moved to the attacker) |
| P-class grace 2 min → 20 min | `AuthRetentionTests.testAPhoneLinkChallengeIsAPendingSecret…`, `testExpiredChallengesAreSwept…` |
| F-2 fix reverted (default `false` in strict environments) | `testStagingAndProductionRequireASenderIndicatorUnlessExplicitlyWaived` (new) |

**Checked and found sound:**
- **Outbound SMS.** Every enqueue path has fixed copy only: `GatewayCopy` (help, menus, SMS-01 static `/get`, SMS-02, SMS-03, SMS-04, SMS-07), `ChannelRouter.smsRendering` (SMS-04 only, for every link source), and the RCS stale-tap notice. The RCS→SMS fallback goes through `sendSMS`, so it sends SMS-04. `sendAccountLink`, `sendSecureHandoff` and `mintToken` are deleted. The only remaining "verification code" texts are dashboard **email** (`EmailVerification.swift:90`), which is out of scope. Business-authored text (conversation replies, the `message` payload over RCS) is the business's content, not a Viadere credential.
- **Nonce.** `VDR-` plus 8 Crockford characters (40 bits, CSPRNG, unbiased modulo 32). Stored as HMAC(pepper, link id ‖ nonce) and compared in constant time. Candidates are only the challenges for the sending number's keyed hash, and the decrypted claimed number is compared with `From` again. The challenge is deleted on a match, including when a later check fails. TTL is 10 min. Only the newest begin per (account, number) is live. Device trust is re-checked when the number is bound. Extraction is case-insensitive, folds I/L/O, and refuses a match glued to other letters or digits.
- **Assurance.** `phone_control_mo` is a label only. `PhoneLinkRecord` is never read by `AuthService`, recovery or any assurance path. Recovery only re-cools links (`coolDownAll`). `confirmLink` refuses MO links, so the requester's own device cannot shorten the wait.
- **Victim-induced text against a linked number.** The link becomes `pending_transfer` and the existing link keeps routing. The owner gets a stored notice with a Keep action. SMS-02 goes to the number. Churn caps are 1/day and 2/week per number, and pending rows count toward them.
- **Retired paths.** `POST /v1/phone-links/start|verify`, `/v1/sms/link-tokens/redeem`, `GET …/preview` and `/v1/handoff/redeem` answer 410. Web `/l/`, `/h/` serve a static 410 page and never read the token. The Kit maps both to `.retiredLink` and the custom scheme accepts neither. `PhoneLinkMO.v1` revokes pending OTP rows (it clears `otp_hash` and the expiry) and open link tokens, and `AuthRetention.v1` empties `link_tokens`.
- **Retention.** The approve-request metadata is purged at 30 days after the terminal state, by the platform cutoff or a shorter tenant cutoff. A row with a signed result is scrubbed to its evidence subset and then follows `signed_decisions`. Holds are applied per business and per consumer. The catch-up migration skips approve rows while any hold is active, but still empties the bearer `link_tokens`. `auth_secrets` is not holdable. The old 400-day sweep is gone. All of this matches the ADR-0026 table and implementation notes.
- **Logs and audit.** Only masked numbers and reason codes appear. The nonce and the inbound text are never stored, logged or forwarded: the text is handled before the menu engine and the `.handled` path returns before the context is persisted.

## Findings

### F-1 (High): dormant-owner rule not implemented; a pending transfer completes without the owner ever seeing the notice
- **Status:** fixed in 09d7683; re-checked: **closed** for the dormant-owner and holder-change paths, follow-ups R-1 to R-4 (see Re-check). `security_notices.fetched_at` (migration `PhoneLinkTransferNotice.v1`); `completeTransfers` requires wait ended + holder's notice fetched + not kept + holder unchanged (else a fresh notice and a new 24 h wait) + requester device active; the losing account gets a `phoneTransferred` notice. Tests: `testADormantOwnerWhoNeverFetchedTheNoticeNeverLosesTheNumber` (failed before the fix), `testATransferCompletesOnlyAfterTheOwnerFetchedTheNoticeAndTheWaitEndedAndTheOwnerDidNotKeep` (replaces the test that asserted the wrong behaviour), `testAnOwnerWhoFetchedTheNoticeAndKeptTheNumberKeepsIt`, `testWhenTheHolderChangedTheNewHolderIsNotifiedAndTheTransferDoesNotMove`.
- **Where:** `Server/Sources/ViadereServerKit/Services/PhoneLinkService.swift:304-328` (`completeTransfers`); `Models/ConsumerModels.swift:236-262` (`SecurityNoticeRecord` has no fetched marker). The test `Server/Tests/ViadereServerKitTests/PhoneLinkMOTests.swift:339` asserts the wrong behaviour.
- **Issue:** ADR-0027 §1.3 condition (b), as clarified in rev 3 (S1-A2-7 note, CLOSED in STAGE1_A2_REV3_CHECK on that basis), requires that the existing account's app has **fetched** the S-PH-07 notice. If it never does, the transfer stays `pending_transfer` indefinitely. `completeTransfers` moves the number as soon as `usableFrom <= now`. That is 24 h when the requester holds two trusted devices, otherwise 72 h. The test with that name lets the old owner never open the app, and the transfer completes. The attack is a victim-induced text ("text this to confirm your delivery") or a spoofed text. Against a dormant owner, it takes over the routing identity in 24 h, which is exactly the case the rule closes. Second gap: `completeTransfers` revokes **whichever** account holds the number when the job runs. If the original owner removed the number and a third account linked it later, the third account loses it without any notice or Keep option.
- **Required change:** Record when the app fetches each security notice. `GET /v1/security-notices` sets `fetched_at` (additive migration). Complete a transfer only when all of these hold:
  1. The waiting period has ended.
  2. The current holder's `phoneTransferRequested` notice for that link has a `fetched_at`.
  3. The holder did not choose Keep.
  4. The holder is still the account that was notified. If not, notify the new holder and restart condition (b).
  5. The requester's account and proving device are still active.

  Rewrite the test at `:339` so a dormant owner never loses the number, and add tests for "fetched and not kept → moves after the wait" and "holder changed → re-notified, not moved".

### F-2 (High, fixed in this review): the sender indicator was optional in every deployment
- **Where:** `Server/Sources/ViadereServerKit/Config/ServerConfig.swift:146` (default `false`), `:158` (`phoneLinkNumber` defaults to the provider's from number, so linking is on wherever an SMS provider is configured). `SMS/TwilioProvider.swift:49`, `SMS/MailerSendSMSProvider.swift:59` and `Channels/RCSInbound.swift:79` all report `.unsupported`.
- **Issue:** S1-A10-4 and ADR-0027 §1.3 make the aggregator's spoof indicator mandatory: "hard fail, not when provided". The ADR implementation note defers this to a linking feature flag, but no such flag exists. Linking was therefore live in staging and production with no spoof check: any From-forging aggregator path could bind a number, which is R-13 without its main control.
- **Change made:** `PHONE_LINK_REQUIRE_SENDER_INDICATOR` now defaults to **on in staging and production** and stays off in development and tests. An explicit `0` is the only way to turn it off, and an unrecognized value refuses to boot (`ServerConfig.phoneLinkRequireSenderIndicator(_:strict:)`, `:149-156`, wired at `:369`). New test: `testStagingAndProductionRequireASenderIndicatorUnlessExplicitlyWaived`. `Server/README.md` and `docs/SECURITY.md` §2.8 are updated to match.
- **Remaining condition (Medium; owner plus A2):** with the current adapters, every link text is now refused in staging and production, while begin still issues nonces, so people see S-PH-04 after 10 minutes. Before linking is offered, do one of the following:
  - make begin answer `unavailable` while the configured provider cannot report an indicator (an adapter capability flag); or
  - close O-2 with a provider that reports one; or
  - have the owner record a time-boxed exception to set `0` on staging for testing only.

### F-3 (Medium): the P-class challenge sweep does not run every minute
- **Status:** fixed in 09d7683; re-checked: **closed** (job settings in R-5). New `ViadereServer maintenance minute` task (Azure job `minute`, `* * * * *`) runs the sweep and the transfers, each `guarded`; test `testTheMinuteTaskSweepsAnExpiredChallenge`.
- **Where:** `Server/Sources/ViadereServerKit/Jobs/BackgroundJobs.swift:8` (the Azure `maintenance` task runs every 5 minutes), `:95-97`.
- **Issue:** ADR-0026 §3 requires the P sweep every 60 s and no row older than `expires_at + 2 min`. On Azure, expired challenges, which hold the nonce HMAC, the encrypted number and the masked number, can live about 7 minutes past expiry. `purgeChallenges` is also not wrapped in `guarded` and runs late in `maintenance`, so any earlier throw in that task skips it. The security impact is nil: an expired challenge cannot bind and its status reads `expired`. This is a privacy-SLO miss. The ST-PRIV-04 test calls `purgeChallenges` directly, so it does not cover the cadence.
- **Required change:** run the sweep from a once-a-minute path (the queue pump tick or its own scheduled task), wrap it in `guarded`, and add a cadence test or an ops check.

### F-4 (Medium): UNLINK shares the per-number link-text limit and is not subject to the sender check
- **Status:** rate-limit half fixed in 09d7683 and re-checked: **closed** (own `phoneUnlinkPerPhone` bucket; test `testUnlinkIsNotBlockedByAFloodOfLinkTexts`). Forged-UNLINK half: ruled **not acceptable** as a plain fail-safe denial of service, because it can be combined with a victim-induced text to get around §1.3 (see Re-check).
- **Where:** `Server/Sources/ViadereServerKit/SMS/GatewayService.swift:47-51`; `Services/PhoneLinkService.swift:144-146`; `PhoneLinkMOTests.swift:277` documents that the real text is dropped once the limit is hit.
- **Issue:** The R-13 attacker can forge `From`. They can spend the victim number's `phoneLinkMOPerPhone` bucket (burst 10, 20/h) with junk `VDR-` texts, and the real owner's `UNLINK`, their safety valve, is then dropped with no reply. In the other direction, a forged `UNLINK` revokes a victim's link with no indicator check. That fails safe, but it is a cheap denial of service. STOP still works, which bounds the impact.
- **Required change:** give `UNLINK` its own generous bucket, as STOP has, and do not count it against link texts. Either apply the sender indicator to `UNLINK` or record in ADR-0027 that a forged UNLINK is an accepted, fail-safe denial of service (owner, A2).

### F-5 (Low): revoked and refused `phone_links` rows have no retention
- **Where:** `Operations/Retention.swift` (no class covers `phone_links`); ADR-0026 §2 does not list the table.
- **Issue:** Links revoked by UNLINK, by Keep, by a completed transfer or by removal keep the encrypted number, the keyed hash and the masked number for as long as the account exists. The churn caps need only 7 days of history.
- **Required change (A10):** add revoked `phone_links` rows to a T class (30 days after revocation, never fewer than 7), or record the period in ADR-0026 and DATA-INVENTORY.

### F-6 (Low): a `pending_transfer` link is shown as linked
- **Where:** `PhoneLinkService.swift:95-97` (`status` returns `.verified` for `pending_transfer`); Kit `PhoneLinkViewModel.linkedText` (S-PH-05).
- **Issue:** The requester is told "Number linked. Businesses can reach you by text there from {date}". A transfer may never complete: the owner can keep the number, and after F-1 a dormant owner blocks it indefinitely.
- **Required change (A9):** add a distinct status or flag and copy for "waiting for the current owner".

### F-7 (Low): S-PH-07 wording deviates
- **Where:** `Services/SecurityNotices.swift:71-72`.
- **Issue:** The UX_COPY text names the `{masked number}`. The implementation says "a phone number on your Viadere account".
- **Required change (A9):** add the masked number to the stored notice (the push can stay generic), or amend UX_COPY.

### F-8 (Low, owner decision): RCS answers and SMS conversation threads still work for `phone_control_mo` links
- **Where:** `Channels/RCSInbound.swift:149-155`; `SMS/GatewayService.swift` (`loadContext`, `deliverBusinessMessage`).
- **Issue:** ADR-0027 §2 limits a `phone_control_mo` number to on-ramp text and SMS-04 **over SMS**. RCS inline answers for non-sensitive interactions, and business conversation threads opened from that number, continue after the cool-down. The ADR implementation note flags RCS for an owner decision, and OQ-5 covers thread continuity. This is listed so the open question is not lost.

### F-9 (Info): SECURITY.md overstates "spends the challenge"
- **Where:** `docs/SECURITY.md:395`.
- **Issue:** It says every failure spends the challenge. A wrong nonce, or a text from another number, deliberately does not, so the real owner's challenge stays alive (`testATextFromAnotherNumberNeverBinds…`). Correct the sentence.

### F-10 (Info): an ordinary text containing a `VDR-xxxxxxxx`-shaped token is swallowed
- **Where:** `PhoneLinkService.swift:148-158`.
- **Issue:** The text gets no reply and is not forwarded to the business. This is acceptable given the prefix and the length, but monitor it in the begin/MO-mismatch metric (ADR-0027 §3.4).

## Conditions to close

1. F-1 fixed with tests (blocks merge to the release branch).
2. Server suite passes on PostgreSQL (`TEST_DATABASE_URL=… TEST_RATE_LIMIT_STORE=database swift test`) with the F-2 change.
3. The F-2 follow-up decided before phone linking is offered anywhere: a capability-gated begin, O-2 closed, or a recorded owner exception.
4. F-3 and F-4 fixed or accepted in ADR-0026 / ADR-0027 by the owner; F-5 to F-9 tracked.

## Re-check (fix `09d7683` + `03ac508`, merged in `af78c34`)

- **Reviewer, roles:** the same independent A2 + A10 reviewer. Only the fix was re-checked, against ADR-0027 §1.3 (rev 3) and the required change listed under F-1.
- **Date:** 2026-11-02

### Verification

| What | Result |
|---|---|
| Server (SQLite) `PhoneLinkMOTests` | 27 tests, 0 failures |
| Server (SQLite) `AuthRetentionTests`, `SMSGatewayTests`, `RCSTests`, `NotificationSettingsTests` | 53 tests, 0 failures |
| New compiler warnings from the fix | none. The `PhoneLinkMOTests` warnings at `:130`, `:460` and `:509` predate it (`f624d954`). |
| PostgreSQL | not run (no database in this container). Condition 2 still stands, and R-2 below can only show up there. |

**The new tests fail when the fix is removed.** The mutations were applied in two rounds, each rebuilt and run, and the sources were restored afterwards.

| Control removed (temporary) | Test that failed |
|---|---|
| `fetchedAt != nil` guard in `completeTransfers` | `testADormantOwnerWhoNeverFetchedTheNoticeNeverLosesTheNumber` (the number moved and the old link was revoked) |
| `isLinkText` counts UNLINK again (shared bucket) | `testUnlinkIsNotBlockedByAFloodOfLinkTexts` (no reply; the link stayed) |
| `purgeChallenges` dropped from `minute()` | `testTheMinuteTaskSweepsAnExpiredChallenge` |
| Holder-changed re-notify branch disabled | `testWhenTheHolderChangedTheNewHolderIsNotifiedAndTheTransferDoesNotMove` (the new holder was never told) |
| `pending()` no longer sets `fetched_at` | `testATransferCompletesOnlyAfterTheOwnerFetchedTheNoticeAndTheWaitEndedAndTheOwnerDidNotKeep` |

### F-1: closed

The finding is fixed. A dormant owner whose app never fetches the notice keeps the number indefinitely. When the holder changes, the new holder gets a new notice and a new 24 h wait, and the losing account is told in the app. Checked against the questions this re-check had to answer:

- **Who can record "fetched".** Only `GET /v1/security-notices` and the dismiss call write it. Both are `deviceSignedBearer` and scoped to `principal.consumerId`, so a device on the requester's account, including the attacker's own, cannot fetch or mark the holder's notices. "Fetched" is therefore always recorded by a device-signed app instance of the holder's account. That device does not have to be **trusted**, though (R-1).
- **Clock and time zone.** No client time is involved. `usableFrom`, `createdAt` and `fetched_at` all come from server `ctx.now` as absolute `Date`s (`timestamptz` on PostgreSQL). The notice is written after the pending row, in the same transaction, so `createdAt >= pending.createdAt` holds. The re-notify path runs at least 24 h after the pending row was created, so ordinary clock skew between instances cannot misorder it.
- **Concurrent requests for one number.** "Keep" revokes every pending row for the number. A second request's notice can satisfy the first request's fetch condition, but the holder sees the same "Keep my number" action either way. Accepted.
- **Fetched but never shown, and keep/complete races.** These gaps remain. They are recorded as R-1 and R-2. Neither reopens the dormant-owner attack.

### F-3: closed

`minute()` runs the sweep and the transfers, each `guarded`. The Azure `job-viadere-minute` runs at `* * * * *`, and the in-process loop gates it to once a minute. **Least privilege:** the job reuses the existing worker user-assigned identity and the full worker secret set: the PostgreSQL `viadere_worker` role (data only), Service Bus, Blob and the worker's Key Vault secrets. That is the same as the `maintenance` job, so it adds no new grant. It is still wider than the job needs (database, pepper and cipher, APNs). Accepted for the lean profile. The settings follow-ups are in R-5.

### F-4: rate-limit half closed; forged UNLINK ruled not acceptable as it stands

UNLINK now has its own bucket, and the test proves that a flood of link texts cannot block it. The forged-UNLINK half is **not** only a fail-safe denial of service:

1. A forged UNLINK, which is never indicator-checked, revokes the dormant owner's link.
2. A victim-induced text (R-13b), sent from the real phone, then passes the indicator check. It binds the number as a fresh `verified` link, not `pending_transfer`, because no holder is left. The old owner's §1.3 protection (an in-app notice they must fetch) is bypassed.

SMS-03 and SMS-02 still reach the phone, and the cool-down still applies, so this is **Medium**, not High.

Required before linking is switched on (owner + A2, record in ADR-0027):
- Refuse UNLINK when the indicator is a positive `suspectedSpoof`. Keep accepting `unsupported` and `notProvided`, so the real owner's safety valve keeps working with the current adapters.
- For a set period after an UNLINK (suggested 7 days, the same window as the churn cap), a new link for **another** account goes through the §1.3 pending-transfer rule against the account that was unlinked. That account must fetch the notice and not keep the number.

Add a test for that composition.

### New findings

**R-1 (Medium): "fetched" is not "seen", and a device in cool-down can fetch but cannot keep.**
- **Where:** `Services/SecurityNotices.swift` `pending()`; Kit `SecurityNoticesViewModel.current`; App `AlertsView.swift:63`, `SettingsView.swift:172`; `AppModel.bootstrap`; `PhoneLinkService.keep` (`DeviceTrust.require`).
- **Issue, part 1:** `pending()` marks every one of up to 50 returned notices as fetched. The app shows only the newest (`current`, with a "+N" count). It also loads notices on cold launch even when the app-lock screen is up. So an owner who opens the app while a newer notice exists records `fetched_at` on a transfer notice that was never on screen. This meets the ADR's word ("fetched") but not its intent ("notified in app").
- **Issue, part 2:** any active device of the holder can record the fetch, but Keep requires a trusted device. An owner on a new phone that is still in cool-down sees the notice and is refused "Keep". The number then moves when the wait ends. UNLINK from the phone remains their only remedy.
- **Required change (before linking is offered):**
  - Do one of:
    - Record an explicit acknowledgement for the specific notice when it is rendered (a `seen` call from the banner).
    - Always rank `phoneTransferRequested` as `current`.
  - Allow "Keep my number" from any active app device of the holder. It only preserves the status quo. Alternatively, count only fetches made by a trusted device.

**R-2 (Medium): lost-update races between complete and Keep/UNLINK; overlapping job runs.**
- **Where:** `PhoneLinkService.completeTransfers` re-reads the pending row with `find` but takes no lock. `keep` and `unlink` likewise update rows by id with no state predicate.
- **Issue:** On PostgreSQL (READ COMMITTED), a Keep or UNLINK that commits between the job's read and its write is overwritten. The number moves despite Keep, or an UNLINKed pending row is set back to `verified`, which fails unsafe. On Azure, `maintenance` (every 5 min, ungated) also calls `minute()`, so two `completeTransfers` runs overlap every 5 minutes. The `job-viadere-minute` `replica_timeout_in_seconds = 1800` also lets a stuck run overlap the next ones. The window is milliseconds, but the job runs every minute.
- **Required change:**
  - Lock the pending row and the holder rows (`DatabaseSupport.lockForUpdate`) inside the transaction, or use conditional updates (`WHERE state = 'pending_transfer'`) and check the affected row count. Do the same in `keep` and `unlink`.
  - Drop `minute()` from the ungated `maintenance` task.
  - Add a PostgreSQL test.

**R-3 (Low): requester condition weaker than required.** `completeTransfers` counts any non-revoked device of the requester. F-1 item 5 asked for the requester's **account** (status `active`) and the **proving device** (not revoked, not expired). Check both.

**R-4 (Low, fail-safe): a notice older than 30 days is never fetched, and nothing re-notifies.**
- **Issue:** `pending()` returns only notices from the last 30 days. If the owner opens the app after day 30, the old notice is never returned, so it is never fetched. Because it still exists, `notices.isEmpty` is false and no new notice is written. The transfer then stays pending for good while the owner is active again. The migration comment says pre-migration notices are "re-notified by the job", but that happens only when no notice row exists.
- **Required change:** re-notify when the newest matching notice is unfetched and older than the list window, and correct the comment. Track this with F-6.

**R-5 (Low, ops): minute job settings.**
- Set `replica_timeout_in_seconds` for `minute` below 60 s.
- Confirm the ~1,440 executions a day fit the lean budget (Container Apps consumption seconds).
- Track a narrower identity or secret set for the job in the `standard` profile.

### Verdict

**APPROVE WITH CONDITIONS.** F-1, the blocking defect, is fixed and tested, and the release-branch block is lifted.

Phone linking must stay **off** until all of these are done. The F-2 condition already keeps it off in practice, because every link text is refused with the current adapters.
- R-1 and R-2 are fixed.
- The forged-UNLINK composition (F-4) is closed or explicitly accepted by the owner in ADR-0027.
- Condition 2 (PostgreSQL run) has passed.

R-3 to R-5, and F-5 to F-9, are tracked with owners.

## Sign-off

Agent review record: A2 + A10 independent code review of `b85033d` (SMS-authentication removal, ADR-0027; auth retention, ADR-0026). Verdict **BLOCK** (F-1); F-2 fixed in this commit. Reviewer: Claude Code agent, 2026-11-02.

Re-check of `af78c34` (F-1/F-3/F-4 fix): verdict **APPROVE WITH CONDITIONS** (R-1, R-2, the forged-UNLINK composition, PostgreSQL run before phone linking is enabled). Reviewer: Claude Code agent, 2026-11-02.
