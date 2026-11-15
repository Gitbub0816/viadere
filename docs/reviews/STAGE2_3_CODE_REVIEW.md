# Stage 2–3 code review: auth delivery, match codes, webhook signature v2

| | |
|---|---|
| Roles | A2 (security), A3 (cryptography), A10 (privacy). Independent reviewer, not the author |
| Scope | Merge `345f103` (`ab3b549`, `d1797c8`, `eaa9303`): `Server/Sources/ViadereServerKit/AuthDelivery/`, `Packages/ViadereCore/Sources/ViadereCore/AuthDelivery/`, `WebhookSignatureV2` (Core and Business SDK), `WebhookService` v2 delivery, `contracts/`, migrations `AuthDelivery.v1` and `AuthMatchTags.v1`, `docs/protocol/vectors/webhook-v2.json`, SECURITY §2.101, flag `AUTH_DELIVERY_ENABLED` |
| Binding design | ADR-0020 (revisions 3 and 3.1), ADR-0021, ADR-0025, ADR-0026, ADR-0031; THREAT_MODEL ST- catalogue; STAGE1_A2_REV3_CHECK and STAGE1_A3_REV3_CHECK conditions (C-13, C-14) |
| Tests run | Server `AuthDelivery\|AuthGrouping\|Webhook` filter: 90 tests pass on SQLite and on PostgreSQL 18 (`viadere_review23`, `TEST_RATE_LIMIT_STORE=database`). This includes the 4 tests this review added. ViadereCore `AuthDelivery\|MatchGroup\|WebhookSignatureV2`: 42 pass. Business SDK `WebhookSignatureV2`: 4 pass. The `webhook-v2.json` vectors were recomputed independently in Python (string to sign, MAC and `Content-Digest`), and all three match |

## Verdict

**APPROVE WITH CONDITIONS.** No Critical or High findings. The flag stays off in staging and production. Before the pilot, the conditions below must be met.

The core controls hold:

- **Tenant isolation.** The tenant comes from the API key only, and `tenant_id`/`audience` in the body are refused. Read, cancel and complete return a byte-identical `404` across tenants, and the attempt is audited. Device routes check `consumer_id`, so delegates get a `404`.
- **The secret is returned once.** It goes into a transaction with a version compare-and-swap, the secret row is deleted in the same transaction, the response carries `no-store`, and a concurrent-open test covers the race.
- **OPENED never means success.** Only the business moves a delivery from `opened` to `completed` or `failed`.
- **Push payloads are opaque.** They hold a generic alert and `adl` only.
- **Logs follow an allow-list.**
- **Destinations are strict.** URLs are https only, with no userinfo, no port and A-labels only, and the host must be exactly on an allow-list. Business-mode links fail closed until Stage 6.
- **Webhook v2 signs the right fields.** The MAC covers method, host, path and query, timestamp, event id, tenant, kid and the body digest. Every field has a closed charset with no LF. `auth.*` events never carry `v1=`.
- **Match-code allocation follows the rule.** It is collision-free and prefix-free, needs 3 digits from 30 open requests, and the lockout bound of at least 639 attacker requests is tested.
- **No budget can be used to lock anyone out.** Per-subject budgets and reports only make deliveries silent. The per-tenant `429` is the only refusal.

Two Medium defects were fixed in this review, each with a test (R23-01, R23-02).

## Findings

| # | Severity | Location | Issue | Required change | Status |
|---|---|---|---|---|---|
| R23-01 | Medium (A3/A10) | `Server/Sources/ViadereServerKit/AuthDelivery/AuthDeliveryService.swift:94` | The create `request_hash` was an **unkeyed** SHA-256 of the canonical request JSON, which includes `otp.code` (4–10 characters, often 6 digits) and `variables`. It is stored in `auth_delivery_records.request_hash` and `business_idempotency.request_hash`. All the other request fields are known or stored, so anyone who can read the database can enumerate about 10^6 candidates and recover a live code. That defeats the separately keyed `AUTH_SECRET_KEY` sealing (P class) | Hash with the server pepper (`ctx.hasher.hmacHex("auth_delivery.create", …)`) | **FIXED** in this review. Test `AuthDeliveryReviewTests.testTheStoredCreateHashIsKeyedAndCannotBeEnumeratedToTheCode` checks that neither stored hash equals the unkeyed digest, and that replay and conflict still work |
| R23-02 | Medium (A2) | `Server/Sources/ViadereServerKit/Services/WebhookService.swift:386` (`enqueueAuthSample`) | `POST /v1/business/webhooks/test` (sample `auth.*` events) skipped three gates that `sendTestEvent` enforces: ownership verification (SEC-API-006), the paused-endpoint check and the `webhook-test` rate limit. Delivery does not re-check `verifiedAt`. Any test-mode key could therefore send unlimited signed POSTs to an **unverified** URL, which is a reflection and abuse channel | Apply the same three gates | **FIXED** in this review. Test `testSampleAuthEventsNeedAVerifiedUnpausedEndpoint` (ownership verification on: unverified → `409`, paused → `409`, verified → `200`) |
| R23-03 | Low (A2) | `WebhookService.swift` deliver path (`else if delivery.eventType.hasPrefix("auth.")`) | The delivery-time block that stops an `auth.*` event going to a v1 subscription was not mutation-checked. When I removed it, every existing test still passed | Add a test that fails without it | **FIXED**. Test `testAQueuedAuthDeliveryForAV1SubscriptionIsNeverSent`: the delivery is not sent, status is `dead`, and `lastError` is `signature_unavailable`. Mutation-checked: with the block removed, the test fails (status `succeeded`) |
| R23-04 | Low (A2) | `AuthDeliveryService.swift:96` (request-id lookup) and the `(business_id, request_id)` uniqueness | The `request_id` lookup and its uniqueness ignore `livemode`, although `record()` enforces it. A test-mode key that reuses a live `request_id` gets `409` (or, with a byte-identical body including the code, the live delivery's view). Test and live namespaces should not interact | Scope the lookup, and the unique index, by `livemode` | Before pilot |
| R23-05 | Low (A2/UX) | `Server/Sources/ViadereServerKit/Push/APNSwiftSender.swift` (alert path drops `PushMessage.collapseID`); `AuthDeliveryDevice.swift:143` | There is no `apns-collapse-id` (ADR-0020 §6.2). A retried dispatch after an ambiguous APNs failure, or a token registered twice, can show duplicate alerts | Plumb `collapseID` through the APNs alert path and set it to the delivery id | **FIXED** (Stage 5): `APNSwiftSender` sets `collapseID`; auth deliveries use the delivery id, Approve pushes the device's request id |
| R23-06 | Low (A3) | `Packages/ViadereBusinessSDK/Sources/ViadereBusinessSDK/WebhooksSignatureV2.swift:74,99` | `replayStore` is optional and defaults to `nil`, so a receiver that copies the minimal example accepts a replay inside the 300 s window. The signature binds the event id, but nothing enforces deduplication | Make `replayStore` a required parameter of `verifyEnvelope` (`auth.*` events), or fail closed without one. State the store as mandatory in BUSINESS-INTEGRATION.md | Before the SDK is published to pilot partners |
| R23-07 | Low (A2) | `Packages/ViadereCore/Sources/ViadereCore/AuthDelivery/AuthDestinationValidator.swift:101` (`checkRedirects`) | The open-redirect heuristic checks query values only. It does not check fragment parameters (`#next=https://evil`, common in SPA routers), path segments (`/r/https://evil`), values that decode to leading whitespace or control characters (`%09//evil`, which browsers strip), or double encoding. The host allow-list and the business-signed statement remain the primary controls, so this is defense in depth | Extend rule 5 to fragment parameters. Refuse values that decode to control or whitespace characters. Document that the business owns redirects on its own host. Add refusal-corpus cases (ST-ML-11) | Before business links can be enabled (Stage 6) |
| R23-08 | Low (A2, availability) | `AuthDeliveryService.swift:338` (`sweep`) | Each sweep loads **every** terminal delivery id (unbounded `.all()`) to delete leftover secrets. That cost grows with 30 days of history on every run | Delete with a join or subquery, or bound the batch the way the expiry query is bounded (`limit(500)`) | Before pilot |
| R23-09 | Low (A2) | `Server/Sources/ViadereServerKit/AuthDelivery/AuthGrouping.swift` (`AuthMatchGroups.check`) | `match_prefix_tag` is not validated with `AuthMatchTags.isValidTag` (only `match_tag` is). Any non-nil string marks the request as 3-digit | Validate `match_prefix_tag` like `match_tag` | **FIXED** (Stage 5): `AuthMatchGroups.check` validates `match_prefix_tag` (`AuthApprovalTests.testTheRouteIsShapedAndGated`) |
| R23-10 | Info (A3) | `docs/protocol/vectors/webhook-v2.json` | The vectors are positive cases only | Add negative vectors: a `v1=`-only header, duplicate `kid`, two `t=`, tenant mismatch, digest mismatch, and a path differing only in percent-encoding case. The TypeScript and Kotlin SDKs will consume these | Before other-language SDKs |
| R23-11 | Info | C-14 (STAGE1_A2_REV3_CHECK) | Match-code allocation exists as Core policy plus a server store with tests. It is **not wired** to any route, because deliveries carry no code and approvals are Stage 5. The SDK has no tag, redraw or per-requester throttle helper yet. The `409` codes are in the contract | Unchanged: ST-MFA-11 must pass before the pilot, and the SDK helpers must ship the throttle as a default (C-14) | Stage 5 / pilot |

Checked and found sound (no finding):

- **Cross-tenant cancel, complete and read.** All return `404` before any idempotency write.
- **Webhook PATCH and test.** Both are filtered by `businessId`.
- **Queue handlers.** They dead-letter on a tenant mismatch.
- **The `open` race.** There is no secret on a lost compare-and-swap, the transaction rolls back, and an expiry commits outside the refused transaction.
- **Deny.** It is reduce-only and needs a device credential. Only the customer's own devices can file a report, so the report count cannot be raised by a stranger.
- **Secret ciphertext.** It is bound to the row and uses a key separate from `DATA_ENCRYPTION_KEY`, which the config enforces.
- **Strict config.** Staging and production refuse `AUTH_DESTINATION_SIGNATURE_REQUIRED=false` and `AUTH_LIVE_KEY_ASSURANCE=none`.
- **Bearer material** is absent from:
  - the push payload;
  - logs (allow-list, route template);
  - audit metadata (ids, method, purpose, template, silent, reason, outcome);
  - webhook bodies (the opaque envelope: delivery id only);
  - error messages;
  - the business `view`.
- **`otpauth`.** It is refused anywhere in the create body, after one percent-decode.
- **Destination validator.** Uppercase hosts, U-labels, IP literals including the obfuscated `10.1`, trailing dots, userinfo, ports, `[`, backslashes and malformed percent-encoding are all refused. `//allowed@evil` and `//allowed:443` in query values are refused.
- **v2 canonicalization.** The verifier rebuilds host and path from the endpoint the receiver **registered**. The digest header is compared with the digest of the received bytes and is never copied into the string to sign. Duplicate `kid` and two `t=` are malformed, a `v1=` entry alone is never accepted, and comparisons are constant-time.
- **Dual period.** `auth.*` events never get `v1=`. Other events get `v1=` for 30 days after the switch, and there is no way back to v1.
- **Dedup horizon.** It is derived from the retry table, with a constant-equality test.
- **Match policy.** The exhaustion count is exact (2-digit codes occupy 10 slots), and the minimum lockout is 29 two-digit plus 610 three-digit codes, which is 639 requests.

### Mutation checks requested by the implementer

| Control | Mutation | Result |
|---|---|---|
| `enqueue` auth-event filter (`!type.isAuthEvent \|\| v2 && opaque envelope`) | Line removed | **Killed** by the existing `AuthDeliveryTests.testAV1SubscriptionNeverReceivesAuthEvents` (queued count 1, expected 0), and by the new `testEnqueueSkipsAV1RowNamingAnAuthEventButQueuesForAV2Row` (v1 with the opaque envelope, v1 with the v1 envelope, and a v2 control). The implementer's note was conservative: the existing test does cover it |
| Deliver-time v1 block | Branch removed | **Survived** all existing tests. **Killed** by the new `testAQueuedAuthDeliveryForAV1SubscriptionIsNeverSent` (R23-03) |

## Rulings on the stated deviations

| Deviation | Ruling |
|---|---|
| Reuses the `auth.challenge` capability instead of a new `auth.delivery` | **Acceptable.** ADR-0020 §2 lists `auth.challenge` among the entitling capabilities. The new elevated scopes `auth_deliveries:write` and `auth_deliveries:read` keep key-level separation. Record it in ADR-0020 |
| Live keys need mTLS because RFC 9421 is not built | **Acceptable** (stricter). A bearer alone is never accepted, and production refuses `none`. RFC 9421 (ADR-0020 §3 profile with vectors) is required before any live partner that cannot do Tier E mTLS |
| `:443` refused rather than stripped | **Acceptable** (stricter). The business signs the URL bytes, so rewriting is worse than refusing. Amend ADR-0021 §3 item 1 to match |
| Link service and email fallback refused | **Acceptable.** They fail closed with explicit `422`s, as ADR-0021 and ADR-0020 §7 require until their gates are met |
| Tenant-keys relay route not built | **Acceptable for now.** With no tenant keys published, business-mode links fail closed (`422 destination_signature_required`), so no link can reach a device that cannot verify it. The route must exist, with ST-ML-12 passing, before any tenant key is registered (Stage 6) |
| "Pause after 3 reports" became silent delivery | **Acceptable.** It meets the fatigue goal (no alerts) without turning reports into a refusal lever, in line with S1-A2-6. Condition before pilot: amend ADR-0020 §5 and §8 and ADR-0022 §5.4 to say so. The customer's own explicit per-business pause (ADR-0020 §2 eligibility) arrives with the Stage 4 app, or is recorded as deferred |
| No APNs collapse-id | **Must fix before pilot** (R23-05, a small change) |
| `enqueue` filter and v1-subscription block not mutation-checked | **Resolved by this review.** Both are now mutation-checked and covered (see the table above) |

## Conditions

| When | Condition |
|---|---|
| Before pilot | R23-04, R23-05 and R23-08 fixed with tests. ADR-0020 and ADR-0021 amended for the accepted deviations. C-14 (ST-MFA-11 and the SDK throttle default) unchanged |
| Before the SDK reaches partners | R23-06 |
| Stage 5 | R23-09 when match tags are wired into `auth-approvals` |
| Stage 6 (before business links are enabled) | R23-07; the tenant-keys relay route with ST-ML-12; RFC 9421 per the deviation ruling if partners need it |
| Before other-language SDKs | R23-10 |
| Always | `AUTH_DELIVERY_ENABLED` stays off in staging and production until the pilot conditions are met |

## Sign-off

Agent review record: independent Stage 2–3 code review by the A2/A3/A10 reviewer agent, 2026-11-02, at `345f103` plus the review fixes in this commit (R23-01, R23-02, R23-03). Verdict: **APPROVE WITH CONDITIONS**. No Critical or High findings.
