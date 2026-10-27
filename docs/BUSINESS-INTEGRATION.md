# Viadere business integration guide

How a verified business integrates with Viadere: issue a structured request (for example, "is this you?" for a card payment),
get the customer's decision back, exchange messages, and let customers connect with a button or QR code.

* Reference: [`openapi.yaml`](openapi.yaml) (OpenAPI 3.1: every operation, schema and webhook event).
* Swift SDK: [`Packages/ViadereBusinessSDK`](../Packages/ViadereBusinessSDK) (typed client, webhook verification, idempotency helpers).
* Wire formats and threat model: [`SECURITY.md`](SECURITY.md).

## 1. Get access

1. **Apply.** Create an organization at `https://viadere.com/dashboard/signup` (you sign in with a passkey; there are no passwords).
   The organization starts `pending`. A Viadere reviewer verifies it; **your handle and permanent code are issued only on
   approval**, and until then you cannot create API keys or webhooks and cannot issue interactions.
2. **Create an API key** in the dashboard (*API keys*). Creating one asks you to confirm with your passkey. Give each key only the
   scopes it needs; the secret is shown once. Use `vdk_test_…` keys while building and `vdk_live_…` in production. A test key can only address a **sandbox** relationship (create one with `POST /v1/business/sandbox/relationships`, or `client.createSandboxRelationship()` in the Swift SDK): it never reaches a real customer, is not pushed, texted, counted or billed, and a live key cannot address a sandbox relationship.
3. **Add a webhook endpoint** (*Webhooks*). The signing secret (`whsec_…`) is shown once.

| Scope | Allows |
|---|---|
| `interactions:write` | issue and cancel interactions |
| `interactions:read` | read outcomes |
| `messages:write` | send messages |
| `statuses:write` | publish ongoing-event statuses |
| `webhooks:manage` | manage webhook endpoints through the API |
| `rewards:write` | loyalty program, rewards, points and redemption validation (`/v1/business/loyalty/*`, `/v1/business/rewards*`, `/v1/business/redemptions/consume`) |

Dashboard roles are least-privilege: **owner**, **admin** (no owner changes), **developer** (keys, webhooks, templates, campaign links),
**support** (consent status), **analyst** (aggregate analytics and usage, read-only).

## 2. Quickstart (Swift)

```swift
import ViadereBusinessSDK
import ViadereCore

let client = try ViadereBusinessClient(apiKey: ProcessInfo.processInfo.environment["VIADERE_API_KEY"]!)
```

Keep the key on your server. Never ship it in an app or a web page.

### Issue an authorize request

```swift
let request = IssueInteractionRequest(
    relationshipId: relationshipId,                       // from the customer's connection to you
    purpose: .security,
    payload: .authorize(AuthorizePayload(
        actionDescription: "Card purchase",
        amount: try MoneyAmount(string: "285.28", currency: .usd),
        merchant: "Example Store", location: "Mesa, Arizona",
        effectOfApproval: "The purchase will go through.")),
    priority: .urgent,                                    // a request; Viadere clamps it
    sensitivity: .high,
    allowedChannels: [.nativePush, .inApp],               // see "Channels" below
    ttlSeconds: 300,
    idempotencyKey: IdempotencyKey.deterministic(namespace: "auth", [transactionId]),
    correlationId: transactionId)

let issued = try await client.issueInteraction(request)
// issued.wasCreated == false means the idempotency key was recognized and you got the original back.
```

The customer's phone shows "Someone is trying to spend $285.28 at Example Store in or near Mesa, Arizona. Is this you?" and they approve
with Face ID. Their device signs the decision; Viadere verifies it and tells you.

### Handle the decision

Use the webhook (preferred) and/or poll as a fallback:

```swift
let outcome = try await client.interactionOutcome(id: issued.interaction.id)
switch outcome.status {
case .approved: /* proceed */ break
case .denied, .reported: /* decline; .reported means the customer says it was not them */ break
case .expired, .cancelled: /* no decision: do not proceed */ break
case .pending: /* still waiting */ break
default: break
}
```

Treat `expired` and `cancelled` as "no". For `authenticate` and `authorize`, only a decision with `assurance` and a `verification`
(the server's attestation that the device signature, the context that was shown and the assurance were verified) is an approval; they
are never approvable by text message. `deviceRef` is a pseudonym of the deciding device, stable for your business and unlinkable across
businesses. You do **not** receive the raw device-signed decision (it contains the customer's global device id); Viadere keeps it and
can export it for a dispute: quote `verification.evidenceRef`.

## 3. Verify webhooks

Every delivery carries:

```
Viadere-Signature: t=1798000000,v1=9c1f…   (several v1= values while a secret is being rotated)
Viadere-Event-Id:   3f2c…                    (deliveries are at-least-once: deduplicate on it)
Viadere-Event-Type: interaction.decided
```

`v1` is `hex(HMAC-SHA256(key: UTF-8 of the whole whsec_… string, message: "{t}." + raw request body))`.

* Verify against the **raw body bytes** you received, not a re-serialized JSON value.
* Compare in constant time. Reject if no `v1` matches, or if `|now − t| > 300 s` (replay protection). Ignore unknown schemes such as `v0=`.
* Respond `2xx` within 10 seconds. Anything else is retried at 30 s, 2 min, 10 min, 1 h, 6 h, 12 h and 24 h, then dead-lettered
  (you can replay dead letters from the dashboard).
* Redirects are never followed, and your URL must be a public `https` URL.

With the SDK:

```swift
let verifier = WebhookVerifier(secrets: [currentSecret])        // add the previous secret during a rotation
let dedup = InMemoryWebhookDeduplicator()

// In your HTTP handler: rawBody is Data, headers is [String: String]
do {
    let event = try verifier.verify(headers: headers, body: rawBody, deduplicator: dedup)
    switch try event.typed() {
    case .interactionDecided(let outcome): /* act on it */ break
    case .messageReceived(let message):    /* message.text is customer-authored: treat it as untrusted input */ break
    case .other: break                      // new event types: acknowledge and ignore
    default: break
    }
    return Response(status: 200)
} catch {
    return Response(status: 400)                                 // do not process
}
```

Without the SDK (any language), the same check in Node.js:

```js
const crypto = require('crypto');
function verify(header, rawBody, secrets, now = Date.now() / 1000) {
  const parts = header.split(',').map(p => p.trim().split('='));
  const t = Number(parts.find(([k]) => k === 't')?.[1]);
  const sigs = parts.filter(([k]) => k === 'v1').map(([, v]) => Buffer.from(v, 'hex'));
  if (!Number.isFinite(t) || Math.abs(now - t) > 300 || sigs.length === 0) return false;
  return secrets.some(secret => {
    const mac = crypto.createHmac('sha256', secret).update(`${t}.`).update(rawBody).digest();
    return sigs.some(s => s.length === mac.length && crypto.timingSafeEqual(s, mac));
  });
}
```

### Events

| Type | When | `data` |
|---|---|---|
| `interaction.decided` | the customer decided | `InteractionOutcome` |
| `interaction.expired` | no decision before expiry | `InteractionOutcome` |
| `interaction.cancelled` | you cancelled, or the customer disconnected | `InteractionOutcome` |
| `message.received` | the customer messaged you | `{sessionId, relationshipId, messageId, text, channel, receivedAt}` |
| `relationship.connected` / `.disconnected` | connection changes | `{relationshipId, source?, occurredAt}` |
| `consent.updated` | a consent changed | `{relationshipId, purpose, granted, occurredAt}` |
| `reward.redeemed` | you consumed a redemption code | `RedemptionReceipt` (pseudonymous) |

The body is `{id, type, createdAt, businessId, apiVersion, data}`. The dashboard delivery log redacts customer-authored text.

## 4. Idempotency

Every `POST` that creates something takes an `Idempotency-Key` header **equal to the body's `idempotencyKey`** (≤ 128 characters of `A-Z a-z 0-9 _ . - :`).

* Same key and same body: you get the original result back (`200` instead of `201`). Retry freely after a timeout.
* Same key and a different body: `409 idempotency_conflict`. Never reuse a key for a different operation.
* **Webhook create, webhook secret rotation and interaction cancel also require an `Idempotency-Key`** (no body key: the header alone identifies the operation; missing or invalid is `422`). A retry with the same key returns the original result, including the **same one-time secret** for 24 hours (`createWebhook` / `rotateWebhookSecret` in the SDK generate and reuse a key across their own retries; pass `idempotencyKey:` to pin one). After 24 hours a replay is `410 gone`: rotate to get a new secret. The same key for another webhook or interaction is `409`.
* Derive keys from the thing you are acting on so a retry from any process produces the same key:
  `IdempotencyKey.deterministic(namespace: "refund", [orderId, lineId])`. Use `IdempotencyKey.generate()` for genuinely new operations, and **store the key before sending**.
* Idempotent retries are safe, so the SDK retries `429`, `5xx` and network failures automatically (honouring `Retry-After`) for `GET`s,
  keyed `POST`s (webhook create, secret rotation and cancel included: every attempt of one call carries the same key).

## 5. Channels and what can be approved where

| Interaction | Native app | RCS | SMS |
|---|---|---|---|
| `authenticate`, `authorize`, unknown kinds, `high`/`critical` sensitivity | Device-signed approval (Face ID / passcode) | Secure handoff link only | Secure handoff link only |
| `confirm`, `choose` (single), `reply` with suggested replies, `acknowledge` at `low`/`standard` sensitivity | Notification actions / in-app | Suggested replies (a tap is an *unauthenticated reply*) | Handoff link (numbered replies are not wired for interactions) |
| `status`, `message` | Notification / Live Activity | Text | Text |

* List `rcs` and/or `sms` in `allowedChannels` to permit them; `rcs` implies SMS fallback. The default is `[nativePush, inApp]`.
* Viadere checks RCS capability per phone and falls back to SMS for the *same* interaction. A sensitive interaction is **never** downgraded to a yes/no text.
* Text you send by SMS or RCS is rendered as a single line after your `[Name]:` attribution (line breaks become spaces, and a leading `Viadere` or `[` is neutralised), so it cannot forge a second speaker or a menu.
* The customer's text thread is shared by every business. While it is connected to *another* business, an interaction you send by SMS is replaced by a content-free notice ("new message from you in the Viadere app"); the content is in the app.
* A phone the customer linked in the last 24 hours from a text link is not used for delivery until a trusted device confirms it.
* Text channels need the customer's verified phone, no STOP, and (for anything but security, account-service and transactional purposes) a consent grant that covers text channels.
* A decision made over RCS arrives with `channel: "rcs"` and **no** `assurance`, `deviceRef` or `verification`.
* RCS postbacks are opaque, signed, single-use tokens bound to the customer's phone and the active menu; a newer message to the same phone supersedes older menus, exactly like SMS numbers.
* Apple Messages for Business is a disabled placeholder and cannot be used until Apple approves multi-merchant brokerage in writing.

## 5a. Loyalty, rewards and redemption

Everything here needs the `rewards:write` scope. Eligibility is decided by Viadere's servers, never by the app: the customer's phone shows a
reward's state and offers its button only when the server says so.

### 1. Create your program (optional, needed for points)
```swift
let client = try ViadereBusinessClient(apiKey: apiKey)
_ = try await client.saveLoyaltyProgram(UpsertLoyaltyProgramRequest(
    programName: "Juniper Club", summary: "A point for every dollar.", termsVersion: "2026-10",
    timeZone: "America/Phoenix",                      // the business's zone: when a "day" starts
    tiers: [LoyaltyTier(name: "Silver", minimumPoints: 100), LoyaltyTier(name: "Gold", minimumPoints: 500)]))
```
Customers see the program in the app, accept the current `termsVersion` and join. Bumping `termsVersion` makes the next join require the new terms.

### 2. Create rewards
```swift
// Free coffee every Tuesday, one per customer per day, evaluated in Phoenix time (DST-safe).
_ = try await client.createReward(IssueRewardRequest(
    title: "Free coffee on Tuesdays", kind: .perk,
    recurrence: RewardRecurrence(weekdays: [2], perDayLimit: 1, timeZone: "America/Phoenix"),
    idempotencyKey: "reward-tuesday-coffee"))
```
| `kind` | Behaviour |
|---|---|
| `coupon`, `offer` | the customer **claims** it (saves it to their account, optionally to Wallet), then redeems it; once per customer unless recurring |
| `perk` | redeemed directly; once per customer unless recurring |
| `pointsReward` | costs `pointsCost` points, held when a code is issued; repeatable while the balance lasts |

Omit `relationshipId` to offer a reward to every connected customer; pass one to issue it to a single customer. Withdraw a reward with `revokeReward(id:)`:
outstanding codes stop validating, held points return, and its Wallet passes are voided.

### 3. Award points
```swift
_ = try await client.adjustPoints(AdjustLoyaltyPointsRequest(relationshipId: rel, delta: 25, reason: "purchase", idempotencyKey: "order-1042-points"))
```
Idempotent per key; a balance never goes below zero; the customer must have joined. Status levels (tiers) follow the current balance.

### 4. Validate a redemption code at the till
The customer taps **Use now** and the app shows a code like `K7M2Q-9XPB4` for about **two minutes**. Your till submits it:
```swift
do {
    let receipt = try await client.consumeRedemption(code: scanned, locationCode: "till-2")
    // hand over `receipt.rewardTitle`; `receipt.consumerReference` is a per-business pseudonym
} catch let error as ViadereAPIError where error.status == 409 { /* already used (error.details?["redeemedAt"]) */ }
  catch let error as ViadereAPIError where error.status == 410 { /* expired or withdrawn */ }
  catch let error as ViadereAPIError where error.status == 404 { /* unknown code */ }
```
Validation and consumption are **one atomic step**: if two tills submit the same code at once, exactly one gets `200`. A code is single use; the per-day limit is
reserved when the code is issued and released if it expires unused. The call is rate-limited (60/min, burst 30 per business) because that bounds code guessing.
If a response is lost, a repeat answers `409`; confirm with the customer rather than assuming. Subscribe to `reward.redeemed` to reconcile.

### 5. Wallet passes
Customers add passes from the app; you do not call a pass API. Viadere signs the passes with its own Pass Type ID certificate (see the server README) and
updates them for you:

| Pass | Issued when the customer adds | Updates |
|---|---|---|
| Loyalty card (`storeCard`) | the card from their membership | points and status change when you adjust points |
| Coupon | a claimed coupon | voided when redeemed or when you revoke the reward |
| Event ticket / boarding pass | a `ticket` interaction you sent (`venue`, `seat`, `startsAt` appear on the pass) | not yet |

Passes never contain a phone number, email, name, member number or redemption code. Wallet pass updates are not a way to send promotional notifications.

### 6. Ongoing events, tickets and Live Activities
Give an order, trip or appointment a stable `correlationId` and send it on every related interaction: the `status` updates (`BusinessStatusUpdateRequest.correlationId`),
the `ticket`, and `confirm`/`choose` actions (for example a `confirm` titled "Check in", a `choose` for rescheduling, an `authorize` with an amount for rebooking). The
customer's Activity tab shows them as one item. A `status` whose `liveActivity` is set drives a Live Activity when its purpose is `transactional`, `accountService` or
`support` and you use a live key; marketing, rewards and security statuses never do.

## 6. Errors

Every error is `{"error":{"code","message","requestId","details?"}}`. Quote `requestId` when contacting support.

| HTTP | `code` | Meaning and what to do |
|---|---|---|
| 400 | `bad_request` | Malformed body, or `Idempotency-Key` header ≠ body `idempotencyKey`. Fix the request. |
| 401 | `unauthorized` | Missing, unknown, revoked or expired key. Check the key and its expiry. |
| 403 | `forbidden` | Key lacks the scope, or your business is not active (pending or suspended). |
| 403 | `consent_required` | The customer has not consented to this `purpose`. Do not retry; ask in your own channel or use an allowed purpose. |
| 404 | `not_found` | Unknown id, or it belongs to another business (indistinguishable by design). |
| 409 | `conflict` | State conflict, e.g. the customer is not connected to you. |
| 409 | `idempotency_conflict` | Key reused with a different body. |
| 410 | `gone` | Resource no longer available (e.g. the customer's data was erased). |
| 422 | `validation_failed` | `error.details` maps field paths to issue codes (for example `expiresAt: invalidLifetime`). |
| 429 | `rate_limited` | Slow down; wait `Retry-After` seconds. |
| 500 | `internal_error` | Retry keyed requests with backoff. |
| 501 | `unavailable` | Feature not configured on this deployment (for example Wallet passes without a pass certificate). |

## 7. Rate limits, quotas and trust

* **API rate:** per business, default burst 120 and 600 requests/minute. **Daily quota:** live interactions per UTC day (free tier default 1,000).
  Both return `429` with `Retry-After`.
* **Abuse controls:** each business has a complaint rate ("not me" reports ÷ interactions) and an opt-out rate (consent revocations and disconnects ÷ relationships).
  Above the configured thresholds (defaults 2% and 10%, minimum sample 20, 7-day window) your quota and API rate are automatically cut to a quarter until the rates recover.
  Viadere operators can also throttle, cap priority downward, or suspend a business; suspension blocks your API keys and interactions immediately.
* **Priority:** `marketing` and `rewards` never exceed `normal`; other purposes cap at `high`; `urgent` is reserved for security `authenticate`/`authorize`.
  **Paying never changes priority, and never bypasses consent.** Plans only raise quotas.
* **Billing:** usage is metered per business (interactions as the platform fee basis; SMS segments and RCS messages as carrier/provider transport, priced separately).
  The dashboard shows an invoice preview; there is no payment processor integration yet and final pricing is not set.

## 8. "Connect with Viadere" button and QR codes

Let customers connect from your site, email or print.

* **Campaign links and QR** (dashboard → *Campaigns*): generates `https://viadere.com/c/{CODE}?ctx=…&sig=…` with a signed campaign context and renders the QR code
  as an SVG on the server (nothing is sent to a third party). The context is optional; if it is missing, expired or invalid, the plain code still resolves.
* **Web component** (no dependencies, no network calls, no tracking, no iframe):

```html
<script src="https://viadere.com/connect-button/v1/viadere-connect.js"
        integrity="sha384-mo265OibvlyjMxjQpT8kkeB3CZlw+XQ25zW9fHSjXaXr7UobQKxViVEpd/WpFr3O"
        crossorigin="anonymous" defer></script>
<viadere-connect code="AF2345"></viadere-connect>
<!-- optional: signed campaign context from the dashboard, theme="light|dark|auto", label="…" -->
<viadere-connect code="AF2345" ctx="eyJ…" sig="abc…" theme="dark"></viadere-connect>
```

* **Plain HTML and CSS** (no JavaScript):

```html
<link rel="stylesheet" href="https://viadere.com/connect-button/v1/viadere-connect.css"
      integrity="sha384-BA8G+Du8p1Om60MoJlpXAmqMqTEE6JwyaVQjA5hTEyyo8X2ImKqqIEIz/KEUyFmC" crossorigin="anonymous">
<a class="vd-connect" href="https://viadere.com/c/AF2345" rel="noopener noreferrer" referrerpolicy="no-referrer">
  <svg class="vd-mark" viewBox="0 0 321.71 146" aria-hidden="true" focusable="false"><!-- mark: Design/svg/viadere-mark-mono-dark.svg, fill="currentColor" --></svg>
  <span>Connect with Viadere</span>
</a>
```

The files are versioned and immutable (`Cache-Control: public, max-age=31536000, immutable`); a change ships under a new path (`/v2/`), so a pinned SRI hash never goes stale.
`GET /connect-button/v1/integrity.json` publishes the current `sha384` of each file. The button only renders a link to `viadere.com/c/{CODE}`: no cookies, storage, analytics or third-party requests.

## 9. Go-live checklist

- [ ] Organization verified; handle and code issued.
- [ ] Live key stored in a secrets manager, scoped to what the integration needs; test key used in CI.
- [ ] Webhook endpoint verifies signatures on the raw body, rejects stale timestamps, deduplicates on `Viadere-Event-Id`, and answers `2xx` quickly (do the work asynchronously).
- [ ] Every `POST` carries a deterministic idempotency key, persisted before sending.
- [ ] `expired`, `cancelled`, `denied` and `reported` are all treated as "do not proceed".
- [ ] You never treat an RCS or SMS reply as approval of a sensitive action.
- [ ] Customer-authored text (`message.received`) is handled as untrusted input.
- [ ] Redemption codes are validated server-side with `consumeRedemption` (never trusted from the app) and `409`/`410` mean "do not hand over the reward".
- [ ] You monitor `429`s, your complaint rate and your opt-out rate; you rotate keys and webhook secrets on a schedule (rotation keeps the old secret valid for 24 hours).
