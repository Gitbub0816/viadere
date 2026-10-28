# Viadere business integration guide

How a verified business integrates with Viadere: issue a structured request (for example, "is this you?" for a card payment),
get the customer's decision back, exchange messages, and let customers connect with a button or QR code.

* Reference: [`openapi.yaml`](openapi.yaml) (OpenAPI 3.1: every operation, schema and webhook event).
* Swift SDK: [`Packages/ViadereBusinessSDK`](../Packages/ViadereBusinessSDK) (typed client, webhook verification, idempotency helpers).
* Wire formats and threat model: [`SECURITY.md`](SECURITY.md).

## 1. Get access

1. **Apply.** Create an organization at `https://viadere.com/dashboard/signup` (you sign in with a passkey; there are no passwords).
   The organization starts `pending`. Follow the checklist under *Organization* (section 1a): **prove you control a domain**, have your **legal entity reviewed**, and wait for a Viadere reviewer to approve the application.
   **Your handle and permanent code are issued only on approval.** Sandbox work (test keys, a webhook endpoint, a test customer) opens as soon as your domain is verified; **live keys** need the approved application and the go-live review.
2. **Create an API key** in the dashboard (*Developers > API keys*). Creating one asks you to confirm with your passkey. Give each key only the
   scopes it needs; the secret is shown once (section 1b). Use `vdk_test_…` keys while building and `vdk_live_…` in production. A test key can only address a **sandbox** relationship (create one with `POST /v1/business/sandbox/relationships`, or `client.createSandboxRelationship()` in the Swift SDK): it never reaches a real customer, is not pushed, texted, counted or billed, and a live key cannot address a sandbox relationship.
3. **Add a webhook endpoint** (*Developers > Webhooks*). The signing secret (`whsec_…`) is shown once, and the endpoint must **prove it is yours** before it receives events (section 3a).

| Scope | Allows |
|---|---|
| `interactions:write` | issue and cancel interactions |
| `interactions:read` | read outcomes |
| `messages:write` | send messages |
| `statuses:write` | publish ongoing-event statuses |
| `webhooks:manage` | manage webhook endpoints through the API |
| `rewards:write` | loyalty program, rewards, points and redemption validation (`/v1/business/loyalty/*`, `/v1/business/rewards*`, `/v1/business/redemptions/consume`) |
| `approvals:manage` | Approve v2: enrollments, requests, results, freeze (`/v1/business/approve/*`) |
| `keydirectory:manage` | publish and read your key-directory entries (`/v1/business/key-directory/*`) |

### 1a. Onboarding: from workspace to production

You never need a VPN or a private network. The checklist under *Organization* shows exactly what is open; each step names where it is done.

| Step | What you do | What Viadere does |
|---|---|---|
| 1. Workspace | Sign up, verify your e-mail, register a passkey, describe your organization and intended use | |
| 2. Control | Add your domain and publish the record shown **either** as a DNS TXT record at `_viadere-verify.<domain>` (value `viadere-verification=<token>`) **or** as the file `https://<domain>/.well-known/viadere-verification.txt` (same value), then press *Check*. Submit your legal entity: registry number, jurisdiction, registry name and **references** to your registration evidence (a registry URL or record id; do not upload documents). Regulated categories (banking, healthcare, government) get an additional review | A reviewer checks the registry and records approve or reject; no document is stored |
| 3. Public identity | | A reviewer approves the application; your **permanent handle and code** are issued |
| 4. Agreements | Read and accept each required agreement at its **current version** (*Compliance > Agreements*): Business Services Agreement, Data Processing Addendum, Acceptable Use Policy, Messaging Consent and Content Policy Addendum, plus capability addenda for approvals (Tier A) and verification (Tier V) | Records who accepted which version, when, and hashes of the address and agent (never the raw values) |
| 5. Integration | Create a **sandbox key**, a **test customer** (*Developers > Sandbox*), send a test message, add and **verify a webhook endpoint**, receive a simulated reply, add a **security contact** (*Security > Alerts and contacts*) | |
| 6. Go-live review | *Organization > Request production access*: describe the use case and expected volume | A reviewer decides; you are mailed. Live keys unlock on approval |
| 7. Ongoing | Keep the domain record in place and accept new versions of agreements when they change materially | Re-checks the domain every `DOMAIN_RECHECK_DAYS` and the agreements; a failure starts a grace period (mailed), then suspension unless fixed. Fixing it lifts that suspension |

The typical low-risk messaging path (workspace, verify control, sandbox key, test message, signed webhook, test reply, request production approval) is the same list; there is no step that needs a VPN.

### 1b. API key lifecycle

* **Format:** `vdk_<test|live>_<kid>.<secret>`. The `kid` (16 characters) is **not secret**: quote it in support requests and logs; the console and the audit trail identify a key by it. The secret is 256 random bits, shown **once** when you create or rotate a key.
  Keys created before key ids existed (`vdk_live_<43 characters>`) keep working.
* **Environment-bound:** a `test` key reaches sandbox customers only and a `live` key can never address one.
* **Expiry** (optional, 30/90/365 days), **last used** (time and a hash of the address, in the key list), **immediate revoke** (effective on the next request), **IP allow-list** (up to 20 addresses or CIDR blocks; the address is the one our edge saw, a client-sent `X-Forwarded-For` does not count).
* **Rotation with overlap:** *Rotate* issues a replacement with the **same** scopes, capabilities, restrictions and expiry and keeps the old key working for the overlap you pick (none, 1 hour, 1 day, 7 days or 30 days), then revokes it automatically. Deploy the new secret during the overlap; the list shows "Rotating until …". A key that is already rotating cannot be rotated again.
* **Who:** Owners, Organization Admins, Developers and Security Admins create and rotate keys within the messaging scopes; **only an Owner or Security Admin** can create a key with a scope or capability beyond them. Organizations can require a **second person's approval** for key creation, rotation and role grants (*Security > Approvals*).
* **If a key leaks:** revoke it (immediately), create a replacement, rotate any webhook secret the key could manage, and tell us. Viadere operators can also revoke a leaked key **without suspending your organization**; you are mailed (the mail never contains a secret).
* **Enterprise (Tier E):** require a **bound client certificate** for a key, see section 8a.

### Capabilities (what a key may do)

Scopes say which **routes** a key may call. Each key also carries **capabilities**, which say what it may do, and Viadere decides every request on `entitlement ∩ key capability ∩ customer consent ∩ evidence ∩ law/policy`:

| Capability | Tier | Needed for |
|---|---|---|
| `message.send` | M (default) | messages, statuses, and every interaction kind except the two below; reading or cancelling those |
| `contact.reachable` | M (default) | checking that an existing connection can receive messages |
| `consent.request` | M (default) | asking a customer to grant a purpose |
| `auth.challenge` | A (granted) | Approve v2 sign-in approvals; legacy `authenticate` interactions |
| `transaction.approve` | A (granted) | Approve v2 transaction approvals; legacy `authorize` interactions (legacy approvals also need the temporary entitlement, below) |
| `age.minimum`, `identity.name`, `identity.address`, `identity.verified` | V (granted) | Verify (not yet generally available); each disclosure needs a per-request customer receipt |

* **Every verified business starts with the three messaging capabilities and nothing else.** Approval and verification capabilities are granted by a Viadere operator after review, with a recorded purpose; your category, plan or verified badge never grants them. Ask your Viadere contact.
* **The dashboard only offers a key the capabilities you hold**, and a key can never do more than your business is entitled to *at the moment of the request*: if Viadere withdraws an entitlement, existing keys lose that capability on their next request.
* Use **separate keys**: a messaging key (`message.send`) for your notification service and a distinct key for sign-in or payment approvals. A leaked messaging key then cannot approve anything: it gets `403 insufficient_scope`.
* `GET /v1/business/capabilities` (SDK: `client.capabilities()`) shows your tiers, entitlements, the key's capabilities, what is `effective` now, and the catalog with each capability's inputs and the exact fields it discloses. Denials are `403` with `insufficient_scope` (the key lacks it), `not_entitled` (the business lacks it) or `capability_disabled` (Viadere switched it off); `error.details.capability` names it. Do not retry them unchanged.

### Customer references

Name a customer by `relationshipId`, by **`subjectRef`**, or both. `subjectRef` (`sub_…`) is a pairwise pseudonym: stable for your business, never the same as that person's reference at another business, and not guessable. It is returned on interactions (`scope.subjectRef`), sandbox relationships, redemption receipts, loyalty results and the `relationship.*`, `consent.updated` and `message.received` webhooks. A reference that is not yours is `404`. The older `scope.consumerId` / `consumerReference` pseudonym is deprecated; store `subjectRef`.

Dashboard roles are least-privilege: **owner**, **admin** (no owner changes), **developer** (keys, webhooks, templates, campaign links),
**support** (consent status), **analyst** (aggregate analytics and usage, read-only).

## 2. Quickstart (Swift)

```swift
import ViadereBusinessSDK
import ViadereCore

let client = try ViadereBusinessClient(apiKey: ProcessInfo.processInfo.environment["VIADERE_API_KEY"]!)
```

Keep the key on your server. Never ship it in an app or a web page.

### Issue an authorize request (legacy path, closed by default)

> **This path is not independently verifiable.** The `verification` you receive is the relay's attestation; you never see the device's signature. While Approve v2 is available (see "Approve" below) `authorize` and `authenticate` at `high` or `critical` sensitivity are refused for live traffic with `403 legacy_approval_not_entitled` unless Viadere granted your business the temporary legacy entitlement (justified, audited, at most 180 days, ending no later than 2027-06-30). The sandbox is unaffected. New integrations use Approve v2.

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
Viadere-Signature:   t=1798000000,v1=9c1f…   (several v1= values while a secret is being rotated)
Viadere-Event-Id:    3f2c…                    (deliveries are at-least-once: deduplicate on it)
Viadere-Delivery-Id: 3f2c…                    (this delivery; stable across retries: your de-duplication key)
Viadere-Key-Id:      whk_ab12cd34_v2          (which signing secret: endpoint + secret version; changes at each rotation)
Viadere-Event-Type:  interaction.decided
Viadere-Webhook-Version: v1                   (v1 = full body, v2 = opaque envelope for approval/verification events)
```

`v1` is `hex(HMAC-SHA256(key: UTF-8 of the whole whsec_… string, message: "{t}." + raw request body))`.

* Verify against the **raw body bytes** you received, not a re-serialized JSON value.
* Compare in constant time. Reject if no `v1` matches, or if `|now − t| > 300 s` (replay protection). Ignore unknown schemes such as `v0=`.
* Respond `2xx` within 10 seconds. Anything else is retried at 30 s, 2 min, 10 min, 1 h, 6 h, 12 h and 24 h, then dead-lettered
  (you can replay dead letters from the dashboard).
* Redirects are never followed, and your URL must be a public `https` URL.

### 3a. Endpoint verification, test events and pausing

A new endpoint receives **nothing** until it proves it controls the URL. Press *Verify* in the console (or call `POST /v1/business/webhooks/{id}/verify`, `client.verifyWebhook(id:)` in the Swift SDK): we POST a signed
`webhook.verification` request with a single-use `challenge`; answer `2xx` with `{"challenge_response": "<hex HMAC-SHA256 keyed by your signing secret over \"viadere.webhook.verification.v1:\" + challenge>"}`. In the Swift SDK: `return try verifier.verificationResponse(headers: headers, body: rawBody)` (it verifies the signature first). **Echoing the challenge does not work** (only a receiver holding the signing secret can answer). A missing or wrong proof reports `no_echo`, a non-2xx reports `http_<status>`,
no connection reports `unreachable`; each attempt uses a new challenge (6 attempts per endpoint per hour). Configure the signing secret on your server first, then verify.

* **Test events:** *Send test event* (or `POST …/test`, `client.testWebhook(id:)`) delivers a signed `webhook.test` event through the real pipeline, with real headers, retries and delivery log.
* **Pause and resume:** `POST …/pause` and `…/resume` (`client.pauseWebhook(id:reason:)`, `client.resumeWebhook(id:)`) stop and restart delivery for one endpoint; events keep queueing and are delivered after the resume (or expire after the retention period).
  During an incident Viadere may pause delivery for your organization or for everyone; the console shows a banner and nothing is lost.
* **Delivery log and replay:** *Developers > Webhooks > Delivery log* shows the last 50 deliveries with attempts and **redacted** payloads (message text and signatures are never shown); a dead-lettered delivery can be replayed.
* **Retry simulator and schema preview:** show the real backoff schedule for N failures and a sample of every event, built from the real types, without sending anything.

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

Without the SDK (any language), the same check in Python (standard library only):

```python
import hashlib, hmac, time

def verify(header: str, raw_body: bytes, secrets: list[str], now: float | None = None, tolerance: int = 300) -> bool:
    now = time.time() if now is None else now
    parts = [p.strip().split("=", 1) for p in header.split(",") if "=" in p]
    try:
        t = int(next(v for k, v in parts if k == "t"))
    except (StopIteration, ValueError):
        return False
    sigs = [v for k, v in parts if k == "v1"]
    if not sigs or abs(now - t) > tolerance:
        return False
    for secret in secrets:                      # during rotation, try every active secret
        mac = hmac.new(secret.encode(), f"{t}.".encode() + raw_body, hashlib.sha256).hexdigest()
        if any(hmac.compare_digest(mac, s.lower()) for s in sigs):   # constant-time compare
            return True
    return False
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
| `verification.completed` | a verification request ended (any outcome) | `{request_id, result_ref}` only; fetch the result (section 5b) |

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

## 5b. Verify: age thresholds and identity attributes

Verify lets a connected customer prove one fact to you: that they meet an age threshold (`age.minimum`) or an identity attribute
(`identity.name`, `identity.address`, `identity.verified`). It is optional, **off until Viadere enables it for your business**, and
available only where Viadere has completed legal and privacy validation (spec Phase 3 gate); availability depends on place, device and
the customer's ID. A result describes the attribute and assurance evaluated. It is not a guarantee of identity or eligibility, it does
not fulfil KYC/AML, age-assurance or other legal duties by itself, and you decide what to do with it.

**What you need.** The capability on your business (granted after review: age needs risk tier V and a stated purpose; identity
attributes and `identity.verified` also need a recorded heightened review whose reference we keep) and on the key. A key that only carries messaging capabilities cannot create or read
verifications (`403 insufficient_scope`). Register a webhook endpoint subscribed to `verification.completed`; its id is your
`callback_id`.

```swift
let created = try await client.createVerificationRequest(
    CreateVerificationRequest(subjectRef: customer, capability: .ageMinimum, parameters: ["years": .integer(21)],
                              purposeCode: "age_restricted_access", callbackId: webhook.id.description, expiresInSeconds: 180),
    idempotencyKey: IdempotencyKey.deterministic(namespace: "age", [orderId]))
```

1. **Create** (`POST /v1/verification-requests`, idempotent). The customer is notified. They see your verified name, the purpose, exactly
   what will be shared, that only you receive it, and when the request expires, and they consent to that. They can verify with an ID in
   Apple Wallet or by scanning an ID document, and can decline.
2. **Wait for `verification.completed`** at your registered endpoint, or poll `GET /v1/verification-requests/{request_id}`. The webhook is
   opaque: `{request_id, result_ref}` and nothing else (spec 14.3). It arrives for **every** end.
3. **Retrieve** with `GET /v1/verification-results/{result_ref}` using your key (`verificationResult(ref:)`). The result is bound to your
   business and that request, valid for 15 minutes, and **single use**: a second call is `410`. Store what you need.

| `outcome` | Meaning |
|---|---|
| `verified` | `result` holds the capability's fields. For `age.minimum`: `meets_threshold: true`, `assurance`, `issued_at`, `expires_at`, `audience`. Never a birthdate, an age, a name or a document number. |
| `not_verified` | `result` is empty. It does **not** say why: under the threshold, declined, abandoned, expired, unsupported document, a provider outage and withdrawn consent are all the same. Do not try to infer more, and offer the customer another route. |

**Your audit log shows the same.** Your organization's audit page and tenant export record a verification as `requested`,
`completed` (only the capability and `verified` or `not_verified`) and `result_retrieved`: never an attempt, a reason, a method or
whether the customer consented first. A customer appears there only as your `subject_ref` for them, never as an identifier that
another business could also hold. Do not build a workaround that tries to learn more (for example from timing).

**Jurisdiction.** Viadere may restrict a capability by region. Your legal-entity jurisdiction (from your approved onboarding review)
and the country that issued the customer's ID are both considered; if your legal-entity jurisdiction is not on record and a block
rule exists for the capability, requests are refused (`403 policy_denied`) rather than allowed.

**Age checks use the earliest date anywhere.** A customer is reported as meeting a threshold only once their birthday has begun in
every time zone (UTC-12), so a result can arrive up to 12 hours after the birthday in your customer's own zone.

**Wallet IDs and revocation.** An ID in Apple Wallet is verified against the issuing authority's certificates and validity dates.
Viadere does not yet check the issuer's revocation (status list) for the credential, so a `verified` Wallet result does not prove the ID
has not been revoked since it was issued. Do not rely on it for that.

**What the customer is told.** For a name or an address the Wallet sheet says the data may be stored, because you receive it and may
keep it under your own terms. For an age threshold or a verified-ID check only a yes or no is kept.

`assurance` names how it was established (`issuer_signed_credential_device_bound`: an ID in Apple Wallet checked against the issuing
authority; `document_and_biometric_match`: a scanned document, liveness check and face match by our provider; `sandbox_simulated`: test
mode). A selfie age estimate is never reported as a verified age. Check `audience` is your business id.

**Test mode.** With a `vdk_test_` key and a sandbox relationship a request completes at once with a simulated result
(`sandbox_simulated`), so you can build the whole flow without a real customer.

**Things to build in.** Treat `not_verified` as "not proven", not as "underage". Do not retain more than you need, and tell customers what you keep.
Do not ask a customer to verify repeatedly: Viadere limits open requests per customer, and each request needs the customer's consent.

## 5c. Approve v2: payments and sign-ins your customer confirms with Face ID

Approve asks a customer to confirm one specific thing ("pay $2,500.00 to Example Merchant") and gives you a **signed result you verify yourself**. It is built so that Viadere, as the relay, **cannot approve for your customer, cannot change what they see without you noticing, and (end to end) cannot read it**.

> **The relay status alone is never sufficient.** `status: "approved"` on a request, a webhook, or a poll is information for your UI. **Release money, grant access or change anything only after you have verified the signed result (`ApprovalVerifier`) against the key you enrolled and the request you created.** Treat any approval you have not verified as a denial.

Requires the scopes `approvals:manage` (enrollment, requests, results, freeze) and `keydirectory:manage` (your key directory), a live key, and the `auth.challenge` / `transaction.approve` capabilities. Approve v2 is behind a release gate and may not be enabled for your environment yet.

### The pieces

| You hold | Purpose |
|---|---|
| **Root key** (P-256, offline or in a KMS/HSM) | Signs every other key you publish. Its id is pinned by customers' phones. Rarely used. |
| **Enrollment-confirmation key** | Signs the confirmation that a customer's key is the one you accepted. |
| **Request-signing key** | Signs each end-to-end request, so the phone can tell it came from you. |
| **HPKE key** (optional) | Lets customers and Viadere deliver encrypted data to you (Verify). |
| **Your own store of customer approval keys** | The keys you verified at enrollment. Results are verified against **this**, never against what Viadere sends later. |

Viadere never holds or generates any of your keys. Keep the root key out of your application servers: use an `ExternalSigningKey` that signs in your KMS.

### Step 1: publish your keys (once, then at rotation)

```swift
let business = BusinessID("…")!
let client = try ViadereBusinessClient(apiKey: liveKey)                 // scope keydirectory:manage
let authority = BusinessKeyAuthority(businessId: business, rootKey: rootKey)   // rootKey: any DeviceSigningKey (software, or ExternalSigningKey over your KMS)

try await client.publishKeyEntry(authority.registrationEntry())                                   // your root, self-signed
let confirmation = SoftwareP256SigningKey()                                                        // or a KMS key: keep the private part with you
let requestSigning = SoftwareP256SigningKey()
try await client.publishKeyEntry(authority.keyEntry(purpose: .approvalEnrollmentConfirmation, publicKey: confirmation.publicKey.x963, serial: 1))
try await client.publishKeyEntry(authority.keyEntry(purpose: .approvalRequestSigning, publicKey: requestSigning.publicKey.x963, serial: 2))

// Check what customers will see. This verifies Viadere's signed tree head, inclusion proofs and your key history.
let directory = try await client.verifiedKeyDirectory(businessId: business, logKeys: [viadereLogKey])   // the log public key: `ViadereServer key-directory-log-key`
print(directory.currentRootKid, directory.nextSerial)                                                  // show the root key id on your own screens
```

Show your **root key id** in your own signed-in pages. The SDK puts it in the QR/link it builds (`rk=`, from `authority.rootKid`): customers' phones compare it with the log, which catches a relay that tries to substitute a root. Each key is valid for at most 400 days (30 to 90 is a good rotation period). Rotate by publishing a new key, switching, then revoking the old one with `authority.revocationEntry(kid:serial:)`. To replace the root itself, `authority.successionEntry(to:)` (both roots sign); customers are alerted and must re-confirm.

**Run the log monitor** so you notice a key you did not publish (a stolen API key, or a relay that appended something):

```
VIADERE_API_KEY=vdk_live_… viadere-key-monitor --business <uuid> --log-key <log public key> --state /var/lib/monitor/state.json
```

Exit code `0` is fine; `2` is an incident (an entry you did not expect, or a log that is inconsistent with what it showed before). Run it every few minutes and alert on non-zero.

### Step 2: enroll a customer's approval key

You can only enroll a customer you already have a relationship with (`subject_ref`, section "Customer references"). Do this inside your own signed-in session for that customer, never over SMS or email.

```swift
// scope approvals:manage. The SDK builds the link and the secret; the relay's own `deep_link` is never shown.
let invitation = try await client.createApprovalEnrollment(subject: subject, capability: .transactionApprove, authority: authority)
try await enrollmentStore.save(invitation)     // YOUR database, keyed by invitation.enrollmentId: it holds the enrollment secret. Never log it.

// Show invitation.link as a QR or button. For a customer who types instead: invitation.displayCode (ABCD-EFGH) AND invitation.checkCode (a second ABCD-EFGH).

// Wait for the webhook `approve.enrollment.device_completed`, then:
let enrolled = try await client.confirmApprovalEnrollment(
    invitation: try await enrollmentStore.load(enrollmentId),
    businessId: business, expectedSubject: subject,
    sas: typedSixDigits,                       // typed path only: the six digits the customer's app shows, typed into YOUR signed-in page
    confirmationKey: confirmation, minimumAssurance: .biometric)
await keyStore.add(enrolled)                   // YOUR store: this is what every later result is verified against
```

**A statement that verifies proves nothing about who sent it.** Viadere (the relay) creates the code, stores the customer's statement and hands it to you, and it knows every id in it: a compromised relay could make a key of its own, sign a perfectly valid statement and give it to you. `confirmApprovalEnrollment` therefore refuses to sign a confirmation until the statement is authenticated with the secret only you and the customer's app hold:

* **Link or QR** (`https://viadere.com/a/CODE?rk=<your root key id>#es=<secret>`): the app returns a *binding tag* (an HMAC of its statement under the secret). The SDK verifies it in constant time. The secret sits in the URL **fragment**, which is never sent to Viadere; do not put it anywhere a server could read it (no redirect through your own tracking page, no logging of the full URL, no analytics on the QR image).
* **Typed code**: the customer enters the code *and* the check code in the app; the app shows six digits; you type them into `sas`. The check code never goes to Viadere, so Viadere cannot compute those digits for a forged statement.
* A forged or swapped statement, a wrong tag or a wrong SAS throws `bindingTagInvalid` / `sasMismatch`, **cancels the enrollment** and revokes the pending key: start a new one (one SAS guess per enrollment). `verificationRequired` means no proof arrived yet; nothing was changed.
* The SDK also refuses a ticket whose root key id is not yours (`rootKeyMismatch`): the `rk` the customer's phone treats as "verified out of band" is your own, not the relay's.
* If you do not confirm within the enrollment's lifetime plus five minutes, Viadere revokes the pending key and sends you `approve.key.revoked`; the customer's phone removes it too and tells them.

`confirmApprovalEnrollment` also verifies the statement itself (signature by its own key, your business id, the customer you started it for, the enrollment id, assurance) **before** it signs. The phone activates the key only if your confirmation names the exact statement it signed, so a relay that swapped the key is detected on the phone. Persist `enrolled` (its `key` holds the kid, public key, subject and assurance) durably; implement `ApprovalKeyStore` over your database (the SDK ships `InMemoryApprovalKeyStore` for tests).

**Registering or changing the root key** is not possible with an API key alone: sign in to the dashboard (Approve > Root key) as a Security Admin or Owner, complete the passkey prompt and authorize the root key id (it must belong to a business with a verified domain); then publish the signed entry within 15 minutes. Each authorization covers one key id once.

**Freeze notifications.** The `approve.frozen` webhook's `request_id` is an opaque `frz_...` reference. Resolve it with `client.approvalFreeze(ref:)` (it returns the `subject_ref` and whether approvals are frozen now).

**The legacy `authorize` / `authenticate` interactions are not an approval path.** Their status is the relay's word; you cannot verify it. While Approve v2 is available they are refused for live traffic (`403 legacy_approval_not_entitled`; high and critical `authenticate` too) unless Viadere granted your business a time-limited legacy entitlement during migration (at most 180 days, ending no later than 2027-06-30). The sandbox is unaffected. Use Approve v2 for sign-in approvals and transaction authorization.

### Step 3: ask for approval

```swift
let builder = ApprovalRequestBuilder(businessId: business, requestSigningKey: requestSigning)
let requestId = ApprovalRequestBuilder.newRequestId()
let challenge = ApprovalRequestBuilder.newChallenge()          // 256 random bits, single use
let details = ApprovalSubject.transaction(TransactionDetails(
    currency: "USD", amountMinor: 250_000, payeeDisplay: "Example Merchant", transactionReference: "bank_tx_123"))

// Store the pending request first: this is what the result will be checked against.
let pending = PendingApproval(requestId: requestId, subject: subject, challenge: challenge, details: details,
                              expiresAt: Date().addingTimeInterval(120))
try await pendingStore.save(pending)

// End to end (recommended): one signed, encrypted copy per enrolled device. Viadere relays ciphertext only.
let request = try await builder.endToEnd(requestId: requestId, subject: subject, challenge: challenge, details: details,
                                         devices: enrolledDevices.map(\.target))      // each target = the kid and HPKE key from enrollment
_ = try await client.createApprovalRequest(request)

// Or server-visible (spec 14.2 body; Viadere can read it and the phone says so):
// let request = try builder.serverVisible(requestId: requestId, subject: subject, challenge: challenge, details: details)
```

`expires_in_seconds` is 30 to 600 (default 120). A customer with no active key gets `409` with `details.reason = "no_active_key"`: run enrollment first. Use a new `request_id` for each attempt; reusing one with different content is `409 idempotency_conflict`. Viadere limits requests per customer (a warning from the third in an hour, a pause after repeated denials); a `429` or `approvals_paused` is the customer-protection system, not an outage: do not retry in a loop.

### Step 4: get the result and verify it

Subscribe a webhook with `envelope_version: "2026-10-27"` for the opaque events. The body carries **ids only**:

```json
{"id":"evt_8d1f","type":"approve.request.decided","version":"2026-10-27","tenant_id":"<your business id>","request_id":"req_…","occurred_at":"2026-10-27T10:15:00Z","result_ref":"res_…"}
```

```swift
let webhookVerifier = WebhookVerifier(secrets: [currentSecret, previousSecretDuringRotation])
let delivered = try webhookVerifier.verifyEnvelope(headers: headers, body: rawBody, deduplicator: dedup)   // signature, timestamp, strict body, dedup
// delivered.deliveryId is the Viadere-Delivery-Id, delivered.keyId the Viadere-Key-Id (whk_…_v<secret version>)

guard delivered.envelope.type == WebhookEventType.approveRequestDecided.rawValue, let ref = delivered.envelope.resultRef else { return }
let result = try await client.approvalResult(resultRef: ref)                                  // the signed JWS and its kid
let pending = try await pendingStore.load(requestId: result.requestId)                        // YOUR record of what you asked

let verifier = ApprovalVerifier(businessId: business, keys: keyStore, replayCache: replayGuard, minimumAMR: .biometric)
do {
    let verified = try await verifier.verify(result: result.result, for: pending)             // consumes the challenge
    // verified.decision == .approve : the customer, with Face ID, approved EXACTLY pending.details. Proceed.
} catch ApprovalVerificationError.notApproved(let decision) {
    // a signed deny or report: .deny / .report
} catch {
    // anything else is a refusal: wrong key, revoked, wrong amount/payee, expired, replayed, weak authentication ...
    // do not proceed; log the error
}
```

`verify` checks, against **your** records: the JWS is `ES256` only (no `none`/`HS256`, no `crit`, no foreign header members), the `kid` is a key you enrolled and confirmed for this customer and is not revoked, the signature is by that key, `aud` is you, the subject, request id and challenge match the request you created, the signed `txn_digest` is the digest of the transaction **you** hold (a changed amount, payee, currency or reference fails), it has not expired, authentication meets your minimum, and the challenge has not been used. Pass a durable `ReplayGuard` (a table with a unique constraint) in production, shared by all your servers.

Polling `client.approvalRequest(requestId:)` is fine for UX, but the only thing you may act on is the verified result.

### Freeze and revocation

* A customer can freeze approvals for everyone or for one business; while frozen, an approval cannot be submitted (only a refusal is accepted; an unanswered request simply expires), and you get `approve.frozen`. Only the customer lifts their own freeze (with Face ID).
* You can freeze a customer on your side with `client.freezeApprovals(subject:frozen:reason:)` (for example after account takeover signs) and lift only your own freeze.
* Revoke a key with `client.revokeApprovalKey(kid:reason:)` **and** mark it revoked in your store, since your store is what you verify against. You also receive `approve.key.revoked` when the customer, a device revocation or a disconnect removes a key.

### Privacy

Each customer has a different approval key and `subject_ref` for you; nothing links them to other businesses. Viadere clears displayed details at the terminal state and keeps requests for 400 days; the signed result is kept as evidence. In end-to-end mode Viadere never sees the amount or payee.


## 6. Errors

Every error is `{"error":{"code","message","requestId","details?"}}`. Quote `requestId` when contacting support.

| HTTP | `code` | Meaning and what to do |
|---|---|---|
| 400 | `bad_request` | Malformed body, or `Idempotency-Key` header ≠ body `idempotencyKey`. Fix the request. |
| 401 | `unauthorized` | Missing, unknown, revoked or expired key. Check the key and its expiry. |
| 403 | `forbidden` | Your business is not active (pending or suspended), or the key's mode does not match the relationship. |
| 403 | `insufficient_scope` | The key lacks the route scope or the capability the request needs (for example a messaging key issuing an `authorize`). |
| 403 | `not_entitled` | Your business does not (or no longer) hold the capability. |
| 403 | `capability_disabled` | Viadere has switched the capability off. |
| 403 | `policy_denied` | A policy rule or evidence requirement denies the request (`error.details.reason`). |
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

## 8a. Enterprise connectivity (Tier E): mutual TLS

Optional, for organizations granted Tier E. API semantics are identical on every transport: private connectivity never bypasses authorization (the API key and its scopes, capabilities and entitlements still decide).
Point your integration at the enterprise hostname (`https://api-mtls.viadere.com`, shown under *Security > Certificates*), present a client certificate issued by the CA you gave us, and bind that certificate (its SHA-256 fingerprint, or the CA)
under *Security > Certificates*. Then create keys with **Require a bound client certificate**; a key can be bound to one certificate, and a certificate belongs to exactly one organization. Cloudflare verifies the certificate at the edge and tells us what it verified;
the server believes that only on a request that carries our edge token, so a header you send yourself changes nothing. You can also require a certificate for **every** key of the organization. Remove a certificate and its keys stop working at once.
A VPN, a private endpoint or dedicated connectivity can be arranged for Tier E through Viadere; they end at the same API layer. Ordinary businesses do not need any of this.

## 9. Go-live checklist

- [ ] Organization verified (domain, legal entity, agreements accepted at their current versions); handle and code issued; go-live approved; a security contact is set.
- [ ] Webhook endpoint verified (*Verify*), and you have sent a test event and received a signed `message.received` simulation.
- [ ] Live key stored in a secrets manager, scoped to what the integration needs; test key used in CI.
- [ ] Webhook endpoint verifies signatures on the raw body, rejects stale timestamps, deduplicates on `Viadere-Event-Id`, and answers `2xx` quickly (do the work asynchronously).
- [ ] Every `POST` carries a deterministic idempotency key, persisted before sending.
- [ ] `expired`, `cancelled`, `denied` and `reported` are all treated as "do not proceed".
- [ ] You never treat an RCS or SMS reply as approval of a sensitive action.
- [ ] Customer-authored text (`message.received`) is handled as untrusted input.
- [ ] Redemption codes are validated server-side with `consumeRedemption` (never trusted from the app) and `409`/`410` mean "do not hand over the reward".
- [ ] If you use Verify: you handle `not_verified` without inferring why, retrieve each result exactly once and store only what you need, and you have your own legal basis for the age or identity check you run.
- [ ] You monitor `429`s, your complaint rate and your opt-out rate; you rotate keys and webhook secrets on a schedule (webhook rotation keeps the old secret valid for 24 hours; API-key rotation keeps the old key for the overlap you choose) and use an IP allow-list and an expiry on live keys.
