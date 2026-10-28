---
title: Home
layout: home
description: Verified, interactive business communication without traditional short-code friction. Know who is asking, see exactly what they want, and answer in one tap.
eyebrow: A trusted way to connect.
headline: Know who is asking. *Answer in one tap.*
lede: Viadere gives businesses a verified identity and gives you a clear request on your phone, right in the notification. Your answer is signed on your device, and the business checks it for itself.
actions:
  - label: For businesses
    href: /businesses/
  - label: Read the developer docs
    href: /developers/
proof:
  - icon: seal
    label: Verified business identity
  - icon: chip
    label: Keys held on your device
  - icon: split
    label: A different pseudonym for every business
---
::: section lineup-band
{{ generate: mockup lineup }}
:::

::: section tight
::: statement
A text from an unknown number. A link you cannot check. A request with no context. Viadere replaces the guesswork with **a verified name, a clear purpose and an answer you can prove.**
:::
:::

::: section alt
::: section-head
::: kicker
{icon:sparkle} Why it matters
:::
## The same moment, *made legible.*

An ordinary text cannot prove who sent it or what “YES” means. A Viadere request carries the verified business, the purpose, the context and an expiry, and a sensitive answer is signed on your phone.
:::

{{ generate: mockup contrast }}
:::

::: section
::: feature
::: feature-copy
::: kicker
{icon:faceid} Approve · {badge:beta}
:::
## Sign-in approvals, right from the lock screen.

When someone signs in to your account, the business can ask Viadere to check with you. You see the verified business, the browser, the place and the time, and you answer with Face ID.

- {icon:check} **Context you can judge:** device, approximate location and time, with a visible expiry.
- {icon:check} **Signed on your iPhone** with a key held in the Secure Enclave, one key per business.
- {icon:check} **“This was not me”** reports the attempt, and the business is told not to proceed.

[Explore Approve](/products/approve/){.more}
:::
::: feature-art
{{ generate: mockup signin }}
:::
:::

::: feature flip
::: feature-copy
::: kicker
{icon:signature} Transaction authorization · {badge:beta}
:::
## “Is this you?” with the amount, payee and place.

A bank or merchant can ask before money moves. The amount, the payee and the reference you see are exactly what your device signs, so the business can tell if anything was changed on the way.

- {icon:check} **Slide to approve** for money, so a stray tap never authorizes a payment.
- {icon:check} **Bound to what you saw:** amount, currency, payee and reference are part of the signature.
- {icon:check} **The business decides.** Viadere delivers the decision; the business processes the payment.

[How a decision is made](/products/approve/#how-a-decision-is-made){.more}
:::
::: feature-art
{{ generate: mockup payment }}
:::
:::

::: feature
::: feature-copy
::: kicker
{icon:message} Messaging · {badge:beta}
:::
## Orders, pickups and support in one verified thread.

A verified business can confirm an order, ask you to choose a time, keep one status card current and answer your questions, all clearly attributed to the business.

- {icon:check} **Structured requests:** confirm, choose, acknowledge or reply, often from the notification itself.
- {icon:check} **One status that updates** instead of a stream of texts, with Live Activities for orders and trips.
- {icon:check} **Consent per purpose.** Turning off marketing never turns off security notices.

[Explore Messaging](/products/messaging/){.more}
:::
::: feature-art
{{ generate: mockup conversation }}
:::
:::

::: feature flip
::: feature-copy
::: kicker
{icon:gift} Rewards and Wallet passes · {badge:beta}
:::
## Rewards that live in Wallet, not in a junk folder.

Businesses can run points, perks like a free coffee on Tuesdays, and single-use redemption codes, with Apple Wallet passes kept up to date. Eligibility is decided on Viadere's servers, never on the phone.

- {icon:check} **One tap to claim**, validated by the business at the till.
- {icon:check} **Single-use codes:** a code that was already redeemed or has expired is refused.
- {icon:check} **Normal priority, always.** Rewards and marketing never jump ahead of security requests.

[Rewards in the Business API](/businesses/#use-cases){.more}
:::
::: feature-art
{{ generate: mockup wallet }}
:::
:::
:::

::: section alt
::: section-head
::: kicker
{icon:clock} On the roadmap
:::
## Planned, and *labelled that way.*

Two products are designed but not available. We show them so that you can judge the intent, not because you can use them today.
:::

::: grid grid-2 gap-lg
::: card
{badge:planned}

### Verify

Confirm one fact, such as “over 21”, without handing over a date of birth, name or ID number. A result describes the attribute and assurance evaluated, and nothing more.

{{ generate: mockup verify }}

[Read the Verify intent](/products/verify/){.more}
:::
::: card
{badge:planned}

### Authenticator

A vault for your passkeys and one-time codes, synced between your devices, with recovery that does not depend on identity checks. It ships only after an independent cryptography and recovery review.

{{ generate: mockup authenticator }}

[Read the Authenticator intent](/products/authenticator/){.more}
:::
:::
:::

::: section
::: section-head
::: kicker
{icon:repeat} How it works
:::
## One request. One decision. *Proof that travels back.*

Businesses integrate once. Viadere checks, routes and records; the customer decides; the business verifies the signed answer itself.
:::

{{ generate: mockup flow }}
:::

::: section dark
::: section-head
::: kicker
{icon:eye-off} Privacy by design
:::
## What the business sees, and *what stays with you.*

A business gets what it needs to act on your answer, and nothing that would let it follow you elsewhere.
:::

{{ generate: mockup privacy }}
:::

::: section
::: devsplit
::: devcopy
::: kicker
{icon:code} For developers
:::
## A typed Swift SDK and a plain JSON API.

Issue a request with an idempotency key, receive a signed webhook, and verify the device signature against the request you created.

- {icon:check} **A sandbox** that never reaches a real customer, for rehearsing every outcome.
- {icon:check} **Idempotent writes** and scoped keys, shown once and revocable.
- {icon:check} **Opaque webhooks** (opt-in) carry identifiers only: no customer data, amount or decision.

::: actions
[Start the quickstart](/developers/quickstart/){.btn} [API reference](/developers/api/){.btn .secondary}
:::
:::
::: devstack
```swift Approve.swift
import ViadereBusinessSDK

let client = try ViadereBusinessClient(apiKey: apiKey)
let builder = ApprovalRequestBuilder(businessId: myId)

// Ask "Is this you?" before a $285.28 purchase.
let request = try builder.serverVisible(
    requestId: ApprovalRequestBuilder.newRequestId(),
    subject: customer.subjectRef,
    challenge: ApprovalRequestBuilder.newChallenge(),
    details: .transaction(TransactionDetails(
        currency: "USD", amountMinor: 28_528,
        payeeDisplay: "Juniper Coffee",
        transactionReference: "ord_7731")))
_ = try await client.createApprovalRequest(request)

// On approve.request.decided, verify it yourself.
let result = try await client.approvalResult(
    resultRef: event.resultRef)
let verified = try await verifier.verify(
    result: result.result, for: pending)
guard verified.decision == .approve else { return deny() }
```

```json webhook · approve.request.decided
{
  "id": "evt_2bW7…",
  "type": "approve.request.decided",
  "version": "2026-10-27",
  "tenant_id": "biz_…",
  "request_id": "req_9QhR…",
  "occurred_at": "2026-10-28T16:41:07Z",
  "result_ref": "res_Xk2v…"
}
```
:::
:::

Code values are illustrative. See [webhooks](/developers/webhooks/) for every event shape and the [SDK guide](/developers/sdks/) for setup.
:::

::: section alt
::: section-head
::: kicker
{icon:seal} Security architecture
:::
## Built on restraint, not on *secrecy claims.*

Viadere is designed to hold as little as it can, and to make every decision checkable by the business that asked. [Read the architecture overview](/security/architecture/).
:::

{{ generate: mockup pillars }}

::: callout
**Honest about limits.** Ordinary SMS is not end-to-end encrypted, so a sign-in or payment is never approved by text reply: a text receives a secure link to the app instead. Viadere has not completed an independent audit or certification, and says so on the [attestations](/security/attestations/) page.
:::
:::

::: section
::: section-head
## Each product, *with its real status.*

Messaging and Approve are in beta for approved businesses. Verify and Authenticator are planned and not available.
:::

{{ generate: product-cards }}
:::

::: section dark cta
::: center
## Build on a trusted way to connect.

Get verified, create a test key and send your first request from the sandbox. Consumers pay nothing to use Viadere.

::: actions
[Get started](/businesses/onboarding/){.btn} [Talk to us](/company/contact/){.btn .secondary}
:::
:::
:::
