---
title: For Businesses
nav_title: Overview
layout: marketing
order: 0
headline: Ask once. *Get an answer you can verify.*
description: Ask customers to confirm, choose, approve or reply, with a verified identity and a signed answer.
disclosures: [business_verification]
hero_art: payment
actions:
  - label: Get started
    href: /businesses/onboarding/
  - label: Pricing and fees
    href: /businesses/pricing/
---
::: section
::: section-head
::: kicker
{icon:store} Use cases
:::
## One API for *the moments that matter.* {#use-cases}

Confirming an order, approving a sign-in, authorizing a payment, answering a support question: each is one structured request with a verified sender and a recorded answer.
:::

::: grid grid-2 gap-lg
::: card
### {icon:faceid} Sign-in and payment approval
Ask “is this you?” with the amount, merchant and location. Check the device-signed answer yourself. [Approve](/products/approve/) is in beta.
:::
::: card
### {icon:bag} Orders, pickups and appointments
Confirm, reschedule or check in with a tap, and keep one status item current instead of sending a stream of texts.
:::
::: card
### {icon:message} Support conversations
Route customer questions to your own tools and answer in the same verified thread. [Messaging](/products/messaging/) is in beta.
:::
::: card
### {icon:gift} Loyalty and rewards
Run points, status levels and redemption codes validated at the till. Eligibility is decided by Viadere's servers.
:::
:::
:::

::: section alt
::: feature
::: feature-copy
::: kicker
{icon:code} Capabilities
:::
## Structured requests, signed outcomes.

- {icon:check} **Request kinds:** `authenticate`, `authorize`, `confirm`, `choose`, `acknowledge`, `reply`, `status`, `ticket`, `message`.
- {icon:check} **Signed webhooks** for every outcome, with at-least-once delivery and retries.
- {icon:check} **Idempotent writes,** scoped API keys and a sandbox that never reaches a real customer.
- {icon:check} **A per-business pseudonym** for each customer. You do not receive their Viadere identity or phone number.

[Read the developer docs](/developers/){.more}
:::
::: feature-art bare
{{ generate: mockup curl }}
:::
:::
:::

::: section
::: section-head
::: kicker
{icon:repeat} How it works
:::
## From request *to verified result.*
:::

{{ generate: mockup flow }}
:::

::: section alt
::: section-head
::: kicker
{icon:sms} Supported channels
:::
## Sensitive requests are never *downgraded to a text yes or no.*
:::

{{ generate: mockup channels }}

| Channel | Status | What it can carry |
|---|---|---|
| Viadere app (push, in-app) | Beta | Everything, including device-signed approvals |
| RCS | Beta | Text and suggested replies, never an authenticated approval |
| SMS | Beta | Text and secure handoff links. SMS fallback is not end-to-end encrypted. |
| Apple Messages for Business | Not available | Disabled until Apple approves multi-merchant brokerage in writing |
:::

::: section
::: section-head
::: kicker
{icon:bolt} Integration walkthrough
:::
## Live in three steps.
:::

::: steps
::: card
### Apply and get verified
Your handle and permanent code are issued only on approval. See [onboarding](/businesses/onboarding/).
:::
::: card
### Build in the sandbox
Create a test key and a sandbox relationship. Issue requests with an idempotency key. See the [quickstart](/developers/quickstart/).
:::
::: card
### Verify and go live
Verify the webhook on the raw body, act on the signed result, then follow the [go-live checklist](/developers/quickstart/#go-live-checklist).
:::
:::
:::

::: section alt
::: grid grid-2 gap-lg
::: card
### {icon:seal} What verification means
::: disclosure
A verified business has completed Viadere's business-identity checks. Verification does not constitute an endorsement, guarantee of legitimacy, or confirmation of regulatory licensing.
:::

Verification is not a regulatory sufficiency guarantee. A financial institution still owns its own customer identification and anti-money-laundering duties. See the [verification services addendum](/legal/verification-services-addendum/) (draft).
:::
::: card
### {icon:sliders} Pricing
Pricing is not final. Paying never changes the priority of your messages and never bypasses a customer's consent: a plan raises quotas only.

[See the fee categories](/businesses/pricing/){.more}
:::
:::
:::

::: section dark cta
::: center
## Start in the sandbox today.

Apply, get verified and send your first request without reaching a real customer.

::: actions
[Begin onboarding](/businesses/onboarding/){.btn} [Read the quickstart](/developers/quickstart/){.btn .secondary}
:::
:::
:::
