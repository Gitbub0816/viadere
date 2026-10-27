---
title: For Businesses
nav_title: Overview
order: 0
description: Ask customers to confirm, choose, approve or reply, with a verified identity and a signed answer.
disclosures: [business_verification]
---
Viadere gives a verified business one API for the moments that matter: confirming an order, approving a sign-in, authorizing a payment, answering a support question.

## Use cases

::: grid grid-2
::: card
### Sign-in and payment approval
Ask "is this you?" with the amount, merchant and location. Check the device-signed answer yourself. [Approve](/products/approve/) is in beta.
:::
::: card
### Orders, pickups and appointments
Confirm, reschedule or check in with a tap, and keep one status item current instead of sending a stream of texts.
:::
::: card
### Support conversations
Route customer questions to your own tools and answer in the same verified thread. [Messaging](/products/messaging/) is in beta.
:::
::: card
### Loyalty and rewards
Run points, status levels and redemption codes validated at the till. Eligibility is decided by Viadere's servers.
:::
:::

## Capabilities

- Structured requests: `authenticate`, `authorize`, `confirm`, `choose`, `acknowledge`, `reply`, `status`, `ticket`, `message`.
- Signed webhooks for every outcome, with at-least-once delivery and retries.
- Idempotent writes, scoped API keys and a sandbox that never reaches a real customer.
- A per-business pseudonym for each customer. You do not receive their Viadere identity or phone number.

## Supported channels

| Channel | Status | What it can carry |
|---|---|---|
| Viadere app (push, in-app) | Beta | Everything, including device-signed approvals |
| RCS | Beta | Text and suggested replies, never an authenticated approval |
| SMS | Beta | Text and secure handoff links. SMS fallback is not end-to-end encrypted. |
| Apple Messages for Business | Not available | Disabled until Apple approves multi-merchant brokerage in writing |

Sensitive requests are never downgraded to a text yes or no.

## Integration walkthrough

1. **Apply** and get verified. Your handle and permanent code are issued only on approval. See [onboarding](/businesses/onboarding/).
2. **Create a test key** and a sandbox relationship. Build against it without touching a real customer.
3. **Issue a request** with an idempotency key. See the [quickstart](/developers/quickstart/).
4. **Verify the webhook** on the raw body and act on the signed result. See [webhooks](/developers/webhooks/).
5. **Go live** with the [checklist](/developers/quickstart/#go-live-checklist).

## What verification means

::: disclosure
A verified business has completed Viadere's business-identity checks. Verification does not constitute an endorsement, guarantee of legitimacy, or confirmation of regulatory licensing.
:::

Verification is not a regulatory sufficiency guarantee. A financial institution still owns its own customer identification and anti-money-laundering duties. See [verification services addendum](/legal/verification-services-addendum/) (draft).

## Pricing

Pricing is not final. See [pricing and fees](/businesses/pricing/) for the fee categories that will apply.
