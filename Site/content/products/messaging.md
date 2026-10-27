---
title: Messaging
status: beta
order: 1
tagline: Verified two-way conversations and structured requests, in the app and through text fallback.
description: Verified two-way conversations and structured requests, in the app and through text fallback.
disclosures: [encryption]
---
Messaging lets a verified business send a customer structured requests (confirm, choose, acknowledge, reply), ongoing status updates and conversation messages, and receive replies.

::: callout
**Beta.** Messaging works today for approved businesses. Interfaces, limits and fees may change, and no uptime commitment has been published.
:::

## What it does

- **Verified sender.** Messages are attributed to the verified business in the Viadere app, with consent recorded per purpose.
- **Structured requests.** Customers answer from the notification where the platform allows it.
- **Status updates.** Orders, appointments and trips can be kept current in one item.
- **One thread over text.** Customers without the app can reach a business through a Viadere number, with the business clearly attributed.

## Channels and what they can carry

| Channel | Used for | Limits |
|---|---|---|
| Viadere app (push and in-app) | Everything, including device-signed decisions | Needs the app |
| RCS | Text with suggested replies | A tap is an unauthenticated reply |
| SMS | Plain text and secure handoff links | Not end-to-end encrypted; no authenticated approvals |

## SMS fallback

When the app or RCS is not available, a request can fall back to SMS. Ordinary SMS is not end-to-end encrypted, and carriers and providers can see message content. Viadere's relay also handles delivery metadata. Security-sensitive requests are never approved by SMS or RCS reply: a text channel receives a secure link to the app instead.


::: disclosure
Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview.
:::

## Related

[Messaging consent and content policy addendum](/legal/messaging-consent-content-policy-addendum/) (draft) and the [Business API](/developers/api/messages/).
