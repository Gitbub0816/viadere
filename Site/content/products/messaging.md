---
title: Messaging
layout: marketing
status: beta
order: 1
headline: Messaging. *Verified threads, structured answers.*
tagline: Verified two-way conversations and structured requests, in the app and through text fallback.
description: Verified two-way conversations and structured requests, in the app and through text fallback.
disclosures: [encryption]
hero_art: conversation
actions:
  - label: Messages API
    href: /developers/api/messages/
  - label: For businesses
    href: /businesses/
---
::: section
::: section-head
::: kicker
{icon:message} What it does
:::
## Everything a verified business needs *to keep a customer informed.*

A verified business can send structured requests (confirm, choose, acknowledge, reply), ongoing status updates and conversation messages, and receive replies.
:::

::: grid grid-4
::: card
### {icon:seal} Verified sender
Messages are attributed to the verified business in the Viadere app, with consent recorded per purpose.
:::
::: card
### {icon:bell} Structured requests
Customers answer from the notification where the platform allows it.
:::
::: card
### {icon:bag} Status updates
Orders, appointments and trips stay current in one item, with Live Activities where they fit.
:::
::: card
### {icon:sms} One thread over text
Customers without the app can reach a business through a Viadere number, with the business clearly attributed.
:::
:::

::: callout
**Beta.** Messaging works today for approved businesses. Interfaces, limits and fees may change, and no uptime commitment has been published.
:::
:::

::: section alt
::: feature flip
::: feature-copy
::: kicker
{icon:gift} Rewards and Wallet
:::
## Loyalty that stays out of the junk folder.

Points, status levels, perks and single-use redemption codes, with Apple Wallet passes kept current. Eligibility is decided on Viadere's servers, and a code that was already redeemed or has expired is refused at the till.

- {icon:check} **Normal priority.** Marketing and rewards never exceed normal priority; urgent is reserved for security sign-in and authorization requests.
- {icon:check} **Separate consent.** Marketing and rewards are separate purposes from security and service messages.
:::
::: feature-art
{{ generate: mockup wallet }}
:::
:::
:::

::: section
::: section-head
::: kicker
{icon:sms} Channels and what they can carry
:::
## The app does everything. *Text does what text can.*
:::

{{ generate: mockup channels }}

| Channel | Used for | Limits |
|---|---|---|
| Viadere app (push and in-app) | Everything, including device-signed decisions | Needs the app |
| RCS | Text with suggested replies | A tap is an unauthenticated reply |
| SMS | Plain text and secure handoff links | Not end-to-end encrypted; no authenticated approvals |
:::

::: section alt
::: prose
## SMS fallback

When the app or RCS is not available, a request can fall back to SMS. Ordinary SMS is not end-to-end encrypted, and carriers and providers can see message content. Viadere's relay also handles delivery metadata. Security-sensitive requests are never approved by SMS or RCS reply: a text channel receives a secure link to the app instead.

::: disclosure
Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview.
:::

Related: [Messaging consent and content policy addendum](/legal/messaging-consent-content-policy-addendum/) (draft) and the [Business API](/developers/api/messages/).
:::
:::
