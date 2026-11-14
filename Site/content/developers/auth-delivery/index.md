---
title: Authentication delivery
nav_title: Auth delivery
order: 45
api: auth-delivery
eyebrow: Auth delivery reference
description: Deliver your own magic link, one-time code or security notice to a customer's Viadere app. A staging pilot that is off by default.
wide: true
---
::: callout
**Staging pilot. Off by default.** This is a second contract, separate from the [Business API](/developers/api/). It is not enabled in production, and nothing on this page is a commitment to a date.
:::

Contract version `{{api-version}}`, generated from `contracts/openapi/auth-delivery-v1.yaml`. The contract names `{{api-server}}` as its server.

## What it is

Authentication delivery is a transport for something your own system already decided to send: a magic link, a one-time code you generated, or a fixed-text security notice. Viadere shows it only in the customer's own Viadere app, by push and then in the in-app inbox, and reports its state.

- **Viadere never verifies the result.** There is no route that checks a one-time code. Your server verifies its own link or code.
- **Opened is never signed in.** `sent`, `delivered` and `opened` never mean success. Only your own `complete` call finishes a delivery.
- **Nothing here goes over SMS.** There is no `sms` channel in this contract.
- **You cannot supply message text.** You pick a Viadere-owned template id and fill only the variables that template declares.

## Feature flag

{{ generate: info-section Feature flag }}

## Authentication and tenancy

{{ generate: info-section Authentication and tenancy }}

Keys need the scopes `auth_deliveries:write` and `auth_deliveries:read` and the `auth.challenge` capability. See [authentication](/developers/authentication/).

## How a delivery works

1. **Register a webhook endpoint with signature v2**, or move an existing endpoint with `PATCH /v1/business/webhooks/{webhookId}`. See [signature v2](/developers/webhooks/#signature-v2).
2. **Create a delivery** with `POST /v1/business/auth-deliveries`. The method is `magic_link`, `otp` or `notice`. A one-time code is shown in the app only after the customer opens the item, never on the Lock Screen.
3. **Follow the state** by webhook or with `GET /v1/business/auth-deliveries/{deliveryId}`.
4. **When the customer opened it, verify your own link or code**, then report the outcome with `POST /v1/business/auth-deliveries/{deliveryId}/complete`.
5. **Treat `denied` as hostile.** It means the customer said "This wasn't me".

Never put an e-mail address, a phone number or a URL in `variables`: they are refused. What you send there is personal data, stored sealed and deleted when the delivery ends.

## Idempotency

{{ generate: info-section Idempotency }}

## Replacing an earlier request

{{ generate: info-section Grouping (ADR-0020 revisions 3 and 3.1) }}

## Non-disclosure

{{ generate: info-section Non-disclosure }}

## Secrets

{{ generate: info-section Secrets }}

## Limits

A flood above your tenant budget is `429` with `Retry-After`. Per-customer budgets never refuse a request: a delivery over budget is created and appears in the customer's inbox without an alert. Throttle unauthenticated sign-in triggers on your side, per client address and per account. The [Node and Kotlin SDKs](/developers/sdks/) do this by default.

## Operations

Data types are listed under [auth delivery schemas](/developers/auth-delivery/schemas/). The operations tagged Device are called by the Viadere app, not by your server.

{{ generate: api-index }}
