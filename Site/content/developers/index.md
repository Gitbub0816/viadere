---
title: Developers
nav_title: Overview
order: 0
description: The Viadere Business API: issue structured requests, receive signed decisions and exchange messages.
wide: true
---
The Business API lets a **verified** business ask a connected customer to confirm, choose, acknowledge, reply, authenticate or authorize something, route support messages, publish ongoing-event statuses, and receive signed webhooks when anything changes.

::: callout
**API version `{{api-version}}`.** Messaging and Approve are in beta, so interfaces may still change. Changes are recorded in the [changelog](/developers/changelog/). This reference is generated from the OpenAPI contract, `docs/openapi.yaml`.
:::

## Start here

::: grid grid-3
::: card
### Quickstart
Get a test key, issue a request and verify the webhook. [Quickstart](/developers/quickstart/)
:::
::: card
### Authentication
Bearer keys, scopes and the test-mode sandbox. [Authentication](/developers/authentication/)
:::
::: card
### API reference
Every endpoint, parameter and response. [API reference](/developers/api/)
:::
::: card
### Webhooks
Event types, signature verification and retries. [Webhooks](/developers/webhooks/)
:::
::: card
### Errors, limits, idempotency
One error shape, explicit limits and safe retries. [Errors](/developers/errors/)
:::
::: card
### SDKs
A Swift SDK with typed client and webhook verification. [SDKs](/developers/sdks/)
:::
:::

## Principles of the API

- **You see a pseudonym.** Each customer is a per-business identifier. You never receive their Viadere identity or phone number.
- **You verify the evidence.** A decision names the deciding device by a per-business pseudonym and carries the server's attestation. You decide whether to proceed.
- **Sensitive means device-signed.** `authenticate`, `authorize` and any high or critical sensitivity can only be approved in the Viadere app, never by SMS or RCS reply.
- **Paying changes quotas, not priority or consent.**

## Base URL

```
https://viadere.com
```

Service health is on the [status page](/status/). Migration guides will appear under [changelog](/developers/changelog/) when a breaking version exists.
