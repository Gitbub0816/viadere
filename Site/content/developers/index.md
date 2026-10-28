---
title: Developers
nav_title: Overview
layout: marketing
subnav: false
order: 0
headline: Build on *verified requests and signed answers.*
description: The Viadere Business API lets a verified business issue structured requests, receive signed decisions and exchange messages.
hero_art: curl
actions:
  - label: Quickstart
    href: /developers/quickstart/
  - label: API reference
    href: /developers/api/
---
::: section
::: prose-wide
::: callout
**API version `{{api-version}}`.** Messaging and Approve are in beta, so interfaces may still change. Changes are recorded in the [changelog](/developers/changelog/). This reference is generated from the OpenAPI contract, `docs/openapi.yaml`.
:::
:::

::: section-head left
::: kicker
{icon:bolt} Start here
:::
## Everything you need, *in the order you need it.*
:::

::: grid grid-3
::: card
### {icon:sparkle} Quickstart
Get a test key, issue a request and verify the webhook. [Quickstart](/developers/quickstart/)
:::
::: card
### {icon:key} Authentication
Bearer keys, scopes and the test-mode sandbox. [Authentication](/developers/authentication/)
:::
::: card
### {icon:doc} API reference
Every endpoint, parameter and response. [API reference](/developers/api/)
:::
::: card
### {icon:bell} Webhooks
Event types, signature verification and retries. [Webhooks](/developers/webhooks/)
:::
::: card
### {icon:repeat} Errors, limits, idempotency
One error shape, explicit limits and safe retries. [Errors](/developers/errors/)
:::
::: card
### {icon:code} SDKs
A Swift SDK with typed client and webhook verification. [SDKs](/developers/sdks/)
:::
:::
:::

::: section alt
::: devsplit
::: devcopy
::: kicker
{icon:code} Swift SDK
:::
## Typed, retrying, *and verifying.*

`ViadereBusinessSDK` is a typed client with webhook verification and idempotency helpers. It retries `429`, `5xx` and network failures for `GET` requests and keyed `POST` requests, honouring `Retry-After`.

[SDK guide](/developers/sdks/){.more}
:::
::: devstack
```swift Quickstart.swift
import ViadereBusinessSDK
import ViadereCore

let client = try ViadereBusinessClient(apiKey: apiKey)
let issued = try await client.issueInteraction(request)
let outcome = try await client.interactionOutcome(
    id: issued.interaction.id)
```
:::
:::
:::

::: section
::: section-head left
::: kicker
{icon:seal} Principles of the API
:::
## Four rules your integration can rely on.
:::

::: grid grid-2 gap-lg
::: card
### {icon:split} You see a pseudonym
Each customer is a per-business identifier. You never receive their Viadere identity or phone number.
:::
::: card
### {icon:signature} You verify the evidence
A decision names the deciding device by a per-business pseudonym and carries the server's attestation. You decide whether to proceed.
:::
::: card
### {icon:faceid} Sensitive means device-signed
`authenticate`, `authorize` and any high or critical sensitivity can only be approved in the Viadere app, never by SMS or RCS reply.
:::
::: card
### {icon:sliders} Paying changes quotas only
Never priority, never consent.
:::
:::

## Base URL

```
https://viadere.com
```

Service health is on the [status page](/status/). Migration guides will appear under [changelog](/developers/changelog/) when a breaking version exists.
:::
