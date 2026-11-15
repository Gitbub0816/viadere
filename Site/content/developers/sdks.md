---
title: SDKs
order: 3
description: Three server-side SDKs, in Swift, TypeScript and Kotlin, each with its real status, and how to call the API from any other language.
wide: true
---
Three SDKs exist in the Viadere repository. None is published to a package registry yet, so each one below says what it covers and how far it has been built and tested.

| SDK | Language | Covers | Status |
|---|---|---|---|
| `ViadereBusinessSDK` | Swift | The whole Business API, both webhook signature versions, Approve v2 and authentication delivery | Built and tested. Not yet published as a versioned release |
| `@viadere/server` | TypeScript, for Node 22 or later | Authentication delivery and webhook signature v2 | Built and tested. Version 0.1.0, unreleased; the package is private until it is published |
| `com.viadere.sdk` | Kotlin | Authentication-delivery contract models and webhook signature v2 | Sources written. **Not yet built or run** |

All three are for your server. Never ship an API key or a webhook secret in an app or a web page.

## Swift

`ViadereBusinessSDK` is in the repository under `Packages/ViadereBusinessSDK`. It is the most complete of the three. [PRODUCT: package URL and release tag when published.]

- A typed client for the [Business API](/developers/api/): interactions, messages, statuses, webhooks, rewards, Wallet passes, capabilities and verification.
- Webhook verification for both signature versions, with deduplication and the [endpoint verification](/developers/webhooks/#endpoint-verification) answer.
- Idempotency helpers, and automatic retries of `429`, `5xx` and network failures for `GET` requests and keyed `POST` requests, honouring `Retry-After`.
- Approve v2: publishing your keys, enrolling a customer's approval key and verifying a signed result against your own records. Approve v2 is built and held behind a release gate.
- The [authentication delivery](/developers/auth-delivery/) calls, which are a staging pilot.
- `viadere-key-monitor`, a command-line tool that watches the key directory for an entry you did not publish.

```swift
let client = try ViadereBusinessClient(apiKey: apiKey)
_ = try await client.createSandboxRelationship()
```

## TypeScript (Node)

`@viadere/server` is in the repository under `sdk/node`. It has zero runtime dependencies and needs Node 22 or later, or another JavaScript runtime with `node:crypto` and `fetch`.

Today it covers [authentication delivery](/developers/auth-delivery/) and webhook [signature v2](/developers/webhooks/#signature-v2). It does not yet cover the rest of the Business API: work to extend it is in progress, and the package README states the current surface.

- A typed client: create, read, cancel and complete a delivery, move an endpoint to signature v2 and send a signed test event.
- A create request is checked against the contract before it is sent.
- Idempotency keys are derived from your `request_id` by default, so a retry after a crash replays the original instead of sending a second push.
- A signature v2 verifier with a replay store that is on by default. The default store is per process: in production pass one that all your servers share.
- A per-requester throttle that is on by default: at most 3 open deliveries per account and client network prefix.
- Its tests run the shared signature vectors, including the negative ones, and fail when the SDK drifts from the contract.

```javascript
import { ViadereClient, WebhookVerifier } from "@viadere/server";

const viadere = new ViadereClient({ apiKey: process.env.VIADERE_API_KEY });
```

It is version 0.1.0 and unreleased. It is not on a package registry, so it cannot be installed with a package manager yet.

## Kotlin

`com.viadere.sdk` is in the repository under `sdk/android`. It holds the authentication-delivery contract models, strict validation of a create request, a signature v2 verifier with a replay store, the per-requester throttle and idempotency keys. It has no runtime dependency beyond the Kotlin standard library.

::: callout
**Not yet built.** The sources and their tests are written, but they have not been compiled or run. Treat this SDK as unverified until its build and tests pass.
:::

It is meant for Kotlin on a server or in tooling. Despite the directory name, do not put a webhook secret or an API key in an Android app.

## Buttons for your site and app

These are not API clients. They render a link and hold no key.

- **Connect with Viadere:** a dependency-free web component and a plain HTML and CSS variant.
- **Verify with Viadere:** a web component, SwiftUI and UIKit views in the Swift SDK, and an Android library. The web component is at version 2: on a computer its panel shows the [Viadere code](/products/viadere-code/) first, with the same link as a QR code one control away. Version 1 keeps working and stays QR-only, and moving to version 2 changes only the two file addresses and their integrity hashes. The iOS and Android buttons still show a QR code first. [Verify](/products/verify/) itself is built and not released, so the button has nothing to open in production.

## Other languages

The API is plain JSON over HTTPS, described by two OpenAPI 3.1 contracts: the [Business API](/developers/api/) and [authentication delivery](/developers/auth-delivery/). Any HTTP client works. Generating a client from a contract is possible; review generated code before using it with live keys. [PRODUCT: publish the contract downloads.]

## Rules for every client

- Keep the API key on your server.
- Send an `Idempotency-Key` on every write, and store it before sending.
- Verify webhooks on the raw body.
- Treat customer-authored text as untrusted input.
