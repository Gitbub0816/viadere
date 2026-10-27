---
title: SDKs
order: 3
description: The Swift Business SDK, and calling the API directly from any language.
wide: true
---
## Swift

`ViadereBusinessSDK` is a typed client with webhook verification and idempotency helpers. It is in the Viadere repository under `Packages/ViadereBusinessSDK`, and is not yet published as a versioned release. [PRODUCT: package URL and release tag when published.]

```swift
let client = try ViadereBusinessClient(apiKey: apiKey)
_ = try await client.createSandboxRelationship()
```

The SDK retries `429`, `5xx` and network failures for `GET` requests and keyed `POST` requests, honouring `Retry-After`.

## Other languages

There is no official SDK for other languages yet. The API is plain JSON over HTTPS, described by an OpenAPI 3.1 contract, so any HTTP client works. Generating a client from the contract is possible; review generated code before using it with live keys. [PRODUCT: publish the contract download.]

## Rules for every client

- Keep the API key on your server.
- Send an `Idempotency-Key` on every write, and store it before sending.
- Verify webhooks on the raw body.
- Treat customer-authored text as untrusted input.
