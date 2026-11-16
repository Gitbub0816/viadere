---
title: Quickstart
order: 1
description: From zero to a verified decision in five steps.
wide: true
---
## 1. Get access

Apply at the [onboarding](/businesses/onboarding/) page. Sandbox work opens as soon as your domain is verified: you can then create a `vdk_test_` key in the dashboard with `interactions:write`, `interactions:read` and `webhooks:manage`. Live keys need the approved application and the go-live review.

Add a webhook endpoint and [verify it](/developers/webhooks/#endpoint-verification). An endpoint receives no events, not even test events, until it has proved it holds the signing secret.

## 2. Create a sandbox relationship

A test key can only address sandbox relationships, never a real customer.

```bash
curl -X POST https://viadere.io/v1/business/sandbox/relationships \
  -H "Authorization: Bearer $VIADERE_TEST_KEY" \
  -H "Idempotency-Key: sandbox-rel-1"
```

## 3. Issue a request

```bash
curl -X POST https://viadere.io/v1/business/interactions \
  -H "Authorization: Bearer $VIADERE_TEST_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: order-1042-confirm" \
  -d '{
    "relationshipId": "11111111-2222-4333-8444-555555555555",
    "kind": "confirm",
    "purpose": "transactional",
    "payload": { "title": "Confirm pickup", "details": "Thursday 10:30 at Main Street", "reference": "BK-20418" },
    "priority": "normal",
    "sensitivity": "standard",
    "allowedChannels": ["nativePush", "inApp"],
    "ttlSeconds": 3600,
    "idempotencyKey": "order-1042-confirm"
  }'
```

The `Idempotency-Key` header must equal the body's `idempotencyKey`. See [idempotency](/developers/idempotency/).

## 4. Read or receive the outcome

Webhooks are preferred. Polling is a fallback: `GET /v1/business/interactions/{interactionId}`. Treat `expired`, `cancelled`, `denied` and `reported` as "do not proceed".

## 5. Verify the webhook

See [webhooks](/developers/webhooks/#verifying-signatures) for the signature check and a Python and a Swift example.

## Swift SDK

```swift
import ViadereBusinessSDK
import ViadereCore

let client = try ViadereBusinessClient(apiKey: ProcessInfo.processInfo.environment["VIADERE_API_KEY"]!)
let issued = try await client.issueInteraction(request)
let outcome = try await client.interactionOutcome(id: issued.interaction.id)
```

See [SDKs](/developers/sdks/).

## Go-live checklist

- [ ] Organization verified (domain, legal entity, agreements accepted at their current versions); handle and code issued; go-live approved; a security contact is set.
- [ ] Webhook endpoint verified, and a test event received.
- [ ] Live key stored in a secrets manager and scoped to what the integration needs; test key used in CI.
- [ ] Webhook endpoint verifies signatures on the raw body, rejects stale timestamps, deduplicates on `Viadere-Event-Id` and answers `2xx` quickly.
- [ ] Every `POST` carries a deterministic idempotency key, stored before sending.
- [ ] `expired`, `cancelled`, `denied` and `reported` are all treated as "do not proceed".
- [ ] You never treat an RCS or SMS reply as approval of a sensitive action.
- [ ] Customer-authored text from `message.received` is handled as untrusted input.
- [ ] Redemption codes are validated server-side, and `409` or `410` means do not hand over the reward.
- [ ] You monitor `429` responses, your complaint rate and your opt-out rate, and rotate keys and webhook secrets on a schedule.
