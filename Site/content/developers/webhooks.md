---
title: Webhooks
order: 40
description: Event types, signed deliveries, retries and how to verify them.
wide: true
---
Viadere sends a signed `POST` to your endpoint when something changes. Deliveries are at-least-once, so deduplicate on `Viadere-Event-Id`.

## Delivery

```
Viadere-Signature:       t=1798000000,v1=9c1f…
Viadere-Event-Id:        3f2c…
Viadere-Delivery-Id:     3f2c…
Viadere-Key-Id:          whk_ab12cd34_v2
Viadere-Event-Type:      interaction.decided
Viadere-Webhook-Version: v1
Content-Type: application/json
```

| Header | Meaning |
|---|---|
| `Viadere-Signature` | Timestamp and one or more signatures. Several `v1=` values appear while a secret is being rotated. |
| `Viadere-Event-Id` | The event. Deliveries are at-least-once, so deduplicate on it. |
| `Viadere-Delivery-Id` | This delivery, stable across its retries. |
| `Viadere-Key-Id` | Which signing secret was used: the endpoint and the secret version. It changes at each rotation. |
| `Viadere-Webhook-Version` | `v1` is the full body. `v2` is an envelope of identifiers only, used for approval and verification events. |

- A new endpoint receives **nothing** until it is verified. See [endpoint verification](#endpoint-verification).
- Respond `2xx` within 10 seconds.
- Anything else is retried at 30 seconds, 2 minutes, 10 minutes, 1 hour, 6 hours, 12 hours and 24 hours, then dead-lettered. You can replay dead letters from the dashboard.
- Redirects are never followed, and your URL must be a public `https` URL.
- The body is `{id, type, createdAt, businessId, apiVersion, data}`.
- Event types are an open set. Acknowledge and ignore types you do not recognize.

## Endpoint verification

Until an endpoint proves it controls its URL, it receives no events, not even test events. Configure the signing secret on your server first, then press *Verify* in the dashboard or call `POST /v1/business/webhooks/{webhookId}/verify`.

Viadere sends a signed `webhook.verification` request with a single-use `challenge`. Answer `2xx` with:

```json
{ "challenge_response": "<hex HMAC-SHA256, keyed by your signing secret, over \"viadere.webhook.verification.v1:\" + challenge>" }
```

- **Echoing the challenge does not work.** Only a receiver that holds the signing secret can answer.
- A missing or wrong proof reports `no_echo`, a non-2xx answer reports `http_<status>`, and no connection reports `unreachable`.
- Each attempt uses a new challenge, with at most 6 attempts per endpoint per hour.
- In the Swift SDK, `verifier.verificationResponse(headers:body:)` checks the signature and builds the answer.

## Test events, pausing and the delivery log

- **Test events.** `POST /v1/business/webhooks/{webhookId}/test` queues a signed `webhook.test` event with no customer data through the normal delivery pipeline, with real headers and retries.
- **Pause and resume.** `POST …/pause` and `POST …/resume` stop and restart delivery for one endpoint. Events keep queueing while paused and go out after the resume, or expire with the delivery retention period.
- **Delivery log.** The dashboard shows recent deliveries with their attempts and redacted payloads. Message text and signatures are never shown. A dead-lettered delivery can be replayed.
- **Secret rotation.** After `POST …/rotate-secret` the previous secret keeps signing for 24 hours, so deploy the new secret inside that window.

## Verifying signatures

`v1` is `hex(HMAC-SHA256(key, "{t}." + raw request body))`, where the key is the UTF-8 bytes of the whole `whsec_…` string, prefix included.

- Verify against the **raw body bytes**, not a re-serialized value.
- Compare in constant time.
- Reject when no `v1` matches, or when the timestamp differs from your clock by more than 300 seconds.
- Several `v1=` values appear while a secret is being rotated. Ignore unknown schemes such as `v0=`.

### Python

```python
import hashlib, hmac, time

def verify(header: str, raw_body: bytes, secrets: list[str], now: float | None = None) -> bool:
    now = time.time() if now is None else now
    parts = [p.strip().split("=", 1) for p in header.split(",")]
    t = next((v for k, v in parts if k == "t"), None)
    sigs = [v for k, v in parts if k == "v1"]
    if t is None or not t.isdigit() or abs(now - int(t)) > 300 or not sigs:
        return False
    signed = t.encode() + b"." + raw_body
    for secret in secrets:
        mac = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        if any(hmac.compare_digest(mac, s) for s in sigs):
            return True
    return False
```

### Swift SDK

```swift
let verifier = WebhookVerifier(secrets: [currentSecret])   // add the previous secret during a rotation
let event = try verifier.verify(headers: headers, body: rawBody, deduplicator: dedup)
switch try event.typed() {
case .interactionDecided(let outcome): break   // act on it
case .messageReceived(let message): break      // message.text is customer-authored: untrusted input
default: break                                 // new event types: acknowledge and ignore
}
```

## Signature v2 {#signature-v2}

Signature v2 is required for the `auth.delivery.*` events of [authentication delivery](/developers/auth-delivery/), which is a staging pilot and off by default. Move an endpoint with `PATCH /v1/business/webhooks/{webhookId}` and `signature_version: "v2"`.

A v2 verifier checks, in this order:

1. The header and its fields are well formed.
2. The timestamp is within 300 seconds of your clock.
3. `Viadere-Tenant` equals your own tenant id.
4. `Content-Digest` equals the digest of the bytes you received.
5. One constant-time comparison per `v2=<key id>:<mac>` entry whose key id you hold. A `v1=` entry alone is never accepted.

Then decode the envelope strictly: no unknown member, the body id equal to the signed `Viadere-Event-Id`, and your tenant.

- Verify against the endpoint URL you **registered**, never one rewritten by a proxy.
- Keep a replay store of event ids for at least 72 hours from first receipt. In production it must be shared by all your servers.
- For 30 days after the switch, the event types the endpoint already received carry both `v2=` and `v1=` entries, so you can deploy the new verifier first. `auth.*` events never carry a `v1=` entry.
- `POST /v1/business/webhooks/test` with a test key sends a signed sample `auth.delivery.*` event.

The Swift, TypeScript and Kotlin [SDKs](/developers/sdks/) each ship a v2 verifier with the replay store on by default. Shared test vectors, including negative ones, are in the repository under `docs/protocol/vectors/`.

## Channels in event data

A decision that arrives over a text channel carries `channel: rcs` and no assurance, device reference or verification. Ordinary SMS is not end-to-end encrypted, and neither text channel can approve a sensitive request. Treat such a result as an unauthenticated reply.

## Events

{{ generate: webhook-events }}
