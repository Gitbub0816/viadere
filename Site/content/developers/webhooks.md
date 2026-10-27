---
title: Webhooks
order: 40
description: Event types, signed deliveries, retries and how to verify them.
wide: true
---
Viadere sends a signed `POST` to your endpoint when something changes. Deliveries are at-least-once, so deduplicate on `Viadere-Event-Id`.

## Delivery

```
Viadere-Signature: t=1798000000,v1=9c1f…
Viadere-Event-Id:  3f2c…
Viadere-Event-Type: interaction.decided
Content-Type: application/json
```

- Respond `2xx` within 10 seconds.
- Anything else is retried at 30 seconds, 2 minutes, 10 minutes, 1 hour, 6 hours, 12 hours and 24 hours, then dead-lettered. You can replay dead letters from the dashboard.
- Redirects are never followed, and your URL must be a public `https` URL.
- The body is `{id, type, createdAt, businessId, apiVersion, data}`.
- Event types are an open set. Acknowledge and ignore types you do not recognize.

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

## Channels in event data

A decision that arrives over a text channel carries `channel: rcs` and no assurance, device reference or verification. Ordinary SMS is not end-to-end encrypted, and neither text channel can approve a sensitive request. Treat such a result as an unauthenticated reply.

## Events

{{ generate: webhook-events }}
