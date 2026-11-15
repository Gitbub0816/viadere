---
title: Idempotency
order: 70
description: How to retry safely.
wide: true
---
{{ generate: info-section Idempotency }}

## Practical rules

- Derive keys from the thing you are acting on, so a retry from any process produces the same key. In Swift: `IdempotencyKey.deterministic(namespace: "refund", [orderId, lineId])`.
- Use a random key only for a genuinely new operation, and **store the key before sending**.
- Never reuse a key for a different operation: the response is `409 idempotency_conflict`.
- A retry returns the original result with `200` instead of `201`.
