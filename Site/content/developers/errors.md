---
title: Errors
order: 50
description: One error shape, and what each status means.
wide: true
---
{{ generate: info-section Errors }}

## Error codes

| HTTP | `code` | Meaning and what to do |
|---|---|---|
| 400 | `bad_request` | Malformed body, or `Idempotency-Key` header not equal to the body `idempotencyKey`. Fix the request. |
| 401 | `unauthorized` | Missing, unknown, revoked or expired key. |
| 403 | `forbidden` | The key lacks the scope, or your business is not active (pending or suspended). |
| 403 | `consent_required` | The customer has not consented to this `purpose`. Do not retry. |
| 404 | `not_found` | Unknown id, or it belongs to another business (indistinguishable by design). |
| 409 | `conflict` | State conflict, for example the customer is not connected to you. |
| 409 | `idempotency_conflict` | Key reused with a different body. |
| 410 | `gone` | Resource no longer available. |
| 422 | `validation_failed` | `error.details` maps field paths to issue codes. |
| 429 | `rate_limited` | Wait `Retry-After` seconds. |
| 500 | `internal_error` | Retry keyed requests with backoff. |
| 501 | `unavailable` | Feature not configured on this deployment. |

## Statuses used in the reference

{{ generate: api-errors }}
