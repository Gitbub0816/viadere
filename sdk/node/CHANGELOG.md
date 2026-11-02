# Changelog

## 0.1.0 (unreleased)

- Typed client for the auth-delivery business API: create, get, cancel, complete, webhook v2 switch and test; idempotency keys, retries with backoff.
- Webhook signature v2 verifier (ADR-0025) with the replay store on by default (R23-06) and strict envelope decoding.
- Per-requester throttle on by default (C-14): 3 open deliveries per account and client network prefix.
- Contract parity test against `contracts/` and conformance to the shared vectors, including the negative vectors (R23-10).
