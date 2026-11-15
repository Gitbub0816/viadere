# Changelog

## 0.1.0 (unreleased)

### Connected Loops (SECURITY section 2.115, additive)

- `getLoopEvent(eventRef)`, `answerLoopEvent(eventRef, { outcome, idempotency_key })` and `getLoopInstance(instanceRef)` for
  `/v1/business/loops/...` (scopes `loops:read` / `loops:write`, live keys). References are checked locally (`lev_` / `lin_` plus a lowercase
  UUID); the answer body is exactly the two members and is retried safely (the key travels in the body).
- `loop.action.submitted` and `loop.instance.expired` join `BUSINESS_WEBHOOK_EVENT_TYPES` and `OPAQUE_ENVELOPE_EVENT_TYPES` (opaque only).
- Types `LoopBusinessEvent`, `LoopBusinessAnswer`, `LoopBusinessApproval`, `LoopBusinessInstance`, `LoopOutcomeCallbackRequest`,
  `LoopOutcomeCallbackResult` and their OpenAPI schemas.

### `auth.delivery.fallback_used` (contract v1.x, additive)

- `WEBHOOK_EVENT_TYPES` (and `WebhookEventType`) gain `auth.delivery.fallback_used`: the code of a delivery that asked for the email fallback left
  by email (`assurance: email`, ADR-0020 section 7), sent once when the provider accepted the email, never when it was suppressed or failed. Opaque
  like every `auth.delivery.*` event; `verifyEnvelope` accepts it; it is not a state transition, so `RequesterThrottle.observeEvent` keeps the slot.
  `parity.test.ts` also checks the list against ViadereCore's `AuthDeliveryEventName`.

### Message images (SECURITY section 2.113)

- `uploadAttachment(sessionId, bytes, contentType)`, `downloadAttachment(reference)` and `attachmentIds` on `sendMessage`; `MessageAttachment` on
  messages and on `message.received` (`attachments`). Uploads are checked locally first (`attachmentPrecheck`, the server's precheck codes) and never
  retried (no idempotency key on the route); downloads are returned only when size, SHA-256 and type match the reference (new `ViadereSdkError` kind
  `attachment_mismatch`). `body` may be empty only with `attachmentIds`, which need `sessionId`.
- The HTTP layer sends raw bodies with their own type and reads binary answers; request signing digests the raw bytes. The `fetch` option's type
  now allows a `Uint8Array` body and an `arrayBuffer()` answer (every real `fetch` has both).
- `MESSAGE_ATTACHMENT_MAX_UPLOAD_BYTES` (2 MiB), `MESSAGE_ATTACHMENT_MAX_PER_MESSAGE`, `MESSAGE_ATTACHMENT_MAX_STORED_BYTES`, the media types and
  states, with a parity test against ViadereCore's `MessageAttachmentPolicy` and `docs/openapi.yaml`. The parity test's property extraction now reads
  member names with digits (`sha256`).

### `push_approval` delivery records (contract v1.x, additive)

- `AuthDeliveryView.method` is now `ViewMethod` (`VIEW_METHODS`: the three creatable methods plus `push_approval`, the read-only record every
  `createAuthApproval` writes); `Method` for create requests is unchanged. `parity.test.ts` checks the new OpenAPI `ViewMethod` enum.

### RFC 9421 request signatures (SECURITY section 2.112)

- **`requestSigner`** client option (opt-in): signs every attempt with an HTTP Message Signature (`ecdsa-p256-sha256`, raw `r||s`, low S; `@method`,
  `@authority`, `@path`, `@query`, `content-digest`, `content-type`; `tag="viadere-api-v1"`; sha-256 `Content-Digest`), a fresh nonce per retry. What a
  live key needs on the auth routes when it is not bound to mutual TLS. The signer is an `Es256Signer` plus its `vsk_` key id, so a KMS can sign.
- `signRequest`, `verifyHttpSignature` (the server's profile, with the normative error codes), `signingKeyProof` (the console's proof of possession),
  `requestContentDigest`; tests against `docs/protocol/vectors/http-signatures-v1.json`. New `ViadereSdkError` kinds `invalid_signing_key`, `signing_failed`.

- Typed client for the auth-delivery business API: create, get, cancel, complete, webhook v2 switch and test; idempotency keys, retries with backoff.
- Webhook signature v2 verifier (ADR-0025) with the replay store on by default (R23-06) and strict envelope decoding.
- Per-requester throttle on by default (C-14): 3 open deliveries per account and client network prefix.
- Contract parity test against `contracts/` and conformance to the shared vectors, including the negative vectors (R23-10).

### The whole business API

- **Client**: every operation of `docs/openapi.yaml` that the Swift SDK offers, plus `auth-approvals` and `auth-links/redeem` from the auth-delivery
  contract: capabilities, sandbox, interactions, messages, statuses, rewards, loyalty, redemptions, Wallet passes, Approve v2 (enrollments, keys,
  requests, results, freeze, settings), push approvals with number matching, link sessions, verification sessions, requests and results, profiles,
  key-directory entries and webhook endpoint management. Wire names field for field (camelCase on the older routes, snake_case on the newer ones).
- **Retries are now limited to requests that are safe to repeat** (a `GET`, an idempotency key, or an idempotent call). Before, the client retried
  everything, which was correct only because every call it had carried a key.
- **Validation** of every request against a schema table tied to the TypeScript interfaces at compile time and to the OpenAPI document by the parity test;
  path parameters are checked against their charset; responses must carry their required members.
- **Verification** on `node:crypto` only (ES256 raw `r‖s`, both `s` forms accepted and normalised to low-S, DER refused; canonical JSON):
  `ApprovalVerifier` / `verifyApprovalResult` (ApprovalResult v1 and v2, number matching with no default, replay guard), the verification-session result
  (`VIADERE-VERIFY-SESSION-RESULT-V1`), link statement, link result and confirmations, the approval-enrollment statement, binding tags and SAS.
- **Flows that trust nothing from the relay**: SDK-built enrollment and link-session links with the secret in the fragment, ticket checks, statement and
  result verification before your confirmation key signs.
- **Webhooks**: signature v1 verifier (`WebhookVerifierV1`) with the endpoint-ownership challenge, typed classic events, and the opaque envelope for
  `approve.*`, `link.*` and `verification.completed` on v1 and v2 (`verifyOpaqueEnvelope`).
- **Fixed**: the API-key check refused the documented key format `vdk_<live|test>_<kid>.<secret>` (the `.`). Keys are now `vdk_live_` or `vdk_test_`
  followed by printable ASCII, 20 to 80 characters, as in the Swift SDK; a key that is neither is refused.
- **Fixed**: the error body's request id is read from `requestId` (the routes of `docs/openapi.yaml`) as well as `request_id`.
- `testAuthWebhook` takes a random idempotency key per call (it was derived from the clock).
- Not ported from the Swift SDK (see the README): HPKE sealing of end-to-end requests, key-authority statements and transparency-log verification,
  grant verification, `signAuthDestination`.
