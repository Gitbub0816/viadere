# @viadere/server

Server-side SDK for the Viadere business API (ADR-0020, ADR-0022, ADR-0025, ADR-0030): a typed client for every business operation, verification of
everything Viadere or a customer's device signs, webhook verification (signature v1 and v2) with a replay store, and the per-requester throttle. For
Node 22+ and other JavaScript runtimes with `node:crypto` and `fetch`.

**Zero runtime dependencies.** All cryptography is `node:crypto`. Dev tooling (TypeScript, Node typings) is pinned exactly in `package.json` with a
committed `package-lock.json` and is never shipped. The package is `private` until the `sdk-release` workflow publishes it (ADR-0030 section 3); the built
`dist/` is **not** committed.

Two rules run through the whole SDK:

- **Nothing the relay says is trusted on its own.** A `status` is information for your UI. You authorize on a signed result that verified against
  **your own records** (the key you enrolled, the request and number you created) or against the Viadere keys **you pinned**.
- **Secrets stay where they belong.** The API key goes in the `Authorization` header and nowhere else, redirects are never followed, and the client,
  the verifiers and the session secrets print as redacted values.

```ts
import { ViadereClient } from "@viadere/server";

const viadere = new ViadereClient({ apiKey: process.env.VIADERE_API_KEY! }); // vdk_live_... or vdk_test_..., server only

const { value: interaction, created } = await viadere.issueInteraction({
  subjectRef,                              // sub_..., your pairwise reference for the customer
  kind: "confirm",
  purpose: "transactional",
  payload: { title: "Confirm pickup", details: "Thursday 10:30 at Main Street" },
  ttlSeconds: 3600,
  idempotencyKey: "order-1042-confirm",    // also sent as the Idempotency-Key header
});
```

## The wire is not uniformly snake_case

Types in `src/types.ts` use the wire names, field for field. The older routes (interactions, messages, statuses, rewards, loyalty, Wallet, capabilities,
profiles, webhook management, the classic webhook event) are **camelCase**; Approve v2, auth deliveries and approvals, link sessions, verification and the
key directory are **snake_case**. That is what `docs/openapi.yaml` and the server define; the SDK does not rename anything.

## Client

Every call validates its request against the contract before sending (`ViadereValidationError`, with the field names and codes of the server's `422`),
checks path parameters against their charset (`invalid_path`: a `../` or a query can never reach a URL), and checks that the response carries the
required members of its schema (`invalid_response`).

| Area | Methods |
|---|---|
| Capabilities, sandbox | `getCapabilities`, `createSandboxRelationship` |
| Interactions | `issueInteraction`, `getInteractionOutcome`, `cancelInteraction` |
| Messages, images, statuses | `sendMessage`, `uploadAttachment`, `downloadAttachment`, `updateStatus` |
| Rewards, loyalty | `createReward`, `listRewards`, `revokeReward`, `getLoyaltyProgram`, `saveLoyaltyProgram`, `adjustLoyaltyPoints`, `consumeRedemption` |
| Wallet passes | `issueWalletPass`, `listWalletPasses`, `updateWalletPass`, `voidWalletPass`, `scanWalletPass` |
| Auth deliveries | `createAuthDelivery`, `getAuthDelivery`, `cancelAuthDelivery`, `completeAuthDelivery`, `redeemAuthLink` |
| Push approvals (number matching) | `createAuthApproval`, `getAuthApproval` |
| Approve v2 | `createApprovalEnrollment`, `getApprovalEnrollment`, `confirmApprovalEnrollment` (`...Raw`), `cancelApprovalEnrollment`, `listApprovalKeys`, `revokeApprovalKey`, `createApprovalRequest`, `getApprovalRequest`, `cancelApprovalRequest`, `getApprovalResult`, `freezeApprovals`, `getApprovalFreeze`, `getApproveSettings`, `putApproveSettings` |
| Link sessions | `createLinkSession`, `getLinkSession`, `reviewLinkSession`, `confirmLinkSession` (`...Raw`), `cancelLinkSession` |
| Verify with Viadere | `createVerificationSession`, `getVerificationSession`, `getVerifiedVerificationSession`, `cancelVerificationSession`, `createVerificationRequest`, `getVerificationRequest`, `getVerificationResult` |
| Profiles | `createProfileRequest`, `getProfileRequest`, `getProfile` |
| Key directory | `publishKeyEntry`, `listKeyEntries` |
| Webhook endpoints | `listWebhooks`, `createWebhook`, `deleteWebhook`, `updateWebhook` (to signature v2), `rotateWebhookSecret`, `verifyWebhook`, `testWebhook`, `pauseWebhook`, `resumeWebhook`, `testAuthWebhook` |

- **Idempotency.** Where the body has an `idempotencyKey` (interactions, messages, statuses, rewards, points) the SDK sends it as the header too.
  Cancels derive a stable key from the object; webhook creation, secret rotation, profile and verification requests take a fresh random key per call
  unless you pass one (persist it before sending if you want a crash-and-retry to replay). A create answers `{ value, created }`: `created: false` is a
  replay of the original (`200`).
- **Retries.** Network failures, `429` and `5xx` are retried (3 attempts, jittered exponential backoff from 0.5 s, `Retry-After` honoured up to 30 s)
  **only when the request is safe to repeat**: every `GET`, every request with an idempotency key, and calls that are idempotent by nature (cancel, void,
  revoke, settings). `consumeRedemption`, `scanWalletPass`, `updateWalletPass`, `publishKeyEntry`, `redeemAuthLink`, the confirms and the session creates are
  never retried: after a lost response, check before you repeat.
- **Images** (`docs/SECURITY.md` section 2.113). `uploadAttachment(sessionId, bytes, contentType)` sends the raw image (`image/png` or `image/jpeg`,
  at most `MESSAGE_ATTACHMENT_MAX_UPLOAD_BYTES`, 2 MiB) after the server's own precheck runs locally (`attachmentPrecheck`: `required`, `too_large`,
  `unsupported_format`, `content_type_mismatch` as a `ViadereValidationError`); the answer is a pending `MessageAttachment`. Name its id in
  `sendMessage({ sessionId, attachmentIds: [id] })` with the same `sessionId` (1 to 4 ids; `body` may then be empty). An upload is **never retried**:
  the route takes no idempotency key. `downloadAttachment(reference)` (any `MessageAttachment`: an upload answer, `message.attachments`, or
  `message.received` `data.attachments`) returns the bytes only when their size, SHA-256 and type match the reference (`attachment_mismatch`
  otherwise); it is retried like every `GET`. With `requestSigner`, the upload's `content-digest` covers the image bytes and `content-type` is the
  image type. A custom `fetch` must accept a `Uint8Array` body and return `arrayBuffer()` for downloads.
- **Errors.** `ViadereApiError` (`status`, `code`, `requestId`, `details`, `retryAfter`, `isRetryable`, `isCapabilityDenied`, `deniedCapability`,
  `isNotDeliverable`). `404 not_deliverable` is one body for an unknown customer, no eligible app, paused and frozen: do not try to tell them apart.
- **Safety.** `http` is accepted only for loopback hosts; a base URL with credentials, a query or a fragment is refused; the key format is checked
  (`vdk_live_...`, `vdk_test_...`).

## Request signing (RFC 9421, opt-in)

A **live** key needs an HTTP Message Signature or mutual TLS on the authentication routes (auth deliveries, push approvals, link redemption): a stolen
bearer key alone cannot send sign-in prompts (`docs/SECURITY.md` section 2.112). Register a P-256 public key under **Security > Request signing**
(Owner or Security Admin, passkey step-up): the console shows a challenge per API key; sign it with `signingKeyProof(challenge, signer)` and paste the
public key (`signer.publicKey`) and the proof. The console then shows the key id `vsk_...`.

```ts
const signer = { keyId: "vsk_0123456789abcdef", ...softwareSigner(privateKey) }; // or { keyId, publicKey, sign: (m) => kms.sign(m) }
const client = new ViadereClient({ apiKey: process.env.VIADERE_API_KEY!, requestSigner: signer });
```

Every attempt, retries included, gets `Content-Digest` (with a body), `Signature-Input` and `Signature` with a fresh nonce and `created`. The covered
components are exactly `"@method" "@authority" "@path" "@query" "content-digest" "content-type"` (the first four without a body), `tag="viadere-api-v1"`,
`ecdsa-p256-sha256` raw `r||s` low S. A signer may return DER or either `s` (KMS output): it is normalised and checked against its public key, and a
failing signer sends nothing (`signing_failed`). `verifyHttpSignature` is the server's profile, in its normative order, for proxies and tests.

## Verifying what is signed

All of it is ECDSA P-256 / SHA-256 with **raw `r‖s` signatures** (64 bytes, base64url) exactly as `docs/SECURITY.md` section 2.1 defines: DER is refused,
both `s` forms of a valid signature are accepted and normalised to low-S, and no replay guard is keyed on a signature string. Payloads are canonical JSON
(section 2.2) and must be byte-for-byte canonical. Public keys are base64url X9.63.

### Approval results (`ApprovalVerifier`)

```ts
const verifier = new ApprovalVerifier({ businessId, keys: myKeyStore, replayGuard: myReplayGuard }); // minimum: biometric

const { result } = await viadere.getApprovalResult(resultRef);            // from the webhook or the request view
const verified = await verifier.verify(result, pending);                   // throws ApprovalVerificationError for every refusal
// only now: grant
```

`verify` checks the ES256 signature under a key **you enrolled** for this customer, that the result is addressed to you, for this customer, request,
nonce and capability, that the transaction digest equals the digest of the transaction **you recorded**, the clock, the key's enrolled strength, the
typed number, and consumes the one-time challenge (and the v2 `jti`) so a replay fails. `pending.numberMatch` has **no default**: `{ required: code }` or
`"not_requested"`, so a result without the typed number can never be accepted for a request that asked for one. `alg` must be exactly `ES256`; `none`,
`HS256`, a `crit` header and any extra header or payload member are refused. Use a shared `ReplayGuard` (a unique key on `(scope, nonce)`) when several
instances verify.

### Push approvals with number matching

```ts
const keys = new AuthApprovalKeys(sdkSecret);                               // 32+ random bytes from your secrets manager; never sent to Viadere
const created = await viadere.createAuthApproval(
  { subjectRef, details: { authentication: { action_display: "Sign in to Example Bank" } }, sessionHandle: keys.sessionHandle(mySessionId) },
  { keys, requester: { clientAddress: req.ip } },
);
show(created.code);            // on YOUR sign-in screen; keep created.pending for the verifier
```

The SDK draws the number (CSPRNG, rejection sampling), sends only its HMAC tags, and redraws on `409 match_code_in_use` / `match_digits_required`.
Payments and `high`/`critical` requests must be end to end: pass `buildEnvelopes`, which receives the number and returns one `E2EEEnvelope` per device.

### Enrollments and link sessions

`createApprovalEnrollment` and `createLinkSession` return an invitation **built by the SDK**: the link carries your own root key id and a fresh 256-bit
secret in the URL fragment (never sent to Viadere). The relay's suggested link is only checked, and a ticket naming another root key or host is refused and
cancelled. **Store `invitation.secret.base64url` server-side** until you confirm (it is redacted from `JSON.stringify` on purpose; rebuild it with
`new ApprovalEnrollmentSecret(stored)` / `new LinkSessionSecret(stored)`).

`confirmApprovalEnrollment` and `reviewLinkSession` + `confirmLinkSession` verify the device's statement, Viadere's `VIADERE-LINK-RESULT-V1` statement
against your pinned `link-descriptor` keys, and the **binding tag or SAS under your secret** before your `approval-enrollment-confirmation` key signs
anything. A valid statement alone proves only possession of its key: the relay can make one. Signing uses an `Es256Signer` (`softwareSigner(keyObject)`, or
your KMS: a function that signs and returns raw `r‖s` or DER).

### Verify with Viadere

```ts
const ticket = await viadere.createVerificationSession({ capability: "age.minimum", parameters: { years: 21 }, purpose_code: "age_restricted_purchase", origin });
// ... the person finishes in the app ...
const session = await viadere.getVerifiedVerificationSession({ sessionId: ticket.session_id, businessId, origin, capability: "age.minimum", viadereKeys: pinned });
if (session.outcome === "verified") { /* ... */ }
```

`getVerifiedVerificationSession` verifies the `VIADERE-VERIFY-SESSION-RESULT-V1` statement against the keys you pinned and checks that it is for **this**
session, your business, the origin and the capability you asked for, and that the result reference is the one it commits to. Never let the browser tell
your server that a person is verified.

The building blocks are exported too: `verifyVerificationSessionResult`, `verifyLinkResult`, `verifyLinkStatement`, `verifyApprovalEnrollmentStatement`,
`verifyApprovalResult`, `transactionDigest`, `signLinkConfirmation`, `signApprovalEnrollmentConfirmation`, `verifyEs256`, `canonicalJson`.

## Per-requester throttle (on by default)

Viadere never refuses or cancels a delivery because of a per-customer count (that would be a lockout lever for a stranger) and it cannot see who started a
sign-in; you can. The client keeps **at most 3 open deliveries or sign-in approvals per account and client network prefix** (`/24` of an IPv4, `/64` of an
IPv6 address) and refuses the next one locally with `ViadereThrottledError` (nothing is sent). Pass `requester.clientAddress` (the address your edge saw).
Slots free when deliveries end: `getAuthDelivery`, `cancelAuthDelivery`, `completeAuthDelivery` and `getAuthApproval` do it for you; from a verified
webhook call `viadere.throttle?.observeEvent(envelope.type, envelope.request_id)`, or `viadere.throttle?.release(created.throttleSlot)`. Tune with
`throttle: { maxOpen }`, share an instance, or turn off with `throttle: false` (not recommended). The state is per process: a multi-process deployment that
needs one cap implements `OpenSlotStore`.

## Webhooks

An endpoint is on **signature v1** until you move it with `updateWebhook(id)`; `auth.delivery.*` events need v2.

```ts
// v1: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>." + raw body)>
const v1 = new WebhookVerifierV1({ secrets: [secretNow, secretBefore], replayStore: sharedStore });
const { event } = await v1.verify({ headers: req.headers, body: rawBody });   // RAW bytes
const typed = typedWebhookEvent(event);                                       // { type: "interaction.decided", data } ... or { type: "other" }

// the endpoint-ownership challenge of verifyWebhook(): an HMAC under your secret, never an echo
if (req.headers["viadere-event-type"] === "webhook.verification") return res.type("json").send(v1.verificationResponse({ headers: req.headers, body: rawBody }));

// v2: method, host, path, timestamp, event id, tenant, key id and body digest are signed
const v2 = new WebhookVerifier({
  endpoint: "https://hooks.example.com/viadere/events", // the URL you REGISTERED, never a proxy-rewritten one
  tenantId: process.env.VIADERE_TENANT_ID!,
  keys: { whk_1a2b3c4d_v1: secretNow, whk_1a2b3c4d_v0: secretBefore },
  replayStore: sharedStore,
});
const { envelope } = await v2.verifyEnvelope({ headers: req.headers, body: rawBody });        // auth.delivery.*
const other = await v2.verifyOpaqueEnvelope({ headers: req.headers, body: rawBody });         // approve.*, link.*, verification.completed
```

Both verifiers check a well-formed header, `|now - t| <= 300 s`, then the MAC in constant time (v2 also the tenant and the `Content-Digest`), decode
strictly, and require the unsigned convenience headers to agree with the signed body. A rejection is `WebhookVerificationError` (`status` 400; 200 for a
duplicate). The opaque envelope carries ids and a `result_ref` only: fetch the result and verify **that**.

**The replay store is on by default** (review R23-06): without `replayStore` a verifier uses an in-memory store with a 72 h retention measured from first
receipt. That is per process. For production pass a shared store implementing `WebhookReplayStore` (an atomic insert on a unique key):

```sql
CREATE TABLE viadere_webhook_events (event_id TEXT PRIMARY KEY, first_seen TIMESTAMPTZ NOT NULL);
INSERT INTO viadere_webhook_events (event_id, first_seen) VALUES ($1, now()) ON CONFLICT DO NOTHING; -- 1 row inserted = first time
DELETE FROM viadere_webhook_events WHERE first_seen < now() - interval '72 hours';
```

Opting out needs `replayStore: "disabled"` (tests only). The id is recorded only after the delivery verified and decoded, so a forged request cannot burn a
genuine id; if your handler fails before it finished, `await verifier.release(eventId)` (v2) lets Viadere's retry through.

## What this SDK does not do (the Swift SDK does)

- **End-to-end request sealing** (HPKE `hpke-0010-0001-0002` and the signed `ApprovalRequest`, Swift `ApprovalRequestBuilder.endToEnd`). The client sends
  envelopes you built; `createAuthApproval` hands the number to your `buildEnvelopes`.
- **Key authority and transparency log**: building and signing `KeyLogEntry` statements (`BusinessKeyAuthority`), verifying directory pages, Merkle
  proofs and tree heads (`KeyDirectoryVerifier`, `KeyLogMonitor`). `publishKeyEntry` and `listKeyEntries` only transport. The three public log routes
  (`/v1/key-directory/sth`, `/consistency`, `/businesses/{id}`) are not offered for the same reason (`OPERATIONS_NOT_OFFERED`).
- **Grant verification** for the link service: `redeemAuthLink` returns the `viadere-grant+jwt`; verify it against the static grant JWKS yourself.
- **`signAuthDestination`** (ADR-0031 section 6): `destination.signature` is passed through as you computed it.
- The display rule "business text must not imitate the Viadere name" is enforced by the server, not locally.

## Conformance

`npm test` compiles with strict TypeScript and runs the Node built-in test runner (336 tests):

- **Parity** (`test/parity.test.ts`): reads `docs/openapi.yaml` and `contracts/openapi/auth-delivery-v1.yaml` and fails when an operation is missing or its
  method or path drifts (operations deliberately not offered are on a commented allow-list, `OPERATIONS_NOT_OFFERED`), when a schema member, a `required`
  list, `additionalProperties: false` or an enum drifts, and when the Swift SDK calls a route this SDK does not have. `src/schemas.ts` ties every
  TypeScript interface to that table at compile time.
- **Shared vectors** (`docs/protocol/vectors/`): `http-signatures-v1.json` (RFC 9421 request signatures: positive cases byte for byte, 55 refusals with
  their codes), `webhook-v2.json`, `webhook-v2-negative.json` (signature v2), `approval-result-v2.json` (ApprovalResult
  v1/v2, match tags, session handles, the code sampler), `link-session-v1.json` (link statement, result and confirmation, the approval-enrollment
  statement, binding tag, check code, SAS, pseudonym, link).
- **No shared vector exists** for the verification-session result, the enrollment secret's tag and SAS, and webhook signature v1: they are tested by
  round trip against the normative format, with tamper, wrong-domain and wrong-key cases.

## Versioning

Semantic Versioning (ADR-0030 section 4). Verification may only get stricter in a minor version when that fixes a security defect (noted in `CHANGELOG.md`).
