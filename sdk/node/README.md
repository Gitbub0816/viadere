# @viadere/server

Server-side SDK for the Viadere authentication-delivery business API (ADR-0020, ADR-0025, ADR-0030): a typed client, webhook signature v2
verification with a replay store, and the per-requester throttle. For Node 22+ and other JavaScript runtimes with `node:crypto` and `fetch`.

**Zero runtime dependencies.** Dev tooling (TypeScript, Node typings) is pinned exactly in `package.json` with a committed `package-lock.json` and is
never shipped. The package is `private` until the `sdk-release` workflow publishes it (ADR-0030 section 3); the built `dist/` is **not** committed.

Viadere is a **transport**. It shows your magic link, your one-time code or your security notice in the customer's own Viadere app and reports the
state. `opened` is never authentication success: you verify your own link or code, then call `completeAuthDelivery`. Viadere never verifies a result.

```ts
import { ViadereClient, WebhookVerifier } from "@viadere/server";

const viadere = new ViadereClient({ apiKey: process.env.VIADERE_API_KEY! }); // vdk_..., server only

const { delivery, created } = await viadere.createAuthDelivery(
  {
    method: "magic_link",
    request_id: "signin_8f3a",            // unique per tenant; also the default idempotency key
    subject_ref: subjectRef,              // sub_..., from the account link
    purpose: "sign_in",
    template: "auth.sign_in_link.v1",
    destination: { link_mode: "business", url: magicLinkUrl },
    session_handle,                       // optional: lets a newer sign_in replace this one
  },
  { requester: { clientAddress: req.ip } }, // who started it, for the throttle
);
```

## Client

| Call | Route |
|---|---|
| `createAuthDelivery(request, { idempotencyKey?, requester? })` | `POST /v1/business/auth-deliveries` (`201`, or `200` replay: `created: false`) |
| `getAuthDelivery(id)` | `GET /v1/business/auth-deliveries/{id}` |
| `cancelAuthDelivery(id)` | `POST .../{id}/cancel` |
| `completeAuthDelivery(id, "succeeded" \| "failed")` | `POST .../{id}/complete` (`409` unless the customer opened it) |
| `updateWebhook(id)` | `PATCH /v1/business/webhooks/{id}` to `signature_version: "v2"` |
| `testAuthWebhook({ webhook_id, type })` | `POST /v1/business/webhooks/test` (test keys only) |

- **Idempotency.** Every `POST` carries `Idempotency-Key`. The default is derived from the object (`request_id`, delivery id and outcome), so a retry after
  a crash, even from another process, replays the original instead of creating a second push. Pass your own to override.
- **Retries.** Network failures, `429` and `5xx` are retried (3 attempts, jittered exponential backoff from 0.5 s, `Retry-After` honoured up to 30 s) with the
  same key. `RetryPolicy` is configurable (`retry: { maxAttempts: 1 }` turns it off).
- **Validation.** A create request is checked against the contract before it is sent (`ViadereValidationError`, same field names and codes as the server's
  `422`). The tenant is your key's business: `tenant_id` and `audience` are refused.
- **Errors.** `ViadereApiError` (`status`, `code`, `requestId`, `retryAfter`, `isNotDeliverable`). `404 not_deliverable` is one body for an unknown customer, no
  eligible app, paused and frozen: do not try to tell them apart.
- **Safety.** Redirects are never followed; `http` is accepted only for loopback hosts; the key never appears in `toString` or `JSON.stringify`.

## Per-requester throttle (on by default)

Viadere never refuses or cancels a delivery because of a per-customer count (that would be a lockout lever for a stranger) and it cannot see who started a
sign-in; you can. The client keeps **at most 3 open deliveries per account and client network prefix** (`/24` of an IPv4, `/64` of an IPv6 address) and
refuses the next one locally with `ViadereThrottledError` (nothing is sent). Pass `requester.clientAddress` (the address your edge saw). Free slots when
deliveries end: `getAuthDelivery`, `cancelAuthDelivery` and `completeAuthDelivery` do it for you; from a verified webhook call
`viadere.throttle?.observeEvent(envelope.type, envelope.request_id)`. Tune with `throttle: { maxOpen }`, share an instance, or turn off with
`throttle: false` (not recommended). The state is per process: a multi-process deployment that needs one cap implements `OpenSlotStore`.

## Webhook verification (signature v2)

```ts
const verifier = new WebhookVerifier({
  endpoint: "https://hooks.example.com/viadere/events", // the URL you REGISTERED, never a proxy-rewritten one
  tenantId: process.env.VIADERE_TENANT_ID!,             // what Viadere-Tenant must equal
  keys: { whk_1a2b3c4d_v1: secretNow, whk_1a2b3c4d_v0: secretBefore }, // keep the previous one during a rotation
  replayStore: sharedStore,                              // production: a shared durable store (see below)
});

app.post("/viadere/events", express.raw({ type: "*/*" }), async (req, res) => {
  try {
    const { envelope, eventId } = await verifier.verifyEnvelope({ headers: req.headers, body: req.body }); // RAW bytes
    viadere.throttle?.observeEvent(envelope.type, envelope.request_id);
    queue.push(envelope);              // then fetch the state: viadere.getAuthDelivery(envelope.request_id)
    res.sendStatus(200);
  } catch (e) {
    if (e instanceof WebhookVerificationError) return res.sendStatus(e.status); // 200 for a duplicate, 400 otherwise
    throw e;
  }
});
```

Checks, in order (ADR-0025 section 2): well-formed header and fields, `|now - t| <= 300 s`, `Viadere-Tenant` equals yours, `Content-Digest` equals the
digest of the bytes you received, then one constant-time MAC comparison per `v2=<kid>:<mac>` entry whose `kid` you hold; a `v1=` entry alone is never
accepted. The envelope is then decoded strictly (no unknown member, version `2026-10-27`, body id equals the signed `Viadere-Event-Id`, your tenant).

**The replay store is on by default** (review R23-06): without `replayStore` the verifier uses an in-memory store with a 72 h retention measured from first
receipt. That is per process. For production pass a shared store implementing `WebhookReplayStore` (an atomic insert on a unique key):

```sql
CREATE TABLE viadere_webhook_events (event_id TEXT PRIMARY KEY, first_seen TIMESTAMPTZ NOT NULL);
INSERT INTO viadere_webhook_events (event_id, first_seen) VALUES ($1, now()) ON CONFLICT DO NOTHING; -- 1 row inserted = first time
DELETE FROM viadere_webhook_events WHERE first_seen < now() - interval '72 hours';
```

Opting out needs `replayStore: "disabled"` (tests only). The id is recorded only after the delivery verified and decoded, so a forged request cannot burn a
genuine id; if your handler fails before it finished, `await verifier.release(eventId)` lets Viadere's retry through.

## Conformance

`npm test` compiles with strict TypeScript and runs the Node built-in test runner (86 tests): the signature vectors in
`docs/protocol/vectors/webhook-v2.json`, the negative and boundary vectors in `docs/protocol/vectors/webhook-v2-negative.json` (R23-10, generated by an
independent Python script), and a **parity test** that reads `contracts/openapi/auth-delivery-v1.yaml` and `contracts/schemas/*.json` and fails when a route,
an enum, a required member or a property of the SDK drifts from the contract.

## Versioning

Semantic Versioning (ADR-0030 section 4). Verification may only get stricter in a minor version when that fixes a security defect (noted in `CHANGELOG.md`).
