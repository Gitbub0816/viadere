import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  deterministicIdempotencyKey,
  generateIdempotencyKey,
  isValidIdempotencyKey,
  networkPrefix,
  RequesterThrottle,
  ViadereApiError,
  ViadereClient,
  ViadereSdkError,
  ViadereThrottledError,
  ViadereValidationError,
  validateCreateRequest,
} from "../src/index.js";
import { API_KEY, DELIVERY_ID, scriptedFetch, SUBJECT_REF, validCreate, view, type Scripted } from "./helpers.js";

function client(script: Scripted[], extra: Partial<ConstructorParameters<typeof ViadereClient>[0]> = {}) {
  const { fetchFn, requests } = scriptedFetch(script);
  const sleeps: number[] = [];
  const c = new ViadereClient({ apiKey: API_KEY, fetch: fetchFn, sleep: async (s) => void sleeps.push(s), random: () => 1, ...extra });
  return { c, requests, sleeps };
}

describe("ViadereClient requests", () => {
  it("creates a delivery with bearer auth, idempotency key and no redirects", async () => {
    const { c, requests } = client([{ status: 201, body: view() }]);
    const { delivery, created } = await c.createAuthDelivery(validCreate());
    assert.equal(created, true);
    assert.equal(delivery.id, DELIVERY_ID);
    const r = requests[0]!;
    assert.equal(r.url, "https://api.viadere.com/v1/business/auth-deliveries");
    assert.equal(r.method, "POST");
    assert.equal(r.headers.Authorization, `Bearer ${API_KEY}`);
    assert.match(r.headers["Idempotency-Key"]!, /^authdl-[0-9a-f]{40}$/);
    assert.equal(r.redirect, "manual");
    assert.equal(JSON.parse(r.body!).request_id, "req-1");
  });

  it("derives the default idempotency key from request_id, so a restart reuses it", async () => {
    const a = client([{ status: 201, body: view() }]);
    const b = client([{ status: 200, body: view() }]);
    await a.c.createAuthDelivery(validCreate());
    const second = await b.c.createAuthDelivery(validCreate());
    assert.equal(a.requests[0]!.headers["Idempotency-Key"], b.requests[0]!.headers["Idempotency-Key"]);
    assert.equal(second.created, false, "200 is an idempotent replay");
  });

  it("gets, cancels and completes", async () => {
    const { c, requests } = client([{ status: 200, body: view({ status: "opened" }) }, { status: 200, body: view({ status: "cancelled" }) }, { status: 200, body: view({ status: "completed" }) }]);
    assert.equal((await c.getAuthDelivery(DELIVERY_ID)).status, "opened");
    assert.equal((await c.cancelAuthDelivery(DELIVERY_ID)).status, "cancelled");
    assert.equal((await c.completeAuthDelivery(DELIVERY_ID, "succeeded")).status, "completed");
    assert.deepEqual(requests.map((r) => `${r.method} ${r.url.replace("https://api.viadere.com", "")}`), [
      `GET /v1/business/auth-deliveries/${DELIVERY_ID}`,
      `POST /v1/business/auth-deliveries/${DELIVERY_ID}/cancel`,
      `POST /v1/business/auth-deliveries/${DELIVERY_ID}/complete`,
    ]);
    assert.equal(requests[0]!.headers["Idempotency-Key"], undefined, "GET carries no key");
    assert.deepEqual(JSON.parse(requests[2]!.body!), { outcome: "succeeded" });
  });

  it("refuses a malformed delivery id before any request", async () => {
    const { c, requests } = client([]);
    await assert.rejects(c.getAuthDelivery("../../x"), (e: unknown) => e instanceof ViadereSdkError && e.kind === "invalid_path");
    assert.equal(requests.length, 0);
  });

  it("updates a webhook to v2 and sends a webhook test", async () => {
    const { c, requests } = client([{ status: 200, body: { id: "x" } }, { status: 200, body: { event_id: "evt_1" } }]);
    await c.updateWebhook("11111111-2222-3333-4444-555555555555");
    assert.deepEqual(JSON.parse(requests[0]!.body!), { signature_version: "v2" });
    assert.equal(requests[0]!.method, "PATCH");
    assert.equal((await c.testAuthWebhook({ webhook_id: "11111111-2222-3333-4444-555555555555", type: "auth.delivery.opened" })).event_id, "evt_1");
  });
});

describe("errors and retries", () => {
  it("maps an error body", async () => {
    const { c } = client([{ status: 404, body: { error: { code: "not_deliverable", message: "No.", request_id: "rq_1" } } }]);
    await assert.rejects(c.createAuthDelivery(validCreate()), (e: unknown) => {
      assert.ok(e instanceof ViadereApiError);
      assert.equal(e.status, 404);
      assert.equal(e.isNotDeliverable, true);
      assert.equal(e.requestId, "rq_1");
      assert.equal(e.isRetryable, false);
      return true;
    });
  });

  it("retries 5xx and 429 with the same key, honouring Retry-After (capped)", async () => {
    const { c, requests, sleeps } = client([
      { status: 503, body: { error: { code: "unavailable", message: "x" } } },
      { status: 429, body: { error: { code: "rate_limited", message: "x" } }, headers: { "Retry-After": "120" } },
      { status: 201, body: view() },
    ]);
    await c.createAuthDelivery(validCreate());
    assert.equal(requests.length, 3);
    assert.equal(new Set(requests.map((r) => r.headers["Idempotency-Key"])).size, 1);
    assert.deepEqual(sleeps, [0.5, 30]);
  });

  it("retries a network failure, then gives a transport error", async () => {
    const { c, requests } = client([new Error("boom"), new Error("boom"), new Error("boom")]);
    await assert.rejects(c.getAuthDelivery(DELIVERY_ID), (e: unknown) => e instanceof ViadereSdkError && e.kind === "transport");
    assert.equal(requests.length, 3);
  });

  it("does not retry a 4xx and never follows a redirect", async () => {
    const { c, requests } = client([{ status: 302, headers: { Location: "https://evil.example" } }]);
    await assert.rejects(c.getAuthDelivery(DELIVERY_ID), (e: unknown) => e instanceof ViadereApiError && e.status === 302);
    assert.equal(requests.length, 1);
  });

  it("answers 409 idempotency_conflict without retrying", async () => {
    const { c, requests } = client([{ status: 409, body: { error: { code: "idempotency_conflict", message: "x" } } }]);
    await assert.rejects(c.createAuthDelivery(validCreate()), (e: unknown) => e instanceof ViadereApiError && e.code === "idempotency_conflict");
    assert.equal(requests.length, 1);
  });
});

describe("construction", () => {
  it("rejects a bad key and an insecure base URL, accepts loopback http", () => {
    assert.throws(() => new ViadereClient({ apiKey: "nope" }), ViadereSdkError);
    assert.throws(() => new ViadereClient({ apiKey: API_KEY, baseUrl: "http://api.example.com" }), ViadereSdkError);
    assert.throws(() => new ViadereClient({ apiKey: API_KEY, baseUrl: "https://user:pw@api.example.com" }), ViadereSdkError);
    new ViadereClient({ apiKey: API_KEY, baseUrl: "http://127.0.0.1:8080/" });
  });
  it("never prints the key", () => {
    const c = new ViadereClient({ apiKey: API_KEY });
    assert.ok(!String(c).includes(API_KEY));
    assert.ok(!JSON.stringify(c).includes(API_KEY));
  });
});

describe("request validation (the contract, before sending)", () => {
  it("refuses tenant_id and audience: the tenant is the key's business", async () => {
    const { c, requests } = client([]);
    await assert.rejects(c.createAuthDelivery(validCreate({ tenant_id: "ten_x" }) as never), ViadereValidationError);
    assert.deepEqual(validateCreateRequest({ ...validCreate(), audience: "a" }), [{ field: "audience", code: "unknown_member" }]);
    assert.equal(requests.length, 0);
  });
  it("checks required members, patterns, ranges and channels (no sms)", () => {
    const fields = (input: unknown) => validateCreateRequest(input).map((p) => p.field).sort();
    assert.deepEqual(fields({}), ["method", "purpose", "request_id", "subject_ref", "template"]);
    assert.deepEqual(fields(validCreate({ subject_ref: "sub_short" })), ["subject_ref"]);
    assert.deepEqual(fields(validCreate({ request_id: "has space" })), ["request_id"]);
    assert.deepEqual(fields(validCreate({ expires_in_seconds: 30 })), ["expires_in_seconds"]);
    assert.deepEqual(fields(validCreate({ channels: ["push", "sms"] })), ["channels[1]"]);
    assert.deepEqual(fields(validCreate({ variables: { name: "" } })), ["variables.name"]);
    assert.deepEqual(fields(validCreate({ otp: { code: "abc", code_kind: "otp" } })), ["otp.code"]);
    assert.deepEqual(fields(validCreate({ destination: { link_mode: "x" } })), ["destination.link_mode"]);
    assert.deepEqual(fields(validCreate({ callback: { webhook_id: "nope" } })), ["callback.webhook_id"]);
    assert.deepEqual(fields(validCreate({ session_handle: "bad handle" })), ["session_handle"]);
    assert.deepEqual(fields(validCreate({ destination: { link_mode: "business", extra: 1 } })), ["destination.extra"]);
    assert.deepEqual(fields(validCreate()), []);
  });
  it("refuses a body over 16 KiB", async () => {
    const { c } = client([]);
    await assert.rejects(c.createAuthDelivery(validCreate({ correlation_id: "x".repeat(128), variables: Object.fromEntries(Array.from({ length: 400 }, (_, i) => [`k${i}`, "v".repeat(60)])) })), ViadereValidationError);
  });
});

describe("idempotency keys", () => {
  it("matches the Swift SDK's deterministic derivation shape and stays within the charset", () => {
    const k = deterministicIdempotencyKey("authdl", ["req-1"]);
    assert.match(k, /^authdl-[0-9a-f]{40}$/);
    assert.notEqual(deterministicIdempotencyKey("n", ["ab", "c"]), deterministicIdempotencyKey("n", ["a", "bc"]));
    assert.ok(isValidIdempotencyKey(generateIdempotencyKey("a b!c")));
    assert.ok(!isValidIdempotencyKey("a".repeat(129)));
    assert.ok(!isValidIdempotencyKey("has space"));
  });
});

describe("per-requester throttle (C-14), on by default", () => {
  const ip = "203.0.113.7";
  function many(n: number, extra: Partial<ConstructorParameters<typeof ViadereClient>[0]> = {}) {
    const script: Scripted[] = [];
    for (let i = 0; i < n; i++) script.push({ status: 201, body: view({ id: `adl_${String(i).padStart(22, "A")}`, request_id: `req-${i}` }) });
    return client(script, extra);
  }

  it("refuses the fourth open delivery for one account and network prefix, locally", async () => {
    const { c, requests } = many(3);
    for (let i = 0; i < 3; i++) await c.createAuthDelivery(validCreate({ request_id: `req-${i}` }), { requester: { clientAddress: ip } });
    await assert.rejects(c.createAuthDelivery(validCreate({ request_id: "req-3" }), { requester: { clientAddress: "203.0.113.200" } }), (e: unknown) => e instanceof ViadereThrottledError && e.retryAfterSeconds >= 1);
    assert.equal(requests.length, 3, "nothing was sent");
  });

  it("does not throttle another network prefix or another account", async () => {
    const { c } = many(5);
    for (let i = 0; i < 3; i++) await c.createAuthDelivery(validCreate({ request_id: `req-${i}` }), { requester: { clientAddress: ip } });
    await c.createAuthDelivery(validCreate({ request_id: "req-3" }), { requester: { clientAddress: "198.51.100.1" } });
    await c.createAuthDelivery(validCreate({ request_id: "req-4", subject_ref: "sub_" + "B".repeat(43) }), { requester: { clientAddress: ip } });
  });

  it("frees a slot when the delivery ends (cancel, complete, get) and when a webhook says so, but not on opened", async () => {
    const { c } = many(7);
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) ids.push((await c.createAuthDelivery(validCreate({ request_id: `req-${i}` }), { requester: { clientAddress: ip } })).delivery.id);
    c.throttle!.observeEvent("auth.delivery.opened", ids[0]!);
    await assert.rejects(c.createAuthDelivery(validCreate({ request_id: "req-x" }), { requester: { clientAddress: ip } }), ViadereThrottledError);
    c.throttle!.observeEvent("auth.delivery.denied", ids[0]!);
    await c.createAuthDelivery(validCreate({ request_id: "req-y" }), { requester: { clientAddress: ip } });
  });

  it("releases the slot when the call fails, and does not double count an idempotent replay", async () => {
    const { c } = client([
      { status: 404, body: { error: { code: "not_deliverable", message: "x" } } },
      { status: 201, body: view() },
      { status: 200, body: view() },
      { status: 200, body: view() },
      { status: 200, body: view() },
    ]);
    await assert.rejects(c.createAuthDelivery(validCreate(), { requester: { clientAddress: ip } }), ViadereApiError);
    for (let i = 0; i < 4; i++) await c.createAuthDelivery(validCreate(), { requester: { clientAddress: ip } });
  });

  it("can be tuned or switched off", async () => {
    const tuned = many(2, { throttle: { maxOpen: 1 } });
    await tuned.c.createAuthDelivery(validCreate({ request_id: "req-0" }));
    await assert.rejects(tuned.c.createAuthDelivery(validCreate({ request_id: "req-1" })), ViadereThrottledError);
    const off = many(5, { throttle: false });
    assert.equal(off.c.throttle, undefined);
    for (let i = 0; i < 5; i++) await off.c.createAuthDelivery(validCreate({ request_id: `req-${i}` }));
  });

  it("a slot expires with its delivery", async () => {
    let now = 1_000_000;
    const throttle = new RequesterThrottle({ maxOpen: 1, now: () => now });
    const slot = throttle.reserve(SUBJECT_REF, ip);
    throttle.confirm(slot, DELIVERY_ID, new Date(now + 60_000).toISOString(), SUBJECT_REF, ip);
    assert.throws(() => throttle.reserve(SUBJECT_REF, ip), ViadereThrottledError);
    now += 61_000;
    throttle.reserve(SUBJECT_REF, ip);
  });

  it("buckets IPv4 by /24 and IPv6 by /64", () => {
    assert.equal(networkPrefix("203.0.113.7"), "203.0.113.0/24");
    assert.equal(networkPrefix("::ffff:203.0.113.7"), "203.0.113.0/24");
    assert.equal(networkPrefix("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
    assert.equal(networkPrefix("2001:DB8::1"), "2001:db8:0:0::/64");
    assert.equal(networkPrefix("not an ip"), "unknown");
    assert.equal(networkPrefix(undefined), "unknown");
  });
});
