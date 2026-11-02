import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  contentDigest,
  endpointParts,
  InMemoryReplayStore,
  mac,
  signatureHeader,
  stringToSign,
  WebhookVerificationError,
  WebhookVerifier,
} from "../src/index.js";
import { readRepoJson } from "./helpers.js";

interface PositiveCase {
  name: string; secret: string; kid: string; t: number; method: string; host: string; path_and_query: string; event_id: string; tenant_id: string;
  body: string; content_digest: string; string_to_sign: string; v2: string;
}
interface NegativeCase {
  name: string; endpoint: string; tenant_id: string; keys: Record<string, string>; now: number;
  headers: Record<string, string>; body: string; expect: string;
}

const positive = readRepoJson<{ cases: PositiveCase[] }>("docs/protocol/vectors/webhook-v2.json").cases;
const negative = readRepoJson<{ cases: NegativeCase[] }>("docs/protocol/vectors/webhook-v2-negative.json").cases;

async function outcome(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
    return "ok";
  } catch (error) {
    assert.ok(error instanceof WebhookVerificationError, `unexpected ${String(error)}`);
    return error.code;
  }
}

describe("webhook v2 positive vectors (docs/protocol/vectors/webhook-v2.json)", () => {
  for (const c of positive) {
    it(`reproduces ${c.name}`, () => {
      const body = Buffer.from(c.body, "utf8");
      const context = { method: c.method, host: c.host, pathAndQuery: c.path_and_query, eventId: c.event_id, tenantId: c.tenant_id };
      assert.equal(contentDigest(body), c.content_digest);
      assert.equal(stringToSign(context, c.t, c.kid, body), c.string_to_sign);
      assert.equal(`${c.kid}:${mac(c.secret, context, c.t, c.kid, body)}`, c.v2);
      assert.equal(signatureHeader([{ kid: c.kid, secret: c.secret }], context, body, c.t), `t=${c.t},v2=${c.v2}`);
    });
  }
});

describe("webhook v2 negative and boundary vectors (docs/protocol/vectors/webhook-v2-negative.json)", () => {
  for (const c of negative) {
    it(c.name, async () => {
      const verifier = new WebhookVerifier({ endpoint: c.endpoint, tenantId: c.tenant_id, keys: c.keys, now: () => c.now * 1000, replayStore: "disabled" });
      const got = await outcome(() => verifier.verify({ headers: c.headers, body: c.body }));
      assert.equal(got, c.expect);
    });
  }
  it("covers every failure class", () => {
    const classes = new Set(negative.map((c) => c.expect));
    for (const code of ["ok", "malformed_signature", "timestamp_outside_tolerance", "tenant_mismatch", "digest_mismatch", "no_matching_signature"]) assert.ok(classes.has(code), code);
  });
});

// ---------------------------------------------------------------------------------------------------------------------------------------------

const ENDPOINT = "https://hooks.example.com/viadere/events";
const TENANT = "ten_7a1b2c3d4e5f60718293a4b5c6d7e8f9";
const KEYS = { whk_1a2b3c4d_v1: "whsec_testsecret_one" };
const T = 1793620800;

function delivery(overrides: { body?: string; t?: number } = {}) {
  const base = positive[0]!;
  const body = overrides.body ?? base.body;
  const context = { method: "POST", host: "hooks.example.com", pathAndQuery: "/viadere/events", eventId: base.event_id, tenantId: TENANT };
  const header = signatureHeader([{ kid: base.kid, secret: base.secret }], context, Buffer.from(body), overrides.t ?? T)!;
  return {
    headers: { "Viadere-Signature": header, "Viadere-Event-Id": base.event_id, "Viadere-Tenant": TENANT, "Content-Digest": contentDigest(Buffer.from(body)), "Viadere-Delivery-Id": "dlv_1", "Viadere-Key-Id": base.kid },
    body,
  };
}

describe("WebhookVerifier", () => {
  it("verifies a delivery and decodes the opaque envelope", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000 });
    const v = await verifier.verifyEnvelope(delivery());
    assert.equal(v.envelope.type, "auth.delivery.opened");
    assert.equal(v.envelope.request_id, "adl_AAAAAAAAAAAAAAAAAAAAAA");
    assert.equal(v.deliveryId, "dlv_1");
    assert.equal(v.keyId, "whk_1a2b3c4d_v1");
  });

  it("has the replay store ON by default (R23-06): the same event twice is a duplicate", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000 });
    await verifier.verifyEnvelope(delivery());
    await assert.rejects(verifier.verifyEnvelope(delivery()), (e: unknown) => e instanceof WebhookVerificationError && e.code === "duplicate_event" && e.status === 200);
  });

  it("opting out of dedup must be explicit", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000, replayStore: "disabled" });
    await verifier.verifyEnvelope(delivery());
    await verifier.verifyEnvelope(delivery());
  });

  it("a forged delivery does not burn the genuine event id", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000 });
    const forged = delivery();
    forged.headers["Viadere-Signature"] = `t=${T},v2=whk_1a2b3c4d_v1:${"A".repeat(43)}`;
    assert.equal(await outcome(() => verifier.verifyEnvelope(forged)), "no_matching_signature");
    await verifier.verifyEnvelope(delivery()); // still the first time
  });

  it("release() lets a failed handler's retry through", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000 });
    const v = await verifier.verifyEnvelope(delivery());
    await verifier.release(v.eventId);
    await verifier.verifyEnvelope(delivery());
  });

  it("a signed but malformed body is rejected without recording the id", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000 });
    const bad = JSON.stringify({ ...JSON.parse(positive[0]!.body), extra: "x" });
    assert.equal(await outcome(() => verifier.verifyEnvelope(delivery({ body: bad }))), "malformed_body");
    await verifier.verifyEnvelope(delivery());
  });

  it("refuses a body whose id or tenant disagrees with the signed headers", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000, replayStore: "disabled" });
    const other = JSON.stringify({ ...JSON.parse(positive[0]!.body), id: "evt_other" });
    assert.equal(await outcome(() => verifier.verifyEnvelope(delivery({ body: other }))), "header_body_mismatch");
  });

  it("refuses a version it does not know and a result_ref", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000, replayStore: "disabled" });
    const parsed = JSON.parse(positive[0]!.body) as Record<string, unknown>;
    assert.equal(await outcome(() => verifier.verifyEnvelope(delivery({ body: JSON.stringify({ ...parsed, version: "2099-01-01" }) }))), "malformed_body");
    assert.equal(await outcome(() => verifier.verifyEnvelope(delivery({ body: JSON.stringify({ ...parsed, result_ref: "x" }) }))), "malformed_body");
  });

  it("reports a missing signature header", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000 });
    assert.equal(await outcome(() => verifier.verify({ headers: {}, body: "{}" })), "missing_header");
  });

  it("accepts a fetch Headers object and case-insensitive names, and refuses a repeated signature header", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000, replayStore: "disabled" });
    const d = delivery();
    await verifier.verify({ headers: new Headers(d.headers), body: d.body });
    const lower = Object.fromEntries(Object.entries(d.headers).map(([k, v]) => [k.toLowerCase(), v]));
    await verifier.verify({ headers: lower, body: d.body });
    const twice = { ...lower, "viadere-signature": [d.headers["Viadere-Signature"], d.headers["Viadere-Signature"]] as readonly string[] };
    assert.equal(await outcome(() => verifier.verify({ headers: twice, body: d.body })), "malformed_signature");
  });

  it("works on the raw bytes: a re-serialised body does not verify", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000, replayStore: "disabled" });
    const d = delivery();
    const reserialised = JSON.stringify(JSON.parse(d.body), null, 1);
    assert.equal(await outcome(() => verifier.verify({ headers: d.headers, body: reserialised })), "digest_mismatch");
    await verifier.verify({ headers: d.headers, body: Buffer.from(d.body) });
  });

  it("clamps the tolerance to 300 s", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, toleranceSeconds: 99999, now: () => (T + 400) * 1000, replayStore: "disabled" });
    assert.equal(await outcome(() => verifier.verify(delivery())), "timestamp_outside_tolerance");
  });

  it("rejects bad construction and never prints a secret", () => {
    assert.throws(() => new WebhookVerifier({ endpoint: "not a url", tenantId: TENANT, keys: KEYS }), RangeError);
    assert.throws(() => new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: {} }), RangeError);
    assert.throws(() => new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: { "Bad Kid": "x" } }), RangeError);
    const text = String(new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS }));
    assert.ok(!text.includes("whsec_"));
  });

  it("a kid of Object.prototype is not a key", async () => {
    const verifier = new WebhookVerifier({ endpoint: ENDPOINT, tenantId: TENANT, keys: KEYS, now: () => T * 1000, replayStore: "disabled" });
    const d = delivery();
    d.headers["Viadere-Signature"] = `t=${T},v2=constructor:${"A".repeat(43)}`;
    assert.equal(await outcome(() => verifier.verify(d)), "no_matching_signature");
  });
});

describe("endpointParts", () => {
  it("keeps the port only when it is not the default, and the path and query as registered", () => {
    assert.deepEqual(endpointParts("https://Hooks.Example.com:443/a"), { host: "hooks.example.com", pathAndQuery: "/a" });
    assert.deepEqual(endpointParts("https://hooks.example.com:8443/a/b%20c?tenant=x&k=1"), { host: "hooks.example.com:8443", pathAndQuery: "/a/b%20c?tenant=x&k=1" });
    assert.deepEqual(endpointParts("https://hooks.example.com"), { host: "hooks.example.com", pathAndQuery: "/" });
    assert.equal(endpointParts("ftp://x.example.com/"), undefined);
  });
});

describe("InMemoryReplayStore", () => {
  it("expires an id 72 h after first receipt, not after the last sighting", () => {
    const store = new InMemoryReplayStore();
    const h = 3600_000;
    assert.equal(store.recordFirstReceipt("evt_a", 0), true);
    assert.equal(store.recordFirstReceipt("evt_a", 71 * h), false);
    assert.equal(store.recordFirstReceipt("evt_a", 72 * h + 1), true);
  });
  it("is bounded", () => {
    const store = new InMemoryReplayStore({ maxEntries: 3 });
    for (let i = 0; i < 10; i++) store.recordFirstReceipt(`evt_${i}`, i);
    assert.equal(store.size, 3);
  });
});
