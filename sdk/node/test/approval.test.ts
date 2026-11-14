import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  ApprovalVerificationError,
  ApprovalVerifier,
  AuthApprovalKeys,
  InMemoryApprovalKeyStore,
  InMemoryReplayGuard,
  base64urlEncode,
  canonicalJson,
  drawMatchCode,
  isValidMatchCode,
  requiredMatchDigits,
  signEs256,
  transactionDigest,
  verifyApprovalResult,
  type ApprovalExpectation,
  type EnrolledApprovalKey,
  type JsonValue,
  type PendingApproval,
} from "../src/index.js";
import { newKey, readRepoJson, SUBJECT_REF } from "./helpers.js";

interface Case { name: string; expectation: "required" | "not_requested"; jws: string; outcome?: string; error?: string }
const vector = readRepoJson<{
  now: number;
  device_key: { public_x963_b64url: string; kid: string };
  context: { aud: string; sub: string; request_id: string; challenge: string; authentication: { action_display: string; match_digits: number }; txn_digest: string; code: string; request_expires_at: number; minimum_amr: "biometric" };
  cases: Case[];
  match_tags: { sdk_secret_hex: string; subject_ref: string; tags: { code: string; match_tag: string; match_prefix_tag: string | null }[] };
  session_handles: { handles: { initiating_session_id: string; session_handle: string }[] };
  code_draws: { digits: 2 | 3; random_hex: string; code: string }[];
}>("docs/protocol/vectors/approval-result-v2.json");

const ctx = vector.context;
const now = new Date(vector.now * 1000);
const key: EnrolledApprovalKey = { kid: vector.device_key.kid, publicKey: vector.device_key.public_x963_b64url, subjectRef: ctx.sub, assurance: "biometric" };
const details = { authentication: { action_display: ctx.authentication.action_display, match_digits: ctx.authentication.match_digits } };
function expectation(kind: "required" | "not_requested", over: Partial<ApprovalExpectation> = {}): ApprovalExpectation {
  return { audience: ctx.aud, subjectRef: ctx.sub, requestId: ctx.request_id, challenge: ctx.challenge, details, numberMatch: kind === "required" ? { required: ctx.code } : "not_requested", requestExpiresAt: new Date(ctx.request_expires_at * 1000), minimumAmr: ctx.minimum_amr, ...over };
}
const snake = (s: string) => s.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase());
const refused = (code: string) => (e: unknown) => e instanceof ApprovalVerificationError && e.code === code;
const approve = vector.cases.find((c) => c.name === "approve_v2_with_the_right_number")!.jws;

describe("ApprovalResult against docs/protocol/vectors/approval-result-v2.json", () => {
  it("the transaction digest of the vector's context", () => {
    assert.equal(transactionDigest(details), ctx.txn_digest);
    assert.notEqual(transactionDigest({ authentication: { action_display: ctx.authentication.action_display } }), ctx.txn_digest, "match_digits is part of the digest");
  });

  for (const c of vector.cases) {
    it(`${c.name}: ${c.outcome ?? c.error}`, () => {
      if (c.outcome !== undefined) assert.equal(verifyApprovalResult(c.jws, expectation(c.expectation), [key], now).decision, c.outcome);
      else assert.throws(() => verifyApprovalResult(c.jws, expectation(c.expectation), [key], now), refused(snake(c.error!)));
    });
  }

  it("every expectation comes from the verifier's own records", () => {
    const check = (over: Partial<ApprovalExpectation>, code: string, keys: EnrolledApprovalKey[] = [key], at = now) => assert.throws(() => verifyApprovalResult(approve, expectation("required", over), keys, at), refused(code), code);
    check({ subjectRef: SUBJECT_REF }, "wrong_subject");
    check({ requestId: "another" }, "wrong_request");
    check({ challenge: "B".repeat(43) }, "challenge_mismatch");
    check({ details: { authentication: { action_display: "Sign in to Evil Bank", match_digits: 2 } } }, "transaction_mismatch");
    check({ details: { transaction: { currency: "USD", amount_minor: 100, payee_display: "Shop", transaction_reference: "r1" } } }, "wrong_capability");
    check({ details: { authentication: { action_display: " padded " } } }, "invalid_expectation");
    check({ numberMatch: { required: "48" } }, "number_mismatch");
    check({ numberMatch: undefined as never }, "invalid_expectation");
    check({ numberMatch: { required: "07" } }, "invalid_expectation");
    check({ requestExpiresAt: new Date((vector.now - 3600) * 1000) }, "decided_after_request_expiry");
    check({}, "unknown_key", []);
    check({}, "key_revoked", [{ ...key, revoked: true }]);
    check({}, "unknown_key", [{ ...key, publicKey: newKey().publicKey }]); // the kid must really be the id of the stored key
    check({}, "wrong_subject", [{ ...key, subjectRef: SUBJECT_REF }]);
    check({}, "amr_exceeds_key", [{ ...key, assurance: "presence" }]);
    check({}, "issued_in_future", [key], new Date((vector.now - 120) * 1000));
    check({}, "expired", [key], new Date((vector.now + 300) * 1000));
  });

  it("refuses alg none, HS256, a crit header, DER and oversized input", async () => {
    const [h, p, s] = approve.split(".") as [string, string, string];
    const header = (o: Record<string, JsonValue>) => Buffer.from(canonicalJson(o), "utf8").toString("base64url");
    const base = { kid: key.kid, typ: "viadere-approval+jws" };
    const bad = (jws: string, code: string) => assert.throws(() => verifyApprovalResult(jws, expectation("required"), [key], now), refused(code), code);
    bad(`${header({ ...base, alg: "none" })}.${p}.${s}`, "unsupported_algorithm");
    bad(`${header({ ...base, alg: "HS256" })}.${p}.${s}`, "unsupported_algorithm");
    bad(`${header({ ...base, alg: "ES256", crit: ["b64"] })}.${p}.${s}`, "unknown_critical_header");
    bad(`${h}.${p}.`, "malformed");
    bad(`${h}.${p}`, "malformed");
    bad(`${h}.${p}.${Buffer.alloc(70, 1).toString("base64url")}`, "malformed");
    bad(`${h}.${p}.${s}=`, "malformed");
    bad(`${Buffer.from('{"alg": "ES256"}').toString("base64url")}.${p}.${s}`, "malformed");
    bad("x".repeat(3000), "malformed");
    bad(42 as never, "malformed");
    // The payload's alg and kid repeat the header: a result signed correctly whose payload names another kid is refused.
    const device = newKey();
    const mine: EnrolledApprovalKey = { kid: device.kid, publicKey: device.publicKey, subjectRef: ctx.sub, assurance: "biometric" };
    const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as Record<string, JsonValue>;
    const input = `${header({ ...base, alg: "ES256", kid: device.kid })}.${Buffer.from(canonicalJson(payload), "utf8").toString("base64url")}`;
    const { signature } = await signEs256(device.signer, Buffer.from(input, "utf8"));
    assert.throws(() => verifyApprovalResult(`${input}.${signature}`, expectation("required"), [mine], now), refused("header_payload_mismatch"));
  });
});

describe("ApprovalVerifier", () => {
  const pending: PendingApproval = { requestId: ctx.request_id, subjectRef: ctx.sub, challenge: ctx.challenge, details, numberMatch: { required: ctx.code }, expiresAt: new Date(ctx.request_expires_at * 1000) };
  function verifier() {
    const keys = new InMemoryApprovalKeyStore();
    keys.add(key);
    return { keys, v: new ApprovalVerifier({ businessId: ctx.aud.toUpperCase(), keys, replayGuard: new InMemoryReplayGuard(), now: () => now }) };
  }

  it("grants once: the challenge and the jti are consumed, a replay is refused", async () => {
    const { v } = verifier();
    assert.equal((await v.check(approve, pending)).decision, "approve");
    assert.equal((await v.check(approve, pending)).decision, "approve", "check consumes nothing");
    assert.equal((await v.verify(approve, pending)).decision, "approve");
    await assert.rejects(v.verify(approve, pending), refused("replayed"));
  });

  it("a signed denial is an error from verify and readable with decisionOf; a failed result burns nothing", async () => {
    const { v, keys } = verifier();
    const deny = vector.cases.find((c) => c.outcome === "deny")!.jws;
    await assert.rejects(v.verify(deny, pending), (e: unknown) => e instanceof ApprovalVerificationError && e.code === "not_approved" && e.detail === "deny");
    assert.equal(await v.decisionOf(deny, pending), "deny");
    await assert.rejects(v.verify(approve, { ...pending, numberMatch: { required: "99" } }), refused("number_mismatch"));
    assert.equal((await v.verify(approve, pending)).decision, "approve", "the wrong expectation did not consume the challenge");
    keys.revoke(key.kid, key.subjectRef);
    await assert.rejects(v.check(approve, pending), refused("key_revoked"));
  });

  it("the default minimum is biometric; the in-memory guard refuses rather than forget", async () => {
    const guard = new InMemoryReplayGuard({ maxEntries: 1 });
    assert.equal(guard.registerIfFresh("a", "s", 2000, 1000), true);
    assert.equal(guard.registerIfFresh("a", "s", 2000, 1000), false);
    assert.equal(guard.registerIfFresh("b", "s", 2000, 1000), false, "full of live entries");
    assert.equal(guard.registerIfFresh("b", "s", 4000, 3000), true, "expired entries are evicted");
  });
});

describe("number matching, match tags and SDK keys (vector)", () => {
  const keys = new AuthApprovalKeys(Buffer.from(vector.match_tags.sdk_secret_hex, "hex"));

  it("match tags and prefix tags", () => {
    for (const t of vector.match_tags.tags) {
      assert.deepEqual(keys.matchTags(vector.match_tags.subject_ref, t.code), t.match_prefix_tag === null ? { tag: t.match_tag } : { tag: t.match_tag, prefixTag: t.match_prefix_tag });
    }
    assert.equal(keys.matchTags(vector.match_tags.subject_ref, "07"), undefined);
    assert.equal(keys.matchTags(vector.match_tags.subject_ref, "1234"), undefined);
  });

  it("session handles", () => {
    for (const h of vector.session_handles.handles) assert.equal(keys.sessionHandle(h.initiating_session_id), h.session_handle);
  });

  it("the code sampler rejects biased samples", () => {
    for (const d of vector.code_draws) {
      const stream = Buffer.from(d.random_hex, "hex");
      let at = 0;
      assert.equal(drawMatchCode(d.digits, (n) => stream.subarray(at, (at += n))), d.code, d.random_hex);
      assert.equal(at, stream.length, "every byte of the vector's stream is consumed");
    }
    for (let i = 0; i < 200; i++) assert.ok(isValidMatchCode(drawMatchCode(3), 3) && isValidMatchCode(drawMatchCode(2), 2));
    assert.equal(requiredMatchDigits("auth.challenge", "medium"), 2);
    assert.equal(requiredMatchDigits("auth.challenge", "high"), 3);
    assert.equal(requiredMatchDigits("transaction.approve", "low"), 3);
  });

  it("never prints key material and refuses a short secret", () => {
    assert.equal(String(keys), "AuthApprovalKeys(***)");
    assert.equal(JSON.stringify({ keys }), '{"keys":"[secret]"}');
    assert.throws(() => new AuthApprovalKeys(Buffer.alloc(16)), RangeError);
  });

  it("the transaction digest of a payment, and its display rules", () => {
    const t = { currency: "USD", amount_minor: 250_000, payee_display: "Northwind Bank", transaction_reference: "INV-1" };
    const expected = canonicalJson({ amount_minor: 250_000, capability: "transaction.approve", currency: "USD", payee_display: "Northwind Bank", transaction_reference: "INV-1", v: 1 });
    assert.equal(expected, '{"amount_minor":250000,"capability":"transaction.approve","currency":"USD","payee_display":"Northwind Bank","transaction_reference":"INV-1","v":1}');
    assert.match(transactionDigest({ transaction: t }), /^[0-9a-f]{64}$/);
    for (const bad of [{ ...t, currency: "XYZ" }, { ...t, amount_minor: 0 }, { ...t, amount_minor: 1.5 }, { ...t, payee_display: "Shop‮evil" }, { ...t, payee_display: "é" }, { ...t, transaction_reference: "has space" }]) {
      assert.throws(() => transactionDigest({ transaction: bad }), RangeError, JSON.stringify(bad));
    }
    assert.equal(base64urlEncode(Buffer.from("ok")), "b2s");
  });
});
