import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BUSINESS_ROUTES, ROUTES, ViadereApiError, ViadereClient, ViadereSdkError, ViadereValidationError } from "../src/index.js";
import { API_KEY, BUSINESS_ID, DELIVERY_ID, SUBJECT_REF, UUID_1, UUID_2, scriptedFetch, validCreate, view, type Scripted } from "./helpers.js";

function client(script: Scripted[], extra: Partial<ConstructorParameters<typeof ViadereClient>[0]> = {}) {
  const { fetchFn, requests } = scriptedFetch(script);
  const sleeps: number[] = [];
  const c = new ViadereClient({ apiKey: API_KEY, fetch: fetchFn, sleep: async (s) => void sleeps.push(s), random: () => 1, ...extra });
  return { c, requests, sleeps };
}

const TS = "2027-01-15T08:00:00.000Z";
const KID = "A".repeat(43);
const SIG = "A".repeat(86);
const statement = { payload: "e30", signature: SIG };
const signed = { kid: KID, ...statement };
const envelope = { v: 1 as const, suite: "hpke-0010-0001-0002" as const, kid: KID, enc: "AA", ct: "AA", ctx: { exp: 1_800_000_000, purpose: "approve.request", recipient: "ak_x", request_id: "req-1", sender: "biz_x" } };

// Minimal well-formed responses (the required members of each schema).
const R = {
  interaction: { schemaVersion: 1, id: UUID_1, businessId: BUSINESS_ID, scope: { consumerId: UUID_2, relationshipId: UUID_2 }, kind: "confirm", purpose: "transactional", payload: { title: "t" }, priority: "normal", sensitivity: "standard", allowedChannels: ["inApp"], createdAt: TS, expiresAt: TS, idempotencyKey: "k-1", challenge: "c" },
  outcome: { interactionId: UUID_1, businessId: BUSINESS_ID, status: "pending" },
  message: { id: UUID_1, sessionId: UUID_2, businessId: BUSINESS_ID, direction: "businessToConsumer", attribution: { senderType: "business", displayName: "Shop" }, body: "hi", channel: "inApp", createdAt: TS, deliveryStatus: "queued" },
  reward: { id: UUID_1, business: {}, title: "Free coffee", status: "available" },
  program: { programName: "Club", summary: "s", termsVersion: "1", timeZone: "UTC", memberCount: 0, updatedAt: TS },
  points: { relationshipId: UUID_2, pointsBalance: 10, applied: true },
  receipt: { redemptionId: UUID_1, rewardId: UUID_1, rewardTitle: "Free coffee", kind: "coupon", consumerReference: UUID_2, redeemedAt: TS },
  pass: { id: UUID_1, kind: "storeCard", issuedBy: "business", voided: false, createdAt: TS, updatedAt: TS },
  scan: { outcome: "member", passId: UUID_1, kind: "storeCard", relationshipId: UUID_2, scannedAt: TS },
  capabilities: { businessId: BUSINESS_ID, environment: "test", tiers: ["M"], entitlements: [], keyScopes: [], effective: [], catalog: [] },
  sandbox: { relationshipId: UUID_2, createdAt: TS },
  subscription: { id: UUID_1, url: "https://hooks.example.com/v", events: ["interaction.decided"], active: true, createdAt: TS },
  enrollment: { enrollment_id: UUID_1, subject_ref: SUBJECT_REF, capability: "auth.challenge", status: "open", expires_at: TS, created_at: TS },
  key: { kid: KID, subject_ref: SUBJECT_REF, status: "active", assurance: "biometric", public_key: "x", hpke_kid: KID, hpke_public_key: "x", created_at: TS, device_statement: statement },
  request: { request_id: "req-1", subject_ref: SUBJECT_REF, capability: "auth.challenge", status: "pending", protection: "server_visible", expires_at: TS, created_at: TS, delivered_to: 1 },
  result: { result_ref: "apr_1", request_id: "req-1", result: "a.b.c", kid: KID, decided_at: TS },
  freeze: { subject_ref: SUBJECT_REF, frozen: true },
  settings: { device_policy: "single_device" },
  link: { session_id: UUID_1, status: "open", capabilities: ["message.send"], created_at: TS, expires_at: TS },
  vsession: { session_id: UUID_1, status: "open", capability: "age.minimum", purpose_code: "age_check", origin: "https://shop.example", created_at: TS, expires_at: TS },
  vrequest: { request_id: "req_" + "A".repeat(22), capability: "age.minimum", subject_ref: SUBJECT_REF, purpose_code: "age_check", status: "pending", created_at: TS, expires_at: TS },
  vresult: { result_ref: "res_" + "B".repeat(43), request_id: "req_" + "A".repeat(22), capability: "age.minimum", subject_ref: SUBJECT_REF, parameters: { years: 18 }, created_at: TS, outcome: "verified", result: { meets_threshold: true } },
  profileRequest: { id: UUID_1, subjectRef: SUBJECT_REF, fieldKeys: ["email"], purpose: "Receipts", status: "pending", livemode: false, createdAt: TS, expiresAt: TS },
  profile: { subjectRef: SUBJECT_REF, fields: [], grantedWithoutValue: [], catalogVersion: 1, livemode: false },
  published: { index: 3, tree_size: 4, sth: statement },
  directory: { sth: statement, entries: [] },
};
const secretResponse = { subscription: R.subscription, secret: "whsec_" + "s".repeat(43) };
const interactionRequest = { relationshipId: UUID_2, kind: "confirm" as const, purpose: "transactional" as const, payload: { title: "Confirm pickup" }, ttlSeconds: 3600, idempotencyKey: "order-1042-confirm" };
const approvalRequest = { request_id: "req-1", subject_ref: SUBJECT_REF, capability: "auth.challenge" as const, challenge: "C".repeat(43), authentication: { action_display: "Sign in to Example Bank" } };

/**
 * One row per operation: how it is called, what must go on the wire, and how it behaves on a transient failure.
 *   idem: "body" = the header equals the body's `idempotencyKey`; "derived" = a deterministic key from the object; "random" = a fresh key per call;
 *         "caller" = the key passed in options; "none" = no header.
 *   retry: whether a 503 is retried. A POST without a key that is not idempotent by nature must not be.
 */
interface Row { op: keyof typeof BUSINESS_ROUTES | keyof typeof ROUTES; call: (c: ViadereClient) => Promise<unknown>; path: string; body?: unknown; response?: unknown; idem: "body" | "derived" | "random" | "caller" | "none"; retry: boolean; query?: string }
const ROWS: Row[] = [
  { op: "getCapabilities", call: (c) => c.getCapabilities(), path: "/v1/business/capabilities", response: R.capabilities, idem: "none", retry: true },
  { op: "createSandboxRelationship", call: (c) => c.createSandboxRelationship(), path: "/v1/business/sandbox/relationships", response: R.sandbox, idem: "none", retry: false },
  { op: "issueInteraction", call: (c) => c.issueInteraction(interactionRequest), path: "/v1/business/interactions", body: interactionRequest, response: R.interaction, idem: "body", retry: true },
  { op: "getInteractionOutcome", call: (c) => c.getInteractionOutcome(UUID_1.toUpperCase()), path: `/v1/business/interactions/${UUID_1}`, response: R.outcome, idem: "none", retry: true },
  { op: "cancelInteraction", call: (c) => c.cancelInteraction(UUID_1), path: `/v1/business/interactions/${UUID_1}/cancel`, response: R.outcome, idem: "derived", retry: true },
  { op: "sendMessage", call: (c) => c.sendMessage({ subjectRef: SUBJECT_REF, body: "Your order is ready", idempotencyKey: "msg-1" }), path: "/v1/business/messages", body: { subjectRef: SUBJECT_REF, body: "Your order is ready", idempotencyKey: "msg-1" }, response: R.message, idem: "body", retry: true },
  { op: "updateStatus", call: (c) => c.updateStatus({ relationshipId: UUID_2, purpose: "transactional", status: { title: "Out for delivery" }, activityKey: "order-1", idempotencyKey: "st-1" }), path: "/v1/business/statuses", response: R.interaction, idem: "body", retry: true },
  { op: "createReward", call: (c) => c.createReward({ title: "Free coffee", idempotencyKey: "rw-1" }), path: "/v1/business/rewards", body: { title: "Free coffee", idempotencyKey: "rw-1" }, response: R.reward, idem: "body", retry: true },
  { op: "listRewards", call: (c) => c.listRewards(), path: "/v1/business/rewards", response: [R.reward], idem: "none", retry: true },
  { op: "revokeReward", call: (c) => c.revokeReward(UUID_1), path: `/v1/business/rewards/${UUID_1}/revoke`, response: R.reward, idem: "none", retry: true },
  { op: "getLoyaltyProgram", call: (c) => c.getLoyaltyProgram(), path: "/v1/business/loyalty/program", response: R.program, idem: "none", retry: true },
  { op: "saveLoyaltyProgram", call: (c) => c.saveLoyaltyProgram({ programName: "Club", summary: "s", termsVersion: "1", timeZone: "UTC" }), path: "/v1/business/loyalty/program", body: { programName: "Club", summary: "s", termsVersion: "1", timeZone: "UTC" }, response: R.program, idem: "none", retry: true },
  { op: "adjustLoyaltyPoints", call: (c) => c.adjustLoyaltyPoints({ relationshipId: UUID_2, delta: 10, idempotencyKey: "pt-1" }), path: "/v1/business/loyalty/points", response: R.points, idem: "body", retry: true },
  { op: "consumeRedemption", call: (c) => c.consumeRedemption({ code: "K7M2Q-9XPB4" }), path: "/v1/business/redemptions/consume", body: { code: "K7M2Q-9XPB4" }, response: R.receipt, idem: "none", retry: false },
  { op: "issueWalletPass", call: (c) => c.issueWalletPass({ subjectRef: SUBJECT_REF, kind: "storeCard" }), path: "/v1/business/wallet/passes", response: R.pass, idem: "none", retry: true },
  { op: "listWalletPasses", call: (c) => c.listWalletPasses({ limit: 20 }), path: "/v1/business/wallet/passes", query: "?limit=20", response: [R.pass], idem: "none", retry: true },
  { op: "updateWalletPass", call: (c) => c.updateWalletPass(UUID_1, { venue: "Gate B4" }), path: `/v1/business/wallet/passes/${UUID_1}`, body: { venue: "Gate B4" }, response: R.pass, idem: "none", retry: false },
  { op: "voidWalletPass", call: (c) => c.voidWalletPass(UUID_1), path: `/v1/business/wallet/passes/${UUID_1}/void`, response: R.pass, idem: "none", retry: true },
  { op: "scanWalletPass", call: (c) => c.scanWalletPass({ code: ` VQ1.${"a".repeat(48)}\n` }), path: "/v1/business/wallet/scan", body: { code: `VQ1.${"a".repeat(48)}` }, response: R.scan, idem: "none", retry: false },
  { op: "getApprovalEnrollment", call: (c) => c.getApprovalEnrollment(UUID_1), path: `/v1/business/approve/enrollments/${UUID_1}`, response: R.enrollment, idem: "none", retry: true },
  { op: "confirmApprovalEnrollment", call: (c) => c.confirmApprovalEnrollmentRaw(UUID_1, { confirmation: signed }), path: `/v1/business/approve/enrollments/${UUID_1}/confirm`, body: { confirmation: signed }, response: R.key, idem: "none", retry: false },
  { op: "cancelApprovalEnrollment", call: (c) => c.cancelApprovalEnrollment(UUID_1), path: `/v1/business/approve/enrollments/${UUID_1}/cancel`, response: R.enrollment, idem: "none", retry: true },
  { op: "listApprovalKeys", call: (c) => c.listApprovalKeys(SUBJECT_REF), path: "/v1/business/approve/keys", query: `?subject_ref=${SUBJECT_REF}`, response: [R.key], idem: "none", retry: true },
  { op: "revokeApprovalKey", call: (c) => c.revokeApprovalKey(KID, { reason: "lost phone" }), path: `/v1/business/approve/keys/${KID}/revoke`, body: { reason: "lost phone" }, response: R.key, idem: "none", retry: true },
  { op: "createApprovalRequest", call: (c) => c.createApprovalRequest(approvalRequest), path: "/v1/business/approve/requests", body: approvalRequest, response: R.request, idem: "none", retry: true },
  { op: "getApprovalRequest", call: (c) => c.getApprovalRequest("req-1"), path: "/v1/business/approve/requests/req-1", response: R.request, idem: "none", retry: true },
  { op: "cancelApprovalRequest", call: (c) => c.cancelApprovalRequest("req-1"), path: "/v1/business/approve/requests/req-1/cancel", response: R.request, idem: "none", retry: true },
  { op: "getApprovalResult", call: (c) => c.getApprovalResult("apr_1"), path: "/v1/business/approve/results/apr_1", response: R.result, idem: "none", retry: true },
  { op: "freezeApprovals", call: (c) => c.freezeApprovals({ subject_ref: SUBJECT_REF, frozen: true }), path: "/v1/business/approve/freeze", body: { subject_ref: SUBJECT_REF, frozen: true }, response: R.freeze, idem: "none", retry: true },
  { op: "getApprovalFreeze", call: (c) => c.getApprovalFreeze("frz_abc"), path: "/v1/business/approve/freezes/frz_abc", response: R.freeze, idem: "none", retry: true },
  { op: "getApproveSettings", call: (c) => c.getApproveSettings(), path: "/v1/business/approve/settings", response: R.settings, idem: "none", retry: true },
  { op: "putApproveSettings", call: (c) => c.putApproveSettings({ device_policy: "single_device" }), path: "/v1/business/approve/settings", body: R.settings, response: R.settings, idem: "none", retry: true },
  { op: "getAuthApproval", call: (c) => c.getAuthApproval("req-1"), path: "/v1/business/auth-approvals/req-1", response: R.request, idem: "none", retry: true },
  { op: "redeemAuthLink", call: (c) => c.redeemAuthLink({ link_client_id: "lcl_1", code: "c".repeat(43), code_verifier: "v".repeat(43) }), path: "/v1/business/auth-links/redeem", body: { link_client_id: "lcl_1", code: "c".repeat(43), code_verifier: "v".repeat(43) }, response: { grant: "a.b.c", delivery_id: DELIVERY_ID }, idem: "none", retry: false },
  { op: "getLinkSession", call: (c) => c.getLinkSession(UUID_1), path: `/v1/business/link-sessions/${UUID_1}`, response: R.link, idem: "none", retry: true },
  { op: "confirmLinkSession", call: (c) => c.confirmLinkSessionRaw(UUID_1, { confirmation: signed, approval_confirmation: signed }), path: `/v1/business/link-sessions/${UUID_1}/confirm`, body: { confirmation: signed, approval_confirmation: signed }, response: R.link, idem: "none", retry: false },
  { op: "cancelLinkSession", call: (c) => c.cancelLinkSession(UUID_1), path: `/v1/business/link-sessions/${UUID_1}/cancel`, response: R.link, idem: "none", retry: true },
  { op: "getVerificationSession", call: (c) => c.getVerificationSession(UUID_1), path: `/v1/business/verification-sessions/${UUID_1}`, response: R.vsession, idem: "none", retry: true },
  { op: "cancelVerificationSession", call: (c) => c.cancelVerificationSession(UUID_1), path: `/v1/business/verification-sessions/${UUID_1}/cancel`, response: R.vsession, idem: "none", retry: true },
  { op: "createVerificationRequest", call: (c) => c.createVerificationRequest({ subject_ref: SUBJECT_REF, capability: "age.minimum", parameters: { years: 18 }, purpose_code: "age_restricted_access" }), path: "/v1/verification-requests", response: R.vrequest, idem: "random", retry: true },
  { op: "getVerificationRequest", call: (c) => c.getVerificationRequest(R.vrequest.request_id), path: `/v1/verification-requests/${R.vrequest.request_id}`, response: R.vrequest, idem: "none", retry: true },
  { op: "getVerificationResult", call: (c) => c.getVerificationResult(R.vresult.result_ref), path: `/v1/verification-results/${R.vresult.result_ref}`, response: R.vresult, idem: "none", retry: true },
  { op: "createProfileRequest", call: (c) => c.createProfileRequest({ subjectRef: SUBJECT_REF, fieldKeys: ["email"], purpose: "Receipts" }, { idempotencyKey: "prof-1" }), path: "/v1/business/profile-requests", response: R.profileRequest, idem: "caller", retry: true },
  { op: "getProfileRequest", call: (c) => c.getProfileRequest(UUID_1), path: `/v1/business/profile-requests/${UUID_1}`, response: R.profileRequest, idem: "none", retry: true },
  { op: "getProfile", call: (c) => c.getProfile(SUBJECT_REF), path: `/v1/business/profiles/${SUBJECT_REF}`, response: R.profile, idem: "none", retry: true },
  { op: "publishKeyEntry", call: (c) => c.publishKeyEntry({ entry: "eyJ2IjoxfQ" }), path: "/v1/business/key-directory/entries", body: { entry: "eyJ2IjoxfQ" }, response: R.published, idem: "none", retry: false },
  { op: "listKeyEntries", call: (c) => c.listKeyEntries({ since: 4 }), path: "/v1/business/key-directory/entries", query: "?since=4", response: R.directory, idem: "none", retry: true },
  { op: "listWebhooks", call: (c) => c.listWebhooks(), path: "/v1/business/webhooks", response: [R.subscription], idem: "none", retry: true },
  { op: "createWebhook", call: (c) => c.createWebhook({ url: "https://hooks.example.com/v", events: ["interaction.decided"] }), path: "/v1/business/webhooks", body: { url: "https://hooks.example.com/v", events: ["interaction.decided"] }, response: secretResponse, idem: "random", retry: true },
  { op: "deleteWebhook", call: (c) => c.deleteWebhook(UUID_1), path: `/v1/business/webhooks/${UUID_1}`, response: {}, idem: "none", retry: false },
  { op: "rotateWebhookSecret", call: (c) => c.rotateWebhookSecret(UUID_1), path: `/v1/business/webhooks/${UUID_1}/rotate-secret`, response: secretResponse, idem: "random", retry: true },
  { op: "verifyWebhook", call: (c) => c.verifyWebhook(UUID_1), path: `/v1/business/webhooks/${UUID_1}/verify`, response: { verified: false, failure: "no_echo" }, idem: "none", retry: true },
  { op: "sendWebhookTestEvent", call: (c) => c.testWebhook(UUID_1), path: `/v1/business/webhooks/${UUID_1}/test`, idem: "none", retry: false },
  { op: "pauseWebhook", call: (c) => c.pauseWebhook(UUID_1, { reason: "maintenance" }), path: `/v1/business/webhooks/${UUID_1}/pause`, body: { reason: "maintenance" }, idem: "none", retry: true },
  { op: "resumeWebhook", call: (c) => c.resumeWebhook(UUID_1), path: `/v1/business/webhooks/${UUID_1}/resume`, idem: "none", retry: true },
];

/** Operations whose request shape is tested with their flow in `flows.test.ts` (tickets, statements, number matching). */
const FLOW_TESTED = ["createApprovalEnrollment", "createLinkSession", "createVerificationSession", "createAuthApproval"];
/** The auth-delivery operations of `client.test.ts`. */
const DELIVERY_TESTED = ["createAuthDelivery", "getAuthDelivery", "cancelAuthDelivery", "completeAuthDelivery", "updateWebhook", "testAuthWebhook"];

describe("every operation: method, path, headers, body, idempotency, retries", () => {
  it("the table covers every route the SDK offers", () => {
    const covered = new Set<string>([...ROWS.map((r) => r.op), ...FLOW_TESTED, ...DELIVERY_TESTED]);
    assert.deepEqual([...Object.keys(BUSINESS_ROUTES), ...Object.keys(ROUTES)].filter((op) => !covered.has(op)), []);
  });

  for (const row of ROWS) {
    const route = ({ ...BUSINESS_ROUTES, ...ROUTES } as Record<string, { method: string; path: string }>)[row.op]!;
    it(`${row.op}: ${route.method} ${route.path}`, async () => {
      const ok = { status: 200, ...(row.response !== undefined ? { body: row.response } : {}) };
      const { c, requests } = client([ok]);
      await row.call(c);
      const r = requests[0]!;
      assert.equal(r.method, route.method);
      assert.equal(r.url, `https://api.viadere.com${row.path}${row.query ?? ""}`);
      // The route template and the concrete path agree segment by segment.
      const template = route.path.split("/");
      const actual = row.path.split("/");
      assert.equal(actual.length, template.length);
      template.forEach((segment, i) => segment.startsWith("{") || assert.equal(actual[i], segment));
      assert.equal(r.headers.Authorization, `Bearer ${API_KEY}`);
      assert.ok(!r.url.includes(API_KEY) && !(r.body ?? "").includes(API_KEY), "the key is only in the Authorization header");
      assert.equal(r.headers.Accept, "application/json");
      assert.match(r.headers["User-Agent"]!, /^viadere-server-node\/\d+\.\d+\.\d+$/);
      assert.equal(r.redirect, "manual");
      if (row.body !== undefined) {
        assert.deepEqual(JSON.parse(r.body!), row.body);
        assert.equal(r.headers["Content-Type"], "application/json");
      } else if (r.body === undefined) assert.equal(r.headers["Content-Type"], undefined);
      const key = r.headers["Idempotency-Key"];
      if (row.idem === "none") assert.equal(key, undefined);
      else assert.match(key!, /^[A-Za-z0-9_.:-]{1,128}$/);
      if (row.idem === "body") assert.equal(key, (JSON.parse(r.body!) as { idempotencyKey: string }).idempotencyKey);
      if (row.idem === "caller") assert.equal(key, "prof-1");
      if (row.idem === "derived" || row.idem === "random") {
        const again = client([ok]);
        await row.call(again.c);
        const second = again.requests[0]!.headers["Idempotency-Key"];
        if (row.idem === "derived") assert.equal(second, key, "the same object gives the same key, in any process");
        else assert.notEqual(second, key, "a fresh key per call");
      }

      // A transient failure is retried only when the request is safe to repeat, and then with the same key.
      const flaky = client([{ status: 503, body: { error: { code: "unavailable", message: "Try later." } } }, ok]);
      if (row.retry) {
        await row.call(flaky.c);
        assert.equal(flaky.requests.length, 2);
        assert.equal(flaky.requests[1]!.headers["Idempotency-Key"], flaky.requests[0]!.headers["Idempotency-Key"]);
        assert.equal(flaky.requests[1]!.body, flaky.requests[0]!.body);
      } else {
        await assert.rejects(row.call(flaky.c), (e: unknown) => e instanceof ViadereApiError && e.status === 503);
        assert.equal(flaky.requests.length, 1, "not retried: it is not safe to repeat");
        const lost = client([new Error("socket hang up"), ok]);
        await assert.rejects(row.call(lost.c), (e: unknown) => e instanceof ViadereSdkError && e.kind === "transport" && /not retried/.test(e.message));
        assert.equal(lost.requests.length, 1);
      }

      // Error mapping: the stable code, the request id (camelCase on these routes) and the details.
      const failing = client([{ status: 403, body: { error: { code: "not_entitled", message: "Not entitled.", requestId: "rq_9", details: { capability: "age.minimum" } } } }]);
      await assert.rejects(row.call(failing.c), (e: unknown) => e instanceof ViadereApiError && e.status === 403 && e.code === "not_entitled" && e.requestId === "rq_9" && e.isCapabilityDenied && e.deniedCapability === "age.minimum" && !e.isRetryable);
      assert.equal(failing.requests.length, 1);

      // A response that is not what the contract says is refused, not passed on.
      if (row.response !== undefined && !(typeof row.response === "object" && row.response !== null && Object.keys(row.response).length === 0)) {
        await assert.rejects(row.call(client([{ status: 200, body: Array.isArray(row.response) ? {} : [] }]).c), (e: unknown) => e instanceof ViadereSdkError && e.kind === "invalid_response");
      }
    });
  }

  it("201 means created, 200 a replay", async () => {
    const { c } = client([{ status: 201, body: R.interaction }, { status: 200, body: R.interaction }, { status: 201, body: R.pass }, { status: 200, body: R.request }]);
    assert.equal((await c.issueInteraction(interactionRequest)).created, true);
    const replay = await c.issueInteraction(interactionRequest);
    assert.equal(replay.created, false);
    assert.equal(replay.value.id, UUID_1);
    assert.equal((await c.issueWalletPass({ subjectRef: SUBJECT_REF, kind: "coupon", rewardId: UUID_1 })).created, true);
    assert.equal((await c.createApprovalRequest(approvalRequest)).created, false);
  });

  it("429 honours Retry-After; 409 idempotency_conflict and 410 are not retried", async () => {
    const a = client([{ status: 429, headers: { "Retry-After": "7" }, body: { error: { code: "rate_limited", message: "Slow down." } } }, { status: 201, body: R.message }]);
    await a.c.sendMessage({ subjectRef: SUBJECT_REF, body: "hi", idempotencyKey: "m-1" });
    assert.deepEqual(a.sleeps, [7]);
    const b = client([{ status: 409, body: { error: { code: "idempotency_conflict", message: "Key reused." } } }]);
    await assert.rejects(b.c.sendMessage({ subjectRef: SUBJECT_REF, body: "other", idempotencyKey: "m-1" }), (e: unknown) => e instanceof ViadereApiError && e.code === "idempotency_conflict");
    const gone = client([{ status: 410, body: { error: { code: "gone", message: "Already retrieved." } } }]);
    await assert.rejects(gone.c.getVerificationResult(R.vresult.result_ref), (e: unknown) => e instanceof ViadereApiError && e.status === 410);
    assert.equal(gone.requests.length, 1);
  });

  it("the secret of a webhook is returned to the caller and never appears in an error", async () => {
    const { c } = client([{ status: 201, body: secretResponse }]);
    const created = await c.createWebhook({ url: "https://hooks.example.com/v", events: ["approve.request.decided"], envelopeVersion: "2026-10-27" });
    assert.equal(created.value.secret, secretResponse.secret);
    assert.ok(!String(c).includes("vdk_test_0123") && !JSON.stringify(c).includes("vdk_"));
  });
});

describe("construction", () => {
  const make = (apiKey: string, baseUrl?: string) => new ViadereClient({ apiKey, ...(baseUrl !== undefined ? { baseUrl } : {}), fetch: scriptedFetch([]).fetchFn });
  it("accepts the documented key formats and refuses everything else", () => {
    assert.equal(make(`vdk_live_${"k".repeat(16)}.${"s".repeat(43)}`).isLive, true, "vdk_live_<kid>.<secret>");
    assert.equal(make(`vdk_test_${"s".repeat(43)}`).isLive, false, "the older format");
    for (const bad of ["", "vdk_", "vdk_prod_0123456789abcdef", "vdk_live_short", "sk_live_0123456789abcdefgh", `vdk_live_${"x".repeat(80)}`, "vdk_live_0123456789 abcdef", "vdk_live_0123456789\nabcdef"]) {
      assert.throws(() => make(bad), (e: unknown) => e instanceof ViadereSdkError && e.kind === "invalid_api_key" && !e.message.includes(bad.slice(9) || "\u0000"), JSON.stringify(bad));
    }
  });
  it("refuses a non-HTTPS base URL exactly as before, and a bad link domain", () => {
    for (const bad of ["http://api.viadere.com", "http://10.0.0.5:8080", "ftp://api.viadere.com", "https://user:pw@api.viadere.com", "https://api.viadere.com/?x=1", "not a url"]) {
      assert.throws(() => make(API_KEY, bad), (e: unknown) => e instanceof ViadereSdkError && e.kind === "insecure_base_url", bad);
    }
    make(API_KEY, "http://localhost:8080");
    make(API_KEY, "http://127.0.0.1:8080/");
    assert.throws(() => new ViadereClient({ apiKey: API_KEY, linkDomain: "Viadere.com" }), RangeError);
    assert.throws(() => new ViadereClient({ apiKey: API_KEY, linkDomain: "10.0.0.1" }), RangeError);
  });
  it("a base URL with a path prefix is kept", async () => {
    const { c, requests } = client([{ status: 200, body: R.capabilities }], { baseUrl: "https://staging.example.com/api/" });
    await c.getCapabilities();
    assert.equal(requests[0]!.url, "https://staging.example.com/api/v1/business/capabilities");
  });
});

describe("validation refusals: nothing is sent", () => {
  async function refused(call: (c: ViadereClient) => Promise<unknown>, field: string, code: string) {
    const { c, requests } = client([]);
    await assert.rejects(call(c), (e: unknown) => e instanceof ViadereValidationError && e.details.some((d) => d.field === field && d.code === code), `${field} ${code}`);
    assert.equal(requests.length, 0);
  }
  async function badPath(call: (c: ViadereClient) => Promise<unknown>) {
    const { c, requests } = client([]);
    await assert.rejects(call(c), (e: unknown) => e instanceof ViadereSdkError && e.kind === "invalid_path");
    assert.equal(requests.length, 0);
  }

  it("path parameters cannot carry a traversal, a query or the wrong shape", async () => {
    await badPath((c) => c.getInteractionOutcome("../../admin"));
    await badPath((c) => c.cancelInteraction(`${UUID_1}/../x`));
    await badPath((c) => c.revokeReward("1"));
    await badPath((c) => c.getApprovalRequest("req 1"));
    await badPath((c) => c.getApprovalRequest("a/b"));
    await badPath((c) => c.getApprovalRequest("x".repeat(129)));
    await badPath((c) => c.getApprovalResult("r?x=1"));
    await badPath((c) => c.getApprovalFreeze(""));
    await badPath((c) => c.revokeApprovalKey("short"));
    await badPath((c) => c.getProfile("sub_short"));
    await badPath((c) => c.listApprovalKeys("sub_x&admin=1"));
    await badPath((c) => c.getVerificationRequest(UUID_1));
    await badPath((c) => c.getVerificationResult("res_x"));
    await badPath((c) => c.getAuthApproval("../x"));
    await badPath((c) => c.updateWalletPass("x", {}));
    await badPath((c) => c.listWalletPasses({ limit: 0 }));
    await badPath((c) => c.listWalletPasses({ limit: 201 }));
    await badPath((c) => c.listKeyEntries({ since: -1 }));
    await badPath((c) => c.deleteWebhook(undefined as never));
    await badPath((c) => c.updateWebhook(UUID_1, { signature_version: "v1" } as never));
  });

  it("an invalid idempotency key is refused", async () => {
    const { c, requests } = client([]);
    await assert.rejects(c.cancelInteraction(UUID_1, { idempotencyKey: "has space" }), (e: unknown) => e instanceof ViadereSdkError && e.kind === "invalid_idempotency_key");
    await assert.rejects(c.rotateWebhookSecret(UUID_1, { idempotencyKey: "x".repeat(129) }), (e: unknown) => e instanceof ViadereSdkError && e.kind === "invalid_idempotency_key");
    assert.equal(requests.length, 0);
  });

  it("interactions, messages, statuses", async () => {
    const { relationshipId: _omit, ...unaddressed } = interactionRequest;
    await refused((c) => c.issueInteraction(unaddressed), "relationshipId|subjectRef", "required");
    await refused((c) => c.issueInteraction({ ...interactionRequest, kind: "transfer" as never }), "kind", "invalid_value");
    await refused((c) => c.issueInteraction({ ...interactionRequest, payload: {} as never }), "payload.title", "required");
    await refused((c) => c.issueInteraction({ ...interactionRequest, kind: "authorize", payload: { actionDescription: "Pay", amount: { value: "12.5e1", currency: "USD" } } }), "payload.amount.value", "invalid_format");
    await refused((c) => c.issueInteraction({ ...interactionRequest, kind: "authenticate", payload: { service: "s", device: "d", attemptedAt: "2027-01-15T08:00:00.000Z" }, ttlSeconds: 901 }), "ttlSeconds", "out_of_range");
    await refused((c) => c.issueInteraction({ ...interactionRequest, ttlSeconds: 0 }), "ttlSeconds", "out_of_range");
    await refused((c) => c.issueInteraction({ ...interactionRequest, allowedChannels: ["sms", "sms"] }), "allowedChannels", "duplicate");
    await refused((c) => c.issueInteraction({ ...interactionRequest, allowedChannels: ["fax" as never] }), "allowedChannels[0]", "invalid_value");
    await refused((c) => c.issueInteraction({ ...interactionRequest, idempotencyKey: "has space" }), "idempotencyKey", "invalid_format");
    await refused((c) => c.issueInteraction({ ...interactionRequest, subjectRef: "sub_x" }), "subjectRef", "invalid_format");
    await refused((c) => c.issueInteraction({ ...interactionRequest, requestedActions: Array.from({ length: 5 }, (_, i) => ({ id: `a${i}`, label: "x", role: "approve" as const })) }), "requestedActions", "invalid_length");
    await refused((c) => c.issueInteraction(null as never), "(body)", "invalid_type");
    await refused((c) => c.sendMessage({ subjectRef: SUBJECT_REF, body: "", idempotencyKey: "m" }), "body", "required");
    await refused((c) => c.sendMessage({ subjectRef: SUBJECT_REF, body: "x".repeat(1601), idempotencyKey: "m" }), "body", "too_long");
    await refused((c) => c.sendMessage({ body: "x", idempotencyKey: "m" }), "relationshipId|subjectRef", "required");
    await refused((c) => c.updateStatus({ relationshipId: UUID_2, purpose: "transactional", status: { title: "t", liveActivity: { type: "delivery", order: { orderReference: "o", stage: "placed" } } }, activityKey: "a", idempotencyKey: "s" }), "status.liveActivity.delivery", "required");
    await refused((c) => c.updateStatus({ relationshipId: UUID_2, purpose: "billing" as never, status: { title: "t" }, activityKey: "a", idempotencyKey: "s" }), "purpose", "invalid_value");
  });

  it("rewards, loyalty, Wallet", async () => {
    await refused((c) => c.createReward({ title: "", idempotencyKey: "r" }), "title", "required");
    await refused((c) => c.createReward({ title: "x", kind: "pointsReward", idempotencyKey: "r" }), "pointsCost", "required");
    await refused((c) => c.createReward({ title: "x", recurrence: { weekdays: [8], perDayLimit: 1, timeZone: "UTC" }, idempotencyKey: "r" }), "recurrence.weekdays[0]", "out_of_range");
    await refused((c) => c.adjustLoyaltyPoints({ relationshipId: UUID_2, delta: 0, idempotencyKey: "p" }), "delta", "out_of_range");
    await refused((c) => c.adjustLoyaltyPoints({ relationshipId: UUID_2, delta: 1.5, idempotencyKey: "p" }), "delta", "invalid_type");
    await refused((c) => c.adjustLoyaltyPoints({ relationshipId: UUID_2, delta: 2_000_000, idempotencyKey: "p" }), "delta", "out_of_range");
    await refused((c) => c.saveLoyaltyProgram({ programName: "x", summary: "s", termsVersion: "1" } as never), "timeZone", "required");
    await refused((c) => c.consumeRedemption({ code: "" }), "code", "required");
    await refused((c) => c.consumeRedemption({ code: "K7M2Q-9XPB4", locationCode: "till 4" }), "locationCode", "invalid_format");
    await refused((c) => c.issueWalletPass({ kind: "storeCard" }), "relationshipId|subjectRef", "required");
    await refused((c) => c.issueWalletPass({ subjectRef: SUBJECT_REF, kind: "passport" as never }), "kind", "invalid_value");
    await refused((c) => c.updateWalletPass(UUID_1, { venue: "x".repeat(81) }), "venue", "too_long");
    await refused((c) => c.scanWalletPass({ code: "VQ1.tooshort" }), "code", "invalid_format");
    await refused((c) => c.scanWalletPass({ code: `VQ2.${"a".repeat(48)}` }), "code", "invalid_format");
  });

  it("Approve v2: closed bodies refuse tenant_id and every unknown member; exactly one request form", async () => {
    await refused((c) => c.createApprovalRequest({ ...approvalRequest, tenant_id: "t" } as never), "tenant_id", "unknown_member");
    await refused((c) => c.createApprovalRequest({ ...approvalRequest, audience: BUSINESS_ID } as never), "audience", "unknown_member");
    await refused((c) => c.createApprovalRequest({ ...approvalRequest, authentication: { action_display: "x", match_digits: 2 } as never }), "authentication.match_digits", "unknown_member");
    await refused((c) => c.createApprovalRequest({ ...approvalRequest, request_id: "has space" }), "request_id", "invalid_format");
    await refused((c) => c.createApprovalRequest({ ...approvalRequest, challenge: "short" }), "challenge", "invalid_format");
    await refused((c) => c.createApprovalRequest({ ...approvalRequest, expires_in_seconds: 601 }), "expires_in_seconds", "out_of_range");
    await refused((c) => c.createApprovalRequest({ request_id: "r", subject_ref: SUBJECT_REF, capability: "auth.challenge" }), "challenge", "required");
    await refused((c) => c.createApprovalRequest({ ...approvalRequest, capability: "transaction.approve" }), "transaction", "required");
    await refused((c) => c.createApprovalRequest({ ...approvalRequest, envelopes: [{ kid: KID, envelope }] }), "challenge", "not_allowed");
    await refused((c) => c.createApprovalRequest({ request_id: "r", subject_ref: SUBJECT_REF, capability: "transaction.approve", envelopes: [] }), "envelopes", "invalid_length");
    await refused((c) => c.createApprovalRequest({ request_id: "r", subject_ref: SUBJECT_REF, capability: "transaction.approve", envelopes: [{ kid: KID, envelope: { ...envelope, suite: "hpke-0020" as never } }] }), "envelopes[0].envelope.suite", "invalid_value");
    await refused((c) => c.createApprovalRequest({ request_id: "r", subject_ref: SUBJECT_REF, capability: "transaction.approve", challenge: "C".repeat(43), transaction: { currency: "usd", amount_minor: 0, payee_display: "P", transaction_reference: "r" } }), "transaction.currency", "invalid_format");
    await refused((c) => c.freezeApprovals({ subject_ref: SUBJECT_REF } as never), "frozen", "required");
    await refused((c) => c.putApproveSettings({ device_policy: "none" as never }), "device_policy", "invalid_value");
    await refused((c) => c.confirmApprovalEnrollmentRaw(UUID_1, { confirmation: { kid: KID, payload: "e30", signature: "der" } }), "confirmation.signature", "too_short");
    await refused((c) => c.confirmLinkSessionRaw(UUID_1, { confirmation: signed, extra: 1 } as never), "extra", "unknown_member");
    await refused((c) => c.revokeApprovalKey(KID, { reason: "x".repeat(121) }), "reason", "too_long");
  });

  it("verification, profiles, link redeem, key directory, webhooks", async () => {
    const v = { subject_ref: SUBJECT_REF, capability: "age.minimum" as const, purpose_code: "age_restricted_access" };
    await refused((c) => c.createVerificationRequest({ ...v, callback_id: "https://hooks.example.com/cb" }), "callback_id", "invalid_format");
    await refused((c) => c.createVerificationRequest({ ...v, capability: "identity.passport" as never }), "capability", "invalid_value");
    await refused((c) => c.createVerificationRequest({ ...v, purpose_code: "Free text purpose" }), "purpose_code", "invalid_format");
    await refused((c) => c.createVerificationRequest({ ...v, expires_in_seconds: 601 }), "expires_in_seconds", "out_of_range");
    await refused((c) => c.createVerificationRequest({ ...v, tenant_id: "t" } as never), "tenant_id", "unknown_member");
    const s = { capability: "age.minimum" as const, purpose_code: "age_check", origin: "https://shop.example" };
    await refused((c) => c.createVerificationSession({ ...s, origin: "http://shop.example" }), "origin", "invalid_format");
    await refused((c) => c.createVerificationSession({ ...s, origin: "https://shop.example/cart" }), "origin", "invalid_format");
    await refused((c) => c.createVerificationSession({ ...s, return_url: "https://evil.example/back" }), "return_url", "invalid_value");
    await refused((c) => c.createVerificationSession({ ...s, parameters: { years: 21.5 } }), "parameters.years", "invalid_type");
    await refused((c) => c.createVerificationSession({ ...s, expires_in_seconds: 30 }), "expires_in_seconds", "out_of_range");
    await refused((c) => c.createProfileRequest({ subjectRef: SUBJECT_REF, fieldKeys: [], purpose: "x" }), "fieldKeys", "invalid_length");
    await refused((c) => c.createProfileRequest({ subjectRef: SUBJECT_REF, fieldKeys: ["email"], purpose: "x".repeat(201) }), "purpose", "too_long");
    const redeem = { link_client_id: "lcl_1", code_verifier: "v".repeat(43) };
    await refused((c) => c.redeemAuthLink(redeem), "code|ach", "exactly_one");
    await refused((c) => c.redeemAuthLink({ ...redeem, code: "c".repeat(43), ach: "ach_1" }), "code|ach", "exactly_one");
    await refused((c) => c.redeemAuthLink({ ...redeem, code: "c".repeat(43), code_verifier: "short" }), "code_verifier", "invalid_format");
    await refused((c) => c.redeemAuthLink({ ...redeem, link_client_id: "client", code: "c".repeat(43) }), "link_client_id", "invalid_format");
    await refused((c) => c.publishKeyEntry({ entry: "not base64url!" }), "entry", "invalid_format");
    await refused((c) => c.createWebhook({ url: "http://hooks.example.com/v", events: ["interaction.decided"] }), "url", "invalid_format");
    await refused((c) => c.createWebhook({ url: "https://hooks.example.com/v", events: [] }), "events", "invalid_length");
    await refused((c) => c.createWebhook({ url: "https://hooks.example.com/v", events: ["interaction.decided"], envelopeVersion: "2025-01-01" as never }), "envelopeVersion", "invalid_value");
    await refused((c) => c.pauseWebhook(UUID_1, { reason: "x".repeat(201) }), "reason", "too_long");
  });

  it("the auth-delivery create still refuses tenant_id", async () => {
    const { c, requests } = client([{ status: 201, body: view() }]);
    await assert.rejects(c.createAuthDelivery(validCreate({ tenant_id: "x" }) as never), ViadereValidationError);
    assert.equal(requests.length, 0);
  });
});
