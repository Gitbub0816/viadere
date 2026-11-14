import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  ApprovalEnrollmentSecret,
  ApprovalVerifier,
  AuthApprovalKeys,
  DOMAINS,
  InMemoryApprovalKeyStore,
  InMemoryReplayGuard,
  LinkSessionSecret,
  StatementVerificationError,
  ViadereApiError,
  ViadereClient,
  ViadereFlowError,
  ViadereThrottledError,
  ViadereValidationError,
  canonicalJson,
  sha256Hex,
  signEs256,
  statementDigest,
  transactionDigest,
  verifyConfirmation,
  type ApprovalEnrollmentInvitation,
  type JsonValue,
  type LinkSessionInvitation,
} from "../src/index.js";
import { API_KEY, BUSINESS_ID, SUBJECT_REF, UUID_1, newKey, scriptedFetch, signStatement, type Scripted } from "./helpers.js";

// These tests play the relay, the customer's device and Viadere's `link-descriptor` key with fresh keys, and check that the SDK trusts none of
// them beyond what its own records and pinned keys establish.

function client(script: Scripted[], extra: Partial<ConstructorParameters<typeof ViadereClient>[0]> = {}) {
  const { fetchFn, requests } = scriptedFetch(script);
  const c = new ViadereClient({ apiKey: API_KEY, fetch: fetchFn, sleep: async () => undefined, random: () => 1, ...extra });
  return { c, requests };
}
const flow = (code: string) => (e: unknown) => e instanceof ViadereFlowError && e.code === code;
const statementError = (code: string) => (e: unknown) => e instanceof StatementVerificationError && e.code === code;
const paths = (requests: { method: string; url: string }[]) => requests.map((r) => `${r.method} ${r.url.replace("https://api.viadere.com", "")}`);

const TS = "2027-01-15T08:00:00.000Z";
const CODE = "K7QFM2XA";
const root = newKey();
const confirmer = newKey();
const viadere = newKey();
const NOW = new Date("2027-01-15T08:00:10.000Z");

describe("Approve v2 enrollment", () => {
  const ticket = (over: Record<string, unknown> = {}) => ({ enrollment_id: UUID_1, code: CODE, deep_link: `https://viadere.com/a/${CODE}?rk=${root.kid}`, expires_at: TS, ...over });
  const view = (over: Record<string, unknown> = {}) => ({ enrollment_id: UUID_1, subject_ref: SUBJECT_REF, capability: "auth.challenge", status: "device_completed", expires_at: TS, created_at: TS, ...over });
  const request = { subject_ref: SUBJECT_REF, capability: "auth.challenge" as const };

  async function deviceStatement(over: Record<string, JsonValue> = {}) {
    const device = newKey();
    const hpke = newKey();
    const signed = await signStatement({ v: 1, type: "approval-enrollment", business_id: BUSINESS_ID, subject_ref: SUBJECT_REF, enrollment_id: UUID_1, kid: device.kid, alg: "ES256", public_key: device.publicKey, hpke_kid: hpke.kid, hpke_public_key: hpke.publicKey, assurance: "biometric", created_at: 1_800_000_010, ...over }, DOMAINS.approvalEnrollment, device.signer);
    return { device, hpke, signed: { payload: signed.payload, signature: signed.signature } };
  }
  function invitation(): ApprovalEnrollmentInvitation {
    const secret = new ApprovalEnrollmentSecret();
    return { enrollmentId: UUID_1, code: CODE, displayCode: "K7QF-M2XA", checkCode: secret.checkCode, rootKid: root.kid, secret, expiresAt: TS, link: "" };
  }

  it("builds the link itself: your root key id, a fresh secret in the fragment, nothing from the relay", async () => {
    const { c, requests } = client([{ status: 201, body: ticket() }]);
    const inv = await c.createApprovalEnrollment(request, { rootKid: root.kid });
    assert.equal(inv.link, `https://viadere.com/a/${CODE}?rk=${root.kid}#es=${inv.secret.base64url}`);
    assert.equal(inv.displayCode, "K7QF-M2XA");
    assert.match(inv.checkCode, /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    assert.deepEqual(JSON.parse(requests[0]!.body!), request, "the secret is never sent to Viadere");
    assert.ok(!JSON.stringify(inv).includes(inv.secret.base64url.slice(0, 20)) || JSON.stringify(inv).includes("#es="), "only the link carries the secret when serialized");
    assert.equal(JSON.parse(JSON.stringify(inv)).secret, "[secret]");
  });

  it("refuses a ticket that names another root, another host, a secret or a malformed code, and cancels the enrollment", async () => {
    const other = newKey().kid;
    for (const bad of [
      ticket({ deep_link: `https://viadere.com/a/${CODE}?rk=${other}` }),
      ticket({ deep_link: `https://viadere.com/a/${CODE}` }),
      ticket({ deep_link: `https://evil.example/a/${CODE}?rk=${root.kid}` }),
      ticket({ deep_link: `https://viadere.com/a/${CODE}?rk=${root.kid}#es=${"A".repeat(43)}` }),
      ticket({ deep_link: `https://viadere.com/a/ABCDEFGH?rk=${root.kid}` }),
      ticket({ code: "k7qfm2xa" }),
    ]) {
      const { c, requests } = client([{ status: 201, body: bad }, { status: 200, body: view({ status: "cancelled" }) }]);
      await assert.rejects(c.createApprovalEnrollment(request, { rootKid: root.kid }), flow("ticket_mismatch"));
      assert.deepEqual(paths(requests), ["POST /v1/business/approve/enrollments", `POST /v1/business/approve/enrollments/${UUID_1}/cancel`]);
    }
    const none = client([]);
    await assert.rejects(none.c.createApprovalEnrollment(request, { rootKid: "not-a-kid" }), flow("ticket_mismatch"));
    await assert.rejects(none.c.createApprovalEnrollment({ ...request, tenant_id: "t" } as never, { rootKid: root.kid }), ViadereValidationError);
    assert.equal(none.requests.length, 0);
    // The staging link domain is honoured, and only it.
    const staging = client([{ status: 201, body: ticket({ deep_link: `https://viadere.cksites.dev/a/${CODE}?rk=${root.kid}` }) }], { linkDomain: "viadere.cksites.dev" });
    assert.match((await staging.c.createApprovalEnrollment(request, { rootKid: root.kid })).link, /^https:\/\/viadere\.cksites\.dev\/a\//);
  });

  it("confirms with the binding tag: verifies the statement, signs the confirmation, returns the key to store", async () => {
    const inv = invitation();
    const { device, hpke, signed } = await deviceStatement();
    const { c, requests } = client([{ status: 200, body: view({ device_statement: signed, binding_tag: inv.secret.bindingTag(signed) }) }, { status: 200, body: { kid: device.kid } }]);
    const key = { kid: device.kid, subject_ref: SUBJECT_REF, status: "active", assurance: "biometric", public_key: device.publicKey, hpke_kid: hpke.kid, hpke_public_key: hpke.publicKey, created_at: TS, device_statement: signed };
    const run = client([{ status: 200, body: view({ device_statement: signed, binding_tag: inv.secret.bindingTag(signed) }) }, { status: 200, body: key }]);
    const confirmed = await run.c.confirmApprovalEnrollment({ invitation: inv, businessId: BUSINESS_ID, expectedSubjectRef: SUBJECT_REF, signer: confirmer.signer, now: NOW });
    assert.deepEqual(confirmed.key, { kid: device.kid, publicKey: device.publicKey, subjectRef: SUBJECT_REF, assurance: "biometric" });
    assert.equal(confirmed.hpkePublicKey, hpke.publicKey);
    assert.deepEqual(paths(run.requests), [`GET /v1/business/approve/enrollments/${UUID_1}`, `POST /v1/business/approve/enrollments/${UUID_1}/confirm`]);
    const sent = JSON.parse(run.requests[1]!.body!) as { confirmation: { kid: string; payload: string; signature: string } };
    assert.deepEqual({ ...verifyConfirmation(sent.confirmation, "approval-enrollment", confirmer.publicKey) }, { v: 1, type: "approval-enrollment-confirmation", business_id: BUSINESS_ID, subject_ref: SUBJECT_REF, enrollment_id: UUID_1, kid: device.kid, statement_digest: statementDigest(signed), confirm_kid: confirmer.kid, confirmed_at: Math.floor(NOW.getTime() / 1000) });
    // A relay answer that is not a key view is refused even after the confirmation was sent.
    await assert.rejects(c.confirmApprovalEnrollment({ invitation: inv, businessId: BUSINESS_ID, expectedSubjectRef: SUBJECT_REF, signer: confirmer.signer }), /not a ApprovalKeyView/);
    assert.equal(requests.length, 2);
  });

  it("a flawless statement from the relay's own key is refused: only the secret holder can bind it", async () => {
    const inv = invitation();
    const { signed } = await deviceStatement();
    // The relay made a key and a valid statement, and a tag under a secret it does not hold.
    const forged = client([{ status: 200, body: view({ device_statement: signed, binding_tag: new ApprovalEnrollmentSecret().bindingTag(signed) }) }, { status: 200, body: view({ status: "cancelled" }) }]);
    await assert.rejects(forged.c.confirmApprovalEnrollment({ invitation: inv, businessId: BUSINESS_ID, expectedSubjectRef: SUBJECT_REF, signer: confirmer.signer }), flow("binding_tag_invalid"));
    assert.deepEqual(paths(forged.requests), [`GET /v1/business/approve/enrollments/${UUID_1}`, `POST /v1/business/approve/enrollments/${UUID_1}/cancel`], "cancelled, never confirmed");
    // No tag and no SAS: nothing is signed and nothing is changed.
    const bare = client([{ status: 200, body: view({ device_statement: signed }) }]);
    await assert.rejects(bare.c.confirmApprovalEnrollment({ invitation: inv, businessId: BUSINESS_ID, expectedSubjectRef: SUBJECT_REF, signer: confirmer.signer }), flow("verification_required"));
    assert.equal(bare.requests.length, 1);
    // A wrong SAS is one guess: cancelled.
    const wrong = client([{ status: 200, body: view({ device_statement: signed }) }, { status: 200, body: view({ status: "cancelled" }) }]);
    const expected = inv.secret.expectedSas(signed);
    await assert.rejects(wrong.c.confirmApprovalEnrollment({ invitation: inv, businessId: BUSINESS_ID, expectedSubjectRef: SUBJECT_REF, sas: expected === "000000" ? "000001" : "000000", signer: confirmer.signer }), flow("sas_mismatch"));
    assert.equal(wrong.requests.length, 2);
    // The right SAS (typed path) confirms.
    const typed = client([{ status: 200, body: view({ device_statement: signed }) }, { status: 200, body: { kid: "k", subject_ref: SUBJECT_REF, status: "active", assurance: "biometric", public_key: "x", hpke_kid: "k", hpke_public_key: "x", created_at: TS, device_statement: signed } }]);
    await typed.c.confirmApprovalEnrollment({ invitation: inv, businessId: BUSINESS_ID, expectedSubjectRef: SUBJECT_REF, sas: `${expected.slice(0, 3)} ${expected.slice(3)}`, signer: confirmer.signer });
    assert.equal(typed.requests[1]!.method, "POST");
  });

  it("refuses a statement for another business, customer or enrollment, a weak key, and an enrollment that is not ready", async () => {
    const inv = invitation();
    const attempt = async (statement: { payload: string; signature: string }, over: Record<string, unknown> = {}, input: Record<string, unknown> = {}) => {
      const { c, requests } = client([{ status: 200, body: view({ device_statement: statement, binding_tag: inv.secret.bindingTag(statement), ...over }) }]);
      const promise = c.confirmApprovalEnrollment({ invitation: inv, businessId: BUSINESS_ID, expectedSubjectRef: SUBJECT_REF, signer: confirmer.signer, ...input });
      return { promise, requests };
    };
    const good = (await deviceStatement()).signed;
    await assert.rejects((await attempt(good, {}, { businessId: UUID_1 })).promise, statementError("wrong_business"));
    await assert.rejects((await attempt(good, {}, { expectedSubjectRef: "sub_" + "B".repeat(43) })).promise, statementError("wrong_subject"));
    await assert.rejects((await attempt((await deviceStatement({ enrollment_id: BUSINESS_ID })).signed)).promise, statementError("wrong_enrollment"));
    await assert.rejects((await attempt((await deviceStatement({ assurance: "presence" })).signed)).promise, statementError("assurance_too_low"));
    await (await attempt((await deviceStatement({ assurance: "presence" })).signed, {}, { minimumAssurance: "presence" })).promise.catch((e: unknown) => assert.ok(!(e instanceof StatementVerificationError)));
    await assert.rejects((await attempt((await deviceStatement({ assurance: "passcode" })).signed)).promise, statementError("malformed"));
    await assert.rejects((await attempt({ ...good, signature: (await deviceStatement()).signed.signature })).promise, statementError("bad_signature"));
    const open = await attempt(good, { status: "open" });
    await assert.rejects(open.promise, flow("not_ready"));
    assert.equal(open.requests.length, 1);
  });
});

describe("link sessions", () => {
  const request = { customer_ref: "cust-1042", capabilities: ["transaction.approve", "message.send"] as ("transaction.approve" | "message.send")[] };
  const ticket = (over: Record<string, unknown> = {}) => ({ session_id: UUID_1, code: CODE, link: `https://viadere.com/k/${CODE}`, root_kid: root.kid, expires_at: TS, ...over });
  const fresh = { rootKid: root.kid, customerAuthenticatedAt: new Date(NOW.getTime() - 60_000), now: NOW };

  it("needs a step-up within five minutes, before anything is sent", async () => {
    const { c, requests } = client([]);
    await assert.rejects(c.createLinkSession(request, { ...fresh, customerAuthenticatedAt: new Date(NOW.getTime() - 301_000) }), flow("step_up_required"));
    await assert.rejects(c.createLinkSession(request, { ...fresh, customerAuthenticatedAt: new Date(NOW.getTime() + 120_000) }), flow("step_up_required"));
    await assert.rejects(c.createLinkSession(request, { rootKid: root.kid } as never), flow("step_up_required"));
    await assert.rejects(c.createLinkSession({ ...request, capabilities: ["age.minimum" as never] }, fresh), ViadereValidationError);
    assert.equal(requests.length, 0);
  });

  it("builds the link with its own secret and refuses a ticket for another root or host", async () => {
    const { c, requests } = client([{ status: 201, body: ticket() }]);
    const inv = await c.createLinkSession(request, fresh);
    assert.equal(inv.link, `https://viadere.com/k/${CODE}#es=${inv.secret.base64url}`);
    assert.deepEqual(inv.capabilities, ["message.send", "transaction.approve"], "canonical order");
    assert.deepEqual(JSON.parse(requests[0]!.body!), request);
    for (const bad of [ticket({ root_kid: newKey().kid }), ticket({ link: `https://evil.example/k/${CODE}` }), ticket({ link: `https://viadere.com/k/${CODE}#es=${"A".repeat(43)}` }), ticket({ link: `https://viadere.com/k/ABCDEFGH` })]) {
      const r = client([{ status: 201, body: bad }, { status: 200, body: { session_id: UUID_1, status: "cancelled", capabilities: [], created_at: TS, expires_at: TS } }]);
      await assert.rejects(r.c.createLinkSession(request, fresh), flow("ticket_mismatch"));
      assert.equal(r.requests[1]!.url, `https://api.viadere.com/v1/business/link-sessions/${UUID_1}/cancel`);
    }
  });

  async function completed(over: { result?: Record<string, JsonValue>; statement?: Record<string, JsonValue>; resultSigner?: ReturnType<typeof newKey>; capabilities?: string[] } = {}) {
    const secret = new LinkSessionSecret();
    const capabilities = over.capabilities ?? ["message.send", "transaction.approve"];
    const invitation: LinkSessionInvitation = { sessionId: UUID_1, code: CODE, displayCode: "K7QF-M2XA", checkCode: secret.checkCode, rootKid: root.kid, secret, capabilities, expiresAt: TS, link: "" };
    const device = newKey();
    const approvalKey = newKey();
    const hpke = newKey();
    const needsApproval = capabilities.includes("transaction.approve");
    const approvalSigned = await signStatement({ v: 1, type: "approval-enrollment", business_id: BUSINESS_ID, subject_ref: SUBJECT_REF, enrollment_id: UUID_1, kid: approvalKey.kid, alg: "ES256", public_key: approvalKey.publicKey, hpke_kid: hpke.kid, hpke_public_key: hpke.publicKey, assurance: "biometric", created_at: 1_800_000_010 }, DOMAINS.approvalEnrollment, approvalKey.signer);
    const approvalStatement = { payload: approvalSigned.payload, signature: approvalSigned.signature };
    const s = await signStatement({ v: 1, type: "link-statement", session_id: UUID_1, business_id: BUSINESS_ID, subject_ref: SUBJECT_REF, capabilities, descriptor_digest: "d".repeat(64), kid: device.kid, public_key: device.publicKey, alg: "ES256", created_at: 1_800_000_011, ...(needsApproval ? { approval_statement_digest: statementDigest(approvalStatement) } : {}), ...over.statement }, DOMAINS.linkStatement, device.signer);
    const statement = { payload: s.payload, signature: s.signature };
    const signer = over.resultSigner ?? viadere;
    const result = await signStatement({ v: 1, type: "link-result", session_id: UUID_1, business_id: BUSINESS_ID, subject_ref: SUBJECT_REF, statement_digest: statementDigest(statement), completed_at: 1_800_000_012, signer_kid: signer.kid, ...(needsApproval ? { approval_statement_digest: statementDigest(approvalStatement) } : {}), ...over.result }, DOMAINS.linkResult, signer.signer);
    const view = { session_id: UUID_1, status: "device_completed", capabilities, created_at: TS, expires_at: TS, subject_ref: SUBJECT_REF, connection_id: SUBJECT_REF, statement, binding_tag: secret.bindingTag(statement), ...(needsApproval ? { approval_statement: approvalStatement } : {}), result };
    return { invitation, view, device, approvalKey, hpke, statement, approvalStatement };
  }
  const cancelled = { status: 200, body: { session_id: UUID_1, status: "cancelled", capabilities: [], created_at: TS, expires_at: TS } };

  it("reviews a completed session against pinned keys and its own records, then confirms with both confirmations", async () => {
    const s = await completed();
    const { c, requests } = client([{ status: 200, body: s.view }, { status: 200, body: { ...s.view, status: "confirmed" } }]);
    const review = await c.reviewLinkSession({ invitation: s.invitation, businessId: BUSINESS_ID, viadereKeys: [viadere.publicKey] });
    assert.equal(review.subjectRef, SUBJECT_REF);
    assert.equal(review.sas, s.invitation.secret.expectedSas(s.statement));
    assert.match(review.pseudonym, /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    assert.equal(review.hasBindingTag, true);
    const confirmed = await c.confirmLinkSession(review, { sasCheck: "compared_by_customer", signer: confirmer.signer, now: NOW });
    assert.equal(confirmed.connectionKid, s.device.kid);
    assert.deepEqual(confirmed.approval?.key, { kid: s.approvalKey.kid, publicKey: s.approvalKey.publicKey, subjectRef: SUBJECT_REF, assurance: "biometric" });
    assert.deepEqual(paths(requests), [`GET /v1/business/link-sessions/${UUID_1}`, `POST /v1/business/link-sessions/${UUID_1}/confirm`]);
    const body = JSON.parse(requests[1]!.body!) as { confirmation: never; approval_confirmation: never };
    const link = verifyConfirmation(body.confirmation, "link", confirmer.publicKey);
    assert.equal(link.verification, "sas_compared");
    assert.equal(link.statement_digest, statementDigest(s.statement));
    assert.equal(link.kid, s.device.kid);
    assert.equal(verifyConfirmation(body.approval_confirmation, "approval-enrollment", confirmer.publicKey).statement_digest, statementDigest(s.approvalStatement));
  });

  it("never confirms without a SAS check; a compared SAS needs the binding tag; a wrong typed SAS cancels", async () => {
    const s = await completed({ capabilities: ["message.send"] });
    const { binding_tag: _tag, ...typedPath } = s.view;
    const a = client([{ status: 200, body: typedPath }, cancelled]);
    const review = await a.c.reviewLinkSession({ invitation: s.invitation, businessId: BUSINESS_ID, viadereKeys: [viadere.publicKey] });
    assert.equal(review.hasBindingTag, false);
    assert.equal(review.approval, undefined);
    await assert.rejects(a.c.confirmLinkSession(review, { signer: confirmer.signer } as never), flow("sas_comparison_required"));
    await assert.rejects(a.c.confirmLinkSession(review, { sasCheck: "compared_by_customer", signer: confirmer.signer }), flow("typed_sas_required"));
    assert.equal(a.requests.length, 1);
    await assert.rejects(a.c.confirmLinkSession(review, { sasCheck: { typed: review.sas === "111111" ? "222222" : "111111" }, signer: confirmer.signer }), flow("sas_mismatch"));
    assert.equal(a.requests[1]!.url, `https://api.viadere.com/v1/business/link-sessions/${UUID_1}/cancel`);
    const b = client([{ status: 200, body: { ...typedPath, status: "confirmed" } }]);
    const confirmed = await b.c.confirmLinkSession(review, { sasCheck: { typed: review.sas }, signer: confirmer.signer });
    assert.equal(confirmed.approval, undefined);
    const sent = JSON.parse(b.requests[0]!.body!) as { confirmation: never; approval_confirmation?: never };
    assert.equal(verifyConfirmation(sent.confirmation, "link", confirmer.publicKey).verification, "sas_typed");
    assert.equal(sent.approval_confirmation, undefined);
  });

  it("refuses a result that is unpinned or about another statement, a swapped statement, extra capabilities and a wrong tag", async () => {
    const review = async (s: Awaited<ReturnType<typeof completed>>, view: Record<string, unknown> = s.view, script: Scripted[] = []) => {
      const { c, requests } = client([{ status: 200, body: view }, ...script]);
      return { promise: c.reviewLinkSession({ invitation: s.invitation, businessId: BUSINESS_ID, viadereKeys: [viadere.publicKey] }), requests };
    };
    // The relay signs the result with its own key.
    await assert.rejects((await review(await completed({ resultSigner: newKey() }))).promise, statementError("untrusted_signer"));
    // A genuine result about another statement.
    await assert.rejects((await review(await completed({ result: { statement_digest: "e".repeat(64) } }))).promise, statementError("statement_mismatch"));
    await assert.rejects((await review(await completed({ result: { business_id: UUID_1 } }))).promise, statementError("statement_mismatch"));
    // The statement names another account than the result.
    await assert.rejects((await review(await completed({ statement: { subject_ref: "sub_" + "B".repeat(42) + "A" } }))).promise, statementError("wrong_subject"));
    // The device linked more than you asked for.
    const more = await completed();
    more.invitation.capabilities = ["message.send"];
    await assert.rejects((await review(more)).promise, statementError("wrong_capabilities"));
    // The approval statement was dropped by the relay.
    const dropped = await completed();
    const { approval_statement: _a, ...withoutApproval } = dropped.view;
    await assert.rejects((await review(dropped, withoutApproval)).promise, statementError("statement_mismatch"));
    // A tag under another secret: cancelled.
    const s = await completed();
    const forged = await review(s, { ...s.view, binding_tag: new LinkSessionSecret().bindingTag(s.statement) }, [cancelled]);
    await assert.rejects(forged.promise, flow("binding_tag_invalid"));
    assert.equal(forged.requests.length, 2);
    const open = await review(s, { ...s.view, status: "open" });
    await assert.rejects(open.promise, flow("not_ready"));
  });
});

describe("verification sessions", () => {
  const request = { capability: "age.minimum" as const, parameters: { years: 21 }, purpose_code: "age_restricted_purchase", origin: "https://shop.northwind.example", return_url: "https://shop.northwind.example/checkout?step=2" };
  const ticket = (over: Record<string, unknown> = {}) => ({ session_id: UUID_1, code: CODE, link: `https://viadere.com/v/${CODE}`, expires_at: TS, ...over });
  const resultRef = "res_" + "R".repeat(43);
  const view = (over: Record<string, unknown> = {}) => ({ session_id: UUID_1, status: "completed", capability: "age.minimum", purpose_code: "age_restricted_purchase", origin: request.origin, created_at: TS, expires_at: TS, ...over });
  const signedResult = (over: Record<string, JsonValue> = {}, signer = viadere) =>
    signStatement({ v: 1, type: "verify-session-result", session_id: UUID_1, business_id: BUSINESS_ID, request_id: "req_" + "A".repeat(22), subject_ref: SUBJECT_REF, capability: "age.minimum", parameters: { years: 21 }, purpose_code: "age_restricted_purchase", origin: request.origin, outcome: "verified", result_ref_digest: sha256Hex(resultRef), completed_at: 1_800_000_200, signer_kid: signer.kid, ...over }, DOMAINS.verifySessionResult, signer.signer);
  const expected = { sessionId: UUID_1, businessId: BUSINESS_ID, origin: request.origin, capability: "age.minimum", viadereKeys: [viadere.publicKey] };

  it("creates a session and checks the relay's link before anything shows it", async () => {
    const { c, requests } = client([{ status: 201, body: ticket() }]);
    assert.equal((await c.createVerificationSession(request)).link, `https://viadere.com/v/${CODE}`);
    assert.deepEqual(JSON.parse(requests[0]!.body!), request);
    assert.equal(requests[0]!.headers["Idempotency-Key"], undefined);
    for (const bad of [ticket({ link: `https://evil.example/v/${CODE}` }), ticket({ link: `https://viadere.com/v/${CODE}?next=https://evil.example` }), ticket({ link: `https://viadere.com/k/${CODE}` }), ticket({ code: "ABCD-EFGH" })]) {
      const r = client([{ status: 201, body: bad }, { status: 200, body: view({ status: "cancelled" }) }]);
      await assert.rejects(r.c.createVerificationSession(request), flow("ticket_mismatch"));
      assert.equal(r.requests[1]!.url, `https://api.viadere.com/v1/business/verification-sessions/${UUID_1}/cancel`);
    }
  });

  it("trusts only a result it verified: pinned key, this session, business, origin, capability and result reference", async () => {
    const ok = client([{ status: 200, body: view({ result: await signedResult(), result_ref: resultRef, subject_ref: SUBJECT_REF }) }]);
    const verified = await ok.c.getVerifiedVerificationSession(expected);
    assert.deepEqual({ outcome: verified.outcome, subjectRef: verified.subjectRef, resultRef: verified.resultRef }, { outcome: "verified", subjectRef: SUBJECT_REF, resultRef });
    const no = client([{ status: 200, body: view({ result: await signedResult({ outcome: "not_verified" }), result_ref: resultRef }) }]);
    assert.equal((await no.c.getVerifiedVerificationSession(expected)).outcome, "not_verified");

    const refuse = async (body: Record<string, unknown>, check: (e: unknown) => boolean, input = expected) => assert.rejects(client([{ status: 200, body }]).c.getVerifiedVerificationSession(input), check);
    // The relay says "completed" with no signed result, or with one it signed itself.
    await refuse(view({ result_ref: resultRef }), flow("not_ready"));
    await refuse(view({ status: "accepted" }), flow("not_ready"));
    await refuse(view({ result: await signedResult({}, newKey()), result_ref: resultRef }), statementError("untrusted_signer"));
    // A genuine result of another session, business, origin or capability (a replay across sessions).
    await refuse(view({ result: await signedResult({ session_id: BUSINESS_ID }), result_ref: resultRef }), statementError("wrong_session"));
    await refuse(view({ result: await signedResult({ business_id: UUID_1 }), result_ref: resultRef }), statementError("wrong_business"));
    await refuse(view({ result: await signedResult({ origin: "https://evil.example" }), result_ref: resultRef }), statementError("wrong_origin"));
    await refuse(view({ result: await signedResult({ capability: "identity.name" }), result_ref: resultRef }), statementError("wrong_capability"));
    await refuse(view({ result: await signedResult(), result_ref: resultRef }), statementError("wrong_capability"), { ...expected, capability: "identity.verified" });
    // The result reference was swapped for another result's.
    await refuse(view({ result: await signedResult(), result_ref: "res_" + "S".repeat(43) }), flow("result_ref_mismatch"));
  });
});

describe("push approvals with number matching", () => {
  const keys = new AuthApprovalKeys(Buffer.alloc(32, 7));
  const requestView = (over: Record<string, unknown> = {}) => ({ request_id: "req-9", subject_ref: SUBJECT_REF, capability: "auth.challenge", status: "pending", protection: "server_visible", expires_at: new Date(Date.now() + 120_000).toISOString(), created_at: TS, delivered_to: 1, ...over });
  const draft = { requestId: "req-9", subjectRef: SUBJECT_REF, details: { authentication: { action_display: "Sign in to Example Bank" } }, sessionHandle: keys.sessionHandle("sess-1") };
  const stream = (hex: string) => {
    const bytes = Buffer.from(hex, "hex");
    let at = 0;
    return (n: number) => bytes.subarray(at, (at += n));
  };
  const conflict = (code: string) => ({ status: 409, body: { error: { code, message: "No." } } });

  it("draws the code, sends the tags and the code, and returns what the verifier needs", async () => {
    const { c, requests } = client([{ status: 201, body: requestView() }]);
    const created = await c.createAuthApproval(draft, { keys, requester: { clientAddress: "203.0.113.9" }, random: stream("0000"), now: NOW });
    assert.equal(created.code, "10");
    const body = JSON.parse(requests[0]!.body!) as Record<string, unknown>;
    assert.deepEqual(body, {
      request_id: "req-9", subject_ref: SUBJECT_REF, capability: "auth.challenge", risk: "medium", expires_in_seconds: 120, match_tag: keys.matchTags(SUBJECT_REF, "10")!.tag, session_handle: draft.sessionHandle,
      challenge: created.pending.challenge, authentication: { action_display: "Sign in to Example Bank", match_digits: 2 }, number_match: { digits: 2, code: "10" },
    });
    assert.match(requests[0]!.headers["Idempotency-Key"]!, /^authapproval-[0-9a-f]{32}$/);
    assert.match(created.pending.challenge, /^[A-Za-z0-9_-]{43}$/);
    assert.deepEqual(created.pending.numberMatch, { required: "10" });
    assert.deepEqual(created.pending.details, { authentication: { action_display: "Sign in to Example Bank", match_digits: 2 } });
    assert.equal(created.pending.expiresAt.getTime(), NOW.getTime() + 120_000);
    assert.equal(transactionDigest(created.pending.details), transactionDigest({ authentication: { action_display: "Sign in to Example Bank", match_digits: 2 } }));
  });

  it("redraws on match_code_in_use with a new key, switches to 3 digits on match_digits_required, and gives up cleanly", async () => {
    const { c, requests } = client([conflict("match_code_in_use"), conflict("match_digits_required"), { status: 201, body: requestView() }]);
    const created = await c.createAuthApproval(draft, { keys, random: stream("0000" + "ffef" + "0384") });
    assert.equal(created.code, "100");
    const bodies = requests.map((r) => JSON.parse(r.body!) as { number_match: { digits: number; code: string }; match_prefix_tag?: string; authentication: { match_digits: number } });
    assert.deepEqual(bodies.map((b) => b.number_match), [{ digits: 2, code: "10" }, { digits: 2, code: "99" }, { digits: 3, code: "100" }]);
    assert.equal(bodies[2]!.match_prefix_tag, keys.matchTags(SUBJECT_REF, "10")!.tag, "the prefix tag is the tag of the first two digits");
    assert.equal(bodies[2]!.authentication.match_digits, 3);
    assert.equal(new Set(requests.map((r) => r.headers["Idempotency-Key"])).size, 3, "a new key for every draw");
    assert.equal(new Set(bodies.map((b) => JSON.stringify(b.number_match))).size, 3);
    const exhausted = client([conflict("match_code_space_exhausted")], { throttle: false });
    await assert.rejects(exhausted.c.createAuthApproval(draft, { keys }), flow("no_free_code"));
    const always = client(Array.from({ length: 20 }, () => conflict("match_code_in_use")), { throttle: false });
    await assert.rejects(always.c.createAuthApproval(draft, { keys }), flow("no_free_code"));
    assert.equal(always.requests.length, 20);
    const other = client([conflict("approvals_paused")], { throttle: false });
    await assert.rejects(other.c.createAuthApproval(draft, { keys }), (e: unknown) => e instanceof ViadereApiError && e.code === "approvals_paused");
  });

  it("payments and high risk are 3 digits and end to end: the code goes to your envelope builder, never to Viadere in the clear", async () => {
    const none = client([]);
    const payment = { requestId: "req-9", subjectRef: SUBJECT_REF, details: { transaction: { currency: "USD", amount_minor: 250_000, payee_display: "Northwind Bank", transaction_reference: "INV-1" } } };
    await assert.rejects(none.c.createAuthApproval(payment, { keys }), flow("end_to_end_required"));
    await assert.rejects(none.c.createAuthApproval({ ...draft, risk: "high" }, { keys }), flow("end_to_end_required"));
    assert.equal(none.requests.length, 0);
    const envelope = { v: 1 as const, suite: "hpke-0010-0001-0002" as const, kid: "A".repeat(43), enc: "AA", ct: "AA", ctx: { exp: 1_800_000_000, purpose: "approve.request", recipient: "ak_x", request_id: "req-9", sender: "biz_x" } };
    let seen: { digits: number; code: string } | undefined;
    const { c, requests } = client([{ status: 201, body: requestView({ capability: "transaction.approve", protection: "end_to_end" }) }]);
    const created = await c.createAuthApproval(payment, { keys, random: stream("0384"), buildEnvelopes: (input) => ((seen = input.numberMatch), [{ kid: "A".repeat(43), envelope }]) });
    assert.deepEqual(seen, { digits: 3, code: "100" });
    const body = JSON.parse(requests[0]!.body!) as Record<string, unknown>;
    assert.deepEqual(body.number_match, { digits: 3 }, "no code in the clear");
    assert.equal(body.risk, "high", "a payment is never below high");
    assert.ok(!("challenge" in body) && !("transaction" in body) && !requests[0]!.body!.includes('"100"'));
    assert.equal(created.code, "100");
  });

  it("the per-requester throttle runs first and frees the slot when the request ends or the call fails", async () => {
    const ok = () => ({ status: 201, body: requestView() });
    const { c, requests } = client([ok(), ok(), ok(), { status: 200, body: requestView({ status: "approved", result_ref: "apr_1" }) }, ok()]);
    const at = { keys, requester: { clientAddress: "203.0.113.9" } };
    for (let i = 0; i < 3; i++) await c.createAuthApproval({ ...draft, requestId: `req-${i}` }, at);
    await assert.rejects(c.createAuthApproval({ ...draft, requestId: "req-3" }, at), ViadereThrottledError);
    assert.equal(requests.length, 3, "refused locally");
    await c.getAuthApproval("req-0"); // decided: the slot is free again
    await c.createAuthApproval({ ...draft, requestId: "req-3" }, at);
    const failing = client([{ status: 404, body: { error: { code: "not_deliverable", message: "No." } } }, { status: 404, body: { error: { code: "not_deliverable", message: "No." } } }, { status: 404, body: { error: { code: "not_deliverable", message: "No." } } }, { status: 404, body: { error: { code: "not_deliverable", message: "No." } } }]);
    for (let i = 0; i < 4; i++) await assert.rejects(failing.c.createAuthApproval(draft, at), ViadereApiError);
    assert.equal(failing.requests.length, 4, "a failed call does not hold a slot");
    await assert.rejects(c.createAuthApproval(draft, {} as never), TypeError);
  });

  it("end to end with the verifier: the created request's pending record verifies the device's signed result, once", async () => {
    const { c } = client([{ status: 201, body: requestView() }], { throttle: false });
    const created = await c.createAuthApproval(draft, { keys, random: stream("0000") });
    const device = newKey();
    const header = { alg: "ES256", kid: device.kid, typ: "viadere-approval+jws" };
    const iat = Math.floor(Date.now() / 1000);
    const claims = (match: string): Record<string, JsonValue> => ({ v: 2, alg: "ES256", kid: device.kid, aud: BUSINESS_ID, sub: SUBJECT_REF, request_id: "req-9", challenge: created.pending.challenge, cap: "auth.challenge", decision: "approve", amr: "biometric", iat, exp: iat + 300, txn_digest: transactionDigest(created.pending.details), jti: Buffer.alloc(16, 9).toString("base64url"), match });
    const jws = async (payload: Record<string, JsonValue>) => {
      const input = `${Buffer.from(canonicalJson(header)).toString("base64url")}.${Buffer.from(canonicalJson(payload)).toString("base64url")}`;
      return `${input}.${(await signEs256(device.signer, Buffer.from(input))).signature}`;
    };
    const store = new InMemoryApprovalKeyStore();
    store.add({ kid: device.kid, publicKey: device.publicKey, subjectRef: SUBJECT_REF, assurance: "biometric" });
    const verifier = new ApprovalVerifier({ businessId: BUSINESS_ID, keys: store, replayGuard: new InMemoryReplayGuard() });
    await assert.rejects(verifier.verify(await jws(claims("11")), created.pending), (e: unknown) => (e as { code?: string }).code === "number_mismatch");
    assert.equal((await verifier.verify(await jws(claims(created.code)), created.pending)).decision, "approve");
    await assert.rejects(verifier.verify(await jws(claims(created.code)), created.pending), (e: unknown) => (e as { code?: string }).code === "replayed");
  });
});
