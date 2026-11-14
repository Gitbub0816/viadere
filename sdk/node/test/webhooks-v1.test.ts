import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { describe, it } from "node:test";
import { WebhookVerificationError, WebhookVerifier, WebhookVerifierV1, signatureHeader, signatureHeaderV1, contentDigest, typedWebhookEvent, verifySignatureV1 } from "../src/index.js";
import { BUSINESS_ID, SUBJECT_REF, UUID_1, UUID_2 } from "./helpers.js";

// Signature v1 has no shared vector file in `docs/protocol/vectors/`: these tests pin the documented construction
// (`hex HMAC-SHA256(secret, "<t>." + raw body)`, the key being the UTF-8 bytes of the whole `whsec_...` string) with an independent computation.

const SECRET = "whsec_" + "a".repeat(43);
const OLD_SECRET = "whsec_" + "b".repeat(43);
const NOW = 1_800_000_000;
const rejects = (code: string) => (e: unknown) => e instanceof WebhookVerificationError && e.code === code;

function event(type: string, data: unknown, id = UUID_1) {
  return JSON.stringify({ id, type, createdAt: "2027-01-15T08:00:00.000Z", businessId: BUSINESS_ID, apiVersion: "2026-10-27", data });
}
function request(body: string, secrets = [SECRET], extra: Record<string, string> = {}, at = NOW) {
  return { headers: { "viadere-signature": signatureHeaderV1(secrets, Buffer.from(body), at), ...extra }, body };
}
function verifier(options: Partial<ConstructorParameters<typeof WebhookVerifierV1>[0]> = {}) {
  return new WebhookVerifierV1({ secrets: [SECRET], now: () => NOW * 1000, ...options });
}
const outcome = { interactionId: UUID_2, businessId: BUSINESS_ID, status: "approved", decision: "approve" };

describe("webhook signature v1", () => {
  it("is hex HMAC-SHA256(secret, t + '.' + raw body)", () => {
    const body = Buffer.from('{"a":1}');
    const expected = createHmac("sha256", SECRET).update(`${NOW}.{"a":1}`).digest("hex");
    assert.equal(signatureHeaderV1([SECRET], body, NOW), `t=${NOW},v1=${expected}`);
    assert.deepEqual(verifySignatureV1({ header: `t=${NOW},v1=${expected}`, body, secrets: [SECRET], nowSeconds: NOW }), { timestamp: NOW, secret: SECRET });
  });

  it("verifies an event, with either secret during a rotation, and reports the matched delivery headers", async () => {
    const body = event("interaction.decided", outcome);
    const verified = await verifier().verify(request(body, [SECRET], { "Viadere-Event-Id": UUID_1.toUpperCase(), "Viadere-Event-Type": "interaction.decided", "Viadere-Delivery-Id": "dlv_1", "Viadere-Key-Id": "whk_1a2b3c4d_v2" }));
    assert.equal(verified.event.type, "interaction.decided");
    assert.equal(verified.timestamp, NOW);
    assert.equal(verified.deliveryId, "dlv_1");
    assert.equal(verified.keyId, "whk_1a2b3c4d_v2");
    // Viadere signs with the new and the old secret during a rotation; a receiver that still holds only the old one keeps verifying.
    await verifier({ secrets: [OLD_SECRET] }).verify(request(body, [SECRET, OLD_SECRET]));
    await verifier({ secrets: [SECRET, OLD_SECRET] }).verify(request(body, [OLD_SECRET]));
  });

  it("rejects a wrong secret, a changed body, a stale or future timestamp and a malformed header", async () => {
    const body = event("interaction.decided", outcome);
    await assert.rejects(verifier({ secrets: [OLD_SECRET] }).verify(request(body)), rejects("no_matching_signature"));
    await assert.rejects(verifier().verify({ ...request(body), body: body.replace("approved", "denied") }), rejects("no_matching_signature"));
    await assert.rejects(verifier().verify(request(body, [SECRET], {}, NOW - 301)), rejects("timestamp_outside_tolerance"));
    await assert.rejects(verifier().verify(request(body, [SECRET], {}, NOW + 301)), rejects("timestamp_outside_tolerance"));
    await verifier().verify(request(body, [SECRET], {}, NOW - 300));
    await assert.rejects(verifier({ toleranceSeconds: 10 }).verify(request(body, [SECRET], {}, NOW - 11)), rejects("timestamp_outside_tolerance"));
    await assert.rejects(verifier({ toleranceSeconds: 86_400 }).verify(request(body, [SECRET], {}, NOW - 301)), rejects("timestamp_outside_tolerance"), "the tolerance is capped at 300 s");
    await assert.rejects(verifier().verify({ headers: {}, body }), rejects("missing_header"));
    const good = signatureHeaderV1([SECRET], Buffer.from(body), NOW);
    for (const header of ["", "t=1", `v1=${"0".repeat(64)}`, `t=${NOW},v1=abc`, `t=${NOW},t=${NOW},${good.split(",")[1]}`, `${good},junk`, `t=${NOW}x,${good.split(",")[1]}`, good + "\nx=1"]) {
      await assert.rejects(verifier().verify({ headers: { "Viadere-Signature": header }, body }), rejects("malformed_signature"), header);
    }
    // A v2-only header is not a v1 signature; an unknown scheme next to a valid v1 is ignored.
    await assert.rejects(verifier().verify({ headers: { "Viadere-Signature": `t=${NOW},v2=whk_a_v1:${"A".repeat(43)}` }, body }), rejects("malformed_signature"));
    await verifier().verify({ headers: { "Viadere-Signature": `${good},v9=whatever` }, body });
  });

  it("requires the unsigned headers to agree with the signed body, and a well-formed event", async () => {
    const body = event("interaction.decided", outcome);
    await assert.rejects(verifier().verify(request(body, [SECRET], { "Viadere-Event-Id": UUID_2 })), rejects("header_body_mismatch"));
    await assert.rejects(verifier().verify(request(body, [SECRET], { "Viadere-Event-Type": "interaction.expired" })), rejects("header_body_mismatch"));
    for (const bad of ["not json", "[]", JSON.stringify({ id: UUID_1, type: "x" }), event("interaction.decided", outcome, "not-a-uuid")]) {
      await assert.rejects(verifier().verify(request(bad)), rejects("malformed_body"), bad);
    }
  });

  it("dedupes by event id by default, only after a delivery verified", async () => {
    const v = verifier();
    const body = event("interaction.decided", outcome);
    await assert.rejects(v.verify({ headers: { "Viadere-Signature": signatureHeaderV1([OLD_SECRET], Buffer.from(body), NOW) }, body }), rejects("no_matching_signature"));
    await v.verify(request(body));
    await assert.rejects(v.verify(request(body)), (e: unknown) => e instanceof WebhookVerificationError && e.code === "duplicate_event" && e.status === 200);
    const off = verifier({ replayStore: "disabled" });
    await off.verify(request(body));
    await off.verify(request(body));
  });

  it("never prints a secret and needs at least one", () => {
    assert.equal(String(verifier()), "WebhookVerifierV1(1 secret(s))");
    assert.ok(!JSON.stringify({ v: verifier() }).includes("whsec_"));
    assert.throws(() => new WebhookVerifierV1({ secrets: [] }), RangeError);
    assert.throws(() => new WebhookVerifierV1({ secrets: [""] }), RangeError);
  });

  it("answers the endpoint-ownership challenge with an HMAC, never an echo", () => {
    const body = JSON.stringify({ type: "webhook.verification", challenge: "c-123" });
    const answer = JSON.parse(verifier({ secrets: [OLD_SECRET, SECRET] }).verificationResponse(request(body, [SECRET], { "Viadere-Event-Type": "webhook.verification" }))) as { challenge_response: string };
    assert.equal(answer.challenge_response, createHmac("sha256", SECRET).update("viadere.webhook.verification.v1:c-123").digest("hex"));
    assert.notEqual(answer.challenge_response, "c-123");
    assert.throws(() => verifier({ secrets: [OLD_SECRET] }).verificationResponse(request(body)), rejects("no_matching_signature"));
    assert.throws(() => verifier().verificationResponse(request(event("interaction.decided", outcome))), rejects("not_a_verification_request"));
    assert.throws(() => verifier().verificationResponse(request(JSON.stringify({ type: "webhook.verification", challenge: "" }))), rejects("not_a_verification_request"));
    assert.throws(() => verifier().verificationResponse(request(body, [SECRET], { "Viadere-Event-Type": "interaction.decided" })), rejects("header_body_mismatch"));
    assert.throws(() => verifier().verificationResponse(request(body, [SECRET], {}, NOW - 400)), rejects("timestamp_outside_tolerance"));
  });
});

describe("typed events", () => {
  const parse = (type: string, data: unknown) => typedWebhookEvent(JSON.parse(event(type, data)));
  it("decodes the data of each known type and passes unknown types through", () => {
    assert.deepEqual(parse("interaction.decided", outcome), { type: "interaction.decided", data: outcome });
    const message = { sessionId: UUID_1, relationshipId: UUID_2, subjectRef: SUBJECT_REF, messageId: UUID_1, text: "hi", channel: "sms", receivedAt: "2027-01-15T08:00:00.000Z" };
    assert.equal(parse("message.received", message).type, "message.received");
    assert.equal(parse("relationship.connected", { relationshipId: UUID_1, occurredAt: "2027-01-15T08:00:00.000Z", publicName: "Sam P." }).type, "relationship.connected");
    assert.equal(parse("consent.updated", { relationshipId: UUID_1, purpose: "marketing", granted: false, occurredAt: "2027-01-15T08:00:00.000Z" }).type, "consent.updated");
    assert.equal(parse("verification.completed", { request_id: "req_" + "A".repeat(22), result_ref: "res_" + "B".repeat(43) }).type, "verification.completed");
    assert.equal(parse("profile.access_revoked", { subjectRef: SUBJECT_REF, fieldKeys: ["email"], occurredAt: "2027-01-15T08:00:00.000Z" }).type, "profile.access_revoked");
    assert.deepEqual(parse("webhook.test", {}), { type: "other", eventType: "webhook.test", data: {} });
    assert.deepEqual(parse("something.new", 5), { type: "other", eventType: "something.new", data: 5 });
  });
  it("refuses data that lacks a required member or carries an extra one where the schema is closed", () => {
    assert.throws(() => parse("message.received", { text: "hi" }), rejects("malformed_body"));
    assert.throws(() => parse("interaction.decided", { status: "approved" }), rejects("malformed_body"));
    assert.throws(() => parse("verification.completed", { request_id: "req_" + "A".repeat(22), result_ref: "res_" + "B".repeat(43), outcome: "verified" }), rejects("malformed_body"));
    assert.equal(parse("constructor", {}).type, "other", "a type named like an Object.prototype member is just an unknown type");
  });
});

describe("the opaque envelope (approve.*, link.*, verification.completed)", () => {
  const envelope = (over: Record<string, unknown> = {}) => JSON.stringify({ id: "evt_1", type: "approve.request.decided", version: "2026-10-27", tenant_id: "ten_1", request_id: "req_1", occurred_at: "2027-01-15T08:00:00.000Z", result_ref: "apr_1", ...over });

  it("signature v1: strict members, version and header agreement", async () => {
    const verified = await verifier().verifyEnvelope(request(envelope(), [SECRET], { "Viadere-Event-Id": "evt_1", "Viadere-Event-Type": "approve.request.decided", "Viadere-Webhook-Version": "2026-10-27" }));
    assert.equal(verified.envelope.result_ref, "apr_1");
    await assert.rejects(verifier().verifyEnvelope(request(envelope({ status: "approved" }))), rejects("malformed_body"));
    await assert.rejects(verifier().verifyEnvelope(request(envelope({ version: "2025-01-01" }))), rejects("malformed_body"));
    await assert.rejects(verifier().verifyEnvelope(request(envelope(), [SECRET], { "Viadere-Event-Id": "evt_2" })), rejects("header_body_mismatch"));
    await assert.rejects(verifier().verifyEnvelope(request(envelope(), [OLD_SECRET])), rejects("no_matching_signature"));
    const v = verifier();
    await v.verifyEnvelope(request(envelope()));
    await assert.rejects(v.verifyEnvelope(request(envelope())), rejects("duplicate_event"));
  });

  it("signature v2: the envelope id is the signed event id and the tenant is yours", async () => {
    const keys = { whk_1a2b3c4d_v1: "s3cret" };
    const v2 = () => new WebhookVerifier({ endpoint: "https://hooks.example.com/viadere", tenantId: "ten_1", keys, now: () => NOW * 1000 });
    const send = (body: string, eventId = "evt_1") => {
      const bytes = Buffer.from(body);
      const context = { method: "POST", host: "hooks.example.com", pathAndQuery: "/viadere", eventId, tenantId: "ten_1" };
      return { headers: { "Viadere-Signature": signatureHeader([{ kid: "whk_1a2b3c4d_v1", secret: "s3cret" }], context, bytes, NOW)!, "Viadere-Event-Id": eventId, "Viadere-Tenant": "ten_1", "Content-Digest": contentDigest(bytes) }, body };
    };
    const verified = await v2().verifyOpaqueEnvelope(send(envelope({ type: "verification.completed", result_ref: "res_" + "B".repeat(43) })));
    assert.equal(verified.envelope.type, "verification.completed");
    await assert.rejects(v2().verifyOpaqueEnvelope(send(envelope(), "evt_2")), rejects("header_body_mismatch"));
    await assert.rejects(v2().verifyOpaqueEnvelope(send(envelope({ tenant_id: "ten_2" }))), rejects("header_body_mismatch"));
    await assert.rejects(v2().verifyOpaqueEnvelope(send(envelope({ amount: 5 }))), rejects("malformed_body"));
    // The auth-delivery decoder stays strict about its own event family.
    await assert.rejects(v2().verifyEnvelope(send(envelope())), rejects("malformed_body"));
  });
});
