import assert from "node:assert/strict";
import { createHash, createPrivateKey } from "node:crypto";
import { describe, it } from "node:test";
import {
  MESSAGE_ATTACHMENT_MAX_UPLOAD_BYTES,
  ViadereApiError,
  ViadereClient,
  ViadereSdkError,
  ViadereValidationError,
  attachmentPrecheck,
  p256PublicKeyOf,
  requestContentDigest,
  softwareSigner,
  verifyHttpSignature,
  type MessageAttachment,
  type RequestSigningKey,
} from "../src/index.js";
import { API_KEY, SUBJECT_REF, UUID_1, UUID_2, readRepoJson, scriptedFetch, type Scripted } from "./helpers.js";

// Message attachments (SECURITY.md section 2.113): uploads are checked before they are sent and never retried, the raw body is what the RFC 9421
// signature digests, downloads are returned only when they match their reference, and message ids are checked locally.

const SESSION = "6f1e2d3c-4b5a-4968-8776-655443322110";
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...Buffer.from("IHDR fake image body")]);
const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, ...Buffer.from("fake jpeg")]);

function reference(bytes: Uint8Array, overrides: Partial<MessageAttachment> = {}): MessageAttachment {
  return { id: UUID_1, sessionId: SESSION, mediaType: "image/png", byteSize: bytes.length, width: 4, height: 3,
           sha256: createHash("sha256").update(bytes).digest("hex"), state: "pending", expiresAt: "2027-01-15T09:00:00.000Z", ...overrides };
}

function client(script: Scripted[], extra: Partial<ConstructorParameters<typeof ViadereClient>[0]> = {}) {
  const { fetchFn, requests } = scriptedFetch(script);
  const sleeps: number[] = [];
  const c = new ViadereClient({ apiKey: API_KEY, fetch: fetchFn, sleep: async (s) => void sleeps.push(s), random: () => 1, ...extra });
  return { c, requests, sleeps };
}

describe("message attachments: upload", () => {
  it("sends the raw image with its type, no JSON and no idempotency key", async () => {
    const stored = reference(JPEG, { mediaType: "image/jpeg" });
    const { c, requests } = client([{ status: 201, body: stored }]);
    assert.deepEqual(await c.uploadAttachment(SESSION.toUpperCase(), PNG, "image/png"), stored);
    const r = requests[0]!;
    assert.equal(r.method, "POST");
    assert.equal(r.url, `https://api.viadere.com/v1/business/conversations/${SESSION}/attachments`);
    assert.deepEqual(r.bytes, PNG, "the bytes travel as they are");
    assert.equal(r.body, undefined);
    assert.equal(r.headers["Content-Type"], "image/png");
    assert.equal(r.headers.Authorization, `Bearer ${API_KEY}`);
    assert.equal(r.headers["Idempotency-Key"], undefined);
    assert.equal(r.redirect, "manual");
  });

  it("is never retried: the route takes no idempotency key", async () => {
    for (const first of [{ status: 503, body: { error: { code: "unavailable", message: "Try later." } } }, new Error("socket hang up")] as Scripted[]) {
      const { c, requests, sleeps } = client([first, { status: 201, body: reference(PNG) }]);
      await assert.rejects(c.uploadAttachment(SESSION, PNG, "image/png"), (e: unknown) => e instanceof ViadereApiError || (e instanceof ViadereSdkError && e.kind === "transport"));
      assert.equal(requests.length, 1);
      assert.deepEqual(sleeps, []);
    }
  });

  it("refuses what the server's precheck would refuse, before anything is sent", async () => {
    const cases: [Uint8Array, string, string, string][] = [
      [new Uint8Array(0), "image/png", "(body)", "required"],
      [new Uint8Array(MESSAGE_ATTACHMENT_MAX_UPLOAD_BYTES + 1).fill(0x89), "image/png", "(body)", "too_large"],
      [JPEG, "image/png", "contentType", "content_type_mismatch"],
      [PNG, "image/jpeg", "contentType", "content_type_mismatch"],
      [new Uint8Array(Buffer.from("GIF89a....")), "image/png", "(body)", "unsupported_format"],
      [new Uint8Array(Buffer.from("<svg xmlns='http://www.w3.org/2000/svg'/>")), "image/png", "(body)", "unsupported_format"],
      [PNG, "image/gif", "contentType", "unsupported_format"],
      [PNG, "application/json", "contentType", "unsupported_format"],
    ];
    for (const [bytes, type, field, code] of cases) {
      const { c, requests } = client([]);
      await assert.rejects(c.uploadAttachment(SESSION, bytes, type), (e: unknown) => e instanceof ViadereValidationError && e.details[0]?.field === field && e.details[0]?.code === code, `${type} ${code}`);
      assert.equal(requests.length, 0);
    }
    await assert.rejects(client([]).c.uploadAttachment("../x", PNG, "image/png"), (e: unknown) => e instanceof ViadereSdkError && e.kind === "invalid_path");
    // Exactly the cap is sent; a type with parameters is sent bare.
    const atCap = new Uint8Array(MESSAGE_ATTACHMENT_MAX_UPLOAD_BYTES);
    atCap.set(PNG);
    assert.equal(attachmentPrecheck(atCap, "image/png"), undefined);
    const { c, requests } = client([{ status: 201, body: reference(PNG) }]);
    await c.uploadAttachment(SESSION, atCap, "Image/PNG; charset=binary");
    assert.equal(requests[0]!.bytes!.length, MESSAGE_ATTACHMENT_MAX_UPLOAD_BYTES);
    assert.equal(requests[0]!.headers["Content-Type"], "image/png");
  });

  it("refuses an answer that is not an attachment of this conversation", async () => {
    await assert.rejects(client([{ status: 201, body: reference(PNG, { sessionId: UUID_2 }) }]).c.uploadAttachment(SESSION, PNG, "image/png"),
                         (e: unknown) => e instanceof ViadereSdkError && e.kind === "attachment_mismatch");
    await assert.rejects(client([{ status: 201, body: { id: UUID_1 } }]).c.uploadAttachment(SESSION, PNG, "image/png"),
                         (e: unknown) => e instanceof ViadereSdkError && e.kind === "invalid_response");
  });

  it("a signed upload digests the raw bytes, keeps the image type, and the profile verifies it (vectors' key)", async () => {
    const vectors = readRepoJson<{ now: number; signer_private_key_hex: string }>("docs/protocol/vectors/http-signatures-v1.json");
    const prefix = Buffer.from("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420", "hex");
    const privateKey = createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(vectors.signer_private_key_hex, "hex")]), format: "der", type: "pkcs8" });
    const signer: RequestSigningKey = { keyId: "vsk_0123456789abcdef", ...softwareSigner(privateKey) };
    const { c, requests } = client([{ status: 201, body: reference(PNG) }], { requestSigner: signer, now: () => vectors.now });
    await c.uploadAttachment(SESSION, PNG, "image/png");
    const r = requests[0]!;
    assert.equal(r.headers["Content-Digest"], requestContentDigest(PNG));
    assert.equal(r.headers["Content-Type"], "image/png");
    assert.match(r.headers["Signature-Input"]!, /"content-digest" "content-type"\)/);
    const url = new URL(r.url);
    const verify = (body: Uint8Array, type: string) => verifyHttpSignature(
      { method: "POST", target: url.pathname, headers: Object.entries({ ...r.headers, "Content-Type": type }), body },
      { now: vectors.now, authorities: ["api.viadere.com"], businessId: "b", apiKeyId: "k",
        resolveKey: () => ({ publicKey: p256PublicKeyOf(privateKey).base64url, businessId: "b", apiKeyId: "k", revoked: false }), registerNonce: () => true });
    assert.equal(await verify(PNG, "image/png"), "vsk_0123456789abcdef");
    const tampered = new Uint8Array(PNG);
    tampered[tampered.length - 1]! ^= 1;
    await assert.rejects(verify(tampered, "image/png"), "a changed image does not verify");
    await assert.rejects(verify(PNG, "image/jpeg"), "a relabelled image does not verify");
  });
});

describe("message attachments: download", () => {
  it("returns the bytes only when they match the reference", async () => {
    const ref = reference(PNG, { state: "attached" });
    const { c, requests } = client([{ status: 200, bytes: PNG, headers: { "Content-Type": "image/png" } }]);
    assert.deepEqual(await c.downloadAttachment(ref), PNG);
    const r = requests[0]!;
    assert.equal(r.method, "GET");
    assert.equal(r.url, `https://api.viadere.com/v1/business/conversations/${SESSION}/attachments/${UUID_1}`);
    assert.equal(r.headers.Accept, "image/png, image/jpeg");
    assert.equal(r.bytes, undefined);
    assert.equal(r.body, undefined);
  });

  it("discards a download that does not match (digest, size, another image, a dangerous type)", async () => {
    const ref = reference(PNG, { state: "attached" });
    const flipped = new Uint8Array(PNG);
    flipped[3]! ^= 0x20;
    const bad: Scripted[] = [
      { status: 200, bytes: flipped, headers: { "Content-Type": "image/png" } },
      { status: 200, bytes: new Uint8Array([...PNG, 0]), headers: { "Content-Type": "image/png" } },
      { status: 200, bytes: JPEG, headers: { "Content-Type": "image/png" } },
      { status: 200, bytes: PNG, headers: { "Content-Type": "text/html" } },
    ];
    for (const response of bad) {
      await assert.rejects(client([response]).c.downloadAttachment(ref), (e: unknown) => e instanceof ViadereSdkError && e.kind === "attachment_mismatch");
    }
  });

  it("is retried like every GET", async () => {
    const ref = reference(JPEG, { mediaType: "image/jpeg", state: "attached" });
    const { c, requests } = client([{ status: 503, body: { error: { code: "unavailable", message: "Try later." } } }, { status: 200, bytes: JPEG, headers: { "Content-Type": "image/jpeg" } }]);
    assert.deepEqual(await c.downloadAttachment(ref), JPEG);
    assert.equal(requests.length, 2);
  });

  it("refuses a reference that cannot be checked", async () => {
    for (const ref of [reference(PNG, { sha256: "ABC" }), reference(PNG, { byteSize: 0 }), reference(PNG, { mediaType: "image/gif" as "image/png" }), reference(PNG, { id: "../x" })]) {
      const { c, requests } = client([]);
      await assert.rejects(c.downloadAttachment(ref), (e: unknown) => e instanceof ViadereValidationError);
      assert.equal(requests.length, 0);
    }
  });
});

describe("message attachments: sending", () => {
  const message = { id: UUID_2, sessionId: SESSION, businessId: UUID_1, direction: "businessToConsumer", attribution: { senderType: "business", displayName: "Shop" },
                    body: "", channel: "inApp", createdAt: "2027-01-15T08:00:00.000Z", deliveryStatus: "queued", attachments: [reference(PNG, { state: "attached" })] };

  it("a message names its images with their conversation, and may have no text", async () => {
    const { c, requests } = client([{ status: 201, body: message }]);
    const sent = await c.sendMessage({ subjectRef: SUBJECT_REF, sessionId: SESSION, body: "", idempotencyKey: "msg-1", attachmentIds: [UUID_1] });
    assert.equal(sent.value.attachments?.[0]?.id, UUID_1);
    assert.deepEqual(JSON.parse(requests[0]!.body!), { subjectRef: SUBJECT_REF, sessionId: SESSION, body: "", idempotencyKey: "msg-1", attachmentIds: [UUID_1] });
    assert.equal(requests[0]!.headers["Idempotency-Key"], "msg-1");
  });

  it("ids that cannot be sent are refused locally", async () => {
    const base = { subjectRef: SUBJECT_REF, body: "Here", idempotencyKey: "m" };
    const cases: [Record<string, unknown>, string, string][] = [
      [{ ...base, attachmentIds: [UUID_1] }, "sessionId", "required"],
      [{ ...base, sessionId: SESSION, attachmentIds: [] }, "attachmentIds", "invalid_length"],
      [{ ...base, sessionId: SESSION, attachmentIds: [UUID_1, UUID_1] }, "attachmentIds", "duplicate"],
      [{ ...base, sessionId: SESSION, attachmentIds: [UUID_1, UUID_2, SESSION, "a0e9c2b5-3f41-4d6a-9b7c-0d1e2f3a4b5c", "b0e9c2b5-3f41-4d6a-9b7c-0d1e2f3a4b5c"] }, "attachmentIds", "invalid_length"],
      [{ ...base, sessionId: SESSION, attachmentIds: ["not-a-uuid"] }, "attachmentIds[0]", "invalid_format"],
      [{ ...base, body: "" }, "body", "required"],
    ];
    for (const [request, field, code] of cases) {
      const { c, requests } = client([]);
      await assert.rejects(c.sendMessage(request as never), (e: unknown) => e instanceof ViadereValidationError && e.details.some((d) => d.field === field && d.code === code), `${field} ${code}`);
      assert.equal(requests.length, 0);
    }
  });
});
