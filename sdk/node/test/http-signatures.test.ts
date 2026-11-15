import assert from "node:assert/strict";
import { createPrivateKey, generateKeyPairSync } from "node:crypto";
import { describe, it } from "node:test";
import {
  HttpSignatureError,
  ViadereClient,
  ViadereSdkError,
  p256PublicKeyOf,
  signRequest,
  signingKeyProof,
  softwareSigner,
  verifyHttpSignature,
  type RequestSigningKey,
  type SignedRequest,
} from "../src/index.js";
import { API_KEY, DELIVERY_ID, readRepoJson, scriptedFetch, view } from "./helpers.js";

// RFC 9421 request signatures, Viadere profile (docs/SECURITY.md section 2.112), against the cross-language vectors generated independently in
// Python (docs/protocol/vectors/http-signatures-v1.json): positive cases byte for byte, every refusal with its code.

interface VRequest { method: string; path_and_query: string; headers: [string, string][]; body: string }
interface VPresenter { business_id: string; api_key_id: string }
interface VCase {
  name: string; request: VRequest; presenter: VPresenter; expected_error?: string; used_nonces?: { scope: string; nonce: string }[];
  signature_base?: string; signature_input?: string; signature?: string; content_digest?: string | null; signature_raw_b64url?: string;
  keyid?: string; nonce?: string; created?: number;
}
interface Vectors {
  now: number; accepted_authorities: string[]; signer_private_key_hex: string;
  keys: { keyid: string; public_key: string; business_id: string; api_key_id: string; revoked: boolean }[];
  positive: VCase[]; negative: VCase[];
}

const vectors = readRepoJson<Vectors>("docs/protocol/vectors/http-signatures-v1.json");
const vectorKey = vectors.keys[0]!;

function signed(r: VRequest): SignedRequest {
  return { method: r.method, target: r.path_and_query, headers: r.headers, body: Buffer.from(r.body, "utf8") };
}

async function run(c: VCase, used = new Set<string>()): Promise<string> {
  return verifyHttpSignature(signed(c.request), {
    now: vectors.now,
    authorities: vectors.accepted_authorities,
    businessId: c.presenter.business_id,
    apiKeyId: c.presenter.api_key_id,
    resolveKey: (id) => {
      const k = vectors.keys.find((x) => x.keyid === id);
      return k && { publicKey: k.public_key, businessId: k.business_id, apiKeyId: k.api_key_id, revoked: k.revoked };
    },
    registerNonce: (scope, nonce) => {
      const key = scope + "|" + nonce;
      if (used.has(key)) return false;
      used.add(key);
      return true;
    },
  });
}

/** A signer that returns the vector's deterministic (RFC 6979) signature bytes, so the header values must match exactly. */
function fixedSigner(raw: string, keyId: string): RequestSigningKey {
  return { keyId, publicKey: vectorKey.public_key, sign: () => new Uint8Array(Buffer.from(raw, "base64url")) };
}

function vectorPrivateKey() {
  // PKCS#8 for a raw P-256 scalar: the fixed SEC1 wrapper, then the 32 bytes.
  const prefix = Buffer.from("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420", "hex");
  return createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(vectors.signer_private_key_hex, "hex")]), format: "der", type: "pkcs8" });
}

describe("RFC 9421 request signatures: vectors", () => {
  it("there is a vector for every refusal and every positive case verifies", async () => {
    assert.ok(vectors.positive.length >= 5);
    assert.ok(vectors.negative.length >= 50);
    for (const c of vectors.positive) assert.equal(await run(c), "vsk_0123456789abcdef", c.name);
  });

  it("signing reproduces the positive vectors byte for byte", async () => {
    for (const c of vectors.positive.filter((p) => p.name !== "parameters_reordered_with_alg")) {
      const type = c.request.headers.find(([n]) => n === "Content-Type")?.[1];
      const headers = await signRequest(fixedSigner(c.signature_raw_b64url!, c.keyid!), {
        method: c.request.method, url: "https://viadere.com" + c.request.path_and_query, body: c.request.body === "" ? undefined : c.request.body,
        contentType: type, created: c.created!, nonce: c.nonce!,
      });
      assert.equal(headers["Signature-Input"], c.signature_input, c.name);
      assert.equal(headers["Signature"], c.signature, c.name);
      assert.equal(headers["Content-Digest"], c.content_digest ?? undefined, c.name);
    }
  });

  it("every negative vector is refused with its code", async () => {
    for (const c of vectors.negative) {
      const used = new Set((c.used_nonces ?? []).map((u) => u.scope + "|" + u.nonce));
      await assert.rejects(run(c, used), (e: unknown) => e instanceof HttpSignatureError && e.code === c.expected_error, c.name);
    }
  });

  it("a failed signature does not spend the nonce, and a nonce is single use", async () => {
    const c = vectors.positive[0]!;
    const used = new Set<string>();
    await assert.rejects(verifyHttpSignature(signed(c.request), {
      now: vectors.now, authorities: ["evil.example"], businessId: c.presenter.business_id, apiKeyId: c.presenter.api_key_id,
      resolveKey: () => ({ publicKey: vectorKey.public_key, businessId: vectorKey.business_id, apiKeyId: vectorKey.api_key_id, revoked: false }),
      registerNonce: (s, n) => { used.add(s + n); return true; },
    }), (e: unknown) => e instanceof HttpSignatureError && e.code === "bad_signature");
    assert.equal(used.size, 0);
    const store = new Set<string>();
    await run(c, store);
    await assert.rejects(run(c, store), (e: unknown) => e instanceof HttpSignatureError && e.code === "replayed");
  });

  it("a real software signature verifies through the profile", async () => {
    const signer = { keyId: "vsk_0123456789abcdef", ...softwareSigner(vectorPrivateKey()) };
    assert.equal(signer.publicKey, vectorKey.public_key);
    const headers = await signRequest(signer, { method: "POST", url: "https://viadere.com/v1/business/auth-deliveries", body: '{"a":1}', contentType: "application/json", created: vectors.now });
    const request: SignedRequest = { method: "POST", target: "/v1/business/auth-deliveries", headers: [["Content-Type", "application/json"], ...Object.entries(headers)], body: Buffer.from('{"a":1}') };
    assert.equal(await run({ name: "real", request: { method: "POST", path_and_query: request.target, headers: request.headers as [string, string][], body: '{"a":1}' }, presenter: vectors.positive[0]!.presenter }), "vsk_0123456789abcdef");
  });
});

describe("RFC 9421 request signatures: client", () => {
  function keyPair() {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    return { privateKey, signer: { keyId: "vsk_0123456789abcdef", ...softwareSigner(privateKey) } as RequestSigningKey };
  }

  it("signs every attempt with a fresh nonce, and the profile verifies each one", async () => {
    const { signer } = keyPair();
    const { fetchFn, requests } = scriptedFetch([{ status: 503 }, { status: 503 }, { status: 200, body: view() }]);
    const now = vectors.now;
    const client = new ViadereClient({ apiKey: API_KEY, baseUrl: "https://api.viadere.com", fetch: fetchFn, sleep: async () => {}, requestSigner: signer, now: () => now });
    await client.cancelAuthDelivery(DELIVERY_ID, { idempotencyKey: "cancel-1" });
    assert.equal(requests.length, 3);
    const nonces = new Set<string>();
    for (const r of requests) {
      const url = new URL(r.url);
      const keyId = await verifyHttpSignature({ method: r.method, target: url.pathname + url.search, headers: Object.entries(r.headers), body: Buffer.from(r.body ?? "") }, {
        now, authorities: ["api.viadere.com"], businessId: "b", apiKeyId: "k",
        resolveKey: () => ({ publicKey: signer.publicKey, businessId: "b", apiKeyId: "k", revoked: false }),
        registerNonce: (_s, n) => { const fresh = !nonces.has(n); nonces.add(n); return fresh; },
      });
      assert.equal(keyId, "vsk_0123456789abcdef");
      assert.equal(r.headers["Authorization"], `Bearer ${API_KEY}`);
    }
    assert.equal(nonces.size, 3);
  });

  it("covers the JSON body with a sha-256 Content-Digest", async () => {
    const { signer } = keyPair();
    const { fetchFn, requests } = scriptedFetch([{ status: 201, body: view() }]);
    const client = new ViadereClient({ apiKey: API_KEY, fetch: fetchFn, sleep: async () => {}, requestSigner: signer });
    await client.createAuthDelivery({ method: "otp", request_id: "r-1", subject_ref: "sub_" + "A".repeat(43), purpose: "sign_in", template: "auth.sign_in_code.v1", otp: { code: "482913", code_kind: "otp" } }).catch(() => undefined);
    const r = requests[0]!;
    assert.match(r.headers["Signature-Input"]!, /^sig1=\("@method" "@authority" "@path" "@query" "content-digest" "content-type"\);created=\d+;expires=\d+;keyid="vsk_0123456789abcdef";nonce="[A-Za-z0-9_-]{22}";tag="viadere-api-v1"$/);
    assert.match(r.headers["Content-Digest"]!, /^sha-256=:[A-Za-z0-9+/]{43}=:$/);
  });

  it("refuses a key id that is not a vsk_ id, and sends nothing when the signer is broken", async () => {
    const { signer } = keyPair();
    assert.throws(() => new ViadereClient({ apiKey: API_KEY, requestSigner: { ...signer, keyId: "mine" } }), (e: unknown) => e instanceof ViadereSdkError && e.kind === "invalid_signing_key");
    const { fetchFn, requests } = scriptedFetch([{ status: 200, body: view() }]);
    const broken: RequestSigningKey = { keyId: "vsk_0123456789abcdef", publicKey: signer.publicKey, sign: () => new Uint8Array(64).fill(1) };
    const client = new ViadereClient({ apiKey: API_KEY, fetch: fetchFn, sleep: async () => {}, requestSigner: broken });
    await assert.rejects(client.getAuthDelivery(DELIVERY_ID), (e: unknown) => e instanceof ViadereSdkError && e.kind === "signing_failed");
    assert.equal(requests.length, 0);
  });

  it("the proof-of-possession helper signs the console's message", async () => {
    const { privateKey, signer } = keyPair();
    const proof = await signingKeyProof("1800000000.abc.def", signer);
    const pub = p256PublicKeyOf(privateKey);
    const { verify } = await import("node:crypto");
    const message = Buffer.from(["viadere-request-signing-key-v1", "1800000000.abc.def", pub.base64url].join("\n"));
    assert.ok(verify("sha256", message, { key: pub.keyObject, dsaEncoding: "ieee-p1363" }, Buffer.from(proof, "base64url")));
  });
});
