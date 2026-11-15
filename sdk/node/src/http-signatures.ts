import { createHash, randomBytes, verify as nodeVerify } from "node:crypto";
import { base64urlDecode, normalizeLowS, parseP256PublicKey, signEs256, type Es256Signer, type P256PublicKey } from "./crypto.js";

// RFC 9421 HTTP Message Signatures with RFC 9530 Content-Digest, the Viadere profile for business API requests (docs/SECURITY.md section 2.112),
// on `node:crypto` only. The signer is what `ViadereClient({ requestSigner })` uses; the verifier is the server's profile, for tests, proxies and
// your own conformance checks, and is checked against `docs/protocol/vectors/http-signatures-v1.json` like the server and the Swift SDK.

export const SIGNATURE_TAG = "viadere-api-v1";
export const SIGNATURE_ALGORITHM = "ecdsa-p256-sha256";
export const SIGNATURE_LABEL = "sig1";
export const BODY_COMPONENTS = ["@method", "@authority", "@path", "@query", "content-digest", "content-type"] as const;
export const BODILESS_COMPONENTS = ["@method", "@authority", "@path", "@query"] as const;
export const SIGNATURE_MAX_AGE_SECONDS = 300;
export const SIGNATURE_MAX_FUTURE_SKEW_SECONDS = 300;
export const SIGNATURE_MAX_LIFETIME_SECONDS = 300;
export const SIGNATURE_NONCE_TTL_SECONDS = 600;

const KEYID = /^vsk_[0-9a-f]{16}$/;
const NONCE = /^[A-Za-z0-9_-]{22,64}$/;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** A request-signing key: an `Es256Signer` (software, KMS or HSM) and the `vsk_...` id the console showed when its public key was registered. */
export interface RequestSigningKey extends Es256Signer {
  readonly keyId: string;
}

/** Why a signature is refused. `code` is the normative code of the vectors (and of the server's audit trail). */
export class HttpSignatureError extends Error {
  constructor(readonly code: string) {
    super(`request signature refused: ${code}`);
    this.name = "HttpSignatureError";
  }
}

/** `sha-256=:<base64>:` of the exact body bytes (RFC 9530). */
export function requestContentDigest(body: Uint8Array | string): string {
  return "sha-256=:" + createHash("sha256").update(body).digest("base64") + ":";
}

/** `@authority` of a URL: lowercase host, default port omitted (WHATWG `URL.host` already does both). */
export function signatureAuthority(url: URL): string {
  return url.host.toLowerCase();
}

/** `@path` and `@query` of a request target exactly as on the request line: `/a?b` -> [`/a`, `?b`]; no query -> `?`. */
export function splitTarget(target: string): [string, string] {
  const mark = target.indexOf("?");
  return mark < 0 ? [target, "?"] : [target.slice(0, mark), target.slice(mark)];
}

type ParamValue = number | string;

function serializeParams(components: readonly string[], params: ReadonlyArray<readonly [string, ParamValue]>): string {
  let out = "(" + components.map((c) => `"${c}"`).join(" ") + ")";
  for (const [name, value] of params) out += `;${name}=` + (typeof value === "number" ? String(value) : `"${value}"`);
  return out;
}

interface Message {
  method: string;
  authority: string;
  target: string;
  contentDigest?: string | undefined;
  contentType?: string | undefined;
}

/** The signature base (RFC 9421 section 2.5), ASCII, LF-joined, no trailing LF. */
export function signatureBase(message: Message, components: readonly string[], params: ReadonlyArray<readonly [string, ParamValue]>): string {
  const [path, query] = splitTarget(message.target);
  const values: Record<string, string | undefined> = {
    "@method": message.method, "@authority": message.authority, "@path": path, "@query": query,
    "content-digest": message.contentDigest, "content-type": message.contentType,
  };
  let out = "";
  const seen = new Set<string>();
  for (const c of components) {
    if (seen.has(c)) throw new HttpSignatureError("wrong_components");
    seen.add(c);
    const v = values[c];
    if (v === undefined) throw new HttpSignatureError(c === "content-digest" ? "digest_required" : c === "content-type" ? "content_type_required" : "wrong_components");
    out += `"${c}": ${v}\n`;
  }
  out += `"@signature-params": ` + serializeParams(components, params);
  if (!/^[\x20-\x7e\n]*$/.test(out)) throw new HttpSignatureError("non_ascii");
  return out;
}

export interface SignRequestInput {
  method: string;
  /** The full URL exactly as it will be fetched. */
  url: string;
  body?: Uint8Array | string | undefined;
  contentType?: string | undefined;
  /** Unix seconds (default: now). */
  created?: number;
  /** Default: 16 random bytes, base64url. */
  nonce?: string;
  /** Seconds between `created` and `expires` (1 to 300, default 300). */
  lifetimeSeconds?: number;
}

/**
 * The header fields to add to one attempt: `Content-Digest` (only with a body), `Signature-Input`, `Signature`. The signature is folded to low S
 * and checked against the signer's public key before it is returned; a KMS may return DER or either `s`.
 */
export async function signRequest(signer: RequestSigningKey, input: SignRequestInput): Promise<Record<string, string>> {
  if (!KEYID.test(signer.keyId)) throw new RangeError("the request-signing key id must be the vsk_ id the console showed");
  const url = new URL(input.url);
  const target = url.pathname + (url.search === "" && input.url.endsWith("?") ? "?" : url.search);
  const nonce = input.nonce ?? randomBytes(16).toString("base64url");
  if (!NONCE.test(nonce)) throw new RangeError("nonce must be 22 to 64 base64url characters");
  const created = input.created ?? Math.floor(Date.now() / 1000);
  const lifetime = Math.min(Math.max(1, input.lifetimeSeconds ?? SIGNATURE_MAX_LIFETIME_SECONDS), SIGNATURE_MAX_LIFETIME_SECONDS);
  const body = input.body === undefined ? undefined : typeof input.body === "string" ? Buffer.from(input.body, "utf8") : input.body;
  const hasBody = body !== undefined && body.length > 0;
  const digest = hasBody ? requestContentDigest(body) : undefined;
  const components = hasBody ? BODY_COMPONENTS : BODILESS_COMPONENTS;
  const params = [["created", created], ["expires", created + lifetime], ["keyid", signer.keyId], ["nonce", nonce], ["tag", SIGNATURE_TAG]] as const;
  const base = signatureBase({ method: input.method.toUpperCase(), authority: signatureAuthority(url), target, contentDigest: digest,
                               contentType: hasBody ? (input.contentType ?? "application/json") : undefined }, components, params);
  const { signature } = await signEs256(signer, Buffer.from(base, "ascii"));
  const raw = base64urlDecode(signature)!;
  const headers: Record<string, string> = {};
  if (digest !== undefined) headers["Content-Digest"] = digest;
  headers["Signature-Input"] = `${SIGNATURE_LABEL}=` + serializeParams(components, params);
  headers["Signature"] = `${SIGNATURE_LABEL}=:` + Buffer.from(raw).toString("base64") + ":";
  return headers;
}

/** The console's proof of possession: the base64url signature over `viadere-request-signing-key-v1 LF challenge LF public key`. */
export async function signingKeyProof(challenge: string, signer: Es256Signer): Promise<string> {
  const message = Buffer.from(["viadere-request-signing-key-v1", challenge, signer.publicKey].join("\n"), "utf8");
  return (await signEs256(signer, message)).signature;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Verification (the server's profile, in its normative order)

export interface SignedRequest {
  method: string;
  /** The request target exactly as on the request line. */
  target: string;
  /** Every field line in order; duplicates are refused, never joined. */
  headers: ReadonlyArray<readonly [string, string]>;
  body: Uint8Array;
}

export interface RegisteredSigningKey {
  publicKey: string;
  businessId: string;
  apiKeyId: string;
  revoked: boolean;
}

export interface VerifyHttpSignatureOptions {
  /** Unix seconds. */
  now: number;
  authorities: readonly string[];
  /** The business and API key that authenticated the request. */
  businessId: string;
  apiKeyId: string;
  resolveKey(keyId: string): RegisteredSigningKey | undefined | Promise<RegisteredSigningKey | undefined>;
  /** Records `nonce` in `scope`; `false` when it was already there. */
  registerNonce(scope: string, nonce: string, ttlSeconds: number): boolean | Promise<boolean>;
}

class Scan {
  i = 0;
  constructor(readonly s: string) {}
  get end(): boolean { return this.i >= this.s.length; }
  peek(): string | undefined { return this.s[this.i]; }
  expect(c: string, code = "malformed_signature_input"): void {
    if (this.s[this.i] !== c) throw new HttpSignatureError(code);
    this.i++;
  }
  key(code = "malformed_signature_input"): string {
    const m = /^[a-z*][a-z0-9_.*-]{0,63}/.exec(this.s.slice(this.i));
    if (!m) throw new HttpSignatureError(code);
    this.i += m[0].length;
    if (/[a-z0-9_.*-]/.test(this.s[this.i] ?? "")) throw new HttpSignatureError(code);
    return m[0];
  }
  string(): string {
    this.expect('"');
    const start = this.i;
    while (this.i < this.s.length && this.s[this.i] !== '"') {
      const c = this.s.charCodeAt(this.i);
      if (c < 0x20 || c > 0x7e || c === 0x5c) throw new HttpSignatureError("malformed_signature_input");
      this.i++;
    }
    const v = this.s.slice(start, this.i);
    this.expect('"');
    return v;
  }
  integer(): number {
    const m = /^[0-9]{1,15}/.exec(this.s.slice(this.i));
    if (!m || (m[0].length > 1 && m[0][0] === "0")) throw new HttpSignatureError("malformed_signature_input");
    this.i += m[0].length;
    return Number(m[0]);
  }
}

function parseInput(value: string): { label: string; components: string[]; params: Array<[string, ParamValue]> } {
  const s = new Scan(value);
  const label = s.key();
  s.expect("=");
  s.expect("(");
  const components: string[] = [];
  let componentParams = false;
  while (s.peek() !== ")") {
    if (components.length > 0) s.expect(" ");
    components.push(s.string());
    while (s.peek() === ";") {
      s.i++;
      s.key();
      if (s.peek() === "=") {
        s.i++;
        if (s.peek() === '"') s.string(); else s.integer();
      }
      componentParams = true;
    }
  }
  s.expect(")");
  const params: Array<[string, ParamValue]> = [];
  while (s.peek() === ";") {
    s.i++;
    const name = s.key();
    s.expect("=");
    params.push([name, s.peek() === '"' ? s.string() : s.integer()]);
  }
  if (s.peek() === ",") throw new HttpSignatureError("multiple_signatures");
  if (!s.end) throw new HttpSignatureError("malformed_signature_input");
  if (componentParams) throw new HttpSignatureError("component_parameters");
  if (`${label}=` + serializeParams(components, params) !== value) throw new HttpSignatureError("malformed_signature_input");
  return { label, components, params };
}

function parseSignature(value: string): { label: string; bytes: Buffer } {
  const s = new Scan(value);
  const label = s.key("malformed_signature");
  s.expect("=", "malformed_signature");
  s.expect(":", "malformed_signature");
  const start = s.i;
  while (!s.end && s.peek() !== ":") {
    if (!/[A-Za-z0-9+/=]/.test(s.peek()!)) throw new HttpSignatureError("malformed_signature");
    s.i++;
  }
  const text = value.slice(start, s.i);
  s.expect(":", "malformed_signature");
  if (s.peek() === ",") throw new HttpSignatureError("multiple_signatures");
  if (!s.end) throw new HttpSignatureError("malformed_signature");
  const bytes = Buffer.from(text, "base64");
  if (bytes.toString("base64") !== text) throw new HttpSignatureError("malformed_signature");
  return { label, bytes };
}

function parseDigest(value: string): Buffer {
  const m = /^sha-256=:([A-Za-z0-9+/]{43}=):$/.exec(value);
  if (!m) throw new HttpSignatureError("malformed_digest");
  const bytes = Buffer.from(m[1]!, "base64");
  if (bytes.length !== 32 || bytes.toString("base64") !== m[1]) throw new HttpSignatureError("malformed_digest");
  return bytes;
}

function same(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** Verifies a signed request with the Viadere profile and returns the `keyid`; throws `HttpSignatureError` with the normative code. */
export async function verifyHttpSignature(request: SignedRequest, options: VerifyHttpSignatureOptions): Promise<string> {
  const values = (name: string) => request.headers.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v.trim());
  // 1. Field lines.
  const inputs = values("signature-input");
  const signatures = values("signature");
  if (inputs.length === 0 && signatures.length === 0) throw new HttpSignatureError("missing_signature");
  if (inputs.length > 1 || signatures.length > 1) throw new HttpSignatureError("duplicate_field");
  if (inputs.length !== 1 || signatures.length !== 1) throw new HttpSignatureError("signature_incomplete");
  const digests = values("content-digest");
  const types = values("content-type");
  if (digests.length > 1 || types.length > 1) throw new HttpSignatureError("duplicate_field");
  // 2. Signature-Input and Signature.
  const input = parseInput(inputs[0]!);
  const signature = parseSignature(signatures[0]!);
  if (input.label !== signature.label) throw new HttpSignatureError("label_mismatch");
  // 3. Body, digest, content type, components.
  const hasBody = request.body.length > 0;
  let contentDigest: string | undefined;
  let contentType: string | undefined;
  if (hasBody) {
    if (digests.length === 0) throw new HttpSignatureError("digest_required");
    if (!parseDigest(digests[0]!).equals(createHash("sha256").update(request.body).digest())) throw new HttpSignatureError("digest_mismatch");
    if (types.length === 0 || types[0] === "") throw new HttpSignatureError("content_type_required");
    contentDigest = digests[0];
    contentType = types[0];
  } else if (digests.length > 0) {
    throw new HttpSignatureError("digest_not_allowed");
  }
  if (!same(input.components, hasBody ? BODY_COMPONENTS : BODILESS_COMPONENTS)) throw new HttpSignatureError("wrong_components");
  // 4. Parameters.
  const allowed = new Set(["created", "expires", "keyid", "nonce", "tag", "alg"]);
  const seen = new Set<string>();
  for (const [name] of input.params) {
    if (!allowed.has(name)) throw new HttpSignatureError("unknown_parameter");
    if (seen.has(name)) throw new HttpSignatureError("duplicate_parameter");
    seen.add(name);
  }
  const p = new Map(input.params);
  for (const [name, value] of input.params) {
    const wantNumber = name === "created" || name === "expires";
    if (wantNumber !== (typeof value === "number")) throw new HttpSignatureError("malformed_parameter");
  }
  for (const name of ["created", "expires", "keyid", "nonce", "tag"]) if (!p.has(name)) throw new HttpSignatureError("missing_parameter");
  const created = p.get("created") as number;
  const expires = p.get("expires") as number;
  const keyId = p.get("keyid") as string;
  const nonce = p.get("nonce") as string;
  if (p.has("alg") && p.get("alg") !== SIGNATURE_ALGORITHM) throw new HttpSignatureError("wrong_algorithm");
  if (p.get("tag") !== SIGNATURE_TAG) throw new HttpSignatureError("wrong_tag");
  if (!KEYID.test(keyId)) throw new HttpSignatureError("malformed_keyid");
  if (!NONCE.test(nonce)) throw new HttpSignatureError("malformed_nonce");
  // 5. Time.
  const now = Math.floor(options.now);
  if (created - now > SIGNATURE_MAX_FUTURE_SKEW_SECONDS) throw new HttpSignatureError("created_in_future");
  if (now - created > SIGNATURE_MAX_AGE_SECONDS) throw new HttpSignatureError("stale");
  if (!(expires > created && expires - created <= SIGNATURE_MAX_LIFETIME_SECONDS)) throw new HttpSignatureError("invalid_expires");
  if (now > expires) throw new HttpSignatureError("expired");
  // 6. Signature encoding.
  if (signature.bytes.length !== 64) throw new HttpSignatureError("not_raw_signature");
  const raw = new Uint8Array(signature.bytes);
  if (!Buffer.from(normalizeLowS(raw)).equals(signature.bytes)) throw new HttpSignatureError("high_s");
  const s = BigInt("0x" + signature.bytes.subarray(32).toString("hex"));
  // 7. Key binding.
  const key = await options.resolveKey(keyId);
  if (key === undefined) throw new HttpSignatureError("unknown_key");
  if (key.revoked) throw new HttpSignatureError("revoked_key");
  if (key.businessId.toLowerCase() !== options.businessId.toLowerCase()) throw new HttpSignatureError("wrong_business");
  if (key.apiKeyId.toLowerCase() !== options.apiKeyId.toLowerCase()) throw new HttpSignatureError("wrong_api_key");
  const publicKey: P256PublicKey | undefined = parseP256PublicKey(key.publicKey);
  // 8. Signature over each accepted authority.
  let ok = false;
  if (publicKey !== undefined && s > 0n && s < N) {
    for (const authority of options.authorities) {
      let base: string;
      try {
        base = signatureBase({ method: request.method, authority, target: request.target, contentDigest, contentType }, input.components, input.params);
      } catch {
        continue;
      }
      if (nodeVerify("sha256", Buffer.from(base, "ascii"), { key: publicKey.keyObject, dsaEncoding: "ieee-p1363" }, signature.bytes)) {
        ok = true;
        break;
      }
    }
  }
  if (!ok) throw new HttpSignatureError("bad_signature");
  // 9. Single-use nonce.
  if (!(await options.registerNonce(`bizsig:${options.businessId.toLowerCase()}:${keyId}`, nonce, SIGNATURE_NONCE_TTL_SECONDS))) throw new HttpSignatureError("replayed");
  return keyId;
}

