import { createHash, createPublicKey, sign as nodeSign, timingSafeEqual, verify as nodeVerify, type KeyObject } from "node:crypto";

// Encodings and ECDSA exactly as `docs/SECURITY.md` section 2.1 and 2.2 define them, on `node:crypto` only.
//
// - base64url: RFC 4648 section 5 alphabet, no padding; `+`, `/` and `=` are refused, so a value has one spelling.
// - ECDSA: P-256 / SHA-256, raw `r || s` (64 bytes), base64url (86 characters). DER is refused. `(r, s)` and `(r, n - s)` are both valid
//   signatures, so both are accepted and normalised to low-S (`s <= n/2`) before use: there is one canonical byte string per signature, and
//   nothing in this SDK keys a replay guard on a signature string.
// - Public keys: base64url of the X9.63 uncompressed point (65 bytes, `0x04 || x || y`); the raw 64-byte `x || y` form is accepted too.
// - Canonical JSON: UTF-8, no whitespace, keys sorted by UTF-16 code units, integers only, the escapes of section 2.2.

const B64URL = /^[A-Za-z0-9_-]*$/;

export function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64url");
}

/** Strict decode: `undefined` for any character outside the alphabet (padding included) or an impossible length. */
export function base64urlDecode(text: string): Uint8Array | undefined {
  if (!B64URL.test(text) || text.length % 4 === 1) return undefined;
  return new Uint8Array(Buffer.from(text, "base64url"));
}

/** `text` is unpadded base64url of exactly `byteLength` bytes, in its one canonical spelling. */
export function isBase64urlOf(text: string, byteLength: number): boolean {
  const bytes = base64urlDecode(text);
  return bytes !== undefined && bytes.length === byteLength && base64urlEncode(bytes) === text;
}

export function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Constant-time string comparison (length is not secret). */
export function constantTimeEquals(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Canonical JSON (section 2.2)

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function writeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x09) out += "\\t";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0d) out += "\\r";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

/** The canonical serialization. Throws `RangeError` for a number that is not a safe integer (no floating point, ever). */
export function canonicalJson(value: JsonValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new RangeError("canonical JSON carries integers only");
    return String(value);
  }
  if (typeof value === "string") return writeString(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(value).sort(); // UTF-16 code unit order
  return "{" + keys.map((k) => writeString(k) + ":" + canonicalJson(value[k] as JsonValue)).join(",") + "}";
}

/**
 * Parses bytes as a JSON object and requires them to be **exactly** canonical (one serialization per statement, so a signature covers one byte
 * string). A duplicate key, a float, an exponent, `-0`, an integer beyond 2^53, whitespace or a non-canonical escape all fail the round trip.
 */
export function parseCanonicalObject(bytes: Uint8Array): Record<string, JsonValue> | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
  let again: string;
  try {
    again = canonicalJson(parsed as JsonValue);
  } catch {
    return undefined;
  }
  const expected = Buffer.from(again, "utf8");
  if (expected.length !== bytes.length || !timingSafeEqual(expected, Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength))) return undefined;
  // A null-prototype copy: a payload member named `__proto__` or `constructor` is data, never behaviour.
  return Object.assign(Object.create(null) as Record<string, JsonValue>, parsed as Record<string, JsonValue>);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// P-256 keys

/** DER `SubjectPublicKeyInfo` header of an uncompressed P-256 key; the 65-byte X9.63 point follows. */
const P256_SPKI_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");

/** A P-256 public key in the wire form, with its key id. */
export interface P256PublicKey {
  /** base64url of the 65-byte X9.63 point (the canonical wire form). */
  readonly base64url: string;
  /** `base64url(SHA-256(SubjectPublicKeyInfo DER))`: the `kid` every Viadere statement uses for this key. */
  readonly kid: string;
  readonly keyObject: KeyObject;
}

/** Parses a wire public key (base64url X9.63, or raw `x || y`). `undefined` unless it is a point on P-256. */
export function parseP256PublicKey(wire: string): P256PublicKey | undefined {
  const bytes = base64urlDecode(wire);
  if (bytes === undefined) return undefined;
  let point: Buffer;
  if (bytes.length === 65 && bytes[0] === 0x04) point = Buffer.from(bytes);
  else if (bytes.length === 64) point = Buffer.concat([Buffer.from([0x04]), bytes]);
  else return undefined;
  const spki = Buffer.concat([P256_SPKI_PREFIX, point]);
  try {
    const keyObject = createPublicKey({ key: spki, format: "der", type: "spki" }); // refuses a point that is not on the curve
    return { base64url: point.toString("base64url"), kid: createHash("sha256").update(spki).digest("base64url"), keyObject };
  } catch {
    return undefined;
  }
}

/** The wire public key of a P-256 `KeyObject` (public or private). */
export function p256PublicKeyOf(key: KeyObject): P256PublicKey {
  const publicKey = key.type === "public" ? key : createPublicKey(key);
  const spki = publicKey.export({ format: "der", type: "spki" });
  if (spki.length !== P256_SPKI_PREFIX.length + 65 || !spki.subarray(0, P256_SPKI_PREFIX.length).equals(P256_SPKI_PREFIX)) throw new RangeError("not a P-256 key");
  return { base64url: spki.subarray(P256_SPKI_PREFIX.length).toString("base64url"), kid: createHash("sha256").update(spki).digest("base64url"), keyObject: publicKey };
}

/** A well-formed `kid`: 43 base64url characters of a 32-byte value. */
export function isKid(value: string): boolean {
  return value.length === 43 && isBase64urlOf(value, 32);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// ECDSA raw r||s, low-S

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = N >> 1n;

function toBigInt(bytes: Uint8Array): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}

/** Folds `s` into the lower half of the group. A value that is not a valid scalar (`s >= n`, or not 64 bytes) is returned unchanged and fails verification. */
export function normalizeLowS(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) return raw;
  const s = toBigInt(raw.subarray(32));
  if (s <= HALF_N || s >= N) return raw;
  const out = new Uint8Array(64);
  out.set(raw.subarray(0, 32), 0);
  out.set(Buffer.from((N - s).toString(16).padStart(64, "0"), "hex"), 32);
  return out;
}

/** Decodes a wire signature (exactly 86 base64url characters, 64 bytes) and normalises it to low-S. DER and every other length are refused. */
export function decodeSignature(wire: string): Uint8Array | undefined {
  if (wire.length !== 86) return undefined;
  const bytes = base64urlDecode(wire);
  return bytes === undefined || bytes.length !== 64 ? undefined : normalizeLowS(bytes);
}

/** Verifies a wire signature over `message` (the verifier hashes with SHA-256). Accepts the high-S and the low-S form of a valid signature. */
export function verifyEs256(key: P256PublicKey | KeyObject, message: Uint8Array, wireSignature: string): boolean {
  const signature = decodeSignature(wireSignature);
  if (signature === undefined) return false;
  const keyObject = "keyObject" in key ? key.keyObject : key;
  try {
    return nodeVerify("sha256", message, { key: keyObject, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    return false;
  }
}

/** A DER `ECDSA-Sig-Value` as a KMS returns it, converted to raw `r || s`. `undefined` when it is not one. */
function derToRaw(der: Uint8Array): Uint8Array | undefined {
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) return undefined;
  const out = new Uint8Array(64);
  let offset = 2;
  for (const at of [0, 32]) {
    if (der[offset] !== 0x02) return undefined;
    const length = der[offset + 1]!;
    let value = der.subarray(offset + 2, offset + 2 + length);
    if (value.length !== length || length === 0 || length > 33) return undefined;
    if (value.length === 33) {
      if (value[0] !== 0) return undefined;
      value = value.subarray(1);
    }
    out.set(value, at + 32 - value.length);
    offset += 2 + length;
  }
  return offset === der.length ? out : undefined;
}

/**
 * A P-256 signing key the SDK can sign statements with: your `approval-enrollment-confirmation` key, for example. Keep the private key in your
 * KMS or HSM and give the SDK the public key and a function that signs; `softwareSigner` wraps a `KeyObject` for tests and small deployments.
 */
export interface Es256Signer {
  /** base64url X9.63 public key. */
  readonly publicKey: string;
  /** Signs `message` with ECDSA P-256 / SHA-256 (the signer hashes). Returns raw `r || s` (64 bytes) or DER; either `s` is fine. */
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export function softwareSigner(privateKey: KeyObject): Es256Signer {
  if (privateKey.type !== "private") throw new RangeError("softwareSigner needs a private key");
  const publicKey = p256PublicKeyOf(privateKey).base64url;
  return { publicKey, sign: (message) => new Uint8Array(nodeSign("sha256", message, { key: privateKey, dsaEncoding: "ieee-p1363" })) };
}

/** Signs `message` and returns the canonical wire signature (raw `r || s`, low-S, base64url). The signature is checked against the signer's own public key before it is returned. */
export async function signEs256(signer: Es256Signer, message: Uint8Array): Promise<{ signature: string; key: P256PublicKey }> {
  const key = parseP256PublicKey(signer.publicKey);
  if (key === undefined) throw new RangeError("the signer's public key is not a P-256 key");
  const produced = await signer.sign(message);
  const raw = produced.length === 64 ? produced : derToRaw(produced);
  if (raw === undefined) throw new RangeError("the signer did not return an ECDSA P-256 signature (raw r||s or DER)");
  const signature = base64urlEncode(normalizeLowS(raw));
  if (!verifyEs256(key, message, signature)) throw new RangeError("the signer's signature does not verify under its public key");
  return { signature, key };
}
