import { createHash, createHmac, randomBytes } from "node:crypto";
import {
  base64urlDecode,
  base64urlEncode,
  canonicalJson,
  constantTimeEquals,
  isBase64urlOf,
  isKid,
  parseCanonicalObject,
  parseP256PublicKey,
  sha256Hex,
  signEs256,
  verifyEs256,
  type Es256Signer,
  type JsonValue,
  type P256PublicKey,
} from "./crypto.js";
import { StatementVerificationError } from "./errors.js";
import { CAPABILITIES, type BusinessSignedStatement, type SignedStatement } from "./types.js";

// Signed statements (`docs/SECURITY.md` sections 2.53, 2.59, 2.100): a canonical-JSON payload, base64url, with an ECDSA P-256 signature over
// `domain || payload bytes`. Every statement type has its own domain string, so a signature made for one purpose never verifies as another.
//
// Nothing here trusts the relay. A business verifies Viadere's statements against the `link-descriptor` public keys **it pinned**, a device's
// statements against the key the statement itself carries (which proves possession only: who sent it is settled by the binding tag or the SAS
// under a secret only the business and the customer's app hold), and its own records decide everything else.

export const DOMAINS = {
  verifySessionResult: "VIADERE-VERIFY-SESSION-RESULT-V1\n",
  linkStatement: "VIADERE-LINK-V1\n",
  linkConfirmation: "VIADERE-LINK-CONFIRM-V1\n",
  linkResult: "VIADERE-LINK-RESULT-V1\n",
  approvalEnrollment: "VIADERE-APPROVAL-ENROLL-V1\n",
  approvalConfirmation: "VIADERE-APPROVAL-CONFIRM-V1\n",
} as const;

/** Largest statement payload, in bytes. */
export const MAX_STATEMENT_PAYLOAD_BYTES = 8 * 1024;

const LOWER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX_DIGEST = /^[0-9a-f]{64}$/;
const SUBJECT_REF = /^sub_[A-Za-z0-9_-]{43}$/;
const VERIFICATION_REQUEST_ID = /^req_[A-Za-z0-9_-]{22}$/;
const PURPOSE_CODE = /^[a-z][a-z0-9_]{1,63}$/;
const PARAMETER_NAME = /^[a-z][a-z0-9_]{0,31}$/;

function fail(code: ConstructorParameters<typeof StatementVerificationError>[0], detail?: string): never {
  throw new StatementVerificationError(code, detail);
}

function isSubjectRef(value: unknown): value is string {
  return typeof value === "string" && SUBJECT_REF.test(value) && isBase64urlOf(value.slice(4), 32);
}

function str(o: Record<string, JsonValue>, key: string): string | undefined {
  const v = o[key];
  return typeof v === "string" ? v : undefined;
}

function int(o: Record<string, JsonValue>, key: string): number | undefined {
  const v = o[key];
  return typeof v === "number" && Number.isSafeInteger(v) ? v : undefined;
}

function sameMembers(o: Record<string, JsonValue>, expected: readonly string[]): boolean {
  const keys = Object.keys(o);
  return keys.length === expected.length && expected.every((k) => Object.hasOwn(o, k));
}

/** The payload bytes of a statement: well-formed, canonical base64url within the size limit. */
function payloadBytes(statement: { payload: unknown }): Uint8Array | undefined {
  if (typeof statement.payload !== "string" || statement.payload.length > (MAX_STATEMENT_PAYLOAD_BYTES * 4) / 3 + 4) return undefined;
  const bytes = base64urlDecode(statement.payload);
  if (bytes === undefined || bytes.length > MAX_STATEMENT_PAYLOAD_BYTES || base64urlEncode(bytes) !== statement.payload) return undefined;
  return bytes;
}

/** Whether `signature` verifies under `key` and `domain` over the payload bytes. Accepts both `s` forms (section 2.1); refuses DER. */
export function statementSignatureIsValid(statement: SignedStatement, domain: string, key: P256PublicKey): boolean {
  const bytes = payloadBytes(statement);
  if (bytes === undefined || typeof statement.signature !== "string") return false;
  return verifyEs256(key, Buffer.concat([Buffer.from(domain, "utf8"), bytes]), statement.signature);
}

/** Lowercase hex SHA-256 of the statement's payload **string**: what binding tags, digests in other statements and confirmations commit to. */
export function statementDigest(statement: { payload: string }): string {
  return sha256Hex(Buffer.from(statement.payload, "utf8"));
}

function canonicalPayload(statement: { payload: unknown }, what: string): Record<string, JsonValue> {
  const bytes = payloadBytes(statement);
  const object = bytes === undefined ? undefined : parseCanonicalObject(bytes);
  return object ?? fail("malformed", what);
}

function pinnedKey(signed: BusinessSignedStatement, trustedKeys: readonly string[]): P256PublicKey {
  if (typeof signed !== "object" || signed === null || typeof signed.kid !== "string") fail("malformed", "statement");
  for (const wire of trustedKeys) {
    const key = parseP256PublicKey(wire);
    if (key !== undefined && constantTimeEquals(key.kid, signed.kid)) return key;
  }
  return fail("untrusted_signer");
}

async function signStatement(object: Record<string, JsonValue>, domain: string, signer: Es256Signer): Promise<BusinessSignedStatement> {
  const bytes = Buffer.from(canonicalJson(object), "utf8");
  const { signature, key } = await signEs256(signer, Buffer.concat([Buffer.from(domain, "utf8"), bytes]));
  return { kid: key.kid, payload: base64urlEncode(bytes), signature };
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Codes, links, origins

const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CANONICAL_CODE = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/;

/** The canonical form of a typed or displayed code (eight characters of the look-alike-free alphabet): case, `-`, space, `_` and `.` are ignored. */
export function canonicalCode(input: string): string | undefined {
  const cleaned = input.toUpperCase().replace(/[-\s_.]/g, "");
  return CANONICAL_CODE.test(cleaned) ? cleaned : undefined;
}

/** `ABCD-EFGH`. */
export function displayCode(canonical: string): string {
  return canonical.length === 8 ? `${canonical.slice(0, 4)}-${canonical.slice(4)}` : canonical;
}

/** A link domain: a plain lowercase DNS name with at least two labels and a non-numeric top-level label (no IP literal, no port). */
export function isValidLinkDomain(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false;
  if (!labels.every((label) => /^[a-z0-9-]{1,63}$/.test(label) && !label.startsWith("-") && !label.endsWith("-"))) return false;
  return !/^[0-9]+$/.test(labels[labels.length - 1]!);
}

/** The canonical web origin (`https://shop.example`) of `text`, or `undefined`: https, a plain DNS host, no port, user info, path, query or fragment. */
export function canonicalOrigin(text: string): string | undefined {
  if (text.length > 300) return undefined;
  const m = /^https:\/\/([^/?#@:\s]+)\/?$/i.exec(text);
  const host = m?.[1]?.toLowerCase();
  return host !== undefined && isValidLinkDomain(host) ? `https://${host}` : undefined;
}

/**
 * Strict parse of a Viadere link the relay suggested: `https://{domain}/{kind}/{CODE}` exactly (no `www.`, port, user info or extra path), with an
 * optional `?rk={root key id}` (enrollment links only) and an optional `#es={secret}`. The string is matched as written, never normalised.
 */
function parseLink(link: string, kind: "a" | "k" | "v", domain: string): { code: string; rootKid?: string; secret?: string } | undefined {
  if (typeof link !== "string" || link.length > 512) return undefined;
  const m = /^https:\/\/([^/?#@:\s]+)\/([akv])\/([A-Z2-9]{8})(?:\?rk=([A-Za-z0-9_-]{43}))?(?:#es=([A-Za-z0-9_-]{43}))?$/.exec(link);
  if (!m || m[1] !== domain || m[2] !== kind || !CANONICAL_CODE.test(m[3]!)) return undefined;
  if (m[4] !== undefined && (kind !== "a" || !isKid(m[4]))) return undefined;
  if (m[5] !== undefined && (kind === "v" || !isBase64urlOf(m[5], 32))) return undefined;
  return { code: m[3]!, ...(m[4] !== undefined ? { rootKid: m[4] } : {}), ...(m[5] !== undefined ? { secret: m[5] } : {}) };
}

export function parseApprovalEnrollmentLink(link: string, domain: string): { code: string; rootKid?: string; secret?: string } | undefined {
  return parseLink(link, "a", domain);
}
export function parseLinkSessionLink(link: string, domain: string): { code: string; secret?: string } | undefined {
  return parseLink(link, "k", domain);
}
/** `https://{domain}/v/{CODE}`: carries no secret, no query, no fragment. */
export function parseVerificationSessionLink(link: string, domain: string): string | undefined {
  return parseLink(link, "v", domain)?.code;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// The 256-bit secret of an enrollment or a link session

function codeFromBits(mac: Buffer): string {
  // 40 bits = eight 5-bit groups of the first five bytes.
  let value = 0n;
  for (const byte of mac.subarray(0, 5)) value = (value << 8n) | BigInt(byte);
  let out = "";
  for (let i = 0; i < 8; i++) out += CODE_ALPHABET[Number((value >> BigInt(35 - 5 * i)) & 31n)];
  return out;
}

function normalizeSas(input: string): string | undefined {
  const cleaned = input.replace(/[ -]/g, "");
  return /^[0-9]{6}$/.test(cleaned) ? cleaned : undefined;
}

abstract class SessionSecret {
  readonly #bytes: Buffer;
  protected abstract readonly domains: { binding: string; check: string; sasKey: string; sas: string };

  /** A fresh secret from the CSPRNG, or the one you stored (`base64url`). Throws `RangeError` unless it is 32 bytes of canonical base64url. */
  constructor(base64url?: string) {
    if (base64url === undefined) this.#bytes = randomBytes(32);
    else {
      if (base64url.length !== 43 || !isBase64urlOf(base64url, 32)) throw new RangeError("the secret must be 43 base64url characters (32 bytes)");
      this.#bytes = Buffer.from(base64url, "base64url");
    }
  }

  /**
   * The secret itself, to **store server-side** with the session id until you confirm or cancel, and to put in the link fragment. Never log it and
   * never send it to Viadere. Losing it only costs a new session.
   */
  get base64url(): string {
    return this.#bytes.toString("base64url");
  }

  /** Redacted: the secret never appears in a log line or a serialized object by accident. Persist `base64url` explicitly. */
  toString(): string {
    return "[secret]";
  }
  toJSON(): string {
    return "[secret]";
  }

  /** `base64url(HMAC-SHA256(secret, domain || statement payload string))`: what the customer's app sends when it opened your link. */
  bindingTag(statement: { payload: string }): string {
    return createHmac("sha256", this.#bytes).update(this.domains.binding, "utf8").update(statement.payload, "utf8").digest("base64url");
  }

  verifyBindingTag(tag: unknown, statement: { payload: string }): boolean {
    return typeof tag === "string" && tag.length === 43 && constantTimeEquals(this.bindingTag(statement), tag);
  }

  /** The 40-bit check code for the typed path (canonical, eight characters; show it with `displayCode`). */
  get checkCode(): string {
    return codeFromBits(createHmac("sha256", this.#bytes).update(this.domains.check, "utf8").digest());
  }

  /** The six digits the app shows for this statement. */
  expectedSas(statement: { payload: string }): string {
    const key = createHash("sha256").update(this.domains.sasKey, "utf8").update(this.checkCode, "utf8").digest();
    const mac = createHmac("sha256", key).update(this.domains.sas, "utf8").update(statement.payload, "utf8").digest();
    return String(mac.readUInt32BE(0) % 1_000_000).padStart(6, "0");
  }

  /** Constant-time comparison of what the person typed (spaces and dashes ignored) with the expected digits. */
  verifySas(typed: string, statement: { payload: string }): boolean {
    const normalized = normalizeSas(typed);
    return normalized !== undefined && constantTimeEquals(normalized, this.expectedSas(statement));
  }
}

/** The enrollment secret of an Approve v2 enrollment (`#es=` of the `/a/` link). */
export class ApprovalEnrollmentSecret extends SessionSecret {
  protected readonly domains = { binding: "VIADERE-ENROLL-BIND-V1\n", check: "VIADERE-ENROLL-CHECK-V1\n", sasKey: "VIADERE-ENROLL-SAS-KEY-V1\n", sas: "VIADERE-ENROLL-SAS-V1\n" };
}

/** The session secret of a link session (`#es=` of the `/k/` link). */
export class LinkSessionSecret extends SessionSecret {
  protected readonly domains = { binding: "VIADERE-LINK-BIND-V1\n", check: "VIADERE-LINK-CHECK-V1\n", sasKey: "VIADERE-LINK-SAS-KEY-V1\n", sas: "VIADERE-LINK-SAS-V1\n" };
}

/** `ABCD-EFGH`, derived from the subject reference: show it next to the SAS ("Viadere account ABCD-EFGH"); the app shows the same value. */
export function linkPseudonym(subjectRef: string): string {
  return displayCode(codeFromBits(createHash("sha256").update("VIADERE-LINK-PSEUDONYM-V1\n", "utf8").update(subjectRef, "utf8").digest()));
}

/** `https://{domain}/a/{CODE}?rk={your root key id}#es={secret}`: built by the SDK, never taken from the relay. */
export function buildApprovalEnrollmentLink(code: string, rootKid: string, secret: ApprovalEnrollmentSecret, domain: string): string {
  return `https://${domain}/a/${code}?rk=${rootKid}#es=${secret.base64url}`;
}

/** `https://{domain}/k/{CODE}#es={secret}`. */
export function buildLinkSessionLink(code: string, secret: LinkSessionSecret, domain: string): string {
  return `https://${domain}/k/${code}#es=${secret.base64url}`;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Verification-session result (Viadere -> business), `VIADERE-VERIFY-SESSION-RESULT-V1`

export interface VerificationSessionResult {
  sessionId: string;
  businessId: string;
  requestId: string;
  subjectRef: string;
  capability: string;
  parameters: Record<string, string | number | boolean>;
  purposeCode: string;
  origin: string;
  /** `verified` or `not_verified` (never why). */
  outcome: "verified" | "not_verified";
  /** Lowercase hex SHA-256 of the result reference this statement commits to. */
  resultRefDigest: string;
  /** Unix seconds. */
  completedAt: number;
}

function flatParameters(value: JsonValue | undefined): Record<string, string | number | boolean> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const entries = Object.entries(value);
  if (entries.length > 8) return undefined;
  for (const [key, item] of entries) {
    if (!PARAMETER_NAME.test(key) || !(typeof item === "string" || typeof item === "boolean" || (typeof item === "number" && Number.isSafeInteger(item)))) return undefined;
  }
  return Object.fromEntries(entries) as Record<string, string | number | boolean>;
}

/**
 * Verifies Viadere's signed account of how a verification session ended against the `link-descriptor` public keys **you pinned** (base64url
 * X9.63): a trusted signer, a valid signature under `VIADERE-VERIFY-SESSION-RESULT-V1`, a canonical payload with exactly the defined members.
 * Then call `checkVerificationSessionResult` with the session **you** created, and `verificationResultMatchesRef`.
 */
export function verifyVerificationSessionResult(signed: BusinessSignedStatement, trustedKeys: readonly string[]): VerificationSessionResult {
  const key = pinnedKey(signed, trustedKeys);
  if (!statementSignatureIsValid(signed, DOMAINS.verifySessionResult, key)) fail("bad_signature");
  const o = canonicalPayload(signed, "result");
  const members = ["v", "type", "session_id", "business_id", "request_id", "subject_ref", "capability", "parameters", "purpose_code", "origin", "outcome", "result_ref_digest", "completed_at", "signer_kid"];
  const sessionId = str(o, "session_id");
  const businessId = str(o, "business_id");
  const requestId = str(o, "request_id");
  const subjectRef = str(o, "subject_ref");
  const capability = str(o, "capability");
  const parameters = flatParameters(o.parameters);
  const purposeCode = str(o, "purpose_code");
  const origin = str(o, "origin");
  const outcome = str(o, "outcome");
  const resultRefDigest = str(o, "result_ref_digest");
  const completedAt = int(o, "completed_at");
  const ok =
    sameMembers(o, members) && o.v === 1 && o.type === "verify-session-result" && o.signer_kid === signed.kid &&
    sessionId !== undefined && LOWER_UUID.test(sessionId) &&
    businessId !== undefined && LOWER_UUID.test(businessId) &&
    requestId !== undefined && VERIFICATION_REQUEST_ID.test(requestId) && isBase64urlOf(requestId.slice(4), 16) &&
    isSubjectRef(subjectRef) &&
    capability !== undefined && (CAPABILITIES as readonly string[]).includes(capability) &&
    parameters !== undefined &&
    purposeCode !== undefined && PURPOSE_CODE.test(purposeCode) &&
    origin !== undefined && canonicalOrigin(origin) === origin &&
    (outcome === "verified" || outcome === "not_verified") &&
    resultRefDigest !== undefined && HEX_DIGEST.test(resultRefDigest) &&
    completedAt !== undefined && completedAt > 0;
  if (!ok) fail("malformed", "result");
  return { sessionId: sessionId!, businessId: businessId!, requestId: requestId!, subjectRef: subjectRef!, capability: capability!, parameters: parameters!, purposeCode: purposeCode!, origin: origin!, outcome: outcome as "verified" | "not_verified", resultRefDigest: resultRefDigest!, completedAt: completedAt! };
}

/** The checks a business makes before acting on a result: **its** session, **its** business, the origin and the capability it asked for. */
export function checkVerificationSessionResult(result: VerificationSessionResult, expected: { sessionId: string; businessId: string; origin: string; capability: string }): void {
  if (result.sessionId !== expected.sessionId.toLowerCase()) fail("wrong_session");
  if (result.businessId !== expected.businessId.toLowerCase()) fail("wrong_business");
  const origin = canonicalOrigin(expected.origin);
  if (origin === undefined || result.origin !== origin) fail("wrong_origin");
  if (result.capability !== expected.capability) fail("wrong_capability");
}

/** Whether `resultRef` is the result reference the signed result commits to (constant time). */
export function verificationResultMatchesRef(result: VerificationSessionResult, resultRef: string): boolean {
  return constantTimeEquals(result.resultRefDigest, sha256Hex(Buffer.from(resultRef, "utf8")));
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Approve v2 enrollment statement (device -> business), `VIADERE-APPROVAL-ENROLL-V1`

/** The access-control class of an approval key. `passcode` is a result claim only: a key is never enrolled with it. */
export type ApprovalAmr = "biometric" | "passcode" | "presence";

function amrRank(amr: ApprovalAmr): number {
  return amr === "biometric" ? 2 : 1;
}

export interface ApprovalEnrollmentStatement {
  businessId: string;
  subjectRef: string;
  enrollmentId: string;
  /** base64url X9.63: the approval key. **Store it** (`EnrolledApprovalKey`): your records, not the relay's, decide which key may approve. */
  publicKey: string;
  kid: string;
  /** The device's per-relationship HPKE key, authenticated by the device's own signature over the statement. */
  hpkePublicKey: string;
  hpkeKid: string;
  assurance: "biometric" | "presence";
  /** Unix seconds. */
  createdAt: number;
}

/**
 * Verifies a device's enrollment statement: canonical payload, exact member set, a key id that really is the id of the key it carries, and a
 * signature by that key. **A valid statement proves possession of its key and nothing else**: authenticate it with the binding tag or the SAS
 * under your own secret before you confirm it.
 */
export function verifyApprovalEnrollmentStatement(signed: SignedStatement): ApprovalEnrollmentStatement {
  const o = canonicalPayload(signed, "statement");
  const members = ["v", "type", "business_id", "subject_ref", "enrollment_id", "kid", "alg", "public_key", "hpke_kid", "hpke_public_key", "assurance", "created_at"];
  if (!sameMembers(o, members) || o.v !== 1 || o.type !== "approval-enrollment" || o.alg !== "ES256") fail("malformed", "members");
  const businessId = str(o, "business_id");
  const subjectRef = str(o, "subject_ref");
  const enrollmentId = str(o, "enrollment_id");
  const keyText = str(o, "public_key");
  const hpkeText = str(o, "hpke_public_key");
  const key = keyText === undefined ? undefined : parseP256PublicKey(keyText);
  const hpke = hpkeText === undefined ? undefined : parseP256PublicKey(hpkeText);
  const assurance = str(o, "assurance");
  const createdAt = int(o, "created_at");
  const ok =
    businessId !== undefined && LOWER_UUID.test(businessId) && isSubjectRef(subjectRef) && enrollmentId !== undefined && LOWER_UUID.test(enrollmentId) &&
    key !== undefined && key.base64url === keyText && hpke !== undefined && hpke.base64url === hpkeText &&
    o.kid === key.kid && o.hpke_kid === hpke.kid && (assurance === "biometric" || assurance === "presence") && createdAt !== undefined && createdAt > 0;
  if (!ok) fail("malformed", "values");
  if (!statementSignatureIsValid(signed, DOMAINS.approvalEnrollment, key!)) fail("bad_signature");
  return { businessId: businessId!, subjectRef: subjectRef!, enrollmentId: enrollmentId!, publicKey: key!.base64url, kid: key!.kid, hpkePublicKey: hpke!.base64url, hpkeKid: hpke!.kid, assurance: assurance as "biometric" | "presence", createdAt: createdAt! };
}

/** The statement must be for this business, this customer and this enrollment: nothing the relay says is trusted. */
export function checkApprovalEnrollmentBinding(statement: ApprovalEnrollmentStatement, expected: { businessId: string; subjectRef: string; enrollmentId: string }): void {
  if (statement.businessId !== expected.businessId.toLowerCase()) fail("wrong_business");
  if (statement.subjectRef !== expected.subjectRef) fail("wrong_subject");
  if (statement.enrollmentId !== expected.enrollmentId.toLowerCase()) fail("wrong_enrollment");
}

/** Whether a key enrolled with `assurance` meets `minimum`. */
export function assuranceSatisfies(assurance: ApprovalAmr, minimum: ApprovalAmr): boolean {
  return amrRank(assurance) >= amrRank(minimum);
}

/**
 * Your signed confirmation of the key you verified (`VIADERE-APPROVAL-CONFIRM-V1`), made with your published `approval-enrollment-confirmation`
 * key. Viadere checks its form but cannot forge it; the phone verifies it before activating the key.
 */
export function signApprovalEnrollmentConfirmation(statement: ApprovalEnrollmentStatement, signed: SignedStatement, signer: Es256Signer, now: Date = new Date()): Promise<BusinessSignedStatement> {
  const confirmKid = parseP256PublicKey(signer.publicKey)?.kid;
  if (confirmKid === undefined) throw new RangeError("the signer's public key is not a P-256 key");
  return signStatement(
    { v: 1, type: "approval-enrollment-confirmation", business_id: statement.businessId, subject_ref: statement.subjectRef, enrollment_id: statement.enrollmentId, kid: statement.kid, statement_digest: statementDigest(signed), confirm_kid: confirmKid, confirmed_at: Math.floor(now.getTime() / 1000) },
    DOMAINS.approvalConfirmation,
    signer,
  );
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Link sessions: the device's statement (`VIADERE-LINK-V1`), Viadere's result (`VIADERE-LINK-RESULT-V1`), your confirmation (`VIADERE-LINK-CONFIRM-V1`)

/** Canonical order, no duplicates: one byte string per capability set. */
export function canonicalCapabilities(capabilities: readonly string[]): string[] {
  return [...new Set(capabilities)].sort();
}

function parseCapabilities(value: JsonValue | undefined): string[] | undefined {
  if (!Array.isArray(value) || value.length === 0 || value.length > 8) return undefined;
  if (!value.every((item) => typeof item === "string" && (CAPABILITIES as readonly string[]).includes(item))) return undefined;
  const list = value as string[];
  const canonical = canonicalCapabilities(list);
  return canonical.length === list.length && canonical.every((c, i) => c === list[i]) ? list : undefined;
}

export interface LinkStatement {
  sessionId: string;
  businessId: string;
  subjectRef: string;
  capabilities: string[];
  descriptorDigest: string;
  /** base64url X9.63: the connection key. */
  publicKey: string;
  kid: string;
  approvalStatementDigest?: string;
  /** Unix seconds. */
  createdAt: number;
}

/** Verifies the device's link statement (canonical payload, exact members, key id of the key it carries, signature by that key). Proves possession only. */
export function verifyLinkStatement(signed: SignedStatement): LinkStatement {
  const o = canonicalPayload(signed, "statement");
  const members = ["v", "type", "session_id", "business_id", "subject_ref", "capabilities", "descriptor_digest", "kid", "public_key", "alg", "created_at"];
  if (Object.hasOwn(o, "approval_statement_digest")) members.push("approval_statement_digest");
  const sessionId = str(o, "session_id");
  const businessId = str(o, "business_id");
  const subjectRef = str(o, "subject_ref");
  const capabilities = parseCapabilities(o.capabilities);
  const descriptorDigest = str(o, "descriptor_digest");
  const keyText = str(o, "public_key");
  const key = keyText === undefined ? undefined : parseP256PublicKey(keyText);
  const createdAt = int(o, "created_at");
  const approvalDigest = str(o, "approval_statement_digest");
  const ok =
    sameMembers(o, members) && o.v === 1 && o.type === "link-statement" && o.alg === "ES256" &&
    sessionId !== undefined && LOWER_UUID.test(sessionId) && businessId !== undefined && LOWER_UUID.test(businessId) && isSubjectRef(subjectRef) && capabilities !== undefined &&
    descriptorDigest !== undefined && HEX_DIGEST.test(descriptorDigest) && key !== undefined && key.base64url === keyText && o.kid === key.kid &&
    createdAt !== undefined && createdAt > 0 && (!Object.hasOwn(o, "approval_statement_digest") || (approvalDigest !== undefined && HEX_DIGEST.test(approvalDigest)));
  if (!ok) fail("malformed", "statement");
  if (!statementSignatureIsValid(signed, DOMAINS.linkStatement, key!)) fail("bad_signature");
  return { sessionId: sessionId!, businessId: businessId!, subjectRef: subjectRef!, capabilities: capabilities!, descriptorDigest: descriptorDigest!, publicKey: key!.base64url, kid: key!.kid, ...(approvalDigest !== undefined ? { approvalStatementDigest: approvalDigest } : {}), createdAt: createdAt! };
}

/** This session, your business, the account Viadere's result names, and **exactly** the capabilities you asked for. */
export function checkLinkStatementBinding(statement: LinkStatement, expected: { sessionId: string; businessId: string; subjectRef: string; capabilities: readonly string[] }): void {
  if (statement.sessionId !== expected.sessionId.toLowerCase()) fail("wrong_session");
  if (statement.businessId !== expected.businessId.toLowerCase()) fail("wrong_business");
  if (statement.subjectRef !== expected.subjectRef) fail("wrong_subject");
  const wanted = canonicalCapabilities(expected.capabilities);
  if (wanted.length !== statement.capabilities.length || !wanted.every((c, i) => c === statement.capabilities[i])) fail("wrong_capabilities");
}

/**
 * The approval statement a link statement commits to. Approval capabilities need one (and it must be the committed one, for this business,
 * customer and session, with a biometric key); other links must not carry one. Returns the verified statement, or `undefined` when none applies.
 */
export function checkLinkApprovalStatement(statement: LinkStatement, approvalStatement: SignedStatement | undefined): ApprovalEnrollmentStatement | undefined {
  const needsKey = statement.capabilities.some((c) => c === "auth.challenge" || c === "transaction.approve");
  if (!needsKey && approvalStatement === undefined && statement.approvalStatementDigest === undefined) return undefined;
  if (!needsKey || approvalStatement === undefined || statement.approvalStatementDigest === undefined) fail("approval_statement_mismatch");
  if (!constantTimeEquals(statementDigest(approvalStatement), statement.approvalStatementDigest)) fail("approval_statement_mismatch");
  let approval: ApprovalEnrollmentStatement;
  try {
    approval = verifyApprovalEnrollmentStatement(approvalStatement);
    checkApprovalEnrollmentBinding(approval, { businessId: statement.businessId, subjectRef: statement.subjectRef, enrollmentId: statement.sessionId });
  } catch {
    fail("approval_statement_mismatch");
  }
  // Both approval capabilities are `high` or `critical`: the key must be the biometric class.
  if (!assuranceSatisfies(approval.assurance, "biometric")) fail("approval_statement_mismatch");
  return approval;
}

export interface LinkResult {
  sessionId: string;
  businessId: string;
  /** The pairwise reference of the Viadere account that completed the session. */
  subjectRef: string;
  statementDigest: string;
  approvalStatementDigest?: string;
  /** Unix seconds. */
  completedAt: number;
}

/** Verifies Viadere's signed account of a completed link session against the `link-descriptor` keys **you pinned** (`VIADERE-LINK-RESULT-V1`). */
export function verifyLinkResult(signed: BusinessSignedStatement, trustedKeys: readonly string[]): LinkResult {
  const key = pinnedKey(signed, trustedKeys);
  if (!statementSignatureIsValid(signed, DOMAINS.linkResult, key)) fail("bad_signature");
  const o = canonicalPayload(signed, "result");
  const members = ["v", "type", "session_id", "business_id", "subject_ref", "statement_digest", "completed_at", "signer_kid"];
  if (Object.hasOwn(o, "approval_statement_digest")) members.push("approval_statement_digest");
  const sessionId = str(o, "session_id");
  const businessId = str(o, "business_id");
  const subjectRef = str(o, "subject_ref");
  const digest = str(o, "statement_digest");
  const completedAt = int(o, "completed_at");
  const approvalDigest = str(o, "approval_statement_digest");
  const ok =
    sameMembers(o, members) && o.v === 1 && o.type === "link-result" && o.signer_kid === signed.kid &&
    sessionId !== undefined && LOWER_UUID.test(sessionId) && businessId !== undefined && LOWER_UUID.test(businessId) && isSubjectRef(subjectRef) &&
    digest !== undefined && HEX_DIGEST.test(digest) && completedAt !== undefined && completedAt > 0 &&
    (!Object.hasOwn(o, "approval_statement_digest") || (approvalDigest !== undefined && HEX_DIGEST.test(approvalDigest)));
  if (!ok) fail("malformed", "result");
  return { sessionId: sessionId!, businessId: businessId!, subjectRef: subjectRef!, statementDigest: digest!, ...(approvalDigest !== undefined ? { approvalStatementDigest: approvalDigest } : {}), completedAt: completedAt! };
}

export type LinkVerification = "sas_typed" | "sas_compared";

/** Your signed confirmation of a link statement (`VIADERE-LINK-CONFIRM-V1`), with how the person verified the SAS in your signed-in session. */
export function signLinkConfirmation(statement: LinkStatement, signed: SignedStatement, verification: LinkVerification, signer: Es256Signer, now: Date = new Date()): Promise<BusinessSignedStatement> {
  const confirmKid = parseP256PublicKey(signer.publicKey)?.kid;
  if (confirmKid === undefined) throw new RangeError("the signer's public key is not a P-256 key");
  return signStatement(
    { v: 1, type: "link-confirmation", business_id: statement.businessId, session_id: statement.sessionId, subject_ref: statement.subjectRef, statement_digest: statementDigest(signed), kid: statement.kid, verification, confirm_kid: confirmKid, confirmed_at: Math.floor(now.getTime() / 1000) },
    DOMAINS.linkConfirmation,
    signer,
  );
}

/**
 * Verifies a confirmation against the confirmation key it must have been made with (base64url X9.63) and returns its canonical payload. For
 * tooling and tests: the phone and the relay are the verifiers in production.
 */
export function verifyConfirmation(signed: BusinessSignedStatement, kind: "link" | "approval-enrollment", confirmationKey: string): Record<string, JsonValue> {
  const key = parseP256PublicKey(confirmationKey);
  if (key === undefined || typeof signed?.kid !== "string" || !constantTimeEquals(key.kid, signed.kid)) fail("key_mismatch");
  if (!statementSignatureIsValid(signed, kind === "link" ? DOMAINS.linkConfirmation : DOMAINS.approvalConfirmation, key)) fail("bad_signature");
  const o = canonicalPayload(signed, "confirmation");
  const members = kind === "link"
    ? ["v", "type", "business_id", "session_id", "subject_ref", "statement_digest", "kid", "verification", "confirm_kid", "confirmed_at"]
    : ["v", "type", "business_id", "subject_ref", "enrollment_id", "kid", "statement_digest", "confirm_kid", "confirmed_at"];
  if (!sameMembers(o, members) || o.v !== 1 || o.type !== (kind === "link" ? "link-confirmation" : "approval-enrollment-confirmation") || o.confirm_kid !== signed.kid) fail("malformed", "confirmation");
  return o;
}
