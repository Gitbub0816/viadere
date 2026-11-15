import { createHmac, hkdfSync, randomBytes } from "node:crypto";
import { base64urlDecode, base64urlEncode, canonicalJson, constantTimeEquals, decodeSignature, isBase64urlOf, isKid, parseCanonicalObject, parseP256PublicKey, sha256Hex, verifyEs256, type JsonValue } from "./crypto.js";
import { ApprovalVerificationError, type ApprovalFailureCode } from "./errors.js";
import type { ApprovalAmr } from "./statements.js";
import type { AuthApprovalAuthenticationDetails, AuthApprovalRisk, TransactionDetails } from "./types.js";

// ApprovalResult verification (`docs/SECURITY.md` section 2.54, ADR-0022 section 3, ADR-0023 section 2) and the number-matching helpers of
// `auth-approvals` (ADR-0022 sections 2 and 5.2). Checked against `docs/protocol/vectors/approval-result-v2.json`.
//
// **The relay's `status` is never sufficient.** A business authorizes only on a signed result that verified here against its own records: the key
// it enrolled for this customer, the request, nonce and transaction it recorded, and the number it drew and showed.

function refuse(code: ApprovalFailureCode, detail?: string): never {
  throw new ApprovalVerificationError(code, detail);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// The transaction digest

/** What an approval is for: exactly one of the two approval capabilities with its displayed parameters. */
export type ApprovalSubject = { transaction: TransactionDetails; authentication?: never } | { authentication: AuthApprovalAuthenticationDetails; transaction?: never };

export function approvalCapabilityOf(subject: ApprovalSubject): "transaction.approve" | "auth.challenge" {
  return subject.transaction !== undefined ? "transaction.approve" : "auth.challenge";
}

/** The payable ISO 4217 currencies a transaction approval may name (the list of `ViadereCore` `ISO4217`, reviewed 2026-10). */
const CURRENCIES = new Set(
  ("BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX VND VUV XAF XOF XPF BHD IQD JOD KWD LYD OMR TND CLF " +
    "AED AFN ALL AMD ANG AOA ARS AUD AWG AZN BAM BBD BDT BMD BND BOB BRL BSD BTN BWP BYN BZD CAD CDF CHF CNY COP CRC CUP CVE CZK DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP " +
    "GMD GTQ GYD HKD HNL HTG HUF IDR ILS INR IRR JMD KES KGS KHR KPW KYD KZT LAK LBP LKR LRD LSL MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MYR MZN NAD NGN NIO NOK NPR NZD PAB " +
    "PEN PGK PHP PKR PLN QAR RON RSD RUB SAR SBD SCR SDG SEK SGD SHP SLE SOS SRD SSP STN SVC SYP SZL THB TJS TMT TOP TRY TTD TWD TZS UAH USD UYU UZS VED VES WST XCD YER ZAR ZMW ZWG").split(" "),
);

/** Control, format, separator, private-use, surrogate and unassigned characters, invisible look-alikes and all but the emoji variation selectors. */
const DISALLOWED_DISPLAY = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}\p{Cn}͏ᅟᅠ឴឵⠀ㅤﾠ᠋-᠍︀-︍\u{E0100}-\u{E01EF}]/u;
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;
const graphemes = new Intl.Segmenter(undefined, { granularity: "grapheme" });

/** NFC, no leading or trailing space, no invisible or reordering character, within the grapheme, scalar and byte limits. */
function isValidDisplay(text: unknown, max: number): text is string {
  if (typeof text !== "string" || text.length === 0 || text !== text.normalize("NFC") || text !== text.trim() || DISALLOWED_DISPLAY.test(text)) return false;
  return [...graphemes.segment(text)].length <= max && [...text].length <= max * 2 && Buffer.byteLength(text, "utf8") <= max * 4;
}

/**
 * The canonical object of what is displayed and signed: `{amount_minor, capability, currency, payee_display, transaction_reference, v: 1}` or
 * `{action_display, capability, reference?, match_digits?, v: 1}`. Throws `RangeError` naming the first field that breaks the display rules
 * (the Swift SDK's additional "must not imitate the Viadere name" rule is enforced by the server, not here).
 */
export function approvalSubjectObject(subject: ApprovalSubject): Record<string, JsonValue> {
  if (subject.transaction !== undefined) {
    const t = subject.transaction;
    if (typeof t.currency !== "string" || !CURRENCIES.has(t.currency)) throw new RangeError("currency");
    if (!Number.isSafeInteger(t.amount_minor) || t.amount_minor < 1 || t.amount_minor > 999_999_999_999) throw new RangeError("amount_minor");
    if (!isValidDisplay(t.payee_display, 80)) throw new RangeError("payee_display");
    if (typeof t.transaction_reference !== "string" || t.transaction_reference.length > 64 || !PRINTABLE_ASCII.test(t.transaction_reference)) throw new RangeError("transaction_reference");
    return { v: 1, capability: "transaction.approve", currency: t.currency, amount_minor: t.amount_minor, payee_display: t.payee_display, transaction_reference: t.transaction_reference };
  }
  const a = subject.authentication;
  if (!isValidDisplay(a.action_display, 120)) throw new RangeError("action_display");
  if (a.reference !== undefined && (typeof a.reference !== "string" || a.reference.length > 64 || !PRINTABLE_ASCII.test(a.reference))) throw new RangeError("reference");
  if (a.match_digits !== undefined && a.match_digits !== 2 && a.match_digits !== 3) throw new RangeError("match_digits");
  return { v: 1, capability: "auth.challenge", action_display: a.action_display, ...(a.reference !== undefined ? { reference: a.reference } : {}), ...(a.match_digits !== undefined ? { match_digits: a.match_digits } : {}) };
}

/**
 * `lowercase hex SHA-256("VIADERE-TXN-V1\n" || canonical JSON)`. You compute it from **your own** record of the transaction; the device computes
 * it from what it displayed; they are equal only when the same parameters were shown.
 */
export function transactionDigest(subject: ApprovalSubject): string {
  return sha256Hex(Buffer.from("VIADERE-TXN-V1\n" + canonicalJson(approvalSubjectObject(subject)), "utf8"));
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Number matching (ADR-0022 section 2), match tags and SDK keys (section 5.2)

/** `code` is exactly `digits` ASCII digits, `digits` is 2 or 3, no leading zero. */
export function isValidMatchCode(code: unknown, digits: number): code is string {
  return (digits === 2 || digits === 3) && typeof code === "string" && code.length === digits && /^[1-9][0-9]+$/.test(code);
}

/** Digits a request needs: 3 for payments and high or critical risk, otherwise 2 (the API may still require 3). */
export function requiredMatchDigits(capability: string, risk: AuthApprovalRisk): 2 | 3 {
  return capability === "transaction.approve" || risk === "high" || risk === "critical" ? 3 : 2;
}

/**
 * A uniformly random code of `digits` digits without a leading zero, from the CSPRNG with **rejection sampling** (no modulo bias): a 16-bit sample
 * is accepted only below the largest multiple of the range size, then reduced. `random` yields bytes (tests inject the vectors' stream).
 */
export function drawMatchCode(digits: 2 | 3, random: (count: number) => Uint8Array = (n) => randomBytes(n)): string {
  if (digits !== 2 && digits !== 3) throw new RangeError("digits must be 2 or 3");
  const low = digits === 2 ? 10 : 100;
  const span = digits === 2 ? 90 : 900;
  const limit = Math.floor(65_536 / span) * span;
  for (;;) {
    const bytes = random(2);
    if (bytes.length !== 2) continue;
    const sample = (bytes[0]! << 8) | bytes[1]!;
    if (sample < limit) return String(low + (sample % span));
  }
}

/**
 * The keys the SDK derives from your SDK secret (`HKDF-SHA256(ikm = secret, no salt, info = label, 32 bytes)`): the match-tag key and the
 * session-handle key. Keep the secret server-side; it never goes to Viadere. Never printed.
 */
export class AuthApprovalKeys {
  readonly #match: Buffer;
  readonly #sessionHandle: Buffer;

  /** `sdkSecret`: at least 32 random bytes from your secrets manager. */
  constructor(sdkSecret: Uint8Array) {
    if (sdkSecret.length < 32) throw new RangeError("the SDK secret must be at least 32 bytes");
    this.#match = Buffer.from(hkdfSync("sha256", sdkSecret, new Uint8Array(0), Buffer.from("viadere-match-tag-key-v1", "utf8"), 32));
    this.#sessionHandle = Buffer.from(hkdfSync("sha256", sdkSecret, new Uint8Array(0), Buffer.from("viadere-session-handle-key-v1", "utf8"), 32));
  }

  toString(): string {
    return "AuthApprovalKeys(***)";
  }
  toJSON(): string {
    return "[secret]";
  }

  /**
   * The **only** documented way to produce a `session_handle`: `base64url(HMAC-SHA256(K_sh, "viadere-session-handle-v1\n" || id))` of your own id
   * of the browser or app session that started this sign-in. Never from the customer, never a constant.
   */
  sessionHandle(initiatingSessionId: string): string {
    return createHmac("sha256", this.#sessionHandle).update("viadere-session-handle-v1\n" + initiatingSessionId, "utf8").digest("base64url");
  }

  /**
   * `match_tag = base64url(HMAC-SHA256(K_match, "viadere-match-tag-v1\n" || subject_ref || "\n" || code))` and, for a 3-digit code, the same over
   * its first two digits. Viadere never sees a code: the tags only keep one person's open codes collision-free and prefix-free.
   */
  matchTags(subjectRef: string, code: string): { tag: string; prefixTag?: string } | undefined {
    if (!isValidMatchCode(code, code.length)) return undefined;
    const tag = (value: string) => createHmac("sha256", this.#match).update(`viadere-match-tag-v1\n${subjectRef}\n${value}`, "utf8").digest("base64url");
    return code.length === 3 ? { tag: tag(code), prefixTag: tag(code.slice(0, 2)) } : { tag: tag(code) };
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// The compact JWS

export const APPROVAL_RESULT_TYPE = "viadere-approval+jws";
export const APPROVAL_RESULT_MAX_BYTES = 2048;
/** Longest `exp - iat` a verifier accepts, in seconds. */
export const APPROVAL_RESULT_MAX_LIFETIME_SECONDS = 600;

export type ApprovalDecision = "approve" | "deny" | "report";
export type ApprovalDenyReason = "number_mismatch" | "not_me" | "destination_unverified";

/** The claims of a verified result (v1, or v2 with `jti` and the optional number-match members). */
export interface ApprovalResultClaims {
  v: 1 | 2;
  kid: string;
  /** The business the result is addressed to. */
  aud: string;
  sub: string;
  request_id: string;
  challenge: string;
  cap: "auth.challenge" | "transaction.approve";
  decision: ApprovalDecision;
  amr: ApprovalAmr;
  /** Unix seconds. */
  iat: number;
  exp: number;
  txn_digest: string;
  jti?: string;
  /** The number the person typed. */
  match?: string;
  deny_reason?: ApprovalDenyReason;
  /** Wrong entries the device counted (0 to 3). Advisory. */
  invalid_match_attempts?: number;
}

const V1_MEMBERS = ["v", "alg", "kid", "aud", "sub", "request_id", "challenge", "cap", "decision", "amr", "iat", "exp", "txn_digest"];
const V2_OPTIONAL = ["match", "deny_reason", "invalid_match_attempts"];
const LOWER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface Parts {
  kid: string;
  signingInput: Buffer;
  signature: string;
  payload: Record<string, JsonValue>;
}

/**
 * Strict structural parse: three base64url segments, a canonical header with only `alg`, `kid`, `typ` (and `crit`, always refused: no critical
 * extension is defined), `alg` exactly `ES256` (`none`, `HS256`, `ES384`... are refused), the type, a canonical payload. Checks no signature.
 */
function parse(compact: unknown): Parts {
  if (typeof compact !== "string" || Buffer.byteLength(compact, "utf8") > APPROVAL_RESULT_MAX_BYTES) refuse("malformed", "size");
  const segments = compact.split(".");
  if (segments.length !== 3 || segments.some((s) => s === "")) refuse("malformed", "segments");
  const headerBytes = base64urlDecode(segments[0]!);
  const payloadBytes = base64urlDecode(segments[1]!);
  const header = headerBytes === undefined ? undefined : parseCanonicalObject(headerBytes);
  const payload = payloadBytes === undefined ? undefined : parseCanonicalObject(payloadBytes);
  if (header === undefined || payload === undefined) refuse("malformed", "encoding");
  // Critical extensions first: a header with an extension this verifier does not understand is refused whatever else it says (RFC 7515 4.1.11).
  if (Object.hasOwn(header, "crit")) {
    const crit = header.crit;
    if (!Array.isArray(crit) || crit.length === 0 || !crit.every((name) => typeof name === "string")) refuse("malformed", "crit");
    refuse("unknown_critical_header", String(crit[0]).slice(0, 40));
  }
  if (!Object.keys(header).every((k) => k === "alg" || k === "typ" || k === "kid")) refuse("malformed", "header members");
  if (typeof header.alg !== "string") refuse("malformed", "alg");
  if (header.alg !== "ES256") refuse("unsupported_algorithm", header.alg.slice(0, 20));
  if (header.typ !== APPROVAL_RESULT_TYPE) refuse("unsupported_type");
  if (typeof header.kid !== "string" || !isKid(header.kid)) refuse("malformed", "kid");
  if (decodeSignature(segments[2]!) === undefined) refuse("malformed", "signature");
  return { kid: header.kid, signingInput: Buffer.from(`${segments[0]}.${segments[1]}`, "utf8"), signature: segments[2]!, payload };
}

/** Decodes the claims of a payload whose signature already verified. Exact member sets: v1 is closed; v2 is v1 plus `jti` plus only the three optional members. */
function claimsOf(parts: Parts): ApprovalResultClaims {
  const o = parts.payload;
  const v = o.v;
  if (typeof v !== "number" || !Number.isSafeInteger(v)) refuse("malformed", "v");
  if (v !== 1 && v !== 2) refuse("unsupported_version", String(v));
  const keys = Object.keys(o);
  const required = v === 1 ? V1_MEMBERS : [...V1_MEMBERS, "jti"];
  const allowed = v === 1 ? V1_MEMBERS : [...required, ...V2_OPTIONAL];
  if (!required.every((k) => Object.hasOwn(o, k)) || !keys.every((k) => allowed.includes(k))) refuse("malformed", "claims");
  if (o.alg !== "ES256" || o.kid !== parts.kid) refuse("header_payload_mismatch");
  const s = (k: string) => (typeof o[k] === "string" ? (o[k] as string) : undefined);
  const n = (k: string) => (typeof o[k] === "number" && Number.isSafeInteger(o[k]) ? (o[k] as number) : undefined);
  const aud = s("aud");
  const sub = s("sub");
  const requestId = s("request_id");
  const challenge = s("challenge");
  const cap = s("cap");
  const decision = s("decision");
  const amr = s("amr");
  const iat = n("iat");
  const exp = n("exp");
  const digest = s("txn_digest");
  const ok =
    aud !== undefined && LOWER_UUID.test(aud) &&
    sub !== undefined && /^sub_[A-Za-z0-9_-]{43}$/.test(sub) && isBase64urlOf(sub.slice(4), 32) &&
    requestId !== undefined && /^[A-Za-z0-9._:-]{1,128}$/.test(requestId) &&
    challenge !== undefined && /^[A-Za-z0-9_-]{22,128}$/.test(challenge) &&
    (cap === "auth.challenge" || cap === "transaction.approve") &&
    (decision === "approve" || decision === "deny" || decision === "report") &&
    (amr === "biometric" || amr === "passcode" || amr === "presence") &&
    iat !== undefined && exp !== undefined && iat > 0 && exp > iat &&
    digest !== undefined && /^[0-9a-f]{64}$/.test(digest);
  if (!ok) refuse("malformed", "claims values");
  const claims: ApprovalResultClaims = { v: v as 1 | 2, kid: parts.kid, aud: aud!, sub: sub!, request_id: requestId!, challenge: challenge!, cap: cap as ApprovalResultClaims["cap"], decision: decision as ApprovalDecision, amr: amr as ApprovalAmr, iat: iat!, exp: exp!, txn_digest: digest! };
  if (v === 1) return claims;
  const jti = s("jti");
  if (jti === undefined || jti.length !== 22 || !isBase64urlOf(jti, 16)) refuse("malformed", "jti");
  claims.jti = jti;
  if (Object.hasOwn(o, "match")) {
    const match = s("match");
    if (match === undefined || !isValidMatchCode(match, match.length)) refuse("malformed", "match");
    claims.match = match;
  }
  if (Object.hasOwn(o, "deny_reason")) {
    const reason = s("deny_reason");
    // `deny_reason` only on a refusal, and consistent with it.
    const consistent = (decision === "report" && reason === "not_me") || (decision === "deny" && (reason === "number_mismatch" || reason === "destination_unverified"));
    if (!consistent) refuse("malformed", "deny_reason");
    claims.deny_reason = reason as ApprovalDenyReason;
  }
  if (Object.hasOwn(o, "invalid_match_attempts")) {
    const attempts = n("invalid_match_attempts");
    if (attempts === undefined || attempts < 0 || attempts > 3) refuse("malformed", "invalid_match_attempts");
    claims.invalid_match_attempts = attempts;
  }
  return claims;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Expectation and verification

/**
 * An approval key **you** recorded when you confirmed an enrollment (`ConfirmedEnrollment.key`). This is the only trustworthy source of keys:
 * never load them from the Viadere API at verification time (the relay could add a key it controls to such a list).
 */
export interface EnrolledApprovalKey {
  kid: string;
  /** base64url X9.63. */
  publicKey: string;
  /** The pairwise customer reference this key was enrolled for. */
  subjectRef: string;
  /** The access-control class the key was **enrolled** with. A result may not claim more. */
  assurance: ApprovalAmr;
  revoked?: boolean;
}

/**
 * What you require about number matching. **There is no default**, so a verifier can never silently accept a result without the typed number for
 * a request that asked for one (a downgrade): `{ required: code }` with the code **you** drew and showed, or `"not_requested"`.
 */
export type NumberMatchExpectation = { required: string } | "not_requested";

/** Everything comes from the verifier's **own records**, never from the result. */
export interface ApprovalExpectation {
  /** Your business id (the result's `aud`). */
  audience: string;
  subjectRef: string;
  requestId: string;
  /** The nonce you generated for this request. */
  challenge: string;
  /** The transaction as your own system recorded it; its digest is recomputed here. */
  details: ApprovalSubject;
  numberMatch: NumberMatchExpectation;
  /** When you set the request to expire; a decision issued later is refused. */
  requestExpiresAt?: Date;
  /** The weakest authentication you accept. */
  minimumAmr?: ApprovalAmr;
  /** Seconds, default 60. */
  maxClockSkewSeconds?: number;
}

export interface VerifiedApproval {
  claims: ApprovalResultClaims;
  decision: ApprovalDecision;
  /** `aud | kid | challenge`: consumed atomically after verification succeeded. */
  replayKey: string;
  /** v2: `aud | jti`, consumed as well. */
  jtiReplayKey: string | undefined;
}

function amrRank(amr: ApprovalAmr): number {
  return amr === "biometric" ? 2 : 1;
}

/**
 * Verifies a compact ApprovalResult against the verifier's own records. Pure: it consumes nothing. Throws `ApprovalVerificationError`; only a
 * returned value with `decision === "approve"` could authorize anything, and to **grant** use `ApprovalVerifier.verify`, which also consumes
 * the one-time challenge.
 */
export function verifyApprovalResult(compact: string, expectation: ApprovalExpectation, keys: readonly EnrolledApprovalKey[], now: Date): VerifiedApproval {
  if (expectation === null || typeof expectation !== "object" || expectation.numberMatch === undefined) refuse("invalid_expectation", "numberMatch is required: { required: code } or \"not_requested\"");
  const numberMatch = expectation.numberMatch;
  if (numberMatch !== "not_requested" && !(typeof numberMatch === "object" && numberMatch !== null && isValidMatchCode(numberMatch.required, String(numberMatch.required).length))) refuse("invalid_expectation", "numberMatch");
  const skew = Math.min(Math.max(expectation.maxClockSkewSeconds ?? 60, 0), 300);
  const parts = parse(compact);
  const key = keys.find((k) => k.kid === parts.kid);
  if (key === undefined) refuse("unknown_key");
  if (key.revoked === true) refuse("key_revoked");
  // The kid is only a handle: the key it names must really have that identifier.
  const publicKey = parseP256PublicKey(key.publicKey);
  if (publicKey === undefined || publicKey.kid !== key.kid) refuse("unknown_key");
  if (!verifyEs256(publicKey, parts.signingInput, parts.signature)) refuse("bad_signature");
  const claims = claimsOf(parts);

  if (claims.aud !== expectation.audience.toLowerCase()) refuse("wrong_audience");
  if (claims.sub !== expectation.subjectRef || key.subjectRef !== expectation.subjectRef) refuse("wrong_subject");
  if (claims.request_id !== expectation.requestId) refuse("wrong_request");
  if (claims.cap !== approvalCapabilityOf(expectation.details)) refuse("wrong_capability");
  if (!constantTimeEquals(claims.challenge, expectation.challenge)) refuse("challenge_mismatch");
  let digest: string;
  try {
    digest = transactionDigest(expectation.details);
  } catch (error) {
    refuse("invalid_expectation", error instanceof RangeError ? error.message : "details");
  }
  if (!constantTimeEquals(claims.txn_digest, digest)) refuse("transaction_mismatch");

  const nowSeconds = now.getTime() / 1000;
  if (claims.iat > nowSeconds + skew) refuse("issued_in_future");
  if (claims.exp <= nowSeconds) refuse("expired");
  if (claims.exp - claims.iat > APPROVAL_RESULT_MAX_LIFETIME_SECONDS) refuse("lifetime_too_long");
  if (expectation.requestExpiresAt !== undefined && claims.iat > expectation.requestExpiresAt.getTime() / 1000 + skew) refuse("decided_after_request_expiry");
  if (amrRank(claims.amr) > amrRank(key.assurance)) refuse("amr_exceeds_key");
  if (expectation.minimumAmr !== undefined && amrRank(claims.amr) < amrRank(expectation.minimumAmr)) refuse("insufficient_authentication");

  // ADR-0022 section 3: a required number needs a v2 result and, on an approve, `match` equal in constant time to the verifier's own code;
  // a request that asked for none refuses any `match`.
  if (numberMatch === "not_requested") {
    if (claims.match !== undefined) refuse("unexpected_match");
  } else {
    if (claims.v !== 2) refuse("number_match_required");
    if (claims.decision === "approve" && (claims.match === undefined || !constantTimeEquals(claims.match, numberMatch.required))) refuse("number_mismatch");
  }
  return { claims, decision: claims.decision, replayKey: `approval:${claims.aud}|${claims.kid}|${claims.challenge}`, jtiReplayKey: claims.jti === undefined ? undefined : `approval-jti:${claims.aud}|${claims.jti}` };
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// The business-side verifier

/** The approval keys you recorded for a customer (revoked ones included, flagged). Back it with your database. */
export interface ApprovalKeyStore {
  keysFor(subjectRef: string): readonly EnrolledApprovalKey[] | Promise<readonly EnrolledApprovalKey[]>;
}

/** For tests and single-process tools. */
export class InMemoryApprovalKeyStore implements ApprovalKeyStore {
  readonly #keys = new Map<string, Map<string, EnrolledApprovalKey>>();
  add(key: EnrolledApprovalKey): void {
    let forSubject = this.#keys.get(key.subjectRef);
    if (!forSubject) this.#keys.set(key.subjectRef, (forSubject = new Map()));
    forSubject.set(key.kid, { ...key });
  }
  revoke(kid: string, subjectRef: string): void {
    const key = this.#keys.get(subjectRef)?.get(kid);
    if (key) key.revoked = true;
  }
  keysFor(subjectRef: string): EnrolledApprovalKey[] {
    return [...(this.#keys.get(subjectRef)?.values() ?? [])];
  }
}

/**
 * The one-time-use cache for approval challenges. Implement it over your database (a unique key on `(scope, nonce)`, an atomic insert) when
 * several instances verify results; rows may be deleted after `expiresAtMs`.
 */
export interface ReplayGuard {
  /** Atomically records `(scope, nonce)` and resolves `true` the first time, `false` for a repeat before `expiresAtMs`. */
  registerIfFresh(nonce: string, scope: string, expiresAtMs: number, nowMs: number): boolean | Promise<boolean>;
}

/** A bounded in-memory guard for one process. */
export class InMemoryReplayGuard implements ReplayGuard {
  readonly #seen = new Map<string, number>();
  readonly #maxEntries: number;
  constructor(options: { maxEntries?: number } = {}) {
    this.#maxEntries = options.maxEntries ?? 100_000;
  }
  registerIfFresh(nonce: string, scope: string, expiresAtMs: number, nowMs: number): boolean {
    const key = `${scope}\n${nonce}`;
    const known = this.#seen.get(key);
    if (known !== undefined && known > nowMs) return false;
    if (this.#seen.size >= this.#maxEntries) {
      for (const [k, expiry] of this.#seen) if (expiry <= nowMs) this.#seen.delete(k);
      // Still full of live entries: refuse rather than forget one (forgetting would let a replay through).
      if (this.#seen.size >= this.#maxEntries) return false;
    }
    this.#seen.set(key, expiresAtMs);
    return true;
  }
}

/** A request as **your own system** recorded it when you created it. */
export interface PendingApproval {
  requestId: string;
  subjectRef: string;
  challenge: string;
  details: ApprovalSubject;
  /** `{ required: code }` with the code you drew and showed, or `"not_requested"`. No default. */
  numberMatch: NumberMatchExpectation;
  expiresAt: Date;
}

export interface ApprovalVerifierOptions {
  /** Your business id: results must be addressed to it. */
  businessId: string;
  keys: ApprovalKeyStore;
  replayGuard: ReplayGuard;
  /** The weakest authentication you accept (default `biometric`; `null` for no minimum). */
  minimumAmr?: ApprovalAmr | null;
  /** Seconds, 0 to 300 (default 60). */
  maxClockSkewSeconds?: number;
  now?: () => Date;
}

/**
 * Verifies signed approval results: **the relay's status is never sufficient.**
 *
 * `verify` checks, against your own records: the ES256 signature under a key you enrolled for this customer; that the result is addressed to you,
 * for this customer, this request, this nonce and capability; that the digest equals the digest of the transaction you recorded; the clock; that
 * the key's enrolled strength covers the authentication claimed and your minimum; the typed number; and that the challenge is **unused**,
 * consuming it atomically so a replay fails. Only a value it returns grants anything.
 */
export class ApprovalVerifier {
  readonly #options: ApprovalVerifierOptions;
  constructor(options: ApprovalVerifierOptions) {
    this.#options = options;
  }

  #expectation(pending: PendingApproval): ApprovalExpectation {
    const minimum = this.#options.minimumAmr === undefined ? "biometric" : this.#options.minimumAmr;
    return {
      audience: this.#options.businessId,
      subjectRef: pending.subjectRef,
      requestId: pending.requestId,
      challenge: pending.challenge,
      details: pending.details,
      numberMatch: pending.numberMatch,
      requestExpiresAt: pending.expiresAt,
      ...(minimum !== null ? { minimumAmr: minimum } : {}),
      maxClockSkewSeconds: this.#options.maxClockSkewSeconds ?? 60,
    };
  }

  #now(): Date {
    return this.#options.now?.() ?? new Date();
  }

  /** Verifies without consuming the challenge (a dry run for tests and tooling). **Never grant access on this.** */
  async check(result: string, pending: PendingApproval): Promise<VerifiedApproval> {
    return verifyApprovalResult(result, this.#expectation(pending), await this.#options.keys.keysFor(pending.subjectRef), this.#now());
  }

  /**
   * Verifies, requires `approve` and consumes the one-time challenge (and the v2 `jti`). Throws `ApprovalVerificationError` for every failure,
   * including `not_approved` for a signed denial and `replayed` for a challenge already used.
   */
  async verify(result: string, pending: PendingApproval): Promise<VerifiedApproval> {
    const now = this.#now();
    const expectation = this.#expectation(pending);
    const verified = verifyApprovalResult(result, expectation, await this.#options.keys.keysFor(pending.subjectRef), now);
    if (verified.decision !== "approve") refuse("not_approved", verified.decision);
    // Consumed only after every other check passed: a forged or wrong result cannot burn a real challenge.
    const horizon = (verified.claims.exp + Math.min(Math.max(expectation.maxClockSkewSeconds ?? 60, 0), 300)) * 1000;
    if (!(await this.#options.replayGuard.registerIfFresh(verified.replayKey, "approval-result", horizon, now.getTime()))) refuse("replayed");
    // v2: the `jti` is recorded too, so the same signed bytes are refused under any other expectation as well.
    if (verified.jtiReplayKey !== undefined && !(await this.#options.replayGuard.registerIfFresh(verified.jtiReplayKey, "approval-jti", horizon, now.getTime()))) refuse("replayed");
    return verified;
  }

  /** The signed decision of a result that verified, including a denial (which `verify` reports as an error). For showing "the customer declined". */
  async decisionOf(result: string, pending: PendingApproval): Promise<ApprovalDecision> {
    return (await this.check(result, pending)).decision;
  }
}

/** A fresh `challenge`: 256 random bits, base64url. Never reuse one. */
export function newApprovalChallenge(): string {
  return base64urlEncode(randomBytes(32));
}

/** A fresh `request_id`. */
export function newApprovalRequestId(): string {
  return "req_" + base64urlEncode(randomBytes(16));
}
