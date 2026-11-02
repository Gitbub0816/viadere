import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { WebhookVerificationError } from "./errors.js";
import { ENVELOPE_VERSION, WEBHOOK_EVENT_TYPES, type AuthDeliveryEnvelope, type WebhookEventType } from "./types.js";

// Webhook signature v2 (ADR-0025, `docs/protocol/vectors/webhook-v2.json`).
//
//   Viadere-Signature: t=<unix>,v2=<kid>:<base64url mac>[,v2=<kid>:<base64url mac>...][,v1=<hex>]
//   string to sign (UTF-8, LF-separated, no trailing LF):
//     VIADERE-WEBHOOK-V2 / METHOD / host / path?query / t / event id / tenant id / kid / lowercase hex SHA-256(body)
//
// A receiver recomputes the string from the request as received and the endpoint URL **it registered** (never a value a proxy rewrote), once for each
// `v2=` entry whose `kid` it holds, and compares in constant time. No signed field can contain LF (each has a closed charset), so none can be shifted
// into the next. A v2 verifier never accepts a `v1=` entry alone.

export const SIGNATURE_SCHEME = "VIADERE-WEBHOOK-V2";
/** Default and maximum clock tolerance in seconds. */
export const DEFAULT_TOLERANCE_SECONDS = 300;

/** The documented minimum time to keep an event id, measured from first receipt (ADR-0025 section 2 rule 4): the retry horizon plus 300 s, rounded up to 72 h. */
export const DEDUP_RETENTION_SECONDS = 72 * 3600;

export const HEADERS = {
  signature: "Viadere-Signature",
  eventId: "Viadere-Event-Id",
  tenant: "Viadere-Tenant",
  contentDigest: "Content-Digest",
  deliveryId: "Viadere-Delivery-Id",
  keyId: "Viadere-Key-Id",
  webhookVersion: "Viadere-Webhook-Version",
} as const;

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Charsets

const METHOD = /^[A-Z]{1,16}$/;
const HOST = /^[a-z0-9.-]+(?::[0-9]{1,5})?$/;
const PCHAR_PATH = /^\/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*$/;
const EVENT_ID = /^evt_[A-Za-z0-9_-]{1,64}$/;
const TENANT_ID = /^[A-Za-z0-9_-]{1,64}$/;
const KEY_ID = /^[a-z0-9_]{1,64}$/;
const MAC = /^[A-Za-z0-9_-]{43}$/;
const DIGITS = /^[0-9]{1,12}$/;

export function isKeyId(value: string): boolean {
  return KEY_ID.test(value);
}

/** The fields of a request that are signed besides the timestamp, key id and body. `host` and `pathAndQuery` come from the registered endpoint. */
export interface SignatureContext {
  method: string;
  host: string;
  pathAndQuery: string;
  eventId: string;
  tenantId: string;
}

function contextValid(c: SignatureContext): boolean {
  return METHOD.test(c.method) && HOST.test(c.host) && c.pathAndQuery.length <= 2048 && PCHAR_PATH.test(c.pathAndQuery) && EVENT_ID.test(c.eventId) && TENANT_ID.test(c.tenantId);
}

/**
 * The host and `path?query` of a registered endpoint URL: lowercase host (the port only when it is not the scheme's default), the path and query as
 * registered (`/` for an empty path). Returns `undefined` for a URL that cannot be signed over.
 */
export function endpointParts(endpoint: string | URL): { host: string; pathAndQuery: string } | undefined {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return undefined;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return undefined;
  const host = url.host.toLowerCase(); // `URL.host` drops the scheme's default port
  const pathAndQuery = (url.pathname === "" ? "/" : url.pathname) + url.search;
  return { host, pathAndQuery };
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Signing primitives (also what the partner harness and tests use to play Viadere)

/** `sha-256=:<base64 of SHA-256(body)>:` (RFC 9530 `Content-Digest`). */
export function contentDigest(body: Uint8Array): string {
  return `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
}

/** The string to sign, or `undefined` when a field is outside its charset. */
export function stringToSign(context: SignatureContext, timestamp: number, kid: string, body: Uint8Array): string | undefined {
  if (!contextValid(context) || !KEY_ID.test(kid) || !Number.isInteger(timestamp) || timestamp <= 0 || String(timestamp).length > 12) return undefined;
  return [SIGNATURE_SCHEME, context.method, context.host, context.pathAndQuery, String(timestamp), context.eventId, context.tenantId, kid, createHash("sha256").update(body).digest("hex")].join("\n");
}

/** The 43-character base64url MAC for one `(kid, secret)`. */
export function mac(secret: string, context: SignatureContext, timestamp: number, kid: string, body: Uint8Array): string | undefined {
  const message = stringToSign(context, timestamp, kid, body);
  if (message === undefined) return undefined;
  return createHmac("sha256", Buffer.from(secret, "utf8")).update(message, "utf8").digest("base64url");
}

/** A `Viadere-Signature` value with one `v2=` entry per `(kid, secret)` (a rotation sends two). Never adds a `v1=` entry. */
export function signatureHeader(secrets: readonly { kid: string; secret: string }[], context: SignatureContext, body: Uint8Array, nowSeconds: number): string | undefined {
  const parts = [`t=${nowSeconds}`];
  for (const entry of secrets) {
    const m = mac(entry.secret, context, nowSeconds, entry.kid, body);
    if (m === undefined) return undefined;
    parts.push(`v2=${entry.kid}:${m}`);
  }
  return parts.join(",");
}

function constantTimeEquals(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

/**
 * Verifies one delivery's signature. `context` is built from the endpoint **you registered** and the request's `Viadere-Event-Id` and `Viadere-Tenant`;
 * `expectedTenant` is your own tenant id; `keys` maps every `kid` you hold to its secret. Returns the signed timestamp. The checks run in this
 * order, and the failure code names the first that failed: malformed, timestamp, tenant, digest, MAC.
 */
export function verifySignature(input: {
  header: string;
  body: Uint8Array;
  contentDigestHeader: string | undefined;
  context: SignatureContext;
  expectedTenant: string;
  keys: Readonly<Record<string, string>>;
  nowSeconds: number;
  toleranceSeconds?: number;
}): number {
  const { header, body, contentDigestHeader, context, expectedTenant, keys, nowSeconds } = input;
  const tolerance = Math.min(Math.max(input.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS, 1), DEFAULT_TOLERANCE_SECONDS);
  if (header.length > 4096 || header.includes("\n") || header.includes("\r")) throw new WebhookVerificationError("malformed_signature");
  // Every signed field has a closed charset (no LF): anything outside it is malformed, not merely a wrong MAC.
  if (!contextValid(context) || !TENANT_ID.test(expectedTenant)) throw new WebhookVerificationError("malformed_signature");

  let timestamp: number | undefined;
  const entries: { kid: string; mac: string }[] = [];
  const kids = new Set<string>();
  for (const raw of header.split(",")) {
    const part = raw.trim();
    const eq = part.indexOf("=");
    if (eq < 0) throw new WebhookVerificationError("malformed_signature");
    const name = part.slice(0, eq);
    const value = part.slice(eq + 1);
    if (name === "t") {
      if (timestamp !== undefined || !DIGITS.test(value)) throw new WebhookVerificationError("malformed_signature");
      timestamp = Number(value);
    } else if (name === "v2") {
      const colon = value.indexOf(":");
      if (colon < 0) throw new WebhookVerificationError("malformed_signature");
      const kid = value.slice(0, colon);
      const m = value.slice(colon + 1);
      if (!KEY_ID.test(kid) || !MAC.test(m) || kids.has(kid)) throw new WebhookVerificationError("malformed_signature");
      kids.add(kid);
      entries.push({ kid, mac: m });
    }
    // `v1=` and unknown schemes are ignored; a v2 verifier never accepts `v1=` alone.
  }
  if (timestamp === undefined || entries.length === 0) throw new WebhookVerificationError("malformed_signature");
  if (Math.abs(nowSeconds - timestamp) > tolerance) throw new WebhookVerificationError("timestamp_outside_tolerance");
  if (!constantTimeEquals(context.tenantId, expectedTenant)) throw new WebhookVerificationError("tenant_mismatch");
  // The digest is compared with the one computed from the received bytes; the header is never copied into the string to sign.
  if (contentDigestHeader === undefined || !constantTimeEquals(contentDigestHeader, contentDigest(body))) throw new WebhookVerificationError("digest_mismatch");
  let matched = false;
  for (const entry of entries) {
    const secret = Object.hasOwn(keys, entry.kid) ? keys[entry.kid] : undefined;
    if (secret === undefined) continue;
    const expected = mac(secret, context, timestamp, entry.kid, body);
    if (expected !== undefined && constantTimeEquals(entry.mac, expected)) matched = true;
  }
  if (!matched) throw new WebhookVerificationError("no_matching_signature");
  return timestamp;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Replay store (ADR-0025 section 2 rule 4, fixes F-22; review R23-06: on by default)

/**
 * A durable record of processed webhook event ids. Keep an id for at least `DEDUP_RETENTION_SECONDS` (72 h) **from first receipt**. Implement it
 * with an atomic insert on a unique key, for example:
 *
 * ```sql
 * CREATE TABLE viadere_webhook_events (event_id TEXT PRIMARY KEY, first_seen TIMESTAMPTZ NOT NULL);
 * INSERT INTO viadere_webhook_events (event_id, first_seen) VALUES ($1, now()) ON CONFLICT DO NOTHING; -- 1 row inserted = first time
 * DELETE FROM viadere_webhook_events WHERE first_seen < now() - interval '72 hours';
 * ```
 */
export interface WebhookReplayStore {
  /** Atomically records `eventId` and resolves `true` the first time, `false` for a repeat still inside the retention window. */
  recordFirstReceipt(eventId: string, nowMs: number): boolean | Promise<boolean>;
  /** Optional: forget an id so Viadere's retry is processed again, when your handler failed before it finished its work. */
  release?(eventId: string): void | Promise<void>;
}

/**
 * Process-local store, the **default**. Entries expire `retentionSeconds` after first receipt and the map is bounded (`maxEntries`, oldest first).
 * With several processes or restarts the guarantee is per process: use a shared store (the SQL above) for production.
 */
export class InMemoryReplayStore implements WebhookReplayStore {
  readonly #seen = new Map<string, number>(); // insertion order == first-receipt order
  readonly #retentionMs: number;
  readonly #maxEntries: number;

  constructor(options: { retentionSeconds?: number; maxEntries?: number } = {}) {
    this.#retentionMs = (options.retentionSeconds ?? DEDUP_RETENTION_SECONDS) * 1000;
    this.#maxEntries = options.maxEntries ?? 100_000;
  }

  recordFirstReceipt(eventId: string, nowMs: number): boolean {
    for (const [id, firstSeen] of this.#seen) {
      if (nowMs - firstSeen < this.#retentionMs) break;
      this.#seen.delete(id);
    }
    if (this.#seen.has(eventId)) return false;
    // A captured delivery cannot be replayed after the signature window anyway; eviction of the oldest entries only costs a re-processed retry.
    if (this.#seen.size >= this.#maxEntries) {
      const oldest = this.#seen.keys().next().value;
      if (oldest !== undefined) this.#seen.delete(oldest);
    }
    this.#seen.set(eventId, nowMs);
    return true;
  }

  release(eventId: string): void {
    this.#seen.delete(eventId);
  }

  get size(): number {
    return this.#seen.size;
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Verifier

export type HeaderBag = Headers | Readonly<Record<string, string | readonly string[] | undefined>>;

function headerValue(headers: HeaderBag, name: string): string | undefined {
  if (typeof Headers !== "undefined" && headers instanceof Headers) return headers.get(name) ?? undefined;
  const wanted = name.toLowerCase();
  let found: string | undefined;
  for (const [key, value] of Object.entries(headers as Readonly<Record<string, string | readonly string[] | undefined>>)) {
    if (key.toLowerCase() !== wanted || value === undefined) continue;
    if (typeof value !== "string") {
      if (value.length !== 1) throw new WebhookVerificationError("malformed_signature"); // a repeated header is ambiguous
      found = value[0];
    } else found = value;
  }
  return found;
}

export interface WebhookVerifierOptions {
  /** The endpoint URL **you registered** with Viadere (never a value a proxy rewrote). */
  endpoint: string | URL;
  /** Your own tenant id (what `Viadere-Tenant` must equal). */
  tenantId: string;
  /** Your signing secrets by key id (`whk_<prefix>_v<n>`). Keep the previous one during a rotation. */
  keys: Readonly<Record<string, string>>;
  /** Clock tolerance in seconds, 1 to 300 (default 300). */
  toleranceSeconds?: number;
  /**
   * Where first-receipt event ids are recorded. **On by default** (an in-memory store with the 72 h retention): a verifier that does not dedupe
   * accepts a replay inside the 300 s window (R23-06). Pass your shared store in production, or `"disabled"` to opt out explicitly (tests only).
   */
  replayStore?: WebhookReplayStore | "disabled";
  /** Clock in epoch milliseconds (tests). */
  now?: () => number;
}

export interface WebhookRequest {
  headers: HeaderBag;
  /** The **raw** body bytes (or the exact string) as received, before any JSON parsing. */
  body: Uint8Array | string;
}

export interface VerifiedWebhook {
  eventId: string;
  tenantId: string;
  timestamp: number;
  body: Uint8Array;
  /** `Viadere-Delivery-Id`: stable across retries of one delivery. */
  deliveryId: string | undefined;
  /** `Viadere-Key-Id`: record it, a change means the secret was rotated. */
  keyId: string | undefined;
}

export interface VerifiedEnvelope extends VerifiedWebhook {
  envelope: AuthDeliveryEnvelope;
}

export class WebhookVerifier {
  readonly #host: string;
  readonly #pathAndQuery: string;
  readonly #tenantId: string;
  readonly #keys: Record<string, string>;
  readonly #tolerance: number;
  readonly #store: WebhookReplayStore | undefined;
  readonly #now: () => number;

  constructor(options: WebhookVerifierOptions) {
    const parts = endpointParts(options.endpoint);
    if (!parts || !HOST.test(parts.host) || !PCHAR_PATH.test(parts.pathAndQuery)) throw new RangeError("endpoint must be the https URL registered with Viadere");
    if (!TENANT_ID.test(options.tenantId)) throw new RangeError("tenantId is not a valid tenant id");
    const keys: Record<string, string> = Object.create(null) as Record<string, string>;
    for (const [kid, secret] of Object.entries(options.keys)) {
      if (!KEY_ID.test(kid)) throw new RangeError(`"${kid}" is not a key id (whk_<prefix>_v<n>)`);
      if (secret.length === 0) throw new RangeError(`the secret of ${kid} is empty`);
      keys[kid] = secret;
    }
    if (Object.keys(keys).length === 0) throw new RangeError("keys must hold at least one secret");
    this.#host = parts.host;
    this.#pathAndQuery = parts.pathAndQuery;
    this.#tenantId = options.tenantId;
    this.#keys = keys;
    this.#tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
    this.#store = options.replayStore === "disabled" ? undefined : (options.replayStore ?? new InMemoryReplayStore());
    this.#now = options.now ?? Date.now;
  }

  /** Never prints a secret. */
  toString(): string {
    return `WebhookVerifier(${this.#host}${this.#pathAndQuery}, tenant ${this.#tenantId}, ${Object.keys(this.#keys).length} key(s))`;
  }

  /** Verifies signature, timestamp window, tenant and digest, then records the event id. Does not look at the body's content. */
  async verify(request: WebhookRequest): Promise<VerifiedWebhook> {
    const verified = this.#verifySignature(request);
    await this.#record(verified.eventId);
    return verified;
  }

  /**
   * Verifies an `auth.delivery.*` delivery and decodes its opaque envelope (no unknown member, version `2026-10-27`, your tenant, a body id equal to
   * the signed `Viadere-Event-Id`). The envelope names **what** happened to **which** delivery; it carries no result. `opened` is not success: fetch the
   * state with `getAuthDelivery`, verify your own link or code, then call `completeAuthDelivery`.
   */
  async verifyEnvelope(request: WebhookRequest): Promise<VerifiedEnvelope> {
    const verified = this.#verifySignature(request);
    const envelope = this.#decodeEnvelope(verified.body, verified.eventId);
    // Recorded last: only a delivery that verified and decoded burns an event id, so a forged one cannot, and a malformed one stays retryable.
    await this.#record(verified.eventId);
    return { ...verified, envelope };
  }

  /** Forgets an event id (when your handler failed before finishing), so the next retry is processed. A no-op for stores without `release`. */
  async release(eventId: string): Promise<void> {
    await this.#store?.release?.(eventId);
  }

  #verifySignature(request: WebhookRequest): VerifiedWebhook {
    const body = typeof request.body === "string" ? Buffer.from(request.body, "utf8") : request.body;
    const header = headerValue(request.headers, HEADERS.signature);
    if (header === undefined) throw new WebhookVerificationError("missing_header");
    const eventId = headerValue(request.headers, HEADERS.eventId);
    if (eventId === undefined) throw new WebhookVerificationError("missing_header");
    const tenant = headerValue(request.headers, HEADERS.tenant);
    if (tenant === undefined) throw new WebhookVerificationError("missing_header");
    const timestamp = verifySignature({
      header,
      body,
      contentDigestHeader: headerValue(request.headers, HEADERS.contentDigest),
      context: { method: "POST", host: this.#host, pathAndQuery: this.#pathAndQuery, eventId, tenantId: tenant },
      expectedTenant: this.#tenantId,
      keys: this.#keys,
      nowSeconds: Math.floor(this.#now() / 1000),
      toleranceSeconds: this.#tolerance,
    });
    return { eventId, tenantId: tenant, timestamp, body, deliveryId: headerValue(request.headers, HEADERS.deliveryId), keyId: headerValue(request.headers, HEADERS.keyId) };
  }

  #decodeEnvelope(body: Uint8Array, signedEventId: string): AuthDeliveryEnvelope {
    let parsed: unknown;
    try {
      parsed = JSON.parse(Buffer.from(body).toString("utf8"));
    } catch {
      throw new WebhookVerificationError("malformed_body");
    }
    const e = parsed as Record<string, unknown> | null;
    if (typeof e !== "object" || e === null || Array.isArray(e)) throw new WebhookVerificationError("malformed_body");
    const allowed = ["id", "type", "version", "tenant_id", "request_id", "occurred_at", "result_ref"];
    if (Object.keys(e).some((k) => !allowed.includes(k))) throw new WebhookVerificationError("malformed_body");
    if (e.result_ref !== undefined && e.result_ref !== null) throw new WebhookVerificationError("malformed_body");
    const ok =
      typeof e.id === "string" && EVENT_ID.test(e.id) &&
      typeof e.type === "string" && (WEBHOOK_EVENT_TYPES as readonly string[]).includes(e.type) &&
      e.version === ENVELOPE_VERSION &&
      typeof e.tenant_id === "string" && TENANT_ID.test(e.tenant_id) &&
      typeof e.request_id === "string" && /^adl_[A-Za-z0-9_-]{22}$/.test(e.request_id) &&
      typeof e.occurred_at === "string" && !Number.isNaN(Date.parse(e.occurred_at));
    if (!ok) throw new WebhookVerificationError("malformed_body");
    // The signed headers and the signed body must tell the same story.
    if (e.id !== signedEventId || e.tenant_id !== this.#tenantId) throw new WebhookVerificationError("header_body_mismatch");
    return { id: e.id as string, type: e.type as WebhookEventType, version: ENVELOPE_VERSION, tenant_id: e.tenant_id as string, request_id: e.request_id as string, occurred_at: e.occurred_at as string };
  }

  async #record(eventId: string): Promise<void> {
    if (this.#store && !(await this.#store.recordFirstReceipt(eventId, this.#now()))) throw new WebhookVerificationError("duplicate_event");
  }
}
