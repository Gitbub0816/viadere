import { createHmac, timingSafeEqual } from "node:crypto";
import { WebhookVerificationError } from "./errors.js";
import * as schemas from "./schemas.js";
import type {
  ConsentUpdatedData,
  InteractionOutcome,
  MessageReceivedData,
  OpaqueWebhookEnvelope,
  ProfileAccessEventData,
  RedemptionReceipt,
  RelationshipEventData,
  VerificationCompletedData,
  WebhookEventEnvelope,
} from "./types.js";
import { validateRequest } from "./validation.js";
import { DEFAULT_TOLERANCE_SECONDS, HEADERS, InMemoryReplayStore, decodeOpaqueEnvelope, headerValue, type WebhookReplayStore, type WebhookRequest } from "./webhooks.js";

// Webhook signature v1 (`docs/openapi.yaml` `WebhookSignature`, the Swift SDK's `WebhookVerifier`): what every endpoint receives until it is
// moved to signature v2 with `updateWebhook`.
//
//   Viadere-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>." + raw body)>[,v1=<hex>...]
//
// The HMAC key is the UTF-8 bytes of the whole `whsec_...` string. During a rotation the header carries two `v1=` values; a match with any secret
// you hold is accepted. Use the **raw request body bytes** exactly as received, never a re-serialized JSON value. `Viadere-Event-Id` and
// `Viadere-Event-Type` are not signed: they must agree with the signed body.

const EVENT_TYPE_HEADER = "Viadere-Event-Type";
const VERIFICATION_CONTEXT = "viadere.webhook.verification.v1:";

function v1Mac(secret: string, timestamp: string, body: Uint8Array): Buffer {
  return createHmac("sha256", Buffer.from(secret, "utf8")).update(`${timestamp}.`, "utf8").update(body).digest();
}

/** A `Viadere-Signature` v1 value, one `v1=` per secret (what Viadere sends; for tests and the partner harness). */
export function signatureHeaderV1(secrets: readonly string[], body: Uint8Array, nowSeconds: number): string {
  return [`t=${nowSeconds}`, ...secrets.map((secret) => `v1=${v1Mac(secret, String(nowSeconds), body).toString("hex")}`)].join(",");
}

/**
 * Verifies a v1 signature header and returns the secret that matched. Checks, in order: well-formed header, `|now - t| <= tolerance`, then a
 * constant-time comparison of every `v1=` candidate with the MAC under every secret. Unknown schemes in the header are ignored.
 */
export function verifySignatureV1(input: { header: string; body: Uint8Array; secrets: readonly string[]; nowSeconds: number; toleranceSeconds?: number }): { timestamp: number; secret: string } {
  const tolerance = Math.min(Math.max(input.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS, 1), DEFAULT_TOLERANCE_SECONDS);
  if (input.header.length > 4096 || /[\r\n]/.test(input.header)) throw new WebhookVerificationError("malformed_signature");
  let timestamp: string | undefined;
  const candidates: Buffer[] = [];
  for (const raw of input.header.split(",")) {
    const part = raw.trim();
    const eq = part.indexOf("=");
    if (eq < 0) throw new WebhookVerificationError("malformed_signature");
    const name = part.slice(0, eq);
    const value = part.slice(eq + 1);
    if (name === "t") {
      if (timestamp !== undefined || !/^[0-9]{1,12}$/.test(value)) throw new WebhookVerificationError("malformed_signature");
      timestamp = value;
    } else if (name === "v1") {
      if (!/^[0-9a-fA-F]{64}$/.test(value)) throw new WebhookVerificationError("malformed_signature");
      candidates.push(Buffer.from(value, "hex"));
    }
  }
  if (timestamp === undefined || candidates.length === 0) throw new WebhookVerificationError("malformed_signature");
  if (Math.abs(input.nowSeconds - Number(timestamp)) > tolerance) throw new WebhookVerificationError("timestamp_outside_tolerance");
  let matched: string | undefined;
  for (const secret of input.secrets) {
    const expected = v1Mac(secret, timestamp, input.body);
    for (const candidate of candidates) {
      if (timingSafeEqual(candidate, expected) && matched === undefined) matched = secret;
    }
  }
  if (matched === undefined) throw new WebhookVerificationError("no_matching_signature");
  return { timestamp: Number(timestamp), secret: matched };
}

export interface WebhookVerifierV1Options {
  /** The endpoint's `whsec_...` secret; pass the previous one too during a rotation (any match is accepted). Never logged. */
  secrets: readonly string[];
  /** Clock tolerance in seconds, 1 to 300 (default 300). */
  toleranceSeconds?: number;
  /**
   * Where first-receipt event ids are recorded. **On by default** (an in-memory store, 72 h retention): deliveries are at-least-once and a
   * captured delivery can be replayed inside the tolerance window. Pass your shared store in production, or `"disabled"` to opt out (tests only).
   */
  replayStore?: WebhookReplayStore | "disabled";
  /** Clock in epoch milliseconds (tests). */
  now?: () => number;
}

export interface VerifiedEvent {
  event: WebhookEventEnvelope;
  timestamp: number;
  /** `Viadere-Delivery-Id`: stable across retries of one delivery. */
  deliveryId: string | undefined;
  /** `Viadere-Key-Id`: record it, a change means the secret was rotated. */
  keyId: string | undefined;
}

export interface VerifiedOpaqueEnvelope {
  envelope: OpaqueWebhookEnvelope;
  timestamp: number;
  deliveryId: string | undefined;
  keyId: string | undefined;
}

/** A decoded event. An unknown type (Viadere may add more) is `other`: acknowledge it with `2xx` and ignore it. */
export type TypedWebhookEvent =
  | { type: "interaction.decided" | "interaction.expired" | "interaction.cancelled"; data: InteractionOutcome }
  | { type: "message.received"; data: MessageReceivedData }
  | { type: "relationship.connected" | "relationship.disconnected"; data: RelationshipEventData }
  | { type: "consent.updated"; data: ConsentUpdatedData }
  | { type: "reward.redeemed"; data: RedemptionReceipt }
  | { type: "verification.completed"; data: VerificationCompletedData }
  | { type: "profile.access_granted" | "profile.access_revoked" | "profile.request_expired"; data: ProfileAccessEventData }
  | { type: "other"; eventType: string; data: unknown };

const DATA_SCHEMAS: Readonly<Record<string, schemas.SchemaDef>> = {
  "interaction.decided": schemas.InteractionOutcome,
  "interaction.expired": schemas.InteractionOutcome,
  "interaction.cancelled": schemas.InteractionOutcome,
  "message.received": schemas.MessageReceivedData,
  "relationship.connected": schemas.RelationshipEventData,
  "relationship.disconnected": schemas.RelationshipEventData,
  "consent.updated": schemas.ConsentUpdatedData,
  "reward.redeemed": schemas.RedemptionReceipt,
  "verification.completed": schemas.VerificationCompletedData,
  "profile.access_granted": schemas.ProfileAccessEventData,
  "profile.access_revoked": schemas.ProfileAccessEventData,
  "profile.request_expired": schemas.ProfileAccessEventData,
};

/** Decodes `event.data` according to `event.type`. Throws `malformed_body` when the data of a known type lacks a required member. */
export function typedWebhookEvent(event: WebhookEventEnvelope): TypedWebhookEvent {
  const schema = Object.hasOwn(DATA_SCHEMAS, event.type) ? DATA_SCHEMAS[event.type] : undefined;
  if (schema === undefined) return { type: "other", eventType: event.type, data: event.data };
  if (validateRequest(schema, event.data).length > 0) throw new WebhookVerificationError("malformed_body");
  return { type: event.type, data: event.data } as TypedWebhookEvent;
}

function parseObject(body: Uint8Array): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new WebhookVerificationError("malformed_body");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new WebhookVerificationError("malformed_body");
  return parsed as Record<string, unknown>;
}

/** Verifies signature-v1 deliveries: classic events, the opaque envelope of an endpoint that opted in, and the endpoint-ownership challenge. */
export class WebhookVerifierV1 {
  readonly #secrets: readonly string[];
  readonly #tolerance: number;
  readonly #store: WebhookReplayStore | undefined;
  readonly #now: () => number;

  constructor(options: WebhookVerifierV1Options) {
    if (options.secrets.length === 0 || options.secrets.some((s) => typeof s !== "string" || s.length === 0)) throw new RangeError("secrets must hold at least one non-empty secret");
    this.#secrets = [...options.secrets];
    this.#tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
    this.#store = options.replayStore === "disabled" ? undefined : (options.replayStore ?? new InMemoryReplayStore());
    this.#now = options.now ?? Date.now;
  }

  /** Never prints a secret. */
  toString(): string {
    return `WebhookVerifierV1(${this.#secrets.length} secret(s))`;
  }
  toJSON(): { secrets: number } {
    return { secrets: this.#secrets.length };
  }

  #signature(request: WebhookRequest): { body: Uint8Array; timestamp: number; secret: string } {
    const body = typeof request.body === "string" ? Buffer.from(request.body, "utf8") : request.body;
    const header = headerValue(request.headers, HEADERS.signature);
    if (header === undefined) throw new WebhookVerificationError("missing_header");
    return { body, ...verifySignatureV1({ header, body, secrets: this.#secrets, nowSeconds: Math.floor(this.#now() / 1000), toleranceSeconds: this.#tolerance }) };
  }

  async #record(eventId: string): Promise<void> {
    if (this.#store && !(await this.#store.recordFirstReceipt(eventId, this.#now()))) throw new WebhookVerificationError("duplicate_event");
  }

  /**
   * Verifies the signature over the raw bytes and the timestamp window, decodes the event (`id`, `type`, `createdAt`, `businessId`,
   * `apiVersion`, `data`), requires the convenience headers to agree with the signed body, then records the event id. Decode `data` with
   * `typedWebhookEvent`.
   */
  async verify(request: WebhookRequest): Promise<VerifiedEvent> {
    const { body, timestamp } = this.#signature(request);
    const e = parseObject(body);
    if (validateRequest(schemas.WebhookEventEnvelope, e).length > 0) throw new WebhookVerificationError("malformed_body");
    const event = e as unknown as WebhookEventEnvelope;
    const id = headerValue(request.headers, HEADERS.eventId);
    const type = headerValue(request.headers, EVENT_TYPE_HEADER);
    if ((id !== undefined && id.toLowerCase() !== event.id.toLowerCase()) || (type !== undefined && type !== event.type)) throw new WebhookVerificationError("header_body_mismatch");
    // Recorded last: only a delivery that verified and decoded burns an event id.
    await this.#record(event.id.toLowerCase());
    return { event, timestamp, deliveryId: headerValue(request.headers, HEADERS.deliveryId), keyId: headerValue(request.headers, HEADERS.keyId) };
  }

  /** Verifies a delivery to an endpoint that opted into the opaque envelope (`envelopeVersion: "2026-10-27"`) and is still on signature v1. */
  async verifyEnvelope(request: WebhookRequest): Promise<VerifiedOpaqueEnvelope> {
    const { body, timestamp } = this.#signature(request);
    const envelope = decodeOpaqueEnvelope(body, request.headers);
    await this.#record(envelope.id);
    return { envelope, timestamp, deliveryId: headerValue(request.headers, HEADERS.deliveryId), keyId: headerValue(request.headers, HEADERS.keyId) };
  }

  /**
   * Answers Viadere's endpoint-ownership challenge (`webhook.verification`, sent by `verifyWebhook`). Call it for a request whose
   * `Viadere-Event-Type` is `webhook.verification` and return the result as the `2xx` response body (`Content-Type: application/json`).
   *
   * The request is verified exactly like a delivery, and the answer is `{"challenge_response": hex HMAC-SHA256(signing secret,
   * "viadere.webhook.verification.v1:" + challenge)}`. **Echoing the challenge does not work**: only a receiver that holds the endpoint's signing
   * secret can answer, which is what proves the URL belongs to the registrant.
   */
  verificationResponse(request: WebhookRequest): string {
    const { body, secret } = this.#signature(request);
    let object: Record<string, unknown>;
    try {
      object = parseObject(body);
    } catch {
      throw new WebhookVerificationError("not_a_verification_request");
    }
    const challenge = object.challenge;
    if (object.type !== "webhook.verification" || typeof challenge !== "string" || challenge.length === 0 || challenge.length > 256) throw new WebhookVerificationError("not_a_verification_request");
    const type = headerValue(request.headers, EVENT_TYPE_HEADER);
    if (type !== undefined && type !== "webhook.verification") throw new WebhookVerificationError("header_body_mismatch");
    return JSON.stringify({ challenge_response: createHmac("sha256", Buffer.from(secret, "utf8")).update(VERIFICATION_CONTEXT + challenge, "utf8").digest("hex") });
  }
}
