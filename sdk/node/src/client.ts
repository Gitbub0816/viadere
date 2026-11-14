import {
  AuthApprovalKeys,
  approvalCapabilityOf,
  drawMatchCode,
  newApprovalChallenge,
  newApprovalRequestId,
  requiredMatchDigits,
  type ApprovalSubject,
  type EnrolledApprovalKey,
  type PendingApproval,
} from "./approval.js";
import { constantTimeEquals, isKid, type Es256Signer } from "./crypto.js";
import { StatementVerificationError, ViadereApiError, ViadereFlowError, ViadereSdkError } from "./errors.js";
import { deterministicIdempotencyKey, generateIdempotencyKey, isValidIdempotencyKey } from "./idempotency.js";
import * as schemas from "./schemas.js";
import {
  ApprovalEnrollmentSecret,
  LinkSessionSecret,
  assuranceSatisfies,
  buildApprovalEnrollmentLink,
  buildLinkSessionLink,
  canonicalCapabilities,
  canonicalCode,
  checkApprovalEnrollmentBinding,
  checkLinkApprovalStatement,
  checkLinkStatementBinding,
  checkVerificationSessionResult,
  displayCode,
  isValidLinkDomain,
  linkPseudonym,
  parseApprovalEnrollmentLink,
  parseLinkSessionLink,
  parseVerificationSessionLink,
  signApprovalEnrollmentConfirmation,
  signLinkConfirmation,
  statementDigest,
  verificationResultMatchesRef,
  verifyApprovalEnrollmentStatement,
  verifyLinkResult,
  verifyLinkStatement,
  verifyVerificationSessionResult,
  type ApprovalAmr,
  type ApprovalEnrollmentStatement,
  type LinkResult,
  type LinkStatement,
  type VerificationSessionResult,
} from "./statements.js";
import { RequesterThrottle } from "./throttle.js";
import { COMPLETE_OUTCOMES, type AuthDeliveryCompleteRequest, type AuthDeliveryCreateRequest, type AuthDeliveryView, type AuthWebhookTestRequest, type AuthWebhookTestResponse, type CompleteOutcome, type UpdateWebhookRequest } from "./types.js";
import type * as T from "./types.js";
import { assertValidCreateRequest, DELIVERY_ID_PATTERN } from "./validate.js";
import { assertResponse, assertResponseList, assertValidRequest, pathParameter } from "./validation.js";

export const SDK_VERSION = "0.2.0";

/**
 * Retries for transient failures (network errors, `429`, `5xx`). Only requests that are safe to repeat are retried: every `GET`, every request
 * that carries an idempotency key, and the calls that are idempotent by nature (a cancel, a void, a settings `PUT`). Calls that consume
 * something exactly once (`consumeRedemption`, `scanWalletPass`) are never retried.
 */
export interface RetryPolicy {
  /** Total attempts, including the first (default 3). */
  maxAttempts: number;
  /** Base of the exponential backoff in seconds (default 0.5). */
  baseDelaySeconds: number;
  /** Cap for one wait, `Retry-After` included, in seconds (default 30). */
  maxDelaySeconds: number;
}

export const DEFAULT_RETRY: RetryPolicy = { maxAttempts: 3, baseDelaySeconds: 0.5, maxDelaySeconds: 30 };
export const NO_RETRY: RetryPolicy = { maxAttempts: 1, baseDelaySeconds: 0, maxDelaySeconds: 0 };

type FetchLike = (input: string, init: { method: string; headers: Record<string, string>; body?: string; redirect: "manual"; signal: AbortSignal }) => Promise<{ status: number; headers: { get(name: string): string | null }; text(): Promise<string> }>;

export interface ViadereClientOptions {
  /** Your business API key (`vdk_live_...` or `vdk_test_...`). Keep it on your server: never ship it in a browser or an app. */
  apiKey: string;
  /** Default `https://api.viadere.com`. `http` is accepted only for loopback hosts, for local development against a dev server. */
  baseUrl?: string;
  /**
   * The universal-link host the links you show must use (default `viadere.com`; a staging integration passes the staging host). The SDK builds
   * enrollment and link-session links on it and refuses a relay ticket that names any other host.
   */
  linkDomain?: string;
  retry?: Partial<RetryPolicy>;
  /** Per-attempt timeout in milliseconds (default 30 000). */
  timeoutMs?: number;
  /**
   * The per-requester throttle (C-14), **on by default**: at most 3 open deliveries or sign-in approvals per account and client network prefix;
   * the next `createAuthDelivery` or `createAuthApproval` throws `ViadereThrottledError` before anything is sent. Pass options to tune it, your
   * own instance to share it, or `false` to turn it off (not recommended: Viadere deliberately never refuses by per-customer count, so this cap
   * is the only brake on push-bombing).
   */
  throttle?: RequesterThrottle | { maxOpen?: number } | false;
  /** Test seam: replaces `fetch`. */
  fetch?: FetchLike;
  /** Test seam: waits `seconds`. */
  sleep?: (seconds: number) => Promise<void>;
  /** Test seam: random in [0, 1). */
  random?: () => number;
}

export interface CreateOptions {
  /** Default: derived from `request_id`, so a retry after a crash (even from another process) replays the original. */
  idempotencyKey?: string;
  /**
   * Who started this sign-in, for the throttle: the **client IP address** of the browser or app that asked you to sign in (the address your edge
   * saw, for example from your trusted proxy's header). Without it every request of an account shares one bucket.
   */
  requester?: { clientAddress?: string };
}

export interface CreateResult {
  delivery: AuthDeliveryView;
  /** `false` when the idempotency key was already known and the original result was replayed (`200`). */
  created: boolean;
}

export interface IdempotencyOption {
  idempotencyKey?: string;
}

/** A created resource, and `created: false` when the server recognised the idempotency key (or the natural key) and returned the original (`200`). */
export interface Created<X> {
  value: X;
  created: boolean;
}

/**
 * What you show the customer to enrol an approval key, built **by the SDK**, and what you keep until the enrollment is confirmed.
 *
 * - `link` is `https://{link domain}/a/{CODE}?rk={your root key id}#es={secret}`. Show it as a QR or button in **your own signed-in session**.
 *   Never send it by SMS or email. The secret travels in the URL fragment, which no server (Viadere's included) ever receives.
 * - `displayCode` and `checkCode` are for a customer who types instead of scanning: both go into the app, which then shows six digits that
 *   you pass to `confirmApprovalEnrollment({ sas })`.
 * - `secret` is the 256-bit enrollment secret. **Store `secret.base64url` server-side, tied to `enrollmentId`, until you confirm or cancel**
 *   (it is redacted from `JSON.stringify` and logs on purpose). Never send it to Viadere.
 */
export interface ApprovalEnrollmentInvitation {
  enrollmentId: string;
  /** Canonical code, eight characters. */
  code: string;
  displayCode: string;
  checkCode: string;
  rootKid: string;
  secret: ApprovalEnrollmentSecret;
  expiresAt: string;
  link: string;
}

/** An enrollment you verified and confirmed: **store this in your own database.** `key` is what `ApprovalVerifier` needs. */
export interface ConfirmedEnrollment {
  enrollmentId: string;
  key: EnrolledApprovalKey;
  /** The device's per-relationship HPKE key (base64url X9.63) and its id, authenticated by the device's signature: where end-to-end requests are encrypted to. */
  hpkePublicKey: string;
  hpkeKid: string;
  /** The device's signed statement, kept as evidence. */
  statement: T.SignedStatement;
}

/** What you show the customer to link their Viadere app to your customer record. Same rules as `ApprovalEnrollmentInvitation`. */
export interface LinkSessionInvitation {
  sessionId: string;
  code: string;
  displayCode: string;
  checkCode: string;
  rootKid: string;
  secret: LinkSessionSecret;
  capabilities: string[];
  expiresAt: string;
  /** `https://{link domain}/k/{CODE}#es={secret}`. */
  link: string;
}

/** A completed link session you verified, ready for the person to compare the SAS **in your signed-in session**. */
export interface LinkSessionReview {
  invitation: LinkSessionInvitation;
  /** The pairwise reference of the Viadere account that completed the session. Bind it to your customer record only after you confirmed. */
  subjectRef: string;
  /** Show it next to the SAS: "Viadere account ABCD-EFGH". The app shows the same value. */
  pseudonym: string;
  /** The six digits the app shows: show them (compare) or ask the person to type what their app shows. */
  sas: string;
  /** True when the app opened your QR or link (it proved it holds your secret). Without it only a typed SAS is accepted. */
  hasBindingTag: boolean;
  statement: T.SignedStatement;
  linkStatement: LinkStatement;
  approvalStatement: T.SignedStatement | undefined;
  approval: ApprovalEnrollmentStatement | undefined;
  /** Viadere's signed account of the completion, verified against the `link-descriptor` keys you pinned. */
  result: LinkResult;
}

/** How the person verified the SAS in your signed-in session. **Required**: the SDK never confirms without one. */
export type LinkSasCheck = { typed: string } | "compared_by_customer";

/** A confirmed link: store `subjectRef` with your customer record, and `approval` (if any) as for an Approve v2 enrollment. */
export interface ConfirmedLink {
  sessionId: string;
  subjectRef: string;
  connectionKid: string;
  approval: ConfirmedEnrollment | undefined;
}

/** A completed verification session whose signed result you verified. */
export interface VerifiedVerificationSession {
  result: VerificationSessionResult;
  /** `verified` or `not_verified` (never why). */
  outcome: "verified" | "not_verified";
  subjectRef: string;
  /** Single use: `getVerificationResult(resultRef)` returns the attribute values once. */
  resultRef: string;
}

/** What you ask for. `details` is what the customer sees on the phone; for an authentication the SDK sets `match_digits`. */
export interface AuthApprovalDraft {
  /** Default: a fresh `req_...`. */
  requestId?: string;
  subjectRef: string;
  /** Default: 256 fresh random bits. Never reuse one. */
  challenge?: string;
  details: ApprovalSubject;
  /** Default `medium`. A payment is never below `high`. */
  risk?: T.AuthApprovalRisk;
  /** Seconds, default 120. */
  expiresIn?: number;
  /** From `AuthApprovalKeys.sessionHandle(yourInitiatingSessionId)`. */
  sessionHandle?: string;
}

export interface CreateAuthApprovalOptions {
  keys: AuthApprovalKeys;
  /** The client IP address of the browser or app that started the sign-in, for the throttle. */
  requester?: { clientAddress?: string };
  /**
   * Required for a payment and for `high` or `critical` risk, which must be end to end: build one `E2EEEnvelope` per enrolled device, each
   * carrying your signed `ApprovalRequest` with this number (SECURITY.md 2.54). This SDK does not implement the HPKE sealing itself.
   */
  buildEnvelopes?: (input: { requestId: string; subjectRef: string; challenge: string; details: ApprovalSubject; numberMatch: { digits: 2 | 3; code: string }; expiresIn: number }) => T.ApprovalEnvelopeDelivery[] | Promise<T.ApprovalEnvelopeDelivery[]>;
  now?: Date;
  /** Test seam: the random bytes of the code sampler. */
  random?: (count: number) => Uint8Array;
}

/**
 * The created request: **show `code` on your own sign-in or payment screen** (never send it to the customer's phone yourself) and keep `pending`
 * to verify the result (`ApprovalVerifier.verify` requires this code). The throttle slot is freed when `getAuthApproval` sees the request end,
 * or with `client.throttle?.release(throttleSlot)`.
 */
export interface CreatedAuthApproval {
  view: T.ApprovalRequestView;
  code: string;
  pending: PendingApproval;
  throttleSlot: string | undefined;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);
const RISK_RANK: Readonly<Record<T.AuthApprovalRisk, number>> = { low: 0, medium: 1, high: 2, critical: 3 };
/** The longest a step-up may be old when you create a link session, in milliseconds. */
export const LINK_STEP_UP_WINDOW_MS = 300_000;

interface SendOptions {
  body?: unknown;
  idempotencyKey?: string;
  /** Safe to repeat although it is not a `GET` and carries no key. */
  naturallyIdempotent?: boolean;
  query?: Readonly<Record<string, string>>;
}

/**
 * A typed client for the Viadere business API (`/v1/business/*`, `/v1/verification-*`) for server-side JavaScript runtimes.
 *
 * - Authenticates with your API key; never logs it (`toString`/`toJSON` are redacted). Redirects are never followed (the API does not redirect, and
 *   following one would forward the key to another host).
 * - Sets `Idempotency-Key` where the API takes one and retries `429`, `5xx` and network failures with jittered exponential backoff, honouring
 *   `Retry-After`, only for requests that are safe to repeat.
 * - Validates every request against the contract before sending, and applies the per-requester throttle to sign-in triggers.
 * - **The tenant is your key's business**, never a field of the payload.
 * - Builds the links you show for enrollments and link sessions itself, and verifies every signed statement against your own records and pinned
 *   keys: a relay answer is never trusted on its own.
 */
export class ViadereClient {
  readonly #apiKey: string;
  readonly #baseUrl: string;
  readonly #retry: RetryPolicy;
  readonly #timeoutMs: number;
  readonly #fetch: FetchLike;
  readonly #sleep: (seconds: number) => Promise<void>;
  readonly #random: () => number;
  /** The throttle in use, or `undefined` when switched off. Feed it webhook events with `throttle.observeEvent(type, requestId)`. */
  readonly throttle: RequesterThrottle | undefined;
  /** The universal-link host of the links this client builds and accepts. */
  readonly linkDomain: string;

  constructor(options: ViadereClientOptions) {
    // `vdk_<live|test>_<kid>.<secret>` (or the older `vdk_<live|test>_<43 characters>`): printable ASCII, 20 to 80 characters.
    if (typeof options.apiKey !== "string" || !/^vdk_(?:live|test)_[\x21-\x7e]+$/.test(options.apiKey) || options.apiKey.length < 20 || options.apiKey.length > 80) {
      throw new ViadereSdkError("invalid_api_key", "The API key does not look like a Viadere key (vdk_live_... or vdk_test_...).");
    }
    const base = options.baseUrl ?? "https://api.viadere.com";
    let url: URL;
    try {
      url = new URL(base);
    } catch {
      throw new ViadereSdkError("insecure_base_url", "The base URL is not a valid URL.");
    }
    if (!(url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname)))) {
      throw new ViadereSdkError("insecure_base_url", "The base URL must be https (http is allowed only for loopback hosts, for local development).");
    }
    if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") throw new ViadereSdkError("insecure_base_url", "The base URL must not carry credentials, a query or a fragment.");
    const linkDomain = options.linkDomain ?? "viadere.com";
    if (!isValidLinkDomain(linkDomain)) throw new RangeError("linkDomain must be a plain lowercase DNS name");
    this.#apiKey = options.apiKey;
    this.#baseUrl = url.origin + url.pathname.replace(/\/+$/, "");
    this.linkDomain = linkDomain;
    this.#retry = { ...DEFAULT_RETRY, ...options.retry, maxAttempts: Math.max(1, options.retry?.maxAttempts ?? DEFAULT_RETRY.maxAttempts) };
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    this.#fetch = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
    this.#sleep = options.sleep ?? ((s) => new Promise((resolve) => setTimeout(resolve, s * 1000)));
    this.#random = options.random ?? Math.random;
    this.throttle = options.throttle === false ? undefined : options.throttle instanceof RequesterThrottle ? options.throttle : new RequesterThrottle(options.throttle ?? {});
  }

  /** Whether this client uses a live key (real customers) or a test key (sandbox only). */
  get isLive(): boolean {
    return this.#apiKey.startsWith("vdk_live_");
  }

  toString(): string {
    return `ViadereClient(${this.#baseUrl}, ${this.isLive ? "live" : "test"} key ***)`;
  }

  toJSON(): { baseUrl: string } {
    return { baseUrl: this.#baseUrl };
  }

  // ===========================================================================================================================================
  // Capabilities, sandbox

  /** `GET /v1/business/capabilities`: your tiers, entitlements (the ceiling), this key's capabilities, their intersection and the catalog. */
  async getCapabilities(): Promise<T.BusinessCapabilitiesResponse> {
    return assertResponse(schemas.BusinessCapabilitiesResponse, (await this.#send("GET", "/v1/business/capabilities")).body);
  }

  /** `POST /v1/business/sandbox/relationships` (test keys only): a sandbox consumer connected to your business. Not retried. */
  async createSandboxRelationship(): Promise<T.SandboxRelationship> {
    return assertResponse(schemas.SandboxRelationship, (await this.#send("POST", "/v1/business/sandbox/relationships")).body);
  }

  // ===========================================================================================================================================
  // Interactions, messages, statuses

  /**
   * `POST /v1/business/interactions` (scope `interactions:write`). Idempotent on `request.idempotencyKey`, which is also sent as the header.
   * `authenticate` needs the capability `auth.challenge`, `authorize` needs `transaction.approve`, every other kind `message.send`.
   */
  async issueInteraction(request: T.IssueInteractionRequest): Promise<Created<T.Interaction>> {
    return this.#create(schemas.IssueInteractionRequest, schemas.Interaction, "/v1/business/interactions", request, request.idempotencyKey);
  }

  /** `GET /v1/business/interactions/{id}` (scope `interactions:read`). A text-channel decision carries no `assurance` and no `verification`. */
  async getInteractionOutcome(interactionId: string): Promise<T.InteractionOutcome> {
    return assertResponse(schemas.InteractionOutcome, (await this.#send("GET", `/v1/business/interactions/${pathParameter("uuid", "interactionId", interactionId)}`)).body);
  }

  /** `POST .../cancel`. Cancelling an interaction that is already final returns its outcome unchanged. */
  async cancelInteraction(interactionId: string, options: IdempotencyOption = {}): Promise<T.InteractionOutcome> {
    const id = pathParameter("uuid", "interactionId", interactionId);
    const result = await this.#send("POST", `/v1/business/interactions/${id}/cancel`, { idempotencyKey: options.idempotencyKey ?? deterministicIdempotencyKey("cancel", [id]) });
    return assertResponse(schemas.InteractionOutcome, result.body);
  }

  /** `POST /v1/business/messages` (scope `messages:write`): into the customer's conversation with you. */
  async sendMessage(request: T.BusinessSendMessageRequest): Promise<Created<T.ConversationMessage>> {
    return this.#create(schemas.BusinessSendMessageRequest, schemas.ConversationMessage, "/v1/business/messages", request, request.idempotencyKey);
  }

  /** `POST /v1/business/statuses` (scope `statuses:write`): a newer status with the same `activityKey` replaces the earlier one. */
  async updateStatus(request: T.BusinessStatusUpdateRequest): Promise<Created<T.Interaction>> {
    return this.#create(schemas.BusinessStatusUpdateRequest, schemas.Interaction, "/v1/business/statuses", request, request.idempotencyKey);
  }

  // ===========================================================================================================================================
  // Rewards and loyalty (scope `rewards:write`)

  /** `POST /v1/business/rewards`. Without a customer it joins your program; with one, only that customer sees it. */
  async createReward(request: T.IssueRewardRequest): Promise<Created<T.Reward>> {
    return this.#create(schemas.IssueRewardRequest, schemas.Reward, "/v1/business/rewards", request, request.idempotencyKey);
  }

  /** `GET /v1/business/rewards`: newest first, at most 200. */
  async listRewards(): Promise<T.Reward[]> {
    return assertResponseList(schemas.Reward, (await this.#send("GET", "/v1/business/rewards")).body);
  }

  /** `POST /v1/business/rewards/{id}/revoke`: outstanding codes stop validating and held points return. Safe to repeat. */
  async revokeReward(rewardId: string): Promise<T.Reward> {
    const result = await this.#send("POST", `/v1/business/rewards/${pathParameter("uuid", "rewardId", rewardId)}/revoke`, { naturallyIdempotent: true });
    return assertResponse(schemas.Reward, result.body);
  }

  /** `GET /v1/business/loyalty/program` (`404` until you create one). */
  async getLoyaltyProgram(): Promise<T.BusinessLoyaltyProgram> {
    return assertResponse(schemas.BusinessLoyaltyProgram, (await this.#send("GET", "/v1/business/loyalty/program")).body);
  }

  /** `PUT /v1/business/loyalty/program`: creates or replaces it. Changing `termsVersion` makes customers accept the new terms to join. */
  async saveLoyaltyProgram(program: T.UpsertLoyaltyProgramRequest): Promise<T.BusinessLoyaltyProgram> {
    assertValidRequest(schemas.UpsertLoyaltyProgramRequest, program);
    return assertResponse(schemas.BusinessLoyaltyProgram, (await this.#send("PUT", "/v1/business/loyalty/program", { body: program, naturallyIdempotent: true })).body);
  }

  /** `POST /v1/business/loyalty/points`. A replay of the same key changes nothing and answers `applied: false`. */
  async adjustLoyaltyPoints(request: T.AdjustLoyaltyPointsRequest): Promise<T.LoyaltyPointsResult> {
    assertValidRequest(schemas.AdjustLoyaltyPointsRequest, request);
    return assertResponse(schemas.LoyaltyPointsResult, (await this.#send("POST", "/v1/business/loyalty/points", { body: request, idempotencyKey: request.idempotencyKey })).body);
  }

  /**
   * `POST /v1/business/redemptions/consume`: validates the code a customer shows and consumes it in one atomic step. Exactly one call can ever
   * succeed for a code (`409` already used, `410` expired or withdrawn, `404` unknown). **Never retried**: if the response is lost, a repeat
   * reports "already used", so check with the customer instead of consuming twice.
   */
  async consumeRedemption(request: T.ConsumeRedemptionRequest): Promise<T.RedemptionReceipt> {
    assertValidRequest(schemas.ConsumeRedemptionRequest, request);
    return assertResponse(schemas.RedemptionReceipt, (await this.#send("POST", "/v1/business/redemptions/consume", { body: request })).body);
  }

  // ===========================================================================================================================================
  // Wallet passes (scope `wallet:write`, live keys)

  /** `POST /v1/business/wallet/passes`: one pass per customer and subject; `created: false` for the existing pass. You never receive the pass file. */
  async issueWalletPass(request: T.BusinessIssueWalletPassRequest): Promise<Created<T.BusinessWalletPass>> {
    assertValidRequest(schemas.BusinessIssueWalletPassRequest, request);
    const result = await this.#send("POST", "/v1/business/wallet/passes", { body: request, naturallyIdempotent: true });
    return { value: assertResponse(schemas.BusinessWalletPass, result.body), created: result.status === 201 };
  }

  /** `GET /v1/business/wallet/passes`: newest first; `limit` 1 to 200 (default 50). */
  async listWalletPasses(options: { limit?: number } = {}): Promise<T.BusinessWalletPass[]> {
    const limit = options.limit ?? 50;
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw new ViadereSdkError("invalid_path", "limit must be an integer from 1 to 200.");
    return assertResponseList(schemas.BusinessWalletPass, (await this.#send("GET", "/v1/business/wallet/passes", { query: { limit: String(limit) } })).body);
  }

  /** `PATCH /v1/business/wallet/passes/{id}`: a schedule or venue change, or a fresh code. A few updates per pass per day. Not retried. */
  async updateWalletPass(passId: string, update: T.UpdateWalletPassRequest): Promise<T.BusinessWalletPass> {
    const id = pathParameter("uuid", "passId", passId);
    assertValidRequest(schemas.UpdateWalletPassRequest, update);
    return assertResponse(schemas.BusinessWalletPass, (await this.#send("PATCH", `/v1/business/wallet/passes/${id}`, { body: update })).body);
  }

  /** `POST .../void`: final. Safe to repeat. */
  async voidWalletPass(passId: string): Promise<T.BusinessWalletPass> {
    const result = await this.#send("POST", `/v1/business/wallet/passes/${pathParameter("uuid", "passId", passId)}/void`, { naturallyIdempotent: true });
    return assertResponse(schemas.BusinessWalletPass, result.body);
  }

  /**
   * `POST /v1/business/wallet/scan`: redeems a coupon, checks in a ticket or reservation, or identifies a loyalty member. **Never retried** (a
   * lost response followed by a repeat would report "already used"). A malformed code is refused locally, without a request.
   */
  async scanWalletPass(request: T.WalletScanRequest): Promise<T.WalletScanResult> {
    const trimmed = { ...request, code: typeof request.code === "string" ? request.code.trim() : request.code };
    assertValidRequest(schemas.WalletScanRequest, trimmed);
    return assertResponse(schemas.WalletScanResult, (await this.#send("POST", "/v1/business/wallet/scan", { body: trimmed })).body);
  }

  // ===========================================================================================================================================
  // Authentication delivery (ADR-0020)

  /** `POST /v1/business/auth-deliveries`. Needs scope `auth_deliveries:write` and the `auth.challenge` capability. */
  async createAuthDelivery(request: AuthDeliveryCreateRequest, options: CreateOptions = {}): Promise<CreateResult> {
    assertValidCreateRequest(request);
    const key = options.idempotencyKey ?? deterministicIdempotencyKey("authdl", [request.request_id]);
    const clientAddress = options.requester?.clientAddress;
    const slot = this.throttle?.reserve(request.subject_ref, clientAddress);
    let result: { status: number; body: unknown };
    try {
      result = await this.#send("POST", "/v1/business/auth-deliveries", { body: request, idempotencyKey: key });
    } catch (error) {
      if (slot !== undefined) this.throttle?.release(slot);
      throw error;
    }
    const delivery = this.#view(result.body);
    if (slot !== undefined) this.throttle?.confirm(slot, delivery.id, delivery.expires_at, request.subject_ref, clientAddress);
    this.throttle?.observeStatus(delivery.id, delivery.status);
    return { delivery, created: result.status === 201 };
  }

  /** `GET /v1/business/auth-deliveries/{id}`: the status and events. Never a secret. `opened` is not success. */
  async getAuthDelivery(deliveryId: string): Promise<AuthDeliveryView> {
    const result = await this.#send("GET", `/v1/business/auth-deliveries/${this.#id(deliveryId)}`);
    return this.#observe(this.#view(result.body));
  }

  /** `POST .../cancel`: deletes the secret. A delivery that already ended is returned unchanged. */
  async cancelAuthDelivery(deliveryId: string, options: IdempotencyOption = {}): Promise<AuthDeliveryView> {
    const id = this.#id(deliveryId);
    const result = await this.#send("POST", `/v1/business/auth-deliveries/${id}/cancel`, { idempotencyKey: options.idempotencyKey ?? deterministicIdempotencyKey("authdl-cancel", [id]) });
    return this.#observe(this.#view(result.body));
  }

  /**
   * `POST .../complete`: report **your own** verification outcome. Allowed only after the customer opened the delivery (`409` otherwise): Viadere
   * never infers completion, and `sent`, `delivered` and `opened` never mean success.
   */
  async completeAuthDelivery(deliveryId: string, outcome: CompleteOutcome, options: IdempotencyOption = {}): Promise<AuthDeliveryView> {
    const id = this.#id(deliveryId);
    if (!(COMPLETE_OUTCOMES as readonly string[]).includes(outcome)) throw new ViadereSdkError("invalid_path", 'outcome must be "succeeded" or "failed".');
    const body: AuthDeliveryCompleteRequest = { outcome };
    const result = await this.#send("POST", `/v1/business/auth-deliveries/${id}/complete`, { body, idempotencyKey: options.idempotencyKey ?? deterministicIdempotencyKey("authdl-done", [id, outcome]) });
    return this.#observe(this.#view(result.body));
  }

  /**
   * `POST /v1/business/auth-links/redeem` (link service): exchanges the `vdr_code` your page posted to your backend (same device) or the challenge
   * reference `ach` (cross device) and your PKCE `code_verifier` for the authority's `viadere-grant+jwt`. **Verify the grant** against the static
   * grant JWKS (`typ`, `iss`, `aud`, `cch`, `exp`) and consume its `jti` once before you sign the person in: this SDK does not verify grants.
   * Every refusal is `400 bad_request` with `details.error = invalid_grant`. Not retried (the code is single use).
   */
  async redeemAuthLink(request: T.AuthLinkRedeemRequest): Promise<T.AuthLinkRedeemResponse> {
    assertValidRequest(schemas.AuthLinkRedeemRequest, request);
    return assertResponse(schemas.AuthLinkRedeemResponse, (await this.#send("POST", "/v1/business/auth-links/redeem", { body: request })).body);
  }

  // ===========================================================================================================================================
  // Push approvals with number matching (ADR-0022)

  /**
   * `POST /v1/business/auth-approvals`. Draws the number (CSPRNG, rejection sampling), sends only its HMAC tags (plus the code itself for a
   * server-visible request), and **redraws transparently** on `409 match_code_in_use` and `409 match_digits_required` (then 3 digits), at most 20
   * times, each with a new `Idempotency-Key`. Payments and `high`/`critical` requests use 3 digits and must be end to end (`buildEnvelopes`).
   * The per-requester throttle runs first.
   */
  async createAuthApproval(draft: AuthApprovalDraft, options: CreateAuthApprovalOptions): Promise<CreatedAuthApproval> {
    if (!(options?.keys instanceof AuthApprovalKeys)) throw new TypeError("createAuthApproval needs options.keys (AuthApprovalKeys)");
    const capability = approvalCapabilityOf(draft.details);
    const declared = draft.risk ?? "medium";
    const risk: T.AuthApprovalRisk = capability === "transaction.approve" && RISK_RANK[declared] < RISK_RANK.high ? "high" : declared;
    const endToEnd = RISK_RANK[risk] >= RISK_RANK.high;
    if (endToEnd && options.buildEnvelopes === undefined) throw new ViadereFlowError("end_to_end_required");
    const requestId = draft.requestId ?? newApprovalRequestId();
    const challenge = draft.challenge ?? newApprovalChallenge();
    const expiresIn = draft.expiresIn ?? 120;
    const now = options.now ?? new Date();
    const clientAddress = options.requester?.clientAddress;
    const slot = this.throttle?.reserve(draft.subjectRef, clientAddress);
    try {
      let digits = requiredMatchDigits(capability, risk);
      for (let attempt = 0; attempt < 20; attempt++) {
        const code = drawMatchCode(digits, options.random);
        const tags = options.keys.matchTags(draft.subjectRef, code);
        if (tags === undefined) continue;
        const details: ApprovalSubject = draft.details.authentication !== undefined ? { authentication: { ...draft.details.authentication, match_digits: digits } } : draft.details;
        const common = { request_id: requestId, subject_ref: draft.subjectRef, capability, risk, expires_in_seconds: expiresIn, match_tag: tags.tag, ...(tags.prefixTag !== undefined ? { match_prefix_tag: tags.prefixTag } : {}), ...(draft.sessionHandle !== undefined ? { session_handle: draft.sessionHandle } : {}) };
        let body: T.AuthApprovalCreateRequest;
        if (endToEnd) {
          const envelopes = await options.buildEnvelopes!({ requestId, subjectRef: draft.subjectRef, challenge, details, numberMatch: { digits, code }, expiresIn });
          body = { ...common, envelopes, number_match: { digits } };
        } else {
          body = { ...common, challenge, authentication: details.authentication!, number_match: { digits, code } };
        }
        assertValidRequest(schemas.AuthApprovalCreateRequest, body);
        let result: { status: number; body: unknown };
        try {
          result = await this.#send("POST", "/v1/business/auth-approvals", { body, idempotencyKey: generateIdempotencyKey("authapproval") });
        } catch (error) {
          if (error instanceof ViadereApiError && error.status === 409) {
            if (error.code === "match_code_in_use") continue;
            if (error.code === "match_digits_required") {
              digits = 3;
              continue;
            }
            if (error.code === "match_code_space_exhausted") throw new ViadereFlowError("no_free_code", "exhausted");
          }
          throw error;
        }
        const view = assertResponse<T.ApprovalRequestView>(schemas.ApprovalRequestView, result.body);
        const throttleSlot = slot === undefined ? undefined : `approval:${requestId}`;
        if (slot !== undefined) this.throttle?.confirm(slot, throttleSlot!, view.expires_at, draft.subjectRef, clientAddress);
        const pending: PendingApproval = { requestId, subjectRef: draft.subjectRef, challenge, details, numberMatch: { required: code }, expiresAt: new Date(now.getTime() + expiresIn * 1000) };
        return { view, code, pending, throttleSlot };
      }
      throw new ViadereFlowError("no_free_code");
    } catch (error) {
      if (slot !== undefined) this.throttle?.release(slot);
      throw error;
    }
  }

  /** `GET /v1/business/auth-approvals/{requestId}`: the relay's view. **Never authorize on `status`**: verify the signed result with `ApprovalVerifier`. */
  async getAuthApproval(requestId: string): Promise<T.ApprovalRequestView> {
    const id = pathParameter("token", "requestId", requestId);
    const view = assertResponse<T.ApprovalRequestView>(schemas.ApprovalRequestView, (await this.#send("GET", `/v1/business/auth-approvals/${id}`)).body);
    if (view.status !== "pending") this.throttle?.release(`approval:${requestId}`);
    return view;
  }

  // ===========================================================================================================================================
  // Approve v2 (scope `approvals:manage`)

  /**
   * `POST /v1/business/approve/enrollments`: starts an enrollment and returns the invitation **built by the SDK**. The relay's suggested link is
   * never shown; it is only checked (host, code, no secret) and its root key id compared with **yours** (`rootKid`). A ticket that disagrees is
   * refused and the enrollment cancelled. Not retried.
   */
  async createApprovalEnrollment(request: T.CreateApprovalEnrollmentRequest, options: { rootKid: string }): Promise<ApprovalEnrollmentInvitation> {
    if (typeof options?.rootKid !== "string" || !isKid(options.rootKid)) throw new ViadereFlowError("ticket_mismatch", "rootKid");
    assertValidRequest(schemas.CreateApprovalEnrollmentRequest, request);
    const ticket = assertResponse<T.ApprovalEnrollmentTicket>(schemas.ApprovalEnrollmentTicket, (await this.#send("POST", "/v1/business/approve/enrollments", { body: request })).body);
    const parsed = typeof ticket.deep_link === "string" ? parseApprovalEnrollmentLink(ticket.deep_link, this.linkDomain) : undefined;
    const ok = typeof ticket.code === "string" && canonicalCode(ticket.code) === ticket.code && parsed !== undefined && parsed.code === ticket.code && parsed.secret === undefined && parsed.rootKid !== undefined && constantTimeEquals(parsed.rootKid, options.rootKid);
    if (!ok) {
      await this.cancelApprovalEnrollment(ticket.enrollment_id).catch(() => undefined);
      throw new ViadereFlowError("ticket_mismatch");
    }
    const secret = new ApprovalEnrollmentSecret();
    return { enrollmentId: ticket.enrollment_id, code: ticket.code, displayCode: displayCode(ticket.code), checkCode: displayCode(secret.checkCode), rootKid: options.rootKid, secret, expiresAt: ticket.expires_at, link: buildApprovalEnrollmentLink(ticket.code, options.rootKid, secret, this.linkDomain) };
  }

  /** `GET /v1/business/approve/enrollments/{id}`: includes the device's signed statement once completed. Verify it yourself. */
  async getApprovalEnrollment(enrollmentId: string): Promise<T.ApprovalEnrollmentView> {
    return assertResponse(schemas.ApprovalEnrollmentView, (await this.#send("GET", `/v1/business/approve/enrollments/${pathParameter("uuid", "enrollmentId", enrollmentId)}`)).body);
  }

  /** `POST .../cancel`. Safe to repeat. */
  async cancelApprovalEnrollment(enrollmentId: string): Promise<T.ApprovalEnrollmentView> {
    const result = await this.#send("POST", `/v1/business/approve/enrollments/${pathParameter("uuid", "enrollmentId", enrollmentId)}/cancel`, { naturallyIdempotent: true });
    return assertResponse(schemas.ApprovalEnrollmentView, result.body);
  }

  /**
   * Verifies the device's enrollment statement **yourself** and, if it is right, confirms it with your `approval-enrollment-confirmation` key
   * (`POST .../confirm`). Returns the enrollment to store: from now on your records, not the relay's, decide which key may approve.
   *
   * **A valid statement proves nothing by itself**: the relay can make a key of its own and sign a flawless statement. Before anything is signed
   * the SDK requires proof that the statement came from the customer's app, under the secret only you and that app hold: the **binding tag**
   * (the app opened your link), or `sas`, the six digits the app shows, typed into your own signed-in session. Anything else is refused; a wrong
   * tag or SAS cancels the enrollment (one guess).
   */
  async confirmApprovalEnrollment(input: { invitation: ApprovalEnrollmentInvitation; businessId: string; expectedSubjectRef: string; sas?: string; signer: Es256Signer; minimumAssurance?: ApprovalAmr; now?: Date }): Promise<ConfirmedEnrollment> {
    const id = input.invitation.enrollmentId;
    const view = await this.getApprovalEnrollment(id);
    const signed = view.device_statement;
    if (view.status !== "device_completed" || signed === undefined) throw new ViadereFlowError("not_ready", String(view.status));
    const statement = verifyApprovalEnrollmentStatement(signed);
    // The statement must be for this business, this customer and this enrollment: nothing the relay says is trusted.
    checkApprovalEnrollmentBinding(statement, { businessId: input.businessId, subjectRef: input.expectedSubjectRef, enrollmentId: id });
    if (!assuranceSatisfies(statement.assurance, input.minimumAssurance ?? "biometric")) throw new StatementVerificationError("assurance_too_low");
    // Who made this statement? Only the holder of the secret can say so.
    if (view.binding_tag !== undefined) {
      if (!input.invitation.secret.verifyBindingTag(view.binding_tag, signed)) {
        await this.cancelApprovalEnrollment(id).catch(() => undefined);
        throw new ViadereFlowError("binding_tag_invalid");
      }
    } else {
      if (input.sas === undefined) throw new ViadereFlowError("verification_required");
      if (!input.invitation.secret.verifySas(input.sas, signed)) {
        await this.cancelApprovalEnrollment(id).catch(() => undefined);
        throw new ViadereFlowError("sas_mismatch");
      }
    }
    const confirmation = await signApprovalEnrollmentConfirmation(statement, signed, input.signer, input.now);
    await this.confirmApprovalEnrollmentRaw(id, { confirmation });
    return { enrollmentId: id, key: { kid: statement.kid, publicKey: statement.publicKey, subjectRef: statement.subjectRef, assurance: statement.assurance }, hpkePublicKey: statement.hpkePublicKey, hpkeKid: statement.hpkeKid, statement: signed };
  }

  /**
   * `POST /v1/business/approve/enrollments/{id}/confirm` with a confirmation you signed yourself. Prefer `confirmApprovalEnrollment`, which
   * verifies the statement, the binding tag or SAS and the assurance first. Not retried.
   */
  async confirmApprovalEnrollmentRaw(enrollmentId: string, request: T.ConfirmApprovalEnrollmentRequest): Promise<T.ApprovalKeyView> {
    const id = pathParameter("uuid", "enrollmentId", enrollmentId);
    assertValidRequest(schemas.ConfirmApprovalEnrollmentRequest, request);
    return assertResponse(schemas.ApprovalKeyView, (await this.#send("POST", `/v1/business/approve/enrollments/${id}/confirm`, { body: request })).body);
  }

  /** `GET /v1/business/approve/keys?subject_ref=`. **For display and reconciliation only**: authorize against your own key store. */
  async listApprovalKeys(subjectRef: string): Promise<T.ApprovalKeyView[]> {
    pathParameter("subjectRef", "subjectRef", subjectRef);
    return assertResponseList(schemas.ApprovalKeyView, (await this.#send("GET", "/v1/business/approve/keys", { query: { subject_ref: subjectRef } })).body);
  }

  /** `POST /v1/business/approve/keys/{kid}/revoke`. Also mark the key revoked in your own store: that is what you verify against. Safe to repeat. */
  async revokeApprovalKey(kid: string, request: T.RevokeApprovalKeyRequest = {}): Promise<T.ApprovalKeyView> {
    const id = pathParameter("kid", "kid", kid);
    assertValidRequest(schemas.RevokeApprovalKeyRequest, request);
    return assertResponse(schemas.ApprovalKeyView, (await this.#send("POST", `/v1/business/approve/keys/${id}/revoke`, { body: request, naturallyIdempotent: true })).body);
  }

  /** `POST /v1/business/approve/requests`. `request_id` makes the call idempotent (`created: false` for the original). */
  async createApprovalRequest(request: T.CreateApprovalRequest): Promise<Created<T.ApprovalRequestView>> {
    assertValidRequest(schemas.CreateApprovalRequest, request);
    const result = await this.#send("POST", "/v1/business/approve/requests", { body: request, naturallyIdempotent: true });
    return { value: assertResponse(schemas.ApprovalRequestView, result.body), created: result.status === 201 };
  }

  /** `GET /v1/business/approve/requests/{requestId}`. **Never authorize on `status`**: fetch the result and verify it with `ApprovalVerifier`. */
  async getApprovalRequest(requestId: string): Promise<T.ApprovalRequestView> {
    return assertResponse(schemas.ApprovalRequestView, (await this.#send("GET", `/v1/business/approve/requests/${pathParameter("token", "requestId", requestId)}`)).body);
  }

  /** `POST .../cancel`. A request already decided is `409`. */
  async cancelApprovalRequest(requestId: string): Promise<T.ApprovalRequestView> {
    const result = await this.#send("POST", `/v1/business/approve/requests/${pathParameter("token", "requestId", requestId)}/cancel`, { naturallyIdempotent: true });
    return assertResponse(schemas.ApprovalRequestView, result.body);
  }

  /** `GET /v1/business/approve/results/{resultRef}`: the signed result. **Do not grant anything on this response alone**: verify `result`. */
  async getApprovalResult(resultRef: string): Promise<T.ApprovalResultResponse> {
    return assertResponse(schemas.ApprovalResultResponse, (await this.#send("GET", `/v1/business/approve/results/${pathParameter("token", "resultRef", resultRef)}`)).body);
  }

  /** `POST /v1/business/approve/freeze`: stops (or resumes) approvals for one customer. You can lift only your own freeze. */
  async freezeApprovals(request: T.BusinessFreezeRequest): Promise<T.FreezeStatus> {
    assertValidRequest(schemas.BusinessFreezeRequest, request);
    return assertResponse(schemas.FreezeStatus, (await this.#send("POST", "/v1/business/approve/freeze", { body: request, naturallyIdempotent: true })).body);
  }

  /** `GET /v1/business/approve/freezes/{freezeRef}`: resolves the opaque `request_id` of an `approve.frozen` webhook (`frz_...`). */
  async getApprovalFreeze(freezeRef: string): Promise<T.FreezeStatus> {
    return assertResponse(schemas.FreezeStatus, (await this.#send("GET", `/v1/business/approve/freezes/${pathParameter("token", "freezeRef", freezeRef)}`)).body);
  }

  /** `GET /v1/business/approve/settings`. */
  async getApproveSettings(): Promise<T.ApproveBusinessSettings> {
    return assertResponse(schemas.ApproveBusinessSettings, (await this.#send("GET", "/v1/business/approve/settings")).body);
  }

  /** `PUT /v1/business/approve/settings`. `single_device`: activating a key revokes the customer's other keys for your business. */
  async putApproveSettings(settings: T.ApproveBusinessSettings): Promise<T.ApproveBusinessSettings> {
    assertValidRequest(schemas.ApproveBusinessSettings, settings);
    return assertResponse(schemas.ApproveBusinessSettings, (await this.#send("PUT", "/v1/business/approve/settings", { body: settings, naturallyIdempotent: true })).body);
  }

  // ===========================================================================================================================================
  // Link sessions (scope `links:manage`)

  /**
   * `POST /v1/business/link-sessions` for the customer you **just** authenticated (`customerAuthenticatedAt` at most five minutes ago, else
   * `step_up_required` and nothing is sent). Returns the invitation built by the SDK; a ticket that names another root key or host is refused
   * and the session cancelled. Not retried.
   */
  async createLinkSession(request: T.CreateLinkSessionRequest, options: { rootKid: string; customerAuthenticatedAt: Date; now?: Date }): Promise<LinkSessionInvitation> {
    const now = (options.now ?? new Date()).getTime();
    const authenticated = options?.customerAuthenticatedAt instanceof Date ? options.customerAuthenticatedAt.getTime() : Number.NaN;
    if (!(authenticated <= now + 60_000 && now - authenticated <= LINK_STEP_UP_WINDOW_MS)) throw new ViadereFlowError("step_up_required");
    if (typeof options.rootKid !== "string" || !isKid(options.rootKid)) throw new ViadereFlowError("ticket_mismatch", "rootKid");
    assertValidRequest(schemas.CreateLinkSessionRequest, request);
    const ticket = assertResponse<T.LinkSessionTicket>(schemas.LinkSessionTicket, (await this.#send("POST", "/v1/business/link-sessions", { body: request })).body);
    const parsed = typeof ticket.link === "string" ? parseLinkSessionLink(ticket.link, this.linkDomain) : undefined;
    const ok = typeof ticket.code === "string" && canonicalCode(ticket.code) === ticket.code && parsed !== undefined && parsed.code === ticket.code && parsed.secret === undefined && typeof ticket.root_kid === "string" && constantTimeEquals(ticket.root_kid, options.rootKid);
    if (!ok) {
      await this.cancelLinkSession(ticket.session_id).catch(() => undefined);
      throw new ViadereFlowError("ticket_mismatch");
    }
    const secret = new LinkSessionSecret();
    return { sessionId: ticket.session_id, code: ticket.code, displayCode: displayCode(ticket.code), checkCode: displayCode(secret.checkCode), rootKid: options.rootKid, secret, capabilities: canonicalCapabilities(request.capabilities), expiresAt: ticket.expires_at, link: buildLinkSessionLink(ticket.code, secret, this.linkDomain) };
  }

  /** `GET /v1/business/link-sessions/{id}`. */
  async getLinkSession(sessionId: string): Promise<T.LinkSessionView> {
    return assertResponse(schemas.LinkSessionView, (await this.#send("GET", `/v1/business/link-sessions/${pathParameter("uuid", "sessionId", sessionId)}`)).body);
  }

  /** `POST .../cancel` (also ends a pending connection and key). Idempotent. */
  async cancelLinkSession(sessionId: string): Promise<T.LinkSessionView> {
    const result = await this.#send("POST", `/v1/business/link-sessions/${pathParameter("uuid", "sessionId", sessionId)}/cancel`, { naturallyIdempotent: true });
    return assertResponse(schemas.LinkSessionView, result.body);
  }

  /**
   * After `link.completed`: fetches the session and verifies everything **yourself**: Viadere's signed result against the `link-descriptor` keys
   * you pinned (`viadereKeys`, base64url X9.63), the device's statement (this session, your business, the account the result names, exactly your
   * capabilities), the approval statement it commits to, and the binding tag under your secret. Then show `review.sas` and `review.pseudonym` in
   * your signed-in session.
   */
  async reviewLinkSession(input: { invitation: LinkSessionInvitation; businessId: string; viadereKeys: readonly string[] }): Promise<LinkSessionReview> {
    const { invitation } = input;
    const view = await this.getLinkSession(invitation.sessionId);
    const signed = view.statement;
    if (view.status !== "device_completed" || signed === undefined || view.result === undefined) throw new ViadereFlowError("not_ready", String(view.status));
    const result = verifyLinkResult(view.result, input.viadereKeys);
    const approvalDigest = view.approval_statement === undefined ? undefined : statementDigest(view.approval_statement);
    if (result.sessionId !== invitation.sessionId.toLowerCase() || result.businessId !== input.businessId.toLowerCase() || !constantTimeEquals(result.statementDigest, statementDigest(signed)) || result.approvalStatementDigest !== approvalDigest) {
      throw new StatementVerificationError("statement_mismatch", "result");
    }
    const linkStatement = verifyLinkStatement(signed);
    checkLinkStatementBinding(linkStatement, { sessionId: invitation.sessionId, businessId: input.businessId, subjectRef: result.subjectRef, capabilities: invitation.capabilities });
    const approval = checkLinkApprovalStatement(linkStatement, view.approval_statement);
    if (view.binding_tag !== undefined && !invitation.secret.verifyBindingTag(view.binding_tag, signed)) {
      await this.cancelLinkSession(invitation.sessionId).catch(() => undefined);
      throw new ViadereFlowError("binding_tag_invalid");
    }
    return { invitation, subjectRef: result.subjectRef, pseudonym: linkPseudonym(result.subjectRef), sas: invitation.secret.expectedSas(signed), hasBindingTag: view.binding_tag !== undefined, statement: signed, linkStatement, approvalStatement: view.approval_statement, approval, result };
  }

  /**
   * Confirms a reviewed session with your `approval-enrollment-confirmation` key (`POST .../confirm`). **Refuses without a SAS check**; a wrong
   * typed SAS cancels the session. Afterwards send the customer an out-of-band notice through your own channel ("A Viadere app was linked to
   * your account. Not you?") with a way to revoke.
   */
  async confirmLinkSession(review: LinkSessionReview, input: { sasCheck: LinkSasCheck; signer: Es256Signer; now?: Date }): Promise<ConfirmedLink> {
    const sasCheck = input?.sasCheck;
    if (sasCheck === undefined || sasCheck === null) throw new ViadereFlowError("sas_comparison_required");
    const sessionId = review.invitation.sessionId;
    let verification: "sas_typed" | "sas_compared";
    if (sasCheck === "compared_by_customer") {
      if (!review.hasBindingTag) throw new ViadereFlowError("typed_sas_required");
      verification = "sas_compared";
    } else if (typeof sasCheck === "object" && typeof sasCheck.typed === "string") {
      if (!review.invitation.secret.verifySas(sasCheck.typed, review.statement)) {
        await this.cancelLinkSession(sessionId).catch(() => undefined);
        throw new ViadereFlowError("sas_mismatch");
      }
      verification = "sas_typed";
    } else throw new ViadereFlowError("sas_comparison_required");
    const confirmation = await signLinkConfirmation(review.linkStatement, review.statement, verification, input.signer, input.now);
    let approvalConfirmation: T.BusinessSignedStatement | undefined;
    let approval: ConfirmedEnrollment | undefined;
    if (review.approval !== undefined && review.approvalStatement !== undefined) {
      const a = review.approval;
      approvalConfirmation = await signApprovalEnrollmentConfirmation(a, review.approvalStatement, input.signer, input.now);
      approval = { enrollmentId: sessionId, key: { kid: a.kid, publicKey: a.publicKey, subjectRef: a.subjectRef, assurance: a.assurance }, hpkePublicKey: a.hpkePublicKey, hpkeKid: a.hpkeKid, statement: review.approvalStatement };
    }
    await this.confirmLinkSessionRaw(sessionId, { confirmation, ...(approvalConfirmation !== undefined ? { approval_confirmation: approvalConfirmation } : {}) });
    return { sessionId, subjectRef: review.subjectRef, connectionKid: review.linkStatement.kid, approval };
  }

  /** `POST /v1/business/link-sessions/{id}/confirm` with confirmations you signed yourself. Prefer `reviewLinkSession` and `confirmLinkSession`. Not retried. */
  async confirmLinkSessionRaw(sessionId: string, request: T.ConfirmLinkSessionRequest): Promise<T.LinkSessionView> {
    const id = pathParameter("uuid", "sessionId", sessionId);
    assertValidRequest(schemas.ConfirmLinkSessionRequest, request);
    return assertResponse(schemas.LinkSessionView, (await this.#send("POST", `/v1/business/link-sessions/${id}/confirm`, { body: request })).body);
  }

  // ===========================================================================================================================================
  // "Verify with Viadere": verification sessions, requests and results

  /**
   * `POST /v1/business/verification-sessions` (server side only, live keys). Give the ticket's `link` to the button and keep `session_id` with
   * your visitor's own session. The relay's link is checked before anything shows it (the configured link domain, `/v/{CODE}`, nothing else); a
   * ticket that fails is refused and the session cancelled. Not retried.
   */
  async createVerificationSession(request: T.CreateVerificationSessionRequest): Promise<T.VerificationSessionTicket> {
    assertValidRequest(schemas.CreateVerificationSessionRequest, request);
    const ticket = assertResponse<T.VerificationSessionTicket>(schemas.VerificationSessionTicket, (await this.#send("POST", "/v1/business/verification-sessions", { body: request })).body);
    if (typeof ticket.code !== "string" || canonicalCode(ticket.code) !== ticket.code || typeof ticket.link !== "string" || parseVerificationSessionLink(ticket.link, this.linkDomain) !== ticket.code) {
      await this.cancelVerificationSession(ticket.session_id).catch(() => undefined);
      throw new ViadereFlowError("ticket_mismatch");
    }
    return ticket;
  }

  /** `GET /v1/business/verification-sessions/{id}`. **Trust only `result`**, after verifying it (`getVerifiedVerificationSession`). */
  async getVerificationSession(sessionId: string): Promise<T.VerificationSessionView> {
    return assertResponse(schemas.VerificationSessionView, (await this.#send("GET", `/v1/business/verification-sessions/${pathParameter("uuid", "sessionId", sessionId)}`)).body);
  }

  /** `POST .../cancel` (an accepted session runs to its result). Safe to repeat. */
  async cancelVerificationSession(sessionId: string): Promise<T.VerificationSessionView> {
    const result = await this.#send("POST", `/v1/business/verification-sessions/${pathParameter("uuid", "sessionId", sessionId)}/cancel`, { naturallyIdempotent: true });
    return assertResponse(schemas.VerificationSessionView, result.body);
  }

  /**
   * Reads the session and verifies **everything yourself**: Viadere's signature (`VIADERE-VERIFY-SESSION-RESULT-V1`) against the
   * `link-descriptor` keys you pinned, that the result is for this session, your business, the origin and the capability you asked for, and that
   * the result reference is the one the signed result commits to. Throws `not_ready` until the person finished. **Never let the browser or your
   * app tell your server that a person is verified.**
   */
  async getVerifiedVerificationSession(input: { sessionId: string; businessId: string; origin: string; capability: string; viadereKeys: readonly string[] }): Promise<VerifiedVerificationSession> {
    const view = await this.getVerificationSession(input.sessionId);
    if (view.status !== "completed" || view.result === undefined || typeof view.result_ref !== "string") throw new ViadereFlowError("not_ready", String(view.status));
    const result = verifyVerificationSessionResult(view.result, input.viadereKeys);
    checkVerificationSessionResult(result, input);
    if (!verificationResultMatchesRef(result, view.result_ref)) throw new ViadereFlowError("result_ref_mismatch");
    return { result, outcome: result.outcome, subjectRef: result.subjectRef, resultRef: view.result_ref };
  }

  /** `POST /v1/verification-requests`: asks a connected customer to verify an age threshold or an identity attribute. `callback_id` is a registered webhook endpoint, never a URL. */
  async createVerificationRequest(request: T.CreateVerificationRequest, options: IdempotencyOption = {}): Promise<Created<T.VerificationRequest>> {
    return this.#create(schemas.CreateVerificationRequest, schemas.VerificationRequest, "/v1/verification-requests", request, options.idempotencyKey ?? generateIdempotencyKey("verify"));
  }

  /** `GET /v1/verification-requests/{requestId}`: `pending`, or `completed` with a `result_ref`. */
  async getVerificationRequest(requestId: string): Promise<T.VerificationRequest> {
    return assertResponse(schemas.VerificationRequest, (await this.#send("GET", `/v1/verification-requests/${pathParameter("verificationRequestId", "requestId", requestId)}`)).body);
  }

  /**
   * `GET /v1/verification-results/{resultRef}`: retrieves a result **once** (a second call is `410`; results expire after 15 minutes). Store what
   * you need. `not_verified` never says why.
   */
  async getVerificationResult(resultRef: string): Promise<T.VerificationResult> {
    return assertResponse(schemas.VerificationResult, (await this.#send("GET", `/v1/verification-results/${pathParameter("verificationResultRef", "resultRef", resultRef)}`)).body);
  }

  // ===========================================================================================================================================
  // Profiles (scope `profiles:read`)

  /** `POST /v1/business/profile-requests`: asks a connected customer for profile fields. A field outside your allowed categories is `403 not_entitled`. */
  async createProfileRequest(request: T.CreateProfileRequest, options: IdempotencyOption = {}): Promise<Created<T.ProfileRequestResource>> {
    return this.#create(schemas.CreateProfileRequest, schemas.ProfileRequestResource, "/v1/business/profile-requests", request, options.idempotencyKey ?? generateIdempotencyKey("profile"));
  }

  /** `GET /v1/business/profile-requests/{id}`. */
  async getProfileRequest(requestId: string): Promise<T.ProfileRequestResource> {
    return assertResponse(schemas.ProfileRequestResource, (await this.#send("GET", `/v1/business/profile-requests/${pathParameter("uuid", "requestId", requestId)}`)).body);
  }

  /** `GET /v1/business/profiles/{subjectRef}`: the public name and the fields the customer grants you now. Do not cache beyond your own need. */
  async getProfile(subjectRef: string): Promise<T.BusinessProfileView> {
    return assertResponse(schemas.BusinessProfileView, (await this.#send("GET", `/v1/business/profiles/${pathParameter("subjectRef", "subjectRef", subjectRef)}`)).body);
  }

  // ===========================================================================================================================================
  // Key directory (scope `keydirectory:manage`, live keys)

  /**
   * `POST /v1/business/key-directory/entries`: publishes one signed entry (the base64url canonical `KeyLogEntry`). Not retried: a repeated entry
   * would be refused anyway. This SDK transports entries; it does not build or sign them, and it does not verify the transparency log (see the
   * README): use the Swift SDK's `BusinessKeyAuthority` and `viadere-key-monitor` for that.
   */
  async publishKeyEntry(request: T.PublishKeyEntryRequest): Promise<T.PublishKeyEntryResponse> {
    assertValidRequest(schemas.PublishKeyEntryRequest, request);
    return assertResponse(schemas.PublishKeyEntryResponse, (await this.#send("POST", "/v1/business/key-directory/entries", { body: request })).body);
  }

  /** `GET /v1/business/key-directory/entries`: your own entries with proofs. `since` is the tree size you last verified. **Unverified here.** */
  async listKeyEntries(options: { since?: number } = {}): Promise<T.KeyDirectoryResponse> {
    if (options.since !== undefined && (!Number.isSafeInteger(options.since) || options.since < 0)) throw new ViadereSdkError("invalid_path", "since must be a non-negative integer.");
    const result = await this.#send("GET", "/v1/business/key-directory/entries", options.since !== undefined ? { query: { since: String(options.since) } } : {});
    return assertResponse(schemas.KeyDirectoryResponse, result.body);
  }

  // ===========================================================================================================================================
  // Webhook endpoints (scope `webhooks:manage`)

  /** `GET /v1/business/webhooks`. */
  async listWebhooks(): Promise<T.WebhookSubscription[]> {
    return assertResponseList(schemas.WebhookSubscription, (await this.#send("GET", "/v1/business/webhooks")).body);
  }

  /**
   * `POST /v1/business/webhooks`. The returned `secret` is shown **once**: store it in your secrets manager and never log it. A retry with the
   * same key and body returns the same subscription and secret for 24 hours (then `410`).
   */
  async createWebhook(request: T.CreateWebhookRequest, options: IdempotencyOption = {}): Promise<Created<T.WebhookSecretResponse>> {
    return this.#create(schemas.CreateWebhookRequest, schemas.WebhookSecretResponse, "/v1/business/webhooks", request, options.idempotencyKey ?? generateIdempotencyKey("webhook"));
  }

  /** `DELETE /v1/business/webhooks/{id}`. Pending deliveries to the endpoint are dropped. Not retried. */
  async deleteWebhook(webhookId: string): Promise<void> {
    await this.#send("DELETE", `/v1/business/webhooks/${pathParameter("uuid", "webhookId", webhookId)}`);
  }

  /** `PATCH /v1/business/webhooks/{id}`: move an endpoint to signature v2 (no way back). */
  async updateWebhook(webhookId: string, request: UpdateWebhookRequest = { signature_version: "v2" }, options: IdempotencyOption = {}): Promise<Record<string, unknown>> {
    const id = pathParameter("uuid", "webhookId", webhookId);
    if (request?.signature_version !== "v2" || Object.keys(request).length !== 1) throw new ViadereSdkError("invalid_path", 'The only update is { signature_version: "v2" }.');
    const result = await this.#send("PATCH", `/v1/business/webhooks/${id}`, { body: request, idempotencyKey: options.idempotencyKey ?? deterministicIdempotencyKey("webhook-v2", [id, request.signature_version]) });
    return result.body as Record<string, unknown>;
  }

  /** `POST .../rotate-secret`: the previous secret keeps signing for 24 hours (verify with both). The new secret is shown once. */
  async rotateWebhookSecret(webhookId: string, options: IdempotencyOption = {}): Promise<T.WebhookSecretResponse> {
    const id = pathParameter("uuid", "webhookId", webhookId);
    const result = await this.#send("POST", `/v1/business/webhooks/${id}/rotate-secret`, { idempotencyKey: options.idempotencyKey ?? generateIdempotencyKey("rotate") });
    return assertResponse(schemas.WebhookSecretResponse, result.body);
  }

  /**
   * `POST .../verify`: Viadere sends a signed, single-use challenge the endpoint must answer with `WebhookVerifierV1.verificationResponse` (a
   * plain echo is refused). Until an endpoint is verified it receives no events. A failed check is `verified: false` with a `failure`.
   */
  async verifyWebhook(webhookId: string): Promise<T.WebhookVerificationResult> {
    const result = await this.#send("POST", `/v1/business/webhooks/${pathParameter("uuid", "webhookId", webhookId)}/verify`, { naturallyIdempotent: true });
    return assertResponse(schemas.WebhookVerificationResult, result.body);
  }

  /** `POST .../test`: queues one signed `webhook.test` event (no customer data) through the normal delivery worker. Not retried. */
  async testWebhook(webhookId: string): Promise<void> {
    await this.#send("POST", `/v1/business/webhooks/${pathParameter("uuid", "webhookId", webhookId)}/test`);
  }

  /** `POST .../pause`: events keep queueing and go out after `resumeWebhook`. Idempotent. */
  async pauseWebhook(webhookId: string, request: T.PauseWebhookRequest = {}): Promise<void> {
    const id = pathParameter("uuid", "webhookId", webhookId);
    assertValidRequest(schemas.PauseWebhookRequest, request);
    await this.#send("POST", `/v1/business/webhooks/${id}/pause`, { body: request, naturallyIdempotent: true });
  }

  /** `POST .../resume`. Idempotent. */
  async resumeWebhook(webhookId: string): Promise<void> {
    await this.#send("POST", `/v1/business/webhooks/${pathParameter("uuid", "webhookId", webhookId)}/resume`, { naturallyIdempotent: true });
  }

  /** `POST /v1/business/webhooks/test` (test keys only): a signed sample `auth.delivery.*` event with fixed sample ids to one of your v2 endpoints. */
  async testAuthWebhook(request: AuthWebhookTestRequest, options: IdempotencyOption = {}): Promise<AuthWebhookTestResponse> {
    const result = await this.#send("POST", "/v1/business/webhooks/test", { body: request, idempotencyKey: options.idempotencyKey ?? generateIdempotencyKey("webhook-test") });
    const body = result.body as Partial<AuthWebhookTestResponse> | null;
    if (!body || typeof body.event_id !== "string") throw new ViadereSdkError("invalid_response", "The response is not a webhook test result.");
    return { event_id: body.event_id };
  }

  // -------------------------------------------------------------------------------------------------------------------------------------------

  /** Validates, sends with the idempotency key, checks the response: the shape of every keyed create (`201`, or `200` for a replay). */
  async #create<X>(requestSchema: schemas.SchemaDef, responseSchema: schemas.SchemaDef, path: string, request: unknown, idempotencyKey: string): Promise<Created<X>> {
    assertValidRequest(requestSchema, request);
    const result = await this.#send("POST", path, { body: request, idempotencyKey });
    return { value: assertResponse<X>(responseSchema, result.body), created: result.status === 201 };
  }

  #id(deliveryId: string): string {
    if (typeof deliveryId !== "string" || !DELIVERY_ID_PATTERN.test(deliveryId)) throw new ViadereSdkError("invalid_path", "deliveryId must be adl_ plus 22 base64url characters.");
    return deliveryId;
  }

  #view(body: unknown): AuthDeliveryView {
    const v = body as Partial<AuthDeliveryView> | null;
    if (!v || typeof v !== "object" || typeof v.id !== "string" || typeof v.status !== "string" || typeof v.request_id !== "string") {
      throw new ViadereSdkError("invalid_response", "The response is not an auth delivery.");
    }
    return v as AuthDeliveryView;
  }

  #observe(view: AuthDeliveryView): AuthDeliveryView {
    this.throttle?.observeStatus(view.id, view.status);
    return view;
  }

  async #send(method: string, path: string, options: SendOptions = {}): Promise<{ status: number; body: unknown }> {
    // The key goes in the Authorization header and nowhere else: never in a URL, an error message or a log line.
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.#apiKey}`,
      Accept: "application/json",
      "User-Agent": `viadere-server-node/${SDK_VERSION}`,
    };
    let payload: string | undefined;
    if (options.body !== undefined) {
      payload = JSON.stringify(options.body);
      headers["Content-Type"] = "application/json";
    }
    if (options.idempotencyKey !== undefined) {
      if (typeof options.idempotencyKey !== "string" || !isValidIdempotencyKey(options.idempotencyKey)) throw new ViadereSdkError("invalid_idempotency_key", "The idempotency key must match [A-Za-z0-9_.:-]{1,128}.");
      headers["Idempotency-Key"] = options.idempotencyKey;
    }
    const query = options.query ? "?" + new URLSearchParams(options.query).toString() : "";
    const retryable = method === "GET" || options.idempotencyKey !== undefined || options.naturallyIdempotent === true;
    const maxAttempts = retryable ? this.#retry.maxAttempts : 1;
    for (let attempt = 1; ; attempt++) {
      let response: Awaited<ReturnType<FetchLike>>;
      try {
        response = await this.#fetch(this.#baseUrl + path + query, { method, headers, ...(payload !== undefined ? { body: payload } : {}), redirect: "manual", signal: AbortSignal.timeout(this.#timeoutMs) });
      } catch {
        if (attempt < maxAttempts) {
          await this.#sleep(this.#delay(attempt, undefined));
          continue;
        }
        throw new ViadereSdkError("transport", retryable ? "The request failed locally (network, TLS or timeout) on every attempt." : "The request failed locally (network, TLS or timeout). It was not retried: it is not safe to repeat, and it may have been applied.");
      }
      const text = await response.text().catch(() => "");
      if (response.status >= 200 && response.status < 300) {
        let parsed: unknown;
        try {
          parsed = text === "" ? null : JSON.parse(text);
        } catch {
          throw new ViadereSdkError("invalid_response", "The response body is not JSON.");
        }
        return { status: response.status, body: parsed };
      }
      const retryAfterRaw = response.headers.get("Retry-After");
      const retryAfter = retryAfterRaw !== null && /^\d{1,6}$/.test(retryAfterRaw) ? Number(retryAfterRaw) : undefined;
      let errorBody: unknown;
      try {
        errorBody = JSON.parse(text);
      } catch {
        errorBody = undefined;
      }
      const error = ViadereApiError.fromBody(response.status, errorBody, { retryAfter, requestId: response.headers.get("X-Request-Id") ?? undefined });
      if (error.isRetryable && attempt < maxAttempts) {
        await this.#sleep(this.#delay(attempt, retryAfter));
        continue;
      }
      throw error;
    }
  }

  /** `Retry-After` wins (capped); otherwise exponential backoff with full jitter. */
  #delay(attempt: number, retryAfter: number | undefined): number {
    if (retryAfter !== undefined) return Math.min(Math.max(0, retryAfter), this.#retry.maxDelaySeconds);
    const exponential = Math.min(this.#retry.maxDelaySeconds, this.#retry.baseDelaySeconds * 2 ** (attempt - 1));
    return this.#random() * exponential;
  }
}
