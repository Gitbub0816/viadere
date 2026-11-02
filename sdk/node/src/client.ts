import { ViadereApiError, ViadereSdkError } from "./errors.js";
import { deterministicIdempotencyKey, isValidIdempotencyKey } from "./idempotency.js";
import { RequesterThrottle } from "./throttle.js";
import {
  COMPLETE_OUTCOMES,
  type AuthDeliveryCompleteRequest,
  type AuthDeliveryCreateRequest,
  type AuthDeliveryView,
  type AuthWebhookTestRequest,
  type AuthWebhookTestResponse,
  type CompleteOutcome,
  type UpdateWebhookRequest,
} from "./types.js";
import { assertValidCreateRequest, DELIVERY_ID_PATTERN } from "./validate.js";

export const SDK_VERSION = "0.1.0";

/** Retries for transient failures (network errors, `429`, `5xx`). Only requests that are safe to repeat are retried: every `GET` and every `POST` that carries an idempotency key (the client always sets one). */
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
  /** Your business API key (`vdk_...`). Keep it on your server: never ship it in a browser or an app. */
  apiKey: string;
  /** Default `https://api.viadere.com`. `http` is accepted only for loopback hosts, for local development against a dev server. */
  baseUrl?: string;
  retry?: Partial<RetryPolicy>;
  /** Per-attempt timeout in milliseconds (default 30 000). */
  timeoutMs?: number;
  /**
   * The per-requester throttle (C-14), **on by default**: at most 3 open deliveries per account and client network prefix; the next `create` throws
   * `ViadereThrottledError` before anything is sent. Pass options to tune it, your own instance to share it, or `false` to turn it off (not
   * recommended: Viadere deliberately never refuses by per-customer count, so this cap is the only brake on push-bombing).
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

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * A typed client for the Viadere authentication-delivery business API (`/v1/business/auth-deliveries`, ADR-0020) for server-side JavaScript runtimes.
 *
 * - Authenticates with your API key; never logs it (`toString`/`toJSON` are redacted). Redirects are never followed (the API does not redirect, and
 *   following one would forward the key to another host).
 * - Sets `Idempotency-Key` on every `POST` and retries `429`, `5xx` and network failures with jittered exponential backoff, honouring `Retry-After`.
 * - Validates a create request against the contract before sending, and applies the per-requester throttle.
 * - **The tenant is your key's business**, never a field of the payload.
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

  constructor(options: ViadereClientOptions) {
    if (!/^vdk_[A-Za-z0-9_-]{8,}$/.test(options.apiKey)) throw new ViadereSdkError("invalid_api_key", "The API key does not look like a Viadere key (vdk_...).");
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
    this.#apiKey = options.apiKey;
    this.#baseUrl = url.origin + url.pathname.replace(/\/+$/, "");
    this.#retry = { ...DEFAULT_RETRY, ...options.retry, maxAttempts: Math.max(1, options.retry?.maxAttempts ?? DEFAULT_RETRY.maxAttempts) };
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    this.#fetch = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
    this.#sleep = options.sleep ?? ((s) => new Promise((resolve) => setTimeout(resolve, s * 1000)));
    this.#random = options.random ?? Math.random;
    this.throttle = options.throttle === false ? undefined : options.throttle instanceof RequesterThrottle ? options.throttle : new RequesterThrottle(options.throttle ?? {});
  }

  toString(): string {
    return `ViadereClient(${this.#baseUrl}, key ***)`;
  }

  toJSON(): { baseUrl: string } {
    return { baseUrl: this.#baseUrl };
  }

  /** `POST /v1/business/auth-deliveries`. Needs scope `auth_deliveries:write` and the `auth.challenge` capability. */
  async createAuthDelivery(request: AuthDeliveryCreateRequest, options: CreateOptions = {}): Promise<CreateResult> {
    assertValidCreateRequest(request);
    const key = options.idempotencyKey ?? deterministicIdempotencyKey("authdl", [request.request_id]);
    const clientAddress = options.requester?.clientAddress;
    const slot = this.throttle?.reserve(request.subject_ref, clientAddress);
    let result: { status: number; body: unknown };
    try {
      result = await this.#send("POST", "/v1/business/auth-deliveries", request, key);
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
  async cancelAuthDelivery(deliveryId: string, options: { idempotencyKey?: string } = {}): Promise<AuthDeliveryView> {
    const id = this.#id(deliveryId);
    const result = await this.#send("POST", `/v1/business/auth-deliveries/${id}/cancel`, undefined, options.idempotencyKey ?? deterministicIdempotencyKey("authdl-cancel", [id]));
    return this.#observe(this.#view(result.body));
  }

  /**
   * `POST .../complete`: report **your own** verification outcome. Allowed only after the customer opened the delivery (`409` otherwise): Viadere
   * never infers completion, and `sent`, `delivered` and `opened` never mean success.
   */
  async completeAuthDelivery(deliveryId: string, outcome: CompleteOutcome, options: { idempotencyKey?: string } = {}): Promise<AuthDeliveryView> {
    const id = this.#id(deliveryId);
    if (!(COMPLETE_OUTCOMES as readonly string[]).includes(outcome)) throw new ViadereSdkError("invalid_path", 'outcome must be "succeeded" or "failed".');
    const body: AuthDeliveryCompleteRequest = { outcome };
    const result = await this.#send("POST", `/v1/business/auth-deliveries/${id}/complete`, body, options.idempotencyKey ?? deterministicIdempotencyKey("authdl-done", [id, outcome]));
    return this.#observe(this.#view(result.body));
  }

  /** `PATCH /v1/business/webhooks/{id}`: move an endpoint to signature v2. Needs scope `webhooks:manage`. */
  async updateWebhook(webhookId: string, request: UpdateWebhookRequest = { signature_version: "v2" }, options: { idempotencyKey?: string } = {}): Promise<Record<string, unknown>> {
    if (!/^[0-9a-fA-F-]{36}$/.test(webhookId)) throw new ViadereSdkError("invalid_path", "webhookId must be a UUID.");
    const result = await this.#send("PATCH", `/v1/business/webhooks/${webhookId}`, request, options.idempotencyKey ?? deterministicIdempotencyKey("webhook-v2", [webhookId, request.signature_version]));
    return result.body as Record<string, unknown>;
  }

  /** `POST /v1/business/webhooks/test` (test keys only): a signed sample `auth.delivery.*` event with fixed sample ids to one of your v2 endpoints. */
  async testAuthWebhook(request: AuthWebhookTestRequest, options: { idempotencyKey?: string } = {}): Promise<AuthWebhookTestResponse> {
    const result = await this.#send("POST", "/v1/business/webhooks/test", request, options.idempotencyKey ?? deterministicIdempotencyKey("webhook-test", [request.webhook_id, request.type, String(Date.now())]));
    const body = result.body as Partial<AuthWebhookTestResponse> | null;
    if (!body || typeof body.event_id !== "string") throw new ViadereSdkError("invalid_response", "The response is not a webhook test result.");
    return { event_id: body.event_id };
  }

  // -------------------------------------------------------------------------------------------------------------------------------------------

  #id(deliveryId: string): string {
    if (!DELIVERY_ID_PATTERN.test(deliveryId)) throw new ViadereSdkError("invalid_path", "deliveryId must be adl_ plus 22 base64url characters.");
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

  async #send(method: string, path: string, body?: unknown, idempotencyKey?: string): Promise<{ status: number; body: unknown }> {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.#apiKey}`,
      Accept: "application/json",
      "User-Agent": `viadere-server-node/${SDK_VERSION}`,
    };
    let payload: string | undefined;
    if (body !== undefined) {
      payload = JSON.stringify(body);
      headers["Content-Type"] = "application/json";
    }
    if (idempotencyKey !== undefined) {
      if (!isValidIdempotencyKey(idempotencyKey)) throw new ViadereSdkError("invalid_idempotency_key", "The idempotency key must match [A-Za-z0-9_.:-]{1,128}.");
      headers["Idempotency-Key"] = idempotencyKey;
    }
    // Every GET is safe to repeat and every POST here carries a key, so every request is retryable.
    for (let attempt = 1; ; attempt++) {
      let response: Awaited<ReturnType<FetchLike>>;
      try {
        response = await this.#fetch(this.#baseUrl + path, { method, headers, ...(payload !== undefined ? { body: payload } : {}), redirect: "manual", signal: AbortSignal.timeout(this.#timeoutMs) });
      } catch {
        if (attempt < this.#retry.maxAttempts) {
          await this.#sleep(this.#delay(attempt, undefined));
          continue;
        }
        throw new ViadereSdkError("transport", "The request failed locally (network, TLS or timeout) on every attempt.");
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
      if (error.isRetryable && attempt < this.#retry.maxAttempts) {
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
