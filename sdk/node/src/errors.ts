import type { ApiErrorBody } from "./types.js";

/** The API answered with an error. `code` is the stable machine code; `message` is safe to log. */
export class ViadereApiError extends Error {
  override readonly name = "ViadereApiError";
  readonly status: number;
  readonly code: string | undefined;
  /** Quote this when contacting Viadere support. */
  readonly requestId: string | undefined;
  readonly details: Record<string, string> | undefined;
  /** Seconds from `Retry-After` (429, 503), when present. */
  readonly retryAfter: number | undefined;

  constructor(init: { status: number; code?: string | undefined; message: string; requestId?: string | undefined; details?: Record<string, string> | undefined; retryAfter?: number | undefined }) {
    super(`Viadere API error ${init.status} ${init.code ?? "unknown"}: ${init.message}${init.requestId ? ` (request ${init.requestId})` : ""}`);
    this.status = init.status;
    this.code = init.code;
    this.requestId = init.requestId;
    this.details = init.details;
    this.retryAfter = init.retryAfter;
  }

  /** The request is safe to retry unchanged (rate limited or a server-side failure). */
  get isRetryable(): boolean {
    return this.status === 429 || this.status >= 500;
  }

  /** `404 not_deliverable`: unknown customer, no eligible app, paused or frozen. One body by design (non-disclosure): do not try to tell them apart. */
  get isNotDeliverable(): boolean {
    return this.status === 404 && this.code === "not_deliverable";
  }

  static fromBody(status: number, body: unknown, headers: { retryAfter?: number | undefined; requestId?: string | undefined }): ViadereApiError {
    const error = (body as Partial<ApiErrorBody> | null)?.error;
    if (error && typeof error === "object" && typeof error.message === "string") {
      return new ViadereApiError({
        status,
        code: typeof error.code === "string" ? error.code : undefined,
        message: error.message,
        requestId: typeof error.request_id === "string" ? error.request_id : headers.requestId,
        details: error.details && typeof error.details === "object" ? (error.details as Record<string, string>) : undefined,
        retryAfter: headers.retryAfter,
      });
    }
    return new ViadereApiError({ status, message: "Unexpected response from the Viadere API.", requestId: headers.requestId, retryAfter: headers.retryAfter });
  }
}

export type SdkErrorKind = "invalid_api_key" | "insecure_base_url" | "invalid_response" | "invalid_path" | "invalid_idempotency_key" | "transport";

/** A failure that is not an API answer. */
export class ViadereSdkError extends Error {
  override readonly name = "ViadereSdkError";
  readonly kind: SdkErrorKind;
  constructor(kind: SdkErrorKind, message: string) {
    super(message);
    this.kind = kind;
  }
}

/** The request was refused locally, before it was sent: it does not match the contract. `details` names each field and a code. */
export class ViadereValidationError extends Error {
  override readonly name = "ViadereValidationError";
  readonly details: readonly { field: string; code: string }[];
  constructor(details: readonly { field: string; code: string }[]) {
    super(`Request does not match the contract: ${details.map((d) => `${d.field} (${d.code})`).join(", ")}`);
    this.details = details;
  }
}

/**
 * The per-requester throttle refused the request locally (C-14): more than `maxOpen` deliveries are already open for this account and this client
 * network prefix. Nothing was sent. Show the user a calm "try again shortly" and do not retry in a loop.
 */
export class ViadereThrottledError extends Error {
  override readonly name = "ViadereThrottledError";
  /** Seconds until the oldest open delivery for this key expires (an upper bound: completing or cancelling one frees a slot sooner). */
  readonly retryAfterSeconds: number;
  constructor(retryAfterSeconds: number) {
    super(`Too many open deliveries for this account and network; retry in about ${retryAfterSeconds}s.`);
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export type WebhookFailureCode =
  | "missing_header"
  | "malformed_signature"
  | "timestamp_outside_tolerance"
  | "no_matching_signature"
  | "tenant_mismatch"
  | "digest_mismatch"
  | "malformed_body"
  | "header_body_mismatch"
  | "duplicate_event";

/**
 * Why a webhook was rejected. Answer `400` and do **not** process the event; a `duplicate_event` is acknowledged with `200` (it was already
 * processed). `status` is that suggestion.
 */
export class WebhookVerificationError extends Error {
  override readonly name = "WebhookVerificationError";
  readonly code: WebhookFailureCode;
  constructor(code: WebhookFailureCode) {
    super(`Webhook rejected: ${code}`);
    this.code = code;
  }
  get status(): 200 | 400 {
    return this.code === "duplicate_event" ? 200 : 400;
  }
}
