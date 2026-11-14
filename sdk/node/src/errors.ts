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

  /**
   * The key lacks the capability (`insufficient_scope`), the business is not (or no longer) entitled to it (`not_entitled`), or it is switched off
   * (`capability_disabled`). Retrying unchanged cannot help. `details.capability` names it (`deniedCapability`).
   */
  get isCapabilityDenied(): boolean {
    return this.code === "insufficient_scope" || this.code === "not_entitled" || this.code === "capability_disabled";
  }

  /** The capability the request needed, when the API says so. */
  get deniedCapability(): string | undefined {
    const value = this.details?.capability;
    return typeof value === "string" ? value : undefined;
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
        // `requestId` in `docs/openapi.yaml`, `request_id` in `contracts/openapi/auth-delivery-v1.yaml`: both spellings are read.
        requestId: typeof error.requestId === "string" ? error.requestId : typeof error.request_id === "string" ? error.request_id : headers.requestId,
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

export type ApprovalFailureCode =
  | "malformed"
  | "unsupported_algorithm"
  | "unsupported_type"
  | "unknown_critical_header"
  | "unsupported_version"
  | "unknown_key"
  | "key_revoked"
  | "bad_signature"
  | "header_payload_mismatch"
  | "wrong_audience"
  | "wrong_subject"
  | "wrong_request"
  | "wrong_capability"
  | "challenge_mismatch"
  | "transaction_mismatch"
  | "expired"
  | "issued_in_future"
  | "lifetime_too_long"
  | "decided_after_request_expiry"
  | "not_approved"
  | "insufficient_authentication"
  | "amr_exceeds_key"
  | "replayed"
  | "number_match_required"
  | "number_mismatch"
  | "unexpected_match"
  | "invalid_expectation";

/**
 * Why a signed `ApprovalResult` was refused. **Every code is a refusal**: never treat one as an approval, and never fall back to the relay's
 * `status`. `not_approved` carries the signed decision (`deny` or `report`) in `detail`.
 */
export class ApprovalVerificationError extends Error {
  override readonly name = "ApprovalVerificationError";
  readonly code: ApprovalFailureCode;
  readonly detail: string | undefined;
  constructor(code: ApprovalFailureCode, detail?: string) {
    super(`Approval result refused: ${code}${detail ? ` (${detail})` : ""}`);
    this.code = code;
    this.detail = detail;
  }
}

export type StatementFailureCode =
  | "malformed"
  | "bad_signature"
  | "untrusted_signer"
  | "wrong_session"
  | "wrong_business"
  | "wrong_subject"
  | "wrong_origin"
  | "wrong_capability"
  | "wrong_capabilities"
  | "wrong_descriptor"
  | "wrong_enrollment"
  | "statement_mismatch"
  | "approval_statement_mismatch"
  | "key_mismatch"
  | "assurance_too_low";

/** Why a signed statement (a session result, a link or enrollment statement, a confirmation) was refused. Do not act on the statement. */
export class StatementVerificationError extends Error {
  override readonly name = "StatementVerificationError";
  readonly code: StatementFailureCode;
  readonly detail: string | undefined;
  constructor(code: StatementFailureCode, detail?: string) {
    super(`Statement refused: ${code}${detail ? ` (${detail})` : ""}`);
    this.code = code;
    this.detail = detail;
  }
}

export type FlowFailureCode =
  /** You did not authenticate the customer within the last five minutes: step up first. Nothing was sent. */
  | "step_up_required"
  /** The relay's ticket names another root key, another host, or a malformed code. The session or enrollment was cancelled. */
  | "ticket_mismatch"
  /** The device or the person has not finished yet (or the session ended without a result). `detail` is the status. */
  | "not_ready"
  /** No binding tag and no SAS: ask the person for the six digits the app shows. Nothing was changed. */
  | "verification_required"
  /** The binding tag is not the HMAC of this statement under your secret. Cancelled. */
  | "binding_tag_invalid"
  /** No SAS check was given. */
  | "sas_comparison_required"
  /** A compared SAS is not enough without a binding tag: the person must type the digits. */
  | "typed_sas_required"
  /** The typed digits do not match. Cancelled: one guess. */
  | "sas_mismatch"
  /** The result reference the session returned is not the one the signed result commits to. */
  | "result_ref_mismatch"
  /** No free number-match code after 20 draws, or the code space is exhausted. */
  | "no_free_code"
  /** The request must be end to end (a payment, or `high`/`critical` risk): supply `buildEnvelopes`. */
  | "end_to_end_required";

/** A multi-step flow (enrollment, link session, verification session, auth approval) stopped before anything could be trusted. */
export class ViadereFlowError extends Error {
  override readonly name = "ViadereFlowError";
  readonly code: FlowFailureCode;
  readonly detail: string | undefined;
  constructor(code: FlowFailureCode, detail?: string) {
    super(`Viadere flow stopped: ${code}${detail ? ` (${detail})` : ""}`);
    this.code = code;
    this.detail = detail;
  }
}

export type WebhookFailureCode =
  | "missing_header"
  | "not_a_verification_request"
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
