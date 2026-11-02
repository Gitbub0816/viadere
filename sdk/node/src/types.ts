// Types for the Viadere authentication-delivery business API.
//
// Hand-written and kept in lock-step with `contracts/openapi/auth-delivery-v1.yaml` and `contracts/schemas/`: the parity test
// (`test/parity.test.ts`) fails when a route, an enum, a required member or a property drifts. Viadere is a transport: `opened` is never
// authentication success, only your own `complete` call finishes a delivery (ADR-0020).

export const METHODS = ["magic_link", "otp", "notice"] as const;
export type Method = (typeof METHODS)[number];

export const PURPOSES = ["sign_in", "step_up", "verify_contact", "account_notice"] as const;
export type Purpose = (typeof PURPOSES)[number];

/** There is no `sms`. `email` is refused until the email-fallback gate (ADR-0020 section 7) is met. */
export const CHANNELS = ["push", "inbox", "email"] as const;
export type Channel = (typeof CHANNELS)[number];

export const STATUSES = [
  "created",
  "validated",
  "queued",
  "sent",
  "delivered",
  "opened",
  "completed",
  "expired",
  "cancelled",
  "denied",
  "failed",
] as const;
export type Status = (typeof STATUSES)[number];

/** States after which nothing changes any more. */
export const TERMINAL_STATUSES: readonly Status[] = ["completed", "expired", "cancelled", "denied", "failed"];

export function isTerminalStatus(status: Status): boolean {
  return TERMINAL_STATUSES.includes(status);
}

export const CODE_KINDS = ["otp", "totp"] as const;
export type CodeKind = (typeof CODE_KINDS)[number];

export const LINK_MODES = ["business", "viadere"] as const;
export type LinkMode = (typeof LINK_MODES)[number];

export const COMPLETE_OUTCOMES = ["succeeded", "failed"] as const;
export type CompleteOutcome = (typeof COMPLETE_OUTCOMES)[number];

/** `adl_` plus 22 base64url characters. */
export type DeliveryId = string;
/** `sub_` plus 43 base64url characters. */
export type SubjectRef = string;

export interface AuthDeliveryDestination {
  link_mode: LinkMode;
  url?: string;
  /** Compact `viadere-destination+jws` (ADR-0031 section 3). */
  signature?: string;
  link_client_id?: string;
  return_url?: string;
  code_challenge?: string;
  code_challenge_method?: "S256";
}

export interface AuthDeliveryOtp {
  code: string;
  code_kind: CodeKind;
}

export interface AuthDeliveryCreateRequest {
  method: Method;
  /** Unique per tenant: `[A-Za-z0-9_.:-]{1,128}`. */
  request_id: string;
  subject_ref: SubjectRef;
  purpose: Purpose;
  /** A Viadere-owned template id, for example `auth.sign_in_link.v1`. */
  template: string;
  /** Only keys the template declares; personal data (stored sealed). No URL, e-mail address or phone number. */
  variables?: Record<string, string>;
  destination?: AuthDeliveryDestination;
  otp?: AuthDeliveryOtp;
  correlation_id?: string;
  client_transaction_ref?: string;
  /** 60 to 86400. */
  expires_in_seconds?: number;
  channels?: Channel[];
  fallback?: { email?: { address: string } };
  /** Opaque value derived from your own initiating session (class T, never shown). Only a matching handle lets a new `sign_in` supersede an open one. */
  session_handle?: string;
  callback?: { webhook_id: string };
}

export interface AuthDeliveryEvent {
  status: Status;
  at: string;
  reason?: string;
}

export interface AuthDeliveryView {
  id: DeliveryId;
  request_id: string;
  method: Method;
  purpose: Purpose;
  status: Status;
  expires_at: string;
  created_at: string;
  correlation_id?: string;
  client_transaction_ref?: string;
  reason?: string;
  events?: AuthDeliveryEvent[];
}

export interface AuthDeliveryCompleteRequest {
  outcome: CompleteOutcome;
}

export interface UpdateWebhookRequest {
  signature_version: "v2";
}

export const WEBHOOK_EVENT_TYPES = [
  "auth.delivery.created",
  "auth.delivery.sent",
  "auth.delivery.delivered",
  "auth.delivery.opened",
  "auth.delivery.completed",
  "auth.delivery.failed",
  "auth.delivery.denied",
  "auth.delivery.cancelled",
  "auth.delivery.expired",
] as const;
export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

export interface AuthWebhookTestRequest {
  webhook_id: string;
  type: WebhookEventType;
}

export interface AuthWebhookTestResponse {
  event_id: string;
}

/** The opaque webhook envelope of an `auth.delivery.*` event (`contracts/schemas/auth-delivery-event-v1.schema.json`). */
export interface AuthDeliveryEnvelope {
  id: string;
  type: WebhookEventType;
  version: "2026-10-27";
  tenant_id: string;
  /** The delivery id: fetch the state with `getAuthDelivery`. */
  request_id: DeliveryId;
  occurred_at: string;
}

export const ENVELOPE_VERSION = "2026-10-27";

/** The error body every non-2xx answer carries. */
export interface ApiErrorBody {
  error: { code: string; message: string; request_id?: string; details?: Record<string, string> };
}

/** The business routes, for parity with the contract. */
export const ROUTES = {
  createAuthDelivery: { method: "POST", path: "/v1/business/auth-deliveries" },
  getAuthDelivery: { method: "GET", path: "/v1/business/auth-deliveries/{deliveryId}" },
  cancelAuthDelivery: { method: "POST", path: "/v1/business/auth-deliveries/{deliveryId}/cancel" },
  completeAuthDelivery: { method: "POST", path: "/v1/business/auth-deliveries/{deliveryId}/complete" },
  updateWebhook: { method: "PATCH", path: "/v1/business/webhooks/{webhookId}" },
  testAuthWebhook: { method: "POST", path: "/v1/business/webhooks/test" },
} as const;

/** Members of the closed create request, for validation and parity. */
export const CREATE_REQUEST_MEMBERS = [
  "method",
  "request_id",
  "subject_ref",
  "purpose",
  "template",
  "variables",
  "destination",
  "otp",
  "correlation_id",
  "client_transaction_ref",
  "expires_in_seconds",
  "channels",
  "fallback",
  "session_handle",
  "callback",
] as const;

export const CREATE_REQUEST_REQUIRED = ["method", "request_id", "subject_ref", "purpose", "template"] as const;
