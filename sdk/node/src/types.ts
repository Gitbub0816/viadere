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

/** The error body every non-2xx answer carries. The request id is `requestId` on the routes of `docs/openapi.yaml` and `request_id` in the auth-delivery contract. */
export interface ApiErrorBody {
  error: { code: string; message: string; requestId?: string; request_id?: string; details?: Record<string, string> };
}

/** The business routes of `contracts/openapi/auth-delivery-v1.yaml`, for parity with the contract. */
export const ROUTES = {
  createAuthDelivery: { method: "POST", path: "/v1/business/auth-deliveries" },
  getAuthDelivery: { method: "GET", path: "/v1/business/auth-deliveries/{deliveryId}" },
  cancelAuthDelivery: { method: "POST", path: "/v1/business/auth-deliveries/{deliveryId}/cancel" },
  completeAuthDelivery: { method: "POST", path: "/v1/business/auth-deliveries/{deliveryId}/complete" },
  updateWebhook: { method: "PATCH", path: "/v1/business/webhooks/{webhookId}" },
  testAuthWebhook: { method: "POST", path: "/v1/business/webhooks/test" },
  createAuthApproval: { method: "POST", path: "/v1/business/auth-approvals" },
  getAuthApproval: { method: "GET", path: "/v1/business/auth-approvals/{requestId}" },
  redeemAuthLink: { method: "POST", path: "/v1/business/auth-links/redeem" },
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

// =============================================================================================================================================
// The business API of `docs/openapi.yaml` (interactions, messages, rewards, Wallet, Approve v2, link and verification sessions, profiles, the key
// directory, webhook management) and the two `auth-approvals` / `auth-links` routes of `contracts/openapi/auth-delivery-v1.yaml`.
//
// Member names are the wire names, field for field. **The wire is not uniformly snake_case**: the older routes (interactions, messages, statuses,
// rewards, loyalty, Wallet, capabilities, profiles, webhook management, the classic webhook event) are camelCase; Approve v2, link sessions,
// verification and the key directory are snake_case. `test/parity.test.ts` reads the OpenAPI document and fails when a member, a required list or
// an enum drifts; `src/schemas.ts` ties every interface below to that table at compile time.

/** Lowercase UUID. */
export type Uuid = string;
/** ISO 8601 UTC with milliseconds, e.g. `2026-10-27T08:00:00.000Z`. */
export type Timestamp = string;

export const CAPABILITIES = ["message.send", "contact.reachable", "consent.request", "auth.challenge", "transaction.approve", "age.minimum", "identity.name", "identity.address", "identity.verified"] as const;
/** Stable capability id. Unknown future ids must be treated as not granted. */
export type Capability = (typeof CAPABILITIES)[number];
export const APPROVAL_CAPABILITIES = ["auth.challenge", "transaction.approve"] as const;
export type ApprovalCapability = (typeof APPROVAL_CAPABILITIES)[number];
export const VERIFICATION_CAPABILITIES = ["age.minimum", "identity.name", "identity.address", "identity.verified"] as const;
export type VerificationCapability = (typeof VERIFICATION_CAPABILITIES)[number];
export const LINKABLE_CAPABILITIES = ["message.send", "contact.reachable", "consent.request", "auth.challenge", "transaction.approve"] as const;
export type LinkableCapability = (typeof LINKABLE_CAPABILITIES)[number];
export const BUSINESS_RISK_TIERS = ["M", "A", "V", "E"] as const;
export type BusinessRiskTier = (typeof BUSINESS_RISK_TIERS)[number];

export const INTERACTION_KINDS = ["authenticate", "authorize", "confirm", "choose", "acknowledge", "reply", "status", "reward", "ticket", "message"] as const;
export type InteractionKind = (typeof INTERACTION_KINDS)[number];
export const INTERACTION_PURPOSES = ["security", "accountService", "transactional", "support", "marketing", "rewards"] as const;
export type InteractionPurpose = (typeof INTERACTION_PURPOSES)[number];
export const INTERACTION_PRIORITIES = ["low", "normal", "high", "urgent"] as const;
export type InteractionPriority = (typeof INTERACTION_PRIORITIES)[number];
export const SENSITIVITIES = ["low", "standard", "high", "critical"] as const;
export type Sensitivity = (typeof SENSITIVITIES)[number];
/** Where an interaction may be delivered (not the auth-delivery `Channel`). */
export const INTERACTION_CHANNELS = ["nativePush", "inApp", "web", "sms", "rcs", "appleMessagesForBusiness"] as const;
export type InteractionChannel = (typeof INTERACTION_CHANNELS)[number];
export const ACTION_ROLES = ["approve", "deny", "confirm", "decline", "select", "reply", "acknowledge", "open", "report", "redeem"] as const;
export type ActionRole = (typeof ACTION_ROLES)[number];
export const DECISIONS = ["approve", "deny", "confirm", "decline", "select", "reply", "acknowledge", "report"] as const;
export type Decision = (typeof DECISIONS)[number];
export const DECISION_ASSURANCES = ["none", "devicePasscode", "biometric"] as const;
export type DecisionAssurance = (typeof DECISION_ASSURANCES)[number];
export const INTERACTION_STATUSES = ["pending", "approved", "denied", "confirmed", "declined", "selected", "replied", "acknowledged", "reported", "expired", "cancelled", "delivered"] as const;
export type InteractionStatus = (typeof INTERACTION_STATUSES)[number];

export interface MoneyAmount {
  /** Plain decimal string with the currency's minor-unit digits, e.g. `"285.28"`. Never a float. */
  value: string;
  currency: string;
}
export interface RiskIndicator {
  code: string;
  label: string;
  severity: "info" | "warning" | "high";
}
export interface RequestedAction {
  id: string;
  label: string;
  role: ActionRole;
}
export interface AuthenticatePayload {
  service: string;
  device: string;
  approximateLocation?: string;
  ipRegion?: string;
  attemptedAt: Timestamp;
  riskIndicators?: RiskIndicator[];
}
export interface AuthorizePayload {
  actionDescription: string;
  amount?: MoneyAmount;
  merchant?: string;
  location?: string;
  effectOfApproval?: string;
  riskIndicators?: RiskIndicator[];
}
export interface ConfirmPayload {
  title: string;
  details?: string;
  reference?: string;
  scheduledAt?: Timestamp;
}
export interface ChoiceOption {
  id: string;
  label: string;
}
export interface ChoosePayload {
  prompt: string;
  options: ChoiceOption[];
  allowsMultiple?: boolean;
}
export interface AcknowledgePayload {
  title: string;
  body: string;
  documentURL?: string;
  documentVersion?: string;
  /** Lowercase hex SHA-256 of the document shown. */
  documentDigest?: string;
}
export interface ReplyPayload {
  prompt: string;
  maxLength?: number;
  suggestedReplies?: string[];
}
export interface LiveActivityOrder {
  orderReference: string;
  stage: "placed" | "preparing" | "ready" | "completed" | "cancelled";
  estimatedReadyAt?: Timestamp;
  note?: string;
}
export interface LiveActivityDelivery {
  trackingReference: string;
  stage: "labelCreated" | "inTransit" | "outForDelivery" | "delivered" | "exception";
  carrierName?: string;
  estimatedDeliveryAt?: Timestamp;
  stopsAway?: number;
}
export interface LiveActivityFlight {
  flightNumber: string;
  departureAirport: string;
  arrivalAirport: string;
  stage: "scheduled" | "delayed" | "boarding" | "departed" | "landed" | "cancelled" | "diverted";
  scheduledDeparture: Timestamp;
  estimatedDeparture?: Timestamp;
  estimatedArrival?: Timestamp;
  gate?: string;
  seat?: string;
}
export interface LiveActivityAppointment {
  title: string;
  startsAt: Timestamp;
  location?: string;
  providerName?: string;
  stage: "upcoming" | "checkInOpen" | "checkedIn" | "inProgress" | "completed" | "cancelled";
}
/** `{ type: "delivery", delivery: {...} }`: exactly one state object matching `type`. */
export interface LiveActivityStatus {
  type: "order" | "delivery" | "flight" | "appointment";
  order?: LiveActivityOrder;
  delivery?: LiveActivityDelivery;
  flight?: LiveActivityFlight;
  appointment?: LiveActivityAppointment;
}
export interface StatusPayload {
  title: string;
  body?: string;
  liveActivity?: LiveActivityStatus;
}
export interface MessagePayload {
  text: string;
  sessionId?: Uuid;
}
export interface RewardPayload {
  rewardId: Uuid;
  title: string;
  details?: string;
  redeemBy?: Timestamp;
  walletPassId?: Uuid;
}
export interface TicketPayload {
  title: string;
  ticketType: string;
  holderName?: string;
  validFrom?: Timestamp;
  validUntil?: Timestamp;
  walletPassId?: Uuid;
  venue?: string;
  seat?: string;
  startsAt?: Timestamp;
}
/** The payload object for the declared `kind` (the sibling `kind` is the discriminator). */
export type InteractionPayload = AuthenticatePayload | AuthorizePayload | ConfirmPayload | ChoosePayload | AcknowledgePayload | ReplyPayload | StatusPayload | RewardPayload | TicketPayload | MessagePayload;

/** Name the customer with `relationshipId`, `subjectRef`, or both (they must agree). */
export interface IssueInteractionRequest {
  relationshipId?: Uuid;
  subjectRef?: SubjectRef;
  kind: InteractionKind;
  purpose: InteractionPurpose;
  payload: InteractionPayload;
  requestedActions?: RequestedAction[];
  priority?: InteractionPriority;
  sensitivity?: Sensitivity;
  allowedChannels?: InteractionChannel[];
  /** Lifetime: at most 900 for `authenticate` and `authorize`, 30 days otherwise. */
  ttlSeconds: number;
  /** Also sent as the `Idempotency-Key` header (they must be equal). */
  idempotencyKey: string;
  correlationId?: string;
  accountReference?: string;
}
export interface InteractionScope {
  /** Deprecated per-business pseudonym; use `subjectRef`. */
  consumerId: Uuid;
  relationshipId: Uuid;
  subjectRef?: SubjectRef;
  accountReference?: string;
}
export interface Interaction {
  schemaVersion: 1;
  id: Uuid;
  businessId: Uuid;
  scope: InteractionScope;
  kind: InteractionKind;
  purpose: InteractionPurpose;
  payload: InteractionPayload;
  requestedActions?: RequestedAction[];
  priority: InteractionPriority;
  sensitivity: Sensitivity;
  allowedChannels: InteractionChannel[];
  createdAt: Timestamp;
  expiresAt: Timestamp;
  idempotencyKey: string;
  correlationId?: string;
  /** A one-way reference, not the device challenge. */
  challenge: string;
}
export interface DecisionVerification {
  verified: boolean;
  keyPurpose: "request" | "approvalUserPresence" | "approvalBiometric";
  contextBound: boolean;
  verifiedAt: Timestamp;
  evidenceRef: string;
}
export interface InteractionOutcome {
  interactionId: Uuid;
  businessId: Uuid;
  status: InteractionStatus;
  decision?: Decision;
  selectedOptionIds?: string[];
  reply?: string;
  /** Present for device-signed decisions. **Absent for decisions made on a text channel.** */
  assurance?: DecisionAssurance;
  channel?: InteractionChannel;
  decidedAt?: Timestamp;
  correlationId?: string;
  deviceRef?: string;
  verification?: DecisionVerification;
}
export interface SandboxRelationship {
  relationshipId: Uuid;
  subjectRef?: SubjectRef;
  createdAt: Timestamp;
}

export interface MessageAttribution {
  senderType: "consumer" | "business" | "agent" | "automated" | "viadere";
  displayName: string;
  agentName?: string;
}
export interface ConversationMessage {
  id: Uuid;
  sessionId: Uuid;
  businessId: Uuid;
  direction: "consumerToBusiness" | "businessToConsumer";
  attribution: MessageAttribution;
  body: string;
  channel: InteractionChannel;
  createdAt: Timestamp;
  deliveredAt?: Timestamp;
  readAt?: Timestamp;
  deliveryStatus: "queued" | "sent" | "delivered" | "read" | "failed";
  interactionId?: Uuid;
}
export interface BusinessSendMessageRequest {
  relationshipId?: Uuid;
  subjectRef?: SubjectRef;
  sessionId?: Uuid;
  body: string;
  agentName?: string;
  idempotencyKey: string;
}
export interface BusinessStatusUpdateRequest {
  relationshipId?: Uuid;
  subjectRef?: SubjectRef;
  purpose: InteractionPurpose;
  status: StatusPayload;
  /** Stable key for the ongoing event (an order id) so updates replace earlier ones. */
  activityKey: string;
  idempotencyKey: string;
  correlationId?: string;
}

export const REWARD_KINDS = ["coupon", "perk", "offer", "pointsReward"] as const;
export type RewardKind = (typeof REWARD_KINDS)[number];
export interface RewardRecurrence {
  /** ISO weekdays, 1 = Monday. */
  weekdays: number[];
  perDayLimit: number;
  timeZone: string;
}
export interface IssueRewardRequest {
  relationshipId?: Uuid;
  subjectRef?: SubjectRef;
  title: string;
  kind?: RewardKind;
  details?: string;
  validFrom?: Timestamp;
  validUntil?: Timestamp;
  recurrence?: RewardRecurrence;
  pointsCost?: number;
  issueWalletPass?: boolean;
  idempotencyKey: string;
}
export interface Reward {
  id: Uuid;
  business: Record<string, unknown>;
  title: string;
  details?: string;
  status: "available" | "redeemed" | "expired" | "revoked";
  validFrom?: Timestamp;
  validUntil?: Timestamp;
  recurrence?: RewardRecurrence;
}
export interface LoyaltyTier {
  name: string;
  minimumPoints: number;
}
export interface UpsertLoyaltyProgramRequest {
  programName: string;
  summary: string;
  termsVersion: string;
  timeZone: string;
  tiers?: LoyaltyTier[];
}
export interface BusinessLoyaltyProgram extends UpsertLoyaltyProgramRequest {
  memberCount: number;
  updatedAt: Timestamp;
}
export interface AdjustLoyaltyPointsRequest {
  relationshipId?: Uuid;
  subjectRef?: SubjectRef;
  /** Non-zero; at most 1,000,000 in magnitude. */
  delta: number;
  reason?: string;
  idempotencyKey: string;
}
export interface LoyaltyPointsResult {
  relationshipId: Uuid;
  subjectRef?: SubjectRef;
  pointsBalance: number;
  statusName?: string;
  /** False when this call replayed an earlier request with the same key. */
  applied: boolean;
}
export interface ConsumeRedemptionRequest {
  code: string;
  locationCode?: string;
}
export interface RedemptionReceipt {
  redemptionId: Uuid;
  rewardId: Uuid;
  rewardTitle: string;
  kind: RewardKind;
  /** Deprecated per-business pseudonym; use `subjectRef`. */
  consumerReference: Uuid;
  subjectRef?: SubjectRef;
  redeemedAt: Timestamp;
  pointsSpent?: number;
  locationCode?: string;
}

export const WALLET_PASS_KINDS = ["storeCard", "coupon", "eventTicket", "boardingPass", "generic"] as const;
export type WalletPassKind = (typeof WALLET_PASS_KINDS)[number];
export interface BusinessIssueWalletPassRequest {
  relationshipId?: Uuid;
  subjectRef?: SubjectRef;
  kind: WalletPassKind;
  rewardId?: Uuid;
  interactionId?: Uuid;
}
export interface BusinessWalletPass {
  id: Uuid;
  kind: WalletPassKind;
  relationshipId?: Uuid;
  subjectRef?: SubjectRef;
  rewardId?: Uuid;
  interactionId?: Uuid;
  issuedBy: "customer" | "business";
  voided: boolean;
  usedAt?: Timestamp;
  createdAt: Timestamp;
  updatedAt: Timestamp;
}
export interface UpdateWalletPassRequest {
  venue?: string;
  seat?: string;
  startsAt?: Timestamp;
  rotateScanCode?: boolean;
}
export interface WalletScanRequest {
  /** The scanned QR text, `VQ1.` plus 48 base64url characters. */
  code: string;
  locationCode?: string;
}
export interface WalletScanResult {
  outcome: "redeemed" | "checkedIn" | "member";
  passId: Uuid;
  kind: WalletPassKind;
  relationshipId: Uuid;
  subjectRef?: SubjectRef;
  title?: string;
  pointsBalance?: number;
  redemption?: RedemptionReceipt;
  scannedAt: Timestamp;
}

export interface CapabilityParameterDefinition {
  name: string;
  type: "string" | "integer" | "boolean" | "timestamp" | "object";
  required: boolean;
  allowedIntegers?: number[];
  allowedStrings?: string[];
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  summary: string;
}
export interface CapabilityOutputField {
  name: string;
  type: "string" | "integer" | "boolean" | "timestamp" | "object";
  class: "assertion" | "assurance" | "metadata" | "personal_data";
  summary: string;
}
export interface CapabilityDefinition {
  capability: Capability;
  title: string;
  summary: string;
  parameters: CapabilityParameterDefinition[];
  requiresPurpose: boolean;
  requiredEvidence: "none" | "registeredAuthenticator" | "verifiedAgeThreshold" | "verifiedIdentity";
  sensitivity: Sensitivity;
  minimumTier: BusinessRiskTier;
  consent: { mode: "none" | "activeRelationship" | "relationshipPurpose" | "perRequestReceipt"; purpose: string };
  customerUX: "none" | "notification" | "secureSheet" | "verificationFlow";
  output: { fields: CapabilityOutputField[] };
  maxResultRetentionSeconds: number;
  auditFields: string[];
  revocation: "stops_future_use" | "cancels_pending" | "expires_assertion";
  auditsAllowedDecisions: boolean;
}
export interface BusinessCapabilitiesResponse {
  businessId: Uuid;
  environment: "live" | "test";
  tiers: BusinessRiskTier[];
  /** What Viadere granted the business (the ceiling). */
  entitlements: Capability[];
  /** What this key carries. */
  keyScopes: Capability[];
  /** Key scopes intersected with entitlements, minus anything switched off. */
  effective: Capability[];
  catalog: CapabilityDefinition[];
}

/** The event types of `docs/openapi.yaml` `WebhookEventType`. An open set: acknowledge and ignore a type you do not recognize. */
export const BUSINESS_WEBHOOK_EVENT_TYPES = [
  "interaction.decided",
  "interaction.expired",
  "interaction.cancelled",
  "message.received",
  "relationship.connected",
  "relationship.disconnected",
  "consent.updated",
  "reward.redeemed",
  "approve.enrollment.device_completed",
  "approve.enrollment.confirmed",
  "approve.key.revoked",
  "approve.request.decided",
  "approve.request.expired",
  "approve.frozen",
] as const;
/**
 * Event types the Swift SDK and `ViadereCore` define that the OpenAPI `WebhookEventType` enum does not list (the enum is declared an open set).
 * `webhook.test` is what `testWebhook` queues; the ownership challenge `webhook.verification` is answered with `verificationResponse`.
 */
export const ADDITIONAL_WEBHOOK_EVENT_TYPES = ["verification.completed", "profile.access_granted", "profile.access_revoked", "profile.request_expired", "link.completed", "link.expired", "webhook.test"] as const;
export type BusinessWebhookEventType = (typeof BUSINESS_WEBHOOK_EVENT_TYPES)[number] | (typeof ADDITIONAL_WEBHOOK_EVENT_TYPES)[number] | WebhookEventType | (string & {});

export interface WebhookSubscription {
  id: Uuid;
  url: string;
  events: BusinessWebhookEventType[];
  /** Present when the endpoint opted into the opaque envelope (`OpaqueWebhookEnvelope`). */
  envelopeVersion?: "2026-10-27";
  /** Version of the signing secret; also in the `Viadere-Key-Id` header. */
  secretVersion?: number;
  /** When ownership of the endpoint was proven. Until then it receives no events. */
  verifiedAt?: Timestamp;
  pausedAt?: Timestamp;
  active: boolean;
  createdAt: Timestamp;
}
export interface WebhookVerificationResult {
  verified: boolean;
  /** `no_echo`, `http_<status>` or `unreachable`. */
  failure?: string;
}
export interface PauseWebhookRequest {
  reason?: string;
}
export interface CreateWebhookRequest {
  /** A public `https` URL. */
  url: string;
  events: BusinessWebhookEventType[];
  envelopeVersion?: "2026-10-27";
}
export interface WebhookSecretResponse {
  subscription: WebhookSubscription;
  /** `whsec_...`, shown once. The HMAC key is the UTF-8 bytes of the whole string, prefix included. Store it in your secrets manager; never log it. */
  secret: string;
}
/** The classic (signature v1) webhook event. */
export interface WebhookEventEnvelope {
  id: Uuid;
  type: BusinessWebhookEventType;
  createdAt: Timestamp;
  businessId: Uuid;
  apiVersion: string;
  data: unknown;
}
export interface MessageReceivedData {
  sessionId: Uuid;
  relationshipId: Uuid;
  subjectRef?: SubjectRef;
  messageId: Uuid;
  text: string;
  channel: InteractionChannel;
  receivedAt: Timestamp;
}
export interface RelationshipEventData {
  relationshipId: Uuid;
  subjectRef?: SubjectRef;
  publicName?: string;
  source?: "handle" | "code" | "qr" | "button" | "link" | "search" | "sms" | "appClip";
  occurredAt: Timestamp;
}
export interface ConsentUpdatedData {
  relationshipId: Uuid;
  subjectRef?: SubjectRef;
  purpose: InteractionPurpose;
  granted: boolean;
  occurredAt: Timestamp;
}
export interface ProfileAccessEventData {
  subjectRef: SubjectRef;
  fieldKeys: string[];
  requestId?: Uuid;
  occurredAt: Timestamp;
}
/** `data` of `verification.completed`: fetch the result with `getVerificationResult(result_ref)`. */
export interface VerificationCompletedData {
  request_id: string;
  result_ref: string;
}

export interface ProfileAddress {
  line1: string;
  line2?: string;
  locality: string;
  region?: string;
  postalCode?: string;
  country: string;
}
/** A string, an address object, or (derived fields such as `birthdate.age_over_18` and `verified.*`) a boolean. */
export type ProfileValue = string | boolean | ProfileAddress;
export interface CreateProfileRequest {
  subjectRef: SubjectRef;
  fieldKeys: string[];
  /** Shown to the customer as written; must pass the display-text rules. */
  purpose: string;
  expiresInSeconds?: number;
}
export interface ProfileRequestResource {
  id: Uuid;
  subjectRef: SubjectRef;
  fieldKeys: string[];
  purpose: string;
  status: "pending" | "answered" | "declined" | "expired" | "cancelled";
  approvedKeys?: string[];
  livemode: boolean;
  createdAt: Timestamp;
  expiresAt: Timestamp;
  answeredAt?: Timestamp;
}
export interface ProfileFieldVerification {
  fact?: string;
  method?: string;
  verifiedAt?: Timestamp;
  assurance?: string;
  policyVersion?: string;
}
export interface BusinessProfileField {
  key: string;
  entry?: string;
  value: ProfileValue;
  verification?: ProfileFieldVerification;
}
export interface BusinessProfileView {
  subjectRef: SubjectRef;
  publicName?: string;
  fields: BusinessProfileField[];
  grantedWithoutValue: string[];
  catalogVersion: number;
  livemode: boolean;
}

// ---- Approve v2, link sessions, verification, key directory (snake_case) -------------------------------------------------------------------

/** `{ payload: base64url(canonical JSON), signature: base64url(raw r||s) }` over `domain || payload bytes`. */
export interface SignedStatement {
  payload: string;
  signature: string;
}
/** A signed statement that names its signing key (`kid`): a business operational key, or Viadere's `link-descriptor` key. */
export interface BusinessSignedStatement {
  kid: string;
  payload: string;
  signature: string;
}
export interface E2EEContext {
  exp: number;
  purpose: string;
  recipient: string;
  request_id: string;
  sender: string;
}
export interface E2EEEnvelope {
  v: 1;
  suite: "hpke-0010-0001-0002";
  kid: string;
  enc: string;
  ct: string;
  ctx: E2EEContext;
}
/** The exact displayed parameters of a `transaction.approve` request. What is shown is what is signed. */
export interface TransactionDetails {
  currency: string;
  /** Minor units (cents), a positive integer. */
  amount_minor: number;
  payee_display: string;
  transaction_reference: string;
}
/** The exact displayed parameters of an `auth.challenge` approval. */
export interface AuthenticationDetails {
  action_display: string;
  reference?: string;
}
/**
 * `AuthenticationDetails` of an `auth-approvals` request: `match_digits` (2 or 3) is the number-match length, part of the signed transaction
 * digest (`ViadereCore` `AuthenticationDetails.matchDigits`). `docs/openapi.yaml` does not list the member.
 */
export interface AuthApprovalAuthenticationDetails extends AuthenticationDetails {
  match_digits?: number;
}
export interface CreateApprovalEnrollmentRequest {
  subject_ref: SubjectRef;
  capability: ApprovalCapability;
  expires_in_seconds?: number;
}
export interface ApprovalEnrollmentTicket {
  enrollment_id: Uuid;
  code: string;
  /** The relay's suggestion. **Never shown**: the SDK builds the link with your own root key id and the enrollment secret. */
  deep_link: string;
  expires_at: Timestamp;
}
export const APPROVAL_ENROLLMENT_STATUSES = ["open", "device_completed", "confirmed", "cancelled", "expired"] as const;
export interface ApprovalEnrollmentView {
  enrollment_id: Uuid;
  subject_ref: SubjectRef;
  capability: string;
  status: (typeof APPROVAL_ENROLLMENT_STATUSES)[number];
  expires_at: Timestamp;
  created_at: Timestamp;
  device_statement?: SignedStatement;
  kid?: string;
  confirmation?: BusinessSignedStatement;
  binding_tag?: string;
}
export interface ConfirmApprovalEnrollmentRequest {
  confirmation: BusinessSignedStatement;
}
/** A key the relay lists. **For display and reconciliation only**: authorize against your own store of the keys you verified at enrollment. */
export interface ApprovalKeyView {
  kid: string;
  subject_ref: SubjectRef;
  status: "pending" | "active" | "revoked";
  assurance: "biometric" | "device_passcode";
  public_key: string;
  hpke_kid: string;
  hpke_public_key: string;
  created_at: Timestamp;
  activated_at?: Timestamp;
  revoked_at?: Timestamp;
  revoked_by?: string;
  device_statement: SignedStatement;
}
export interface RevokeApprovalKeyRequest {
  reason?: string;
}
export interface ApprovalEnvelopeDelivery {
  /** The approval key this copy is for. */
  kid: string;
  envelope: E2EEEnvelope;
}
export interface CreateApprovalRequest {
  /** Makes the call idempotent: the same id with different content is `409 idempotency_conflict`. */
  request_id: string;
  subject_ref: SubjectRef;
  capability: ApprovalCapability;
  /** Server-visible only: 22 to 128 base64url characters, single use. */
  challenge?: string;
  transaction?: TransactionDetails;
  authentication?: AuthenticationDetails;
  envelopes?: ApprovalEnvelopeDelivery[];
  expires_in_seconds?: number;
}
export const APPROVAL_REQUEST_STATUSES = ["pending", "approved", "denied", "reported", "expired", "cancelled"] as const;
/** The relay's view. **`status` is information for your UI and is never sufficient to act**: verify the signed result. */
export interface ApprovalRequestView {
  request_id: string;
  subject_ref: SubjectRef;
  capability: string;
  status: (typeof APPROVAL_REQUEST_STATUSES)[number];
  protection: "end_to_end" | "server_visible";
  expires_at: Timestamp;
  created_at: Timestamp;
  decided_at?: Timestamp;
  result_ref?: string;
  reason?: string;
  delivered_to: number;
}
export interface ApprovalResultResponse {
  result_ref: string;
  request_id: string;
  /** Compact JWS, `typ viadere-approval+jws`, `alg ES256`. Verify it with `ApprovalVerifier`. */
  result: string;
  kid: string;
  decided_at: Timestamp;
}
export interface BusinessFreezeRequest {
  subject_ref: SubjectRef;
  frozen: boolean;
  reason?: string;
}
export const APPROVE_DEVICE_POLICIES = ["any_enrolled", "single_device"] as const;
export type ApproveDevicePolicy = (typeof APPROVE_DEVICE_POLICIES)[number];
export interface ApproveBusinessSettings {
  device_policy: ApproveDevicePolicy;
}
export interface FreezeStatus {
  subject_ref: SubjectRef;
  frozen: boolean;
}

export const AUTH_APPROVAL_RISKS = ["low", "medium", "high", "critical"] as const;
export type AuthApprovalRisk = (typeof AUTH_APPROVAL_RISKS)[number];
export interface AuthApprovalNumberMatch {
  digits: number;
  /** Only for a server-visible request; end to end it travels inside the signed envelope. */
  code?: string;
}
/** `POST /v1/business/auth-approvals` (`ViadereCore` `AuthApprovalCreateRequest`; the contract describes the body in prose only). Strict. */
export interface AuthApprovalCreateRequest {
  request_id: string;
  subject_ref: SubjectRef;
  capability: ApprovalCapability;
  risk?: AuthApprovalRisk;
  challenge?: string;
  transaction?: TransactionDetails;
  authentication?: AuthApprovalAuthenticationDetails;
  envelopes?: ApprovalEnvelopeDelivery[];
  expires_in_seconds?: number;
  number_match: AuthApprovalNumberMatch;
  match_tag: string;
  match_prefix_tag?: string;
  session_handle?: string;
}

/** `POST /v1/business/auth-links/redeem`: exactly one of `code` (same device) and `ach` (cross device). */
export interface AuthLinkRedeemRequest {
  link_client_id: string;
  code?: string;
  ach?: string;
  code_verifier: string;
}
export interface AuthLinkRedeemResponse {
  /** The `viadere-grant+jwt`. Verify it against the static grant JWKS and consume its `jti` once before you sign the person in. */
  grant: string;
  delivery_id: string;
}

export interface CreateLinkSessionRequest {
  /** Your own opaque reference (stored only as a keyed hash). */
  customer_ref: string;
  capabilities: LinkableCapability[];
  display_hint?: string;
  expires_in_seconds?: number;
}
export interface LinkSessionTicket {
  session_id: Uuid;
  code: string;
  /** The relay's suggestion. **Never shown**: the SDK builds the link with your secret. */
  link: string;
  root_kid: string;
  expires_at: Timestamp;
}
export const LINK_SESSION_STATUSES = ["open", "device_completed", "confirmed", "expired", "cancelled"] as const;
export interface LinkSessionView {
  session_id: Uuid;
  status: (typeof LINK_SESSION_STATUSES)[number];
  capabilities: string[];
  created_at: Timestamp;
  expires_at: Timestamp;
  subject_ref?: SubjectRef;
  connection_id?: SubjectRef;
  statement?: SignedStatement;
  binding_tag?: string;
  approval_statement?: SignedStatement;
  /** Viadere's signed account (key `link-descriptor`, `VIADERE-LINK-RESULT-V1`). */
  result?: BusinessSignedStatement;
  completed_at?: Timestamp;
  confirmed_at?: Timestamp;
}
export interface ConfirmLinkSessionRequest {
  confirmation: BusinessSignedStatement;
  approval_confirmation?: BusinessSignedStatement;
}

export interface CreateVerificationSessionRequest {
  capability: VerificationCapability;
  /** The capability's typed parameters, e.g. `{ years: 21 }`. Flat; at most 8. */
  parameters?: Record<string, string | number | boolean>;
  purpose_code: string;
  /** `https://{host}` inside one of your verified domains; no port, path, query or fragment. */
  origin: string;
  return_url?: string;
  callback_id?: string;
  expires_in_seconds?: number;
}
export interface VerificationSessionTicket {
  session_id: Uuid;
  code: string;
  /** `https://{link domain}/v/{CODE}`: the button's target and the QR content. No secret. */
  link: string;
  expires_at: Timestamp;
}
export const VERIFICATION_SESSION_STATUSES = ["open", "accepted", "completed", "expired", "cancelled"] as const;
/** **Trust only `result`**, after verifying it against the `link-descriptor` keys you pinned. */
export interface VerificationSessionView {
  session_id: Uuid;
  status: (typeof VERIFICATION_SESSION_STATUSES)[number];
  capability: string;
  purpose_code: string;
  origin: string;
  created_at: Timestamp;
  expires_at: Timestamp;
  request_id?: string;
  subject_ref?: SubjectRef;
  result_ref?: string;
  /** Viadere's signed `VerificationSessionResult` (`VIADERE-VERIFY-SESSION-RESULT-V1`). */
  result?: BusinessSignedStatement;
  completed_at?: Timestamp;
}

export interface CreateVerificationRequest {
  subject_ref: SubjectRef;
  capability: VerificationCapability;
  /** `age.minimum`: `{ years: 13 | 16 | 18 | 21 | 25 }`. The identity capabilities take none. */
  parameters?: Record<string, unknown>;
  purpose_code: string;
  /** The id of a webhook endpoint you registered (subscribed to `verification.completed`). Never a URL. */
  callback_id?: Uuid;
  expires_in_seconds?: number;
}
export interface VerificationRequest {
  request_id: string;
  capability: string;
  subject_ref: SubjectRef;
  purpose_code: string;
  status: "pending" | "completed";
  created_at: Timestamp;
  expires_at: Timestamp;
  /** Present once `completed`. */
  result_ref?: string;
}
export interface VerificationResultFields {
  meets_threshold?: boolean;
  verified?: boolean;
  given_name?: string;
  family_name?: string;
  address?: Record<string, unknown>;
  assurance?: string;
  issued_at?: Timestamp;
  expires_at?: Timestamp;
  audience?: string;
}
/** Retrieved **once**. `not_verified` never says why (underage, declined and a failed check look the same). */
export interface VerificationResult {
  result_ref: string;
  request_id: string;
  capability: string;
  subject_ref: SubjectRef;
  parameters: Record<string, unknown>;
  created_at: Timestamp;
  outcome: "verified" | "not_verified";
  result: VerificationResultFields;
}

export interface PublishKeyEntryRequest {
  /** base64url canonical `KeyLogEntry`. */
  entry: string;
}
export interface SignedTreeHead {
  payload: string;
  signature: string;
}
export interface PublishKeyEntryResponse {
  index: number;
  tree_size: number;
  sth: SignedTreeHead;
}
export interface KeyDirectoryEntry {
  index: number;
  entry: string;
  inclusion_proof: string[];
}
export interface KeyDirectoryResponse {
  sth: SignedTreeHead;
  consistency_from?: number;
  consistency_proof?: string[];
  entries: KeyDirectoryEntry[];
}

/** Event types of the opaque envelope in `docs/openapi.yaml` (`WebhookEnvelopeV2`). */
export const OPAQUE_ENVELOPE_EVENT_TYPES = ["approve.enrollment.device_completed", "approve.enrollment.confirmed", "approve.key.revoked", "approve.request.decided", "approve.request.expired", "approve.frozen"] as const;
/**
 * The opaque envelope (`envelopeVersion: "2026-10-27"`, `WebhookEnvelopeV2` in the OpenAPI document): ids only, no customer data, amount or
 * decision. `result_ref` names what to fetch (`getApprovalResult`, `getVerificationResult`); a status in it would not be trusted anyway.
 */
export interface OpaqueWebhookEnvelope {
  id: string;
  type: string;
  version: "2026-10-27";
  tenant_id: string;
  request_id: string;
  occurred_at: Timestamp;
  result_ref?: string;
}

/** Every operation of `docs/openapi.yaml` this SDK offers, by `operationId`. */
export const BUSINESS_ROUTES = {
  getCapabilities: { method: "GET", path: "/v1/business/capabilities" },
  createProfileRequest: { method: "POST", path: "/v1/business/profile-requests" },
  getProfileRequest: { method: "GET", path: "/v1/business/profile-requests/{requestId}" },
  getProfile: { method: "GET", path: "/v1/business/profiles/{subjectRef}" },
  issueInteraction: { method: "POST", path: "/v1/business/interactions" },
  getInteractionOutcome: { method: "GET", path: "/v1/business/interactions/{interactionId}" },
  cancelInteraction: { method: "POST", path: "/v1/business/interactions/{interactionId}/cancel" },
  sendMessage: { method: "POST", path: "/v1/business/messages" },
  updateStatus: { method: "POST", path: "/v1/business/statuses" },
  createSandboxRelationship: { method: "POST", path: "/v1/business/sandbox/relationships" },
  createApprovalEnrollment: { method: "POST", path: "/v1/business/approve/enrollments" },
  getApprovalEnrollment: { method: "GET", path: "/v1/business/approve/enrollments/{enrollmentId}" },
  confirmApprovalEnrollment: { method: "POST", path: "/v1/business/approve/enrollments/{enrollmentId}/confirm" },
  cancelApprovalEnrollment: { method: "POST", path: "/v1/business/approve/enrollments/{enrollmentId}/cancel" },
  listApprovalKeys: { method: "GET", path: "/v1/business/approve/keys" },
  revokeApprovalKey: { method: "POST", path: "/v1/business/approve/keys/{kid}/revoke" },
  createApprovalRequest: { method: "POST", path: "/v1/business/approve/requests" },
  getApprovalRequest: { method: "GET", path: "/v1/business/approve/requests/{requestId}" },
  cancelApprovalRequest: { method: "POST", path: "/v1/business/approve/requests/{requestId}/cancel" },
  getApprovalResult: { method: "GET", path: "/v1/business/approve/results/{resultRef}" },
  freezeApprovals: { method: "POST", path: "/v1/business/approve/freeze" },
  getApprovalFreeze: { method: "GET", path: "/v1/business/approve/freezes/{freezeRef}" },
  getApproveSettings: { method: "GET", path: "/v1/business/approve/settings" },
  putApproveSettings: { method: "PUT", path: "/v1/business/approve/settings" },
  createLinkSession: { method: "POST", path: "/v1/business/link-sessions" },
  getLinkSession: { method: "GET", path: "/v1/business/link-sessions/{sessionId}" },
  confirmLinkSession: { method: "POST", path: "/v1/business/link-sessions/{sessionId}/confirm" },
  cancelLinkSession: { method: "POST", path: "/v1/business/link-sessions/{sessionId}/cancel" },
  createVerificationSession: { method: "POST", path: "/v1/business/verification-sessions" },
  getVerificationSession: { method: "GET", path: "/v1/business/verification-sessions/{sessionId}" },
  cancelVerificationSession: { method: "POST", path: "/v1/business/verification-sessions/{sessionId}/cancel" },
  publishKeyEntry: { method: "POST", path: "/v1/business/key-directory/entries" },
  listKeyEntries: { method: "GET", path: "/v1/business/key-directory/entries" },
  listWebhooks: { method: "GET", path: "/v1/business/webhooks" },
  createWebhook: { method: "POST", path: "/v1/business/webhooks" },
  deleteWebhook: { method: "DELETE", path: "/v1/business/webhooks/{webhookId}" },
  rotateWebhookSecret: { method: "POST", path: "/v1/business/webhooks/{webhookId}/rotate-secret" },
  verifyWebhook: { method: "POST", path: "/v1/business/webhooks/{webhookId}/verify" },
  sendWebhookTestEvent: { method: "POST", path: "/v1/business/webhooks/{webhookId}/test" },
  pauseWebhook: { method: "POST", path: "/v1/business/webhooks/{webhookId}/pause" },
  resumeWebhook: { method: "POST", path: "/v1/business/webhooks/{webhookId}/resume" },
  getLoyaltyProgram: { method: "GET", path: "/v1/business/loyalty/program" },
  saveLoyaltyProgram: { method: "PUT", path: "/v1/business/loyalty/program" },
  adjustLoyaltyPoints: { method: "POST", path: "/v1/business/loyalty/points" },
  listRewards: { method: "GET", path: "/v1/business/rewards" },
  createReward: { method: "POST", path: "/v1/business/rewards" },
  revokeReward: { method: "POST", path: "/v1/business/rewards/{rewardId}/revoke" },
  consumeRedemption: { method: "POST", path: "/v1/business/redemptions/consume" },
  issueWalletPass: { method: "POST", path: "/v1/business/wallet/passes" },
  listWalletPasses: { method: "GET", path: "/v1/business/wallet/passes" },
  updateWalletPass: { method: "PATCH", path: "/v1/business/wallet/passes/{passId}" },
  voidWalletPass: { method: "POST", path: "/v1/business/wallet/passes/{passId}/void" },
  scanWalletPass: { method: "POST", path: "/v1/business/wallet/scan" },
  createVerificationRequest: { method: "POST", path: "/v1/verification-requests" },
  getVerificationRequest: { method: "GET", path: "/v1/verification-requests/{requestId}" },
  getVerificationResult: { method: "GET", path: "/v1/verification-results/{resultRef}" },
} as const;

/**
 * Operations of `docs/openapi.yaml` this SDK deliberately does not offer. The parity test fails for any operation that is neither in
 * `BUSINESS_ROUTES` nor here, and for an entry here that the document no longer has.
 */
export const OPERATIONS_NOT_OFFERED = {
  // Public, unauthenticated transparency-log reads (`security: []`). The Swift SDK's client does not call them either: they serve log monitors
  // and the device, and are only useful together with the Merkle and key-statement verification this SDK does not port (see the README).
  keyDirectorySignedTreeHead: { method: "GET", path: "/v1/key-directory/sth" },
  keyDirectoryConsistency: { method: "GET", path: "/v1/key-directory/consistency" },
  keyDirectoryBusiness: { method: "GET", path: "/v1/key-directory/businesses/{businessId}" },
} as const;
