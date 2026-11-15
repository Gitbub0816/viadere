import * as T from "./types.js";

// One table for three jobs:
//
//   1. `test/parity.test.ts` compares every entry with the component schema of the same name in `docs/openapi.yaml`: member names, the `required`
//      list, `additionalProperties: false` and the enums. A member added to or removed from the document fails the test.
//   2. `validate.ts` checks a request against its entry before anything is sent (same field names and codes as the server's `422`).
//   3. The client checks that a response carries the required members of its entry (`invalid_response` otherwise).
//
// Each entry is tied to its TypeScript interface at compile time: `define<X>()` refuses a property that `X` does not have, a missing property, and a
// `required` list that differs from the non-optional members of `X`. So the interfaces in `types.ts` cannot drift from this table, and this table
// cannot drift from the OpenAPI document.

export type Rule =
  | { readonly t: "string"; readonly min?: number; readonly max?: number; readonly pattern?: RegExp }
  | { readonly t: "int"; readonly min?: number; readonly max?: number }
  | { readonly t: "bool" }
  | { readonly t: "enum"; readonly values: readonly (string | number)[] }
  | { readonly t: "array"; readonly items: Rule; readonly min?: number; readonly max?: number; readonly unique?: boolean }
  | { readonly t: "object"; readonly schema: SchemaDef }
  /** A JSON object whose members this SDK does not constrain. */
  | { readonly t: "record" }
  | { readonly t: "any" };

export interface SchemaDef {
  readonly name: string;
  /** `additionalProperties: false` in the document: an unknown member is refused. */
  readonly closed: boolean;
  readonly required: readonly string[];
  readonly properties: Readonly<Record<string, Rule>>;
  /** `anyOf: [{required: [a]}, {required: [b]}]`: at least one of these members must be present. */
  readonly oneOfRequired?: readonly string[];
}

type RequiredKeys<X> = { [K in keyof X]-?: {} extends Pick<X, K> ? never : K }[keyof X] & string;
type Covers<All extends string, Listed extends string> = [All] extends [Listed] ? unknown : { readonly missing: Exclude<All, Listed> };
type NoExtra<Listed extends PropertyKey, All extends PropertyKey> = [Exclude<Listed, All>] extends [never] ? unknown : { readonly unknown: Exclude<Listed, All> };

function define<X>() {
  return <const R extends readonly RequiredKeys<X>[], const P extends { readonly [K in keyof X & string]?: Rule }>(
    name: string,
    def: { closed?: boolean; oneOfRequired?: readonly (keyof X & string)[]; required: R & Covers<RequiredKeys<X>, R[number]>; properties: P & Covers<keyof X & string, keyof P & string> & NoExtra<keyof P, keyof X> },
  ): SchemaDef => ({ name, closed: def.closed ?? false, required: def.required, properties: def.properties as Record<string, Rule>, ...(def.oneOfRequired ? { oneOfRequired: def.oneOfRequired } : {}) });
}

const S = (o: { min?: number; max?: number; pattern?: RegExp } = {}): Rule => ({ t: "string", ...o });
const I = (min?: number, max?: number): Rule => ({ t: "int", ...(min !== undefined ? { min } : {}), ...(max !== undefined ? { max } : {}) });
const E = (values: readonly (string | number)[]): Rule => ({ t: "enum", values });
const A = (items: Rule, o: { min?: number; max?: number; unique?: boolean } = {}): Rule => ({ t: "array", items, ...o });
const O = (schema: SchemaDef): Rule => ({ t: "object", schema });
const B: Rule = { t: "bool" };
const REC: Rule = { t: "record" };
const ANY: Rule = { t: "any" };

export const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
export const SUBJECT_REF = /^sub_[A-Za-z0-9_-]{43}$/;
export const TOKEN_PATTERN = /^[A-Za-z0-9_.:-]+$/;
export const VERIFICATION_REQUEST_ID_PATTERN = /^req_[A-Za-z0-9_-]{22}$/;
export const VERIFICATION_RESULT_REF_PATTERN = /^res_[A-Za-z0-9_-]{43}$/;
/** An ISO 8601 timestamp (any fractional precision, `Z` or an offset). */
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

const UUID = S({ pattern: UUID_PATTERN });
const SUBJECT = S({ pattern: SUBJECT_REF });
const TS = S({ pattern: TIMESTAMP_PATTERN });
const IDEMPOTENCY = S({ min: 1, max: 128, pattern: TOKEN_PATTERN });
const CORRELATION = S({ max: 128, pattern: TOKEN_PATTERN });
const KID = S({ min: 43, max: 43, pattern: /^[A-Za-z0-9_-]{43}$/ });

// ---- shared pieces --------------------------------------------------------------------------------------------------------------------------

export const SignedStatement = define<T.SignedStatement>()("SignedStatement", { closed: true, required: ["payload", "signature"], properties: { payload: S({ min: 1 }), signature: S({ min: 86, max: 86 }) } });
export const BusinessSignedStatement = define<T.BusinessSignedStatement>()("BusinessSignedStatement", { closed: true, required: ["kid", "payload", "signature"], properties: { kid: KID, payload: S({ min: 1 }), signature: S({ min: 86, max: 86 }) } });
const E2EEContext = define<T.E2EEContext>()("E2EEEnvelope.ctx", { closed: true, required: ["exp", "purpose", "recipient", "request_id", "sender"], properties: { exp: I(1), purpose: S({ pattern: /^[a-z0-9._-]{1,64}$/ }), recipient: S({ min: 1 }), request_id: S({ min: 1 }), sender: S({ min: 1 }) } });
export const E2EEEnvelope = define<T.E2EEEnvelope>()("E2EEEnvelope", { closed: true, required: ["v", "suite", "kid", "enc", "ct", "ctx"], properties: { v: E([1]), suite: E(["hpke-0010-0001-0002"]), kid: S({ min: 1 }), enc: S({ min: 1 }), ct: S({ min: 1 }), ctx: O(E2EEContext) } });
export const TransactionDetails = define<T.TransactionDetails>()("TransactionDetails", {
  closed: true,
  required: ["currency", "amount_minor", "payee_display", "transaction_reference"],
  properties: { currency: S({ pattern: /^[A-Z]{3}$/ }), amount_minor: I(1), payee_display: S({ min: 1, max: 80 }), transaction_reference: S({ min: 1, max: 64 }) },
});
export const AuthenticationDetails = define<T.AuthenticationDetails>()("AuthenticationDetails", { closed: true, required: ["action_display"], properties: { action_display: S({ min: 1, max: 120 }), reference: S({ max: 64 }) } });
const AuthApprovalAuthenticationDetails = define<T.AuthApprovalAuthenticationDetails>()("AuthApprovalAuthenticationDetails", { closed: true, required: ["action_display"], properties: { action_display: S({ min: 1, max: 120 }), reference: S({ max: 64 }), match_digits: I(2, 3) } });

// ---- interactions, messages, statuses (camelCase) ---------------------------------------------------------------------------------------------

export const MoneyAmount = define<T.MoneyAmount>()("MoneyAmount", { required: ["value", "currency"], properties: { value: S({ pattern: /^[0-9]{1,15}(\.[0-9]+)?$/ }), currency: S({ pattern: /^[A-Z]{3}$/ }) } });
export const RiskIndicator = define<T.RiskIndicator>()("RiskIndicator", { required: ["code", "label", "severity"], properties: { code: S({ max: 40, pattern: TOKEN_PATTERN }), label: S({ max: 80 }), severity: E(["info", "warning", "high"]) } });
export const RequestedAction = define<T.RequestedAction>()("RequestedAction", { required: ["id", "label", "role"], properties: { id: S({ max: 64, pattern: TOKEN_PATTERN }), label: S({ max: 32 }), role: E(T.ACTION_ROLES) } });
export const AuthenticatePayload = define<T.AuthenticatePayload>()("AuthenticatePayload", {
  required: ["service", "device", "attemptedAt"],
  properties: { service: S({ max: 80 }), device: S({ max: 80 }), approximateLocation: S({ max: 80 }), ipRegion: S({ max: 80 }), attemptedAt: TS, riskIndicators: A(O(RiskIndicator), { max: 8 }) },
});
export const AuthorizePayload = define<T.AuthorizePayload>()("AuthorizePayload", {
  required: ["actionDescription"],
  properties: { actionDescription: S({ max: 120 }), amount: O(MoneyAmount), merchant: S({ max: 80 }), location: S({ max: 80 }), effectOfApproval: S({ max: 160 }), riskIndicators: A(O(RiskIndicator), { max: 8 }) },
});
export const ConfirmPayload = define<T.ConfirmPayload>()("ConfirmPayload", { required: ["title"], properties: { title: S({ max: 80 }), details: S({ max: 160 }), reference: S({ max: 64 }), scheduledAt: TS } });
export const ChoiceOption = define<T.ChoiceOption>()("ChoiceOption", { required: ["id", "label"], properties: { id: S({ max: 64, pattern: TOKEN_PATTERN }), label: S({ max: 80 }) } });
export const ChoosePayload = define<T.ChoosePayload>()("ChoosePayload", { required: ["prompt", "options"], properties: { prompt: S({ max: 160 }), options: A(O(ChoiceOption), { min: 2, max: 10 }), allowsMultiple: B } });
export const AcknowledgePayload = define<T.AcknowledgePayload>()("AcknowledgePayload", {
  required: ["title", "body"],
  properties: { title: S({ max: 80 }), body: S({ max: 1000 }), documentURL: S(), documentVersion: S({ max: 40 }), documentDigest: S({ pattern: /^[0-9a-f]{64}$/ }) },
});
export const ReplyPayload = define<T.ReplyPayload>()("ReplyPayload", { required: ["prompt"], properties: { prompt: S({ max: 160 }), maxLength: I(), suggestedReplies: A(S(), { max: 4 }) } });
export const LiveActivityStatus = define<T.LiveActivityStatus>()("LiveActivityStatus", { required: ["type"], properties: { type: E(["order", "delivery", "flight", "appointment"]), order: REC, delivery: REC, flight: REC, appointment: REC } });
export const StatusPayload = define<T.StatusPayload>()("StatusPayload", { required: ["title"], properties: { title: S({ max: 80 }), body: S({ max: 240 }), liveActivity: O(LiveActivityStatus) } });
export const MessagePayload = define<T.MessagePayload>()("MessagePayload", { required: ["text"], properties: { text: S(), sessionId: UUID } });
export const RewardPayload = define<T.RewardPayload>()("RewardPayload", { required: ["rewardId", "title"], properties: { rewardId: UUID, title: S(), details: S(), redeemBy: TS, walletPassId: UUID } });
export const TicketPayload = define<T.TicketPayload>()("TicketPayload", {
  required: ["title", "ticketType"],
  properties: { title: S(), ticketType: S(), holderName: S(), validFrom: TS, validUntil: TS, walletPassId: UUID, venue: S({ max: 80 }), seat: S({ max: 80 }), startsAt: TS },
});
/** The payload schema of each interaction kind (the sibling `kind` is the discriminator). */
export const PAYLOAD_BY_KIND: Readonly<Record<T.InteractionKind, SchemaDef>> = {
  authenticate: AuthenticatePayload,
  authorize: AuthorizePayload,
  confirm: ConfirmPayload,
  choose: ChoosePayload,
  acknowledge: AcknowledgePayload,
  reply: ReplyPayload,
  status: StatusPayload,
  reward: RewardPayload,
  ticket: TicketPayload,
  message: MessagePayload,
};

export const IssueInteractionRequest = define<T.IssueInteractionRequest>()("IssueInteractionRequest", {
  required: ["kind", "purpose", "payload", "ttlSeconds", "idempotencyKey"],
  oneOfRequired: ["relationshipId", "subjectRef"],
  properties: {
    relationshipId: UUID,
    subjectRef: SUBJECT,
    kind: E(T.INTERACTION_KINDS),
    purpose: E(T.INTERACTION_PURPOSES),
    payload: REC,
    requestedActions: A(O(RequestedAction), { max: 4 }),
    priority: E(T.INTERACTION_PRIORITIES),
    sensitivity: E(T.SENSITIVITIES),
    allowedChannels: A(E(T.INTERACTION_CHANNELS), { min: 1, unique: true }),
    ttlSeconds: I(1, 2_592_000),
    idempotencyKey: IDEMPOTENCY,
    correlationId: CORRELATION,
    accountReference: S({ max: 64 }),
  },
});
export const Interaction = define<T.Interaction>()("Interaction", {
  required: ["schemaVersion", "id", "businessId", "scope", "kind", "purpose", "payload", "priority", "sensitivity", "allowedChannels", "createdAt", "expiresAt", "idempotencyKey", "challenge"],
  properties: { schemaVersion: ANY, id: ANY, businessId: ANY, scope: ANY, kind: ANY, purpose: ANY, payload: ANY, requestedActions: ANY, priority: ANY, sensitivity: ANY, allowedChannels: ANY, createdAt: ANY, expiresAt: ANY, idempotencyKey: ANY, correlationId: ANY, challenge: ANY },
});
export const InteractionOutcome = define<T.InteractionOutcome>()("InteractionOutcome", {
  required: ["interactionId", "businessId", "status"],
  properties: { interactionId: ANY, businessId: ANY, status: ANY, decision: ANY, selectedOptionIds: ANY, reply: ANY, assurance: ANY, channel: ANY, decidedAt: ANY, correlationId: ANY, deviceRef: ANY, verification: ANY },
});
export const DecisionVerification = define<T.DecisionVerification>()("DecisionVerification", { required: ["verified", "keyPurpose", "contextBound", "verifiedAt", "evidenceRef"], properties: { verified: ANY, keyPurpose: ANY, contextBound: ANY, verifiedAt: ANY, evidenceRef: ANY } });
export const SandboxRelationship = define<T.SandboxRelationship>()("SandboxRelationship", { required: ["relationshipId", "createdAt"], properties: { relationshipId: ANY, subjectRef: ANY, createdAt: ANY } });
export const MessageAttribution = define<T.MessageAttribution>()("MessageAttribution", { required: ["senderType", "displayName"], properties: { senderType: ANY, displayName: ANY, agentName: ANY } });
export const ConversationMessage = define<T.ConversationMessage>()("ConversationMessage", {
  required: ["id", "sessionId", "businessId", "direction", "attribution", "body", "channel", "createdAt", "deliveryStatus"],
  properties: { id: ANY, sessionId: ANY, businessId: ANY, direction: ANY, attribution: ANY, body: ANY, channel: ANY, createdAt: ANY, deliveredAt: ANY, readAt: ANY, deliveryStatus: ANY, interactionId: ANY, attachments: ANY },
});
export const MessageAttachment = define<T.MessageAttachment>()("MessageAttachment", {
  required: ["id", "sessionId", "mediaType", "byteSize", "width", "height", "sha256", "state"],
  properties: {
    id: UUID,
    sessionId: UUID,
    mediaType: E(T.MESSAGE_ATTACHMENT_MEDIA_TYPES),
    byteSize: I(1, T.MESSAGE_ATTACHMENT_MAX_STORED_BYTES),
    width: I(1, 2048),
    height: I(1, 2048),
    sha256: S({ pattern: /^[0-9a-f]{64}$/ }),
    state: E(T.MESSAGE_ATTACHMENT_STATES),
    expiresAt: TS,
  },
});
export const BusinessSendMessageRequest = define<T.BusinessSendMessageRequest>()("BusinessSendMessageRequest", {
  required: ["body", "idempotencyKey"],
  oneOfRequired: ["relationshipId", "subjectRef"],
  // `body` may be empty only with images: `validation.ts` (EXTRA) checks that and that `attachmentIds` comes with `sessionId`.
  properties: {
    relationshipId: UUID, subjectRef: SUBJECT, sessionId: UUID, body: S({ max: 1600 }), agentName: S({ max: 40 }), idempotencyKey: IDEMPOTENCY,
    attachmentIds: A(UUID, { min: 1, max: T.MESSAGE_ATTACHMENT_MAX_PER_MESSAGE, unique: true }),
  },
});
export const BusinessStatusUpdateRequest = define<T.BusinessStatusUpdateRequest>()("BusinessStatusUpdateRequest", {
  required: ["purpose", "status", "activityKey", "idempotencyKey"],
  oneOfRequired: ["relationshipId", "subjectRef"],
  properties: { relationshipId: UUID, subjectRef: SUBJECT, purpose: E(T.INTERACTION_PURPOSES), status: O(StatusPayload), activityKey: S({ min: 1, max: 64 }), idempotencyKey: IDEMPOTENCY, correlationId: CORRELATION },
});

// ---- rewards, loyalty, Wallet (camelCase) --------------------------------------------------------------------------------------------------------

export const RewardRecurrence = define<T.RewardRecurrence>()("RewardRecurrence", { required: ["weekdays", "perDayLimit", "timeZone"], properties: { weekdays: A(I(1, 7), { min: 1 }), perDayLimit: I(1, 20), timeZone: S({ min: 1 }) } });
export const IssueRewardRequest = define<T.IssueRewardRequest>()("IssueRewardRequest", {
  required: ["title", "idempotencyKey"],
  properties: {
    relationshipId: UUID,
    subjectRef: SUBJECT,
    title: S({ min: 1, max: 80 }),
    kind: E(T.REWARD_KINDS),
    details: S({ max: 300 }),
    validFrom: TS,
    validUntil: TS,
    recurrence: O(RewardRecurrence),
    pointsCost: I(1),
    issueWalletPass: B,
    idempotencyKey: IDEMPOTENCY,
  },
});
export const Reward = define<T.Reward>()("Reward", { required: ["id", "business", "title", "status"], properties: { id: ANY, business: ANY, title: ANY, details: ANY, status: ANY, validFrom: ANY, validUntil: ANY, recurrence: ANY } });
export const LoyaltyTier = define<T.LoyaltyTier>()("LoyaltyTier", { required: ["name", "minimumPoints"], properties: { name: S({ max: 30 }), minimumPoints: I(0) } });
export const UpsertLoyaltyProgramRequest = define<T.UpsertLoyaltyProgramRequest>()("UpsertLoyaltyProgramRequest", {
  required: ["programName", "summary", "termsVersion", "timeZone"],
  properties: { programName: S({ max: 60 }), summary: S({ max: 280 }), termsVersion: S({ max: 32 }), timeZone: S({ min: 1 }), tiers: A(O(LoyaltyTier), { max: 10 }) },
});
/** `allOf: [UpsertLoyaltyProgramRequest, { required: [memberCount, updatedAt] }]`. */
export const BusinessLoyaltyProgram = define<T.BusinessLoyaltyProgram>()("BusinessLoyaltyProgram", {
  required: ["programName", "summary", "termsVersion", "timeZone", "memberCount", "updatedAt"],
  properties: { programName: ANY, summary: ANY, termsVersion: ANY, timeZone: ANY, tiers: ANY, memberCount: ANY, updatedAt: ANY },
});
export const AdjustLoyaltyPointsRequest = define<T.AdjustLoyaltyPointsRequest>()("AdjustLoyaltyPointsRequest", {
  required: ["delta", "idempotencyKey"],
  oneOfRequired: ["relationshipId", "subjectRef"],
  properties: { relationshipId: UUID, subjectRef: SUBJECT, delta: I(-1_000_000, 1_000_000), reason: S({ max: 40, pattern: /^[A-Za-z0-9_.-]+$/ }), idempotencyKey: IDEMPOTENCY },
});
export const LoyaltyPointsResult = define<T.LoyaltyPointsResult>()("LoyaltyPointsResult", { required: ["relationshipId", "pointsBalance", "applied"], properties: { relationshipId: ANY, subjectRef: ANY, pointsBalance: ANY, statusName: ANY, applied: ANY } });
export const ConsumeRedemptionRequest = define<T.ConsumeRedemptionRequest>()("ConsumeRedemptionRequest", { required: ["code"], properties: { code: S({ min: 1, max: 64 }), locationCode: S({ max: 64, pattern: TOKEN_PATTERN }) } });
export const RedemptionReceipt = define<T.RedemptionReceipt>()("RedemptionReceipt", {
  required: ["redemptionId", "rewardId", "rewardTitle", "kind", "consumerReference", "redeemedAt"],
  properties: { redemptionId: ANY, rewardId: ANY, rewardTitle: ANY, kind: ANY, consumerReference: ANY, subjectRef: ANY, redeemedAt: ANY, pointsSpent: ANY, locationCode: ANY },
});
export const BusinessIssueWalletPassRequest = define<T.BusinessIssueWalletPassRequest>()("BusinessIssueWalletPassRequest", {
  required: ["kind"],
  // "Name the customer with `relationshipId` or `subjectRef`": prose in the document, enforced here.
  oneOfRequired: ["relationshipId", "subjectRef"],
  properties: { relationshipId: UUID, subjectRef: SUBJECT, kind: E(T.WALLET_PASS_KINDS), rewardId: UUID, interactionId: UUID },
});
export const BusinessWalletPass = define<T.BusinessWalletPass>()("BusinessWalletPass", {
  required: ["id", "kind", "issuedBy", "voided", "createdAt", "updatedAt"],
  properties: { id: ANY, kind: ANY, relationshipId: ANY, subjectRef: ANY, rewardId: ANY, interactionId: ANY, issuedBy: ANY, voided: ANY, usedAt: ANY, createdAt: ANY, updatedAt: ANY },
});
export const UpdateWalletPassRequest = define<T.UpdateWalletPassRequest>()("UpdateWalletPassRequest", { required: [], properties: { venue: S({ max: 80 }), seat: S({ max: 80 }), startsAt: TS, rotateScanCode: B } });
export const WalletScanRequest = define<T.WalletScanRequest>()("WalletScanRequest", { required: ["code"], properties: { code: S({ pattern: /^VQ1\.[A-Za-z0-9_-]{48}$/ }), locationCode: S({ max: 64, pattern: TOKEN_PATTERN }) } });
export const WalletScanResult = define<T.WalletScanResult>()("WalletScanResult", {
  required: ["outcome", "passId", "kind", "relationshipId", "scannedAt"],
  properties: { outcome: ANY, passId: ANY, kind: ANY, relationshipId: ANY, subjectRef: ANY, title: ANY, pointsBalance: ANY, redemption: ANY, scannedAt: ANY },
});

// ---- capabilities, webhooks, profiles (camelCase) ----------------------------------------------------------------------------------------------

export const BusinessCapabilitiesResponse = define<T.BusinessCapabilitiesResponse>()("BusinessCapabilitiesResponse", {
  required: ["businessId", "environment", "tiers", "entitlements", "keyScopes", "effective", "catalog"],
  properties: { businessId: ANY, environment: ANY, tiers: ANY, entitlements: ANY, keyScopes: ANY, effective: ANY, catalog: ANY },
});
export const CapabilityDefinition = define<T.CapabilityDefinition>()("CapabilityDefinition", {
  required: ["capability", "title", "summary", "parameters", "requiresPurpose", "requiredEvidence", "sensitivity", "minimumTier", "consent", "customerUX", "output", "maxResultRetentionSeconds", "auditFields", "revocation", "auditsAllowedDecisions"],
  properties: { capability: ANY, title: ANY, summary: ANY, parameters: ANY, requiresPurpose: ANY, requiredEvidence: ANY, sensitivity: ANY, minimumTier: ANY, consent: ANY, customerUX: ANY, output: ANY, maxResultRetentionSeconds: ANY, auditFields: ANY, revocation: ANY, auditsAllowedDecisions: ANY },
});
export const WebhookSubscription = define<T.WebhookSubscription>()("WebhookSubscription", {
  required: ["id", "url", "events", "active", "createdAt"],
  properties: { id: ANY, url: ANY, events: ANY, envelopeVersion: ANY, secretVersion: ANY, verifiedAt: ANY, pausedAt: ANY, active: ANY, createdAt: ANY },
});
export const WebhookVerificationResult = define<T.WebhookVerificationResult>()("WebhookVerificationResult", { required: ["verified"], properties: { verified: ANY, failure: ANY } });
export const PauseWebhookRequest = define<T.PauseWebhookRequest>()("PauseWebhookRequest", { required: [], properties: { reason: S({ max: 200 }) } });
export const CreateWebhookRequest = define<T.CreateWebhookRequest>()("CreateWebhookRequest", {
  required: ["url", "events"],
  // The event type is an open set in the document: any well-formed name is sent, and the server decides.
  properties: { url: S({ max: 2048, pattern: /^https:\/\/[^\s]+$/ }), events: A(S({ min: 1, max: 64, pattern: /^[a-z0-9_.]+$/ }), { min: 1, max: 16 }), envelopeVersion: E(["2026-10-27"]) },
});
export const WebhookSecretResponse = define<T.WebhookSecretResponse>()("WebhookSecretResponse", { required: ["subscription", "secret"], properties: { subscription: ANY, secret: ANY } });
export const WebhookEventEnvelope = define<T.WebhookEventEnvelope>()("WebhookEventEnvelope", { required: ["id", "type", "createdAt", "businessId", "apiVersion", "data"], properties: { id: UUID, type: S({ min: 1 }), createdAt: TS, businessId: UUID, apiVersion: S({ min: 1 }), data: ANY } });
export const MessageReceivedData = define<T.MessageReceivedData>()("MessageReceivedData", {
  required: ["sessionId", "relationshipId", "messageId", "text", "channel", "receivedAt"],
  properties: { sessionId: UUID, relationshipId: UUID, subjectRef: SUBJECT, messageId: UUID, text: S(), channel: S(), receivedAt: TS,
                attachments: A(O(MessageAttachment), { max: T.MESSAGE_ATTACHMENT_MAX_PER_MESSAGE }) },
});
export const RelationshipEventData = define<T.RelationshipEventData>()("RelationshipEventData", { required: ["relationshipId", "occurredAt"], properties: { relationshipId: UUID, subjectRef: SUBJECT, publicName: S(), source: S(), occurredAt: TS } });
export const ConsentUpdatedData = define<T.ConsentUpdatedData>()("ConsentUpdatedData", { required: ["relationshipId", "purpose", "granted", "occurredAt"], properties: { relationshipId: UUID, subjectRef: SUBJECT, purpose: S(), granted: B, occurredAt: TS } });
export const ProfileAccessEventData = define<T.ProfileAccessEventData>()("ProfileAccessEventData", { required: ["subjectRef", "fieldKeys", "occurredAt"], properties: { subjectRef: SUBJECT, fieldKeys: A(S()), requestId: UUID, occurredAt: TS } });
export const VerificationCompletedData = define<T.VerificationCompletedData>()("VerificationCompletedData", { closed: true, required: ["request_id", "result_ref"], properties: { request_id: S({ pattern: VERIFICATION_REQUEST_ID_PATTERN }), result_ref: S({ pattern: VERIFICATION_RESULT_REF_PATTERN }) } });
export const CreateProfileRequest = define<T.CreateProfileRequest>()("CreateProfileRequest", {
  required: ["subjectRef", "fieldKeys", "purpose"],
  properties: { subjectRef: SUBJECT, fieldKeys: A(S({ min: 1 }), { min: 1, max: 20 }), purpose: S({ min: 1, max: 200 }), expiresInSeconds: I(3600, 2_592_000) },
});
export const ProfileRequestResource = define<T.ProfileRequestResource>()("ProfileRequestResource", {
  required: ["id", "subjectRef", "fieldKeys", "purpose", "status", "livemode", "createdAt", "expiresAt"],
  properties: { id: ANY, subjectRef: ANY, fieldKeys: ANY, purpose: ANY, status: ANY, approvedKeys: ANY, livemode: ANY, createdAt: ANY, expiresAt: ANY, answeredAt: ANY },
});
export const BusinessProfileView = define<T.BusinessProfileView>()("BusinessProfileView", {
  required: ["subjectRef", "fields", "grantedWithoutValue", "catalogVersion", "livemode"],
  properties: { subjectRef: ANY, publicName: ANY, fields: ANY, grantedWithoutValue: ANY, catalogVersion: ANY, livemode: ANY },
});

// ---- Approve v2 (snake_case) ---------------------------------------------------------------------------------------------------------------------

export const CreateApprovalEnrollmentRequest = define<T.CreateApprovalEnrollmentRequest>()("CreateApprovalEnrollmentRequest", { closed: true, required: ["subject_ref", "capability"], properties: { subject_ref: SUBJECT, capability: E(T.APPROVAL_CAPABILITIES), expires_in_seconds: I(60, 900) } });
export const ApprovalEnrollmentTicket = define<T.ApprovalEnrollmentTicket>()("ApprovalEnrollmentTicket", { required: ["enrollment_id", "code", "deep_link", "expires_at"], properties: { enrollment_id: ANY, code: ANY, deep_link: ANY, expires_at: ANY } });
export const ApprovalEnrollmentView = define<T.ApprovalEnrollmentView>()("ApprovalEnrollmentView", {
  required: ["enrollment_id", "subject_ref", "capability", "status", "expires_at", "created_at"],
  properties: { enrollment_id: ANY, subject_ref: ANY, capability: ANY, status: ANY, expires_at: ANY, created_at: ANY, device_statement: ANY, kid: ANY, confirmation: ANY, binding_tag: ANY },
});
export const ConfirmApprovalEnrollmentRequest = define<T.ConfirmApprovalEnrollmentRequest>()("ConfirmApprovalEnrollmentRequest", { closed: true, required: ["confirmation"], properties: { confirmation: O(BusinessSignedStatement) } });
export const ApprovalKeyView = define<T.ApprovalKeyView>()("ApprovalKeyView", {
  required: ["kid", "subject_ref", "status", "assurance", "public_key", "hpke_kid", "hpke_public_key", "created_at", "device_statement"],
  properties: { kid: ANY, subject_ref: ANY, status: ANY, assurance: ANY, public_key: ANY, hpke_kid: ANY, hpke_public_key: ANY, created_at: ANY, activated_at: ANY, revoked_at: ANY, revoked_by: ANY, device_statement: ANY },
});
export const RevokeApprovalKeyRequest = define<T.RevokeApprovalKeyRequest>()("RevokeApprovalKeyRequest", { closed: true, required: [], properties: { reason: S({ max: 120 }) } });
export const ApprovalEnvelopeDelivery = define<T.ApprovalEnvelopeDelivery>()("ApprovalEnvelopeDelivery", { closed: true, required: ["kid", "envelope"], properties: { kid: KID, envelope: O(E2EEEnvelope) } });
export const CreateApprovalRequest = define<T.CreateApprovalRequest>()("CreateApprovalRequest", {
  closed: true,
  required: ["request_id", "subject_ref", "capability"],
  properties: {
    request_id: S({ pattern: /^[A-Za-z0-9_.:-]{1,128}$/ }),
    subject_ref: SUBJECT,
    capability: E(T.APPROVAL_CAPABILITIES),
    challenge: S({ pattern: /^[A-Za-z0-9_-]{22,128}$/ }),
    transaction: O(TransactionDetails),
    authentication: O(AuthenticationDetails),
    envelopes: A(O(ApprovalEnvelopeDelivery), { min: 1, max: 8 }),
    expires_in_seconds: I(30, 600),
  },
});
export const ApprovalRequestView = define<T.ApprovalRequestView>()("ApprovalRequestView", {
  required: ["request_id", "subject_ref", "capability", "status", "protection", "expires_at", "created_at", "delivered_to"],
  properties: { request_id: ANY, subject_ref: ANY, capability: ANY, status: ANY, protection: ANY, expires_at: ANY, created_at: ANY, decided_at: ANY, result_ref: ANY, reason: ANY, delivered_to: ANY },
});
export const ApprovalResultResponse = define<T.ApprovalResultResponse>()("ApprovalResultResponse", { required: ["result_ref", "request_id", "result", "kid", "decided_at"], properties: { result_ref: ANY, request_id: ANY, result: ANY, kid: ANY, decided_at: ANY } });
export const BusinessFreezeRequest = define<T.BusinessFreezeRequest>()("BusinessFreezeRequest", { closed: true, required: ["subject_ref", "frozen"], properties: { subject_ref: SUBJECT, frozen: B, reason: S({ max: 120 }) } });
export const ApproveBusinessSettings = define<T.ApproveBusinessSettings>()("ApproveBusinessSettings", { closed: true, required: ["device_policy"], properties: { device_policy: E(T.APPROVE_DEVICE_POLICIES) } });
export const FreezeStatus = define<T.FreezeStatus>()("FreezeStatus", { required: ["subject_ref", "frozen"], properties: { subject_ref: ANY, frozen: ANY } });

/** Not a component schema of either OpenAPI document (the contract describes the body in prose): mirrors `ViadereCore` `AuthApprovalCreateRequest`. */
const AuthApprovalNumberMatch = define<T.AuthApprovalNumberMatch>()("AuthApprovalNumberMatch", { closed: true, required: ["digits"], properties: { digits: I(2, 3), code: S({ pattern: /^[1-9][0-9]{1,2}$/ }) } });
export const AuthApprovalCreateRequest = define<T.AuthApprovalCreateRequest>()("AuthApprovalCreateRequest", {
  closed: true,
  required: ["request_id", "subject_ref", "capability", "number_match", "match_tag"],
  properties: {
    request_id: S({ pattern: /^[A-Za-z0-9_.:-]{1,128}$/ }),
    subject_ref: SUBJECT,
    capability: E(T.APPROVAL_CAPABILITIES),
    risk: E(T.AUTH_APPROVAL_RISKS),
    challenge: S({ pattern: /^[A-Za-z0-9_-]{22,128}$/ }),
    transaction: O(TransactionDetails),
    authentication: O(AuthApprovalAuthenticationDetails),
    envelopes: A(O(ApprovalEnvelopeDelivery), { min: 1, max: 8 }),
    expires_in_seconds: I(30, 600),
    number_match: O(AuthApprovalNumberMatch),
    match_tag: KID,
    match_prefix_tag: KID,
    session_handle: S({ pattern: /^[A-Za-z0-9_-]{1,64}$/ }),
  },
});
/** The inline request body of `redeemAuthLink` in `contracts/openapi/auth-delivery-v1.yaml`. */
export const AuthLinkRedeemRequest = define<T.AuthLinkRedeemRequest>()("AuthLinkRedeemRequest", {
  closed: true,
  required: ["link_client_id", "code_verifier"],
  properties: { link_client_id: S({ max: 64, pattern: /^lcl_/ }), code: S({ pattern: /^[A-Za-z0-9_-]{43}$/ }), ach: S({ max: 128, pattern: /^ach_/ }), code_verifier: S({ pattern: /^[A-Za-z0-9._~-]{43,128}$/ }) },
});
export const AuthLinkRedeemResponse = define<T.AuthLinkRedeemResponse>()("AuthLinkRedeemResponse", { closed: true, required: ["grant", "delivery_id"], properties: { grant: ANY, delivery_id: ANY } });

/** `readDestinationKeyRegistrationNonce` in `contracts/openapi/auth-delivery-v1.yaml`. */
export const DestinationKeyNonceRequest = define<T.DestinationKeyNonceRequest>()("DestinationKeyNonceRequest", {
  closed: true,
  required: ["kid"],
  properties: { kid: S({ pattern: /^[A-Za-z0-9_-]{43}$/ }) },
});
export const DestinationKeyNonceResponse = define<T.DestinationKeyNonceResponse>()("DestinationKeyNonceResponse", {
  closed: true,
  required: ["tenant_id", "aud", "kid", "hosts", "nonce", "expires_at"],
  properties: { tenant_id: ANY, aud: ANY, kid: ANY, hosts: ANY, nonce: ANY, expires_at: ANY },
});

// ---- link sessions, verification, key directory (snake_case) ----------------------------------------------------------------------------------

export const CreateLinkSessionRequest = define<T.CreateLinkSessionRequest>()("CreateLinkSessionRequest", {
  closed: true,
  required: ["customer_ref", "capabilities"],
  properties: { customer_ref: S({ min: 1, max: 128, pattern: /^[A-Za-z0-9._:-]+$/ }), capabilities: A(E(T.LINKABLE_CAPABILITIES), { min: 1, max: 8 }), display_hint: S({ max: 40 }), expires_in_seconds: I(60, 300) },
});
export const LinkSessionTicket = define<T.LinkSessionTicket>()("LinkSessionTicket", { required: ["session_id", "code", "link", "root_kid", "expires_at"], properties: { session_id: ANY, code: ANY, link: ANY, root_kid: ANY, expires_at: ANY } });
export const LinkSessionView = define<T.LinkSessionView>()("LinkSessionView", {
  required: ["session_id", "status", "capabilities", "created_at", "expires_at"],
  properties: { session_id: ANY, status: ANY, capabilities: ANY, created_at: ANY, expires_at: ANY, subject_ref: ANY, connection_id: ANY, statement: ANY, binding_tag: ANY, approval_statement: ANY, result: ANY, completed_at: ANY, confirmed_at: ANY },
});
export const ConfirmLinkSessionRequest = define<T.ConfirmLinkSessionRequest>()("ConfirmLinkSessionRequest", { closed: true, required: ["confirmation"], properties: { confirmation: O(BusinessSignedStatement), approval_confirmation: O(BusinessSignedStatement) } });
export const CreateVerificationSessionRequest = define<T.CreateVerificationSessionRequest>()("CreateVerificationSessionRequest", {
  closed: true,
  required: ["capability", "purpose_code", "origin"],
  properties: {
    capability: E(T.VERIFICATION_CAPABILITIES),
    parameters: REC,
    purpose_code: S({ pattern: /^[a-z][a-z0-9_]{1,63}$/ }),
    origin: S({ max: 300, pattern: /^https:\/\/[a-z0-9.-]+$/ }),
    return_url: S({ min: 1, max: 512, pattern: /^https:\/\/[\x21-\x7e]+$/ }),
    callback_id: S({ min: 1, max: 128 }),
    expires_in_seconds: I(60, 300),
  },
});
export const VerificationSessionTicket = define<T.VerificationSessionTicket>()("VerificationSessionTicket", { required: ["session_id", "code", "link", "expires_at"], properties: { session_id: ANY, code: ANY, link: ANY, expires_at: ANY } });
export const VerificationSessionView = define<T.VerificationSessionView>()("VerificationSessionView", {
  required: ["session_id", "status", "capability", "purpose_code", "origin", "created_at", "expires_at"],
  properties: { session_id: ANY, status: ANY, capability: ANY, purpose_code: ANY, origin: ANY, created_at: ANY, expires_at: ANY, request_id: ANY, subject_ref: ANY, result_ref: ANY, result: ANY, completed_at: ANY },
});
export const CreateVerificationRequest = define<T.CreateVerificationRequest>()("CreateVerificationRequest", {
  closed: true,
  required: ["subject_ref", "capability", "purpose_code"],
  properties: { subject_ref: SUBJECT, capability: E(T.VERIFICATION_CAPABILITIES), parameters: REC, purpose_code: S({ pattern: /^[a-z][a-z0-9_]{2,47}$/ }), callback_id: UUID, expires_in_seconds: I(30, 600) },
});
export const VerificationRequest = define<T.VerificationRequest>()("VerificationRequest", {
  required: ["request_id", "capability", "subject_ref", "purpose_code", "status", "created_at", "expires_at"],
  properties: { request_id: ANY, capability: ANY, subject_ref: ANY, purpose_code: ANY, status: ANY, created_at: ANY, expires_at: ANY, result_ref: ANY },
});
export const VerificationResult = define<T.VerificationResult>()("VerificationResult", {
  closed: true,
  required: ["result_ref", "request_id", "capability", "subject_ref", "parameters", "created_at", "outcome", "result"],
  properties: { result_ref: ANY, request_id: ANY, capability: ANY, subject_ref: ANY, parameters: ANY, created_at: ANY, outcome: ANY, result: ANY },
});
export const PublishKeyEntryRequest = define<T.PublishKeyEntryRequest>()("PublishKeyEntryRequest", { closed: true, required: ["entry"], properties: { entry: S({ min: 1, max: 16_384, pattern: /^[A-Za-z0-9_-]+$/ }) } });
export const PublishKeyEntryResponse = define<T.PublishKeyEntryResponse>()("PublishKeyEntryResponse", { required: ["index", "tree_size", "sth"], properties: { index: ANY, tree_size: ANY, sth: ANY } });
export const SignedTreeHead = define<T.SignedTreeHead>()("SignedTreeHead", { closed: true, required: ["payload", "signature"], properties: { payload: ANY, signature: ANY } });
export const KeyDirectoryResponse = define<T.KeyDirectoryResponse>()("KeyDirectoryResponse", { required: ["sth", "entries"], properties: { sth: ANY, consistency_from: ANY, consistency_proof: ANY, entries: ANY } });
export const LoopBusinessAnswer = define<T.LoopBusinessAnswer>()("LoopBusinessAnswer", { required: ["step_id", "field_id", "label", "value"], properties: { step_id: ANY, field_id: ANY, label: ANY, value: ANY } });
export const LoopBusinessApproval = define<T.LoopBusinessApproval>()("LoopBusinessApproval", {
  required: ["approval_id", "amount", "terms", "reference", "context_digest", "assurance", "approved_at"],
  properties: { approval_id: ANY, amount: ANY, terms: ANY, reference: ANY, context_digest: ANY, assurance: ANY, approved_at: ANY },
});
export const LoopBusinessEvent = define<T.LoopBusinessEvent>()("LoopBusinessEvent", {
  required: ["ref", "instance_ref", "loop_key", "revision", "step_id", "action_id", "action_type", "queue", "answers", "outcome", "created_at"],
  properties: { ref: ANY, instance_ref: ANY, loop_key: ANY, revision: ANY, step_id: ANY, action_id: ANY, action_type: ANY, queue: ANY, answers: ANY, approval: ANY, outcome: ANY, created_at: ANY, respond_by: ANY },
});
export const LoopBusinessInstance = define<T.LoopBusinessInstance>()("LoopBusinessInstance", {
  required: ["ref", "loop_key", "revision", "state", "expires_at", "event_refs"],
  properties: { ref: ANY, loop_key: ANY, revision: ANY, state: ANY, expires_at: ANY, event_refs: ANY },
});
export const LoopOutcomeCallbackRequest = define<T.LoopOutcomeCallbackRequest>()("LoopOutcomeCallbackRequest", {
  closed: true,
  required: ["outcome", "idempotency_key"],
  properties: { outcome: E(T.LOOP_CONNECTED_OUTCOMES), idempotency_key: IDEMPOTENCY },
});
export const LoopOutcomeCallbackResult = define<T.LoopOutcomeCallbackResult>()("LoopOutcomeCallbackResult", { required: ["ref", "outcome", "replayed"], properties: { ref: ANY, outcome: ANY, replayed: ANY } });
/** `WebhookEnvelopeV2` in the document. */
export const OpaqueWebhookEnvelope = define<T.OpaqueWebhookEnvelope>()("WebhookEnvelopeV2", {
  closed: true,
  required: ["id", "type", "version", "tenant_id", "request_id", "occurred_at"],
  properties: { id: S({ min: 1, max: 128 }), type: S({ min: 1, max: 64, pattern: /^[a-z0-9_.]+$/ }), version: E(["2026-10-27"]), tenant_id: S({ min: 1, max: 64 }), request_id: S({ min: 1, max: 128 }), occurred_at: TS, result_ref: S({ min: 1, max: 128 }) },
});

/** Every entry that has a component schema of the same name in `docs/openapi.yaml` (the parity test walks this list). */
export const OPENAPI_SCHEMAS: readonly SchemaDef[] = [
  SignedStatement, BusinessSignedStatement, E2EEEnvelope, TransactionDetails, AuthenticationDetails, MoneyAmount, RiskIndicator, RequestedAction, AuthenticatePayload, AuthorizePayload,
  ConfirmPayload, ChoiceOption, ChoosePayload, AcknowledgePayload, ReplyPayload, LiveActivityStatus, StatusPayload, MessagePayload, RewardPayload, TicketPayload, IssueInteractionRequest,
  Interaction, InteractionOutcome, DecisionVerification, SandboxRelationship, MessageAttribution, ConversationMessage, MessageAttachment, BusinessSendMessageRequest, BusinessStatusUpdateRequest, RewardRecurrence,
  IssueRewardRequest, Reward, LoyaltyTier, UpsertLoyaltyProgramRequest, AdjustLoyaltyPointsRequest, LoyaltyPointsResult, ConsumeRedemptionRequest, RedemptionReceipt,
  BusinessIssueWalletPassRequest, BusinessWalletPass, UpdateWalletPassRequest, WalletScanRequest, WalletScanResult, BusinessCapabilitiesResponse, CapabilityDefinition, WebhookSubscription,
  WebhookVerificationResult, PauseWebhookRequest, CreateWebhookRequest, WebhookSecretResponse, WebhookEventEnvelope, MessageReceivedData, RelationshipEventData, ConsentUpdatedData,
  ProfileAccessEventData, CreateProfileRequest, ProfileRequestResource, BusinessProfileView, CreateApprovalEnrollmentRequest, ApprovalEnrollmentTicket, ApprovalEnrollmentView,
  ConfirmApprovalEnrollmentRequest, ApprovalKeyView, RevokeApprovalKeyRequest, ApprovalEnvelopeDelivery, CreateApprovalRequest, ApprovalRequestView, ApprovalResultResponse,
  BusinessFreezeRequest, ApproveBusinessSettings, FreezeStatus, CreateLinkSessionRequest, LinkSessionTicket, LinkSessionView, ConfirmLinkSessionRequest, CreateVerificationSessionRequest,
  VerificationSessionTicket, VerificationSessionView, CreateVerificationRequest, VerificationRequest, VerificationResult, PublishKeyEntryRequest, PublishKeyEntryResponse, SignedTreeHead,
  KeyDirectoryResponse, OpaqueWebhookEnvelope, LoopBusinessAnswer, LoopBusinessApproval, LoopBusinessEvent, LoopBusinessInstance, LoopOutcomeCallbackRequest,
  LoopOutcomeCallbackResult,
];
