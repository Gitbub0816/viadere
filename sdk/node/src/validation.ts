import { ViadereSdkError, ViadereValidationError } from "./errors.js";
import { isValidIdempotencyKey } from "./idempotency.js";
import * as schemas from "./schemas.js";
import type { Rule, SchemaDef } from "./schemas.js";
import { INTERACTION_KINDS, type InteractionKind } from "./types.js";

// Request validation for the business API: every request is checked against its entry in `schemas.ts` (which the parity test ties to
// `docs/openapi.yaml`) before anything is sent, with the field names and codes the server answers in a `422 validation_failed`. A request the
// server would refuse is refused here, without a network call and without consuming an idempotency key.

export type Problem = { field: string; code: string };

/** Largest request body the SDK sends (the server's limit for the business routes is lower for most of them). */
export const MAX_REQUEST_BODY_BYTES = 256 * 1024;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function checkRule(rule: Rule, value: unknown, field: string, problems: Problem[]): void {
  switch (rule.t) {
    case "any":
      return;
    case "record":
      if (!isRecord(value)) problems.push({ field, code: "invalid_type" });
      return;
    case "bool":
      if (typeof value !== "boolean") problems.push({ field, code: "invalid_type" });
      return;
    case "int":
      if (typeof value !== "number" || !Number.isSafeInteger(value)) problems.push({ field, code: "invalid_type" });
      else if ((rule.min !== undefined && value < rule.min) || (rule.max !== undefined && value > rule.max)) problems.push({ field, code: "out_of_range" });
      return;
    case "enum":
      if (!rule.values.includes(value as string | number)) problems.push({ field, code: "invalid_value" });
      return;
    case "string":
      if (typeof value !== "string") return void problems.push({ field, code: "invalid_type" });
      if (rule.min !== undefined && value.length < rule.min) problems.push({ field, code: value.length === 0 ? "required" : "too_short" });
      else if (rule.max !== undefined && value.length > rule.max) problems.push({ field, code: "too_long" });
      else if (rule.pattern && !rule.pattern.test(value)) problems.push({ field, code: "invalid_format" });
      return;
    case "array":
      if (!Array.isArray(value)) return void problems.push({ field, code: "invalid_type" });
      if ((rule.min !== undefined && value.length < rule.min) || (rule.max !== undefined && value.length > rule.max)) problems.push({ field, code: "invalid_length" });
      if (rule.unique && new Set(value).size !== value.length) problems.push({ field, code: "duplicate" });
      value.forEach((item, i) => checkRule(rule.items, item, `${field}[${i}]`, problems));
      return;
    case "object":
      checkSchema(rule.schema, value, `${field}.`, problems, field);
      return;
  }
}

function checkSchema(schema: SchemaDef, value: unknown, prefix: string, problems: Problem[], self = "(body)"): void {
  if (!isRecord(value)) return void problems.push({ field: self, code: "invalid_type" });
  if (schema.closed) {
    for (const key of Object.keys(value)) {
      if (!Object.hasOwn(schema.properties, key)) problems.push({ field: prefix + key, code: "unknown_member" });
    }
  }
  for (const key of schema.required) {
    if (value[key] === undefined) problems.push({ field: prefix + key, code: "required" });
  }
  if (schema.oneOfRequired && !schema.oneOfRequired.some((key) => value[key] !== undefined)) problems.push({ field: prefix + schema.oneOfRequired.join("|"), code: "required" });
  for (const [key, rule] of Object.entries(schema.properties)) {
    // `undefined` is "absent" (it is not serialized); `null` is never a valid member value on this API.
    if (value[key] !== undefined) checkRule(rule, value[key], prefix + key, problems);
  }
}

/** The problems of `input` against a schema of `schemas.ts`. Empty when the request matches the contract. */
export function validateRequest(schema: SchemaDef, input: unknown): Problem[] {
  const problems: Problem[] = [];
  checkSchema(schema, input, "", problems);
  return problems;
}

/** Rules the schema table cannot express: conditional members, cross-member constraints. */
const EXTRA: Readonly<Record<string, (input: Record<string, unknown>, problems: Problem[]) => void>> = {
  IssueInteractionRequest(input, problems) {
    const kind = input.kind;
    if (typeof kind === "string" && (INTERACTION_KINDS as readonly string[]).includes(kind)) {
      if (isRecord(input.payload)) checkSchema(schemas.PAYLOAD_BY_KIND[kind as InteractionKind], input.payload, "payload.", problems, "payload");
      // At most 15 minutes for the security kinds.
      if ((kind === "authenticate" || kind === "authorize") && typeof input.ttlSeconds === "number" && input.ttlSeconds > 900) problems.push({ field: "ttlSeconds", code: "out_of_range" });
    }
  },
  BusinessSendMessageRequest(input, problems) {
    // SECURITY.md §2.113 item 5: images are named with the conversation they were uploaded to; `body` may be empty only when there are images.
    if (input.attachmentIds !== undefined && input.sessionId === undefined) problems.push({ field: "sessionId", code: "required" });
    if (input.body === "" && input.attachmentIds === undefined) problems.push({ field: "body", code: "required" });
  },
  BusinessStatusUpdateRequest(input, problems) {
    liveActivity(isRecord(input.status) ? input.status.liveActivity : undefined, "status.liveActivity", problems);
  },
  AdjustLoyaltyPointsRequest(input, problems) {
    if (input.delta === 0) problems.push({ field: "delta", code: "out_of_range" });
  },
  IssueRewardRequest(input, problems) {
    if (input.kind === "pointsReward" && input.pointsCost === undefined) problems.push({ field: "pointsCost", code: "required" });
  },
  CreateApprovalRequest(input, problems) {
    approvalShape(input, problems);
  },
  AuthApprovalCreateRequest(input, problems) {
    approvalShape(input, problems);
    const match = isRecord(input.number_match) ? input.number_match : undefined;
    const digits = match?.digits;
    const risk = typeof input.risk === "string" ? input.risk : "medium";
    const needsThree = input.capability === "transaction.approve" || risk === "high" || risk === "critical";
    if (needsThree && digits !== 3) problems.push({ field: "number_match.digits", code: "three_required" });
    // A payment and every high or critical request is end to end (`422 e2ee_required`).
    if (needsThree && input.envelopes === undefined) problems.push({ field: "envelopes", code: "e2ee_required" });
    if (input.envelopes !== undefined) {
      // End to end: the code travels inside the signed envelope only.
      if (match?.code !== undefined) problems.push({ field: "number_match.code", code: "not_allowed" });
    } else {
      if (typeof match?.code !== "string" || match.code.length !== digits) problems.push({ field: "number_match.code", code: "invalid" });
      // The requirement is part of the digest the business checks, so a relay cannot strip it.
      if (isRecord(input.authentication) && input.authentication.match_digits !== digits) problems.push({ field: "authentication.match_digits", code: "invalid" });
    }
    if (digits === 3 && input.match_prefix_tag === undefined) problems.push({ field: "match_prefix_tag", code: "required" });
    if (digits === 2 && input.match_prefix_tag !== undefined) problems.push({ field: "match_prefix_tag", code: "not_allowed" });
  },
  AuthLinkRedeemRequest(input, problems) {
    if ((input.code === undefined) === (input.ach === undefined)) problems.push({ field: "code|ach", code: "exactly_one" });
  },
  CreateVerificationSessionRequest(input, problems) {
    flatParameters(input.parameters, problems);
    if (typeof input.origin === "string" && typeof input.return_url === "string" && !input.return_url.startsWith(input.origin + "/")) problems.push({ field: "return_url", code: "invalid_value" });
  },
};

function liveActivity(value: unknown, field: string, problems: Problem[]): void {
  if (!isRecord(value) || typeof value.type !== "string") return;
  // Exactly one state object, the one `type` names.
  for (const state of ["order", "delivery", "flight", "appointment"]) {
    if (state === value.type ? value[state] === undefined : value[state] !== undefined) problems.push({ field: `${field}.${state}`, code: state === value.type ? "required" : "not_allowed" });
  }
}

/** Exactly one form: end to end (`envelopes`, no plaintext member) or server-visible (`challenge` and the details of the capability). */
function approvalShape(input: Record<string, unknown>, problems: Problem[]): void {
  const plaintext = ["challenge", "transaction", "authentication"].filter((key) => input[key] !== undefined);
  if (input.envelopes !== undefined) {
    for (const key of plaintext) problems.push({ field: key, code: "not_allowed" });
    return;
  }
  if (input.challenge === undefined) problems.push({ field: "challenge", code: "required" });
  const wanted = input.capability === "transaction.approve" ? "transaction" : "authentication";
  const other = wanted === "transaction" ? "authentication" : "transaction";
  if (input[wanted] === undefined) problems.push({ field: wanted, code: "required" });
  if (input[other] !== undefined) problems.push({ field: other, code: "not_allowed" });
}

function flatParameters(value: unknown, problems: Problem[]): void {
  if (!isRecord(value)) return;
  const entries = Object.entries(value);
  if (entries.length > 8) problems.push({ field: "parameters", code: "invalid_length" });
  for (const [key, item] of entries) {
    if (!/^[a-z][a-z0-9_]{0,31}$/.test(key)) problems.push({ field: `parameters.${key}`, code: "invalid_format" });
    else if (!(typeof item === "string" || typeof item === "boolean" || (typeof item === "number" && Number.isSafeInteger(item)))) problems.push({ field: `parameters.${key}`, code: "invalid_type" });
  }
}

/** Throws `ViadereValidationError` unless `input` matches `schema` (and its cross-member rules) and fits the body limit. */
export function assertValidRequest(schema: SchemaDef, input: unknown): void {
  const problems = validateRequest(schema, input);
  if (problems.length === 0 && isRecord(input)) EXTRA[schema.name]?.(input, problems);
  if (problems.length > 0) throw new ViadereValidationError(problems);
  if (Buffer.byteLength(JSON.stringify(input), "utf8") > MAX_REQUEST_BODY_BYTES) throw new ViadereValidationError([{ field: "(body)", code: "too_large" }]);
}

/** Throws `invalid_response` unless `body` is an object that carries the required members of `schema`. */
export function assertResponse<X>(schema: SchemaDef, body: unknown): X {
  if (!isRecord(body) || schema.required.some((key) => body[key] === undefined)) throw new ViadereSdkError("invalid_response", `The response is not a ${schema.name}.`);
  return body as X;
}

export function assertResponseList<X>(schema: SchemaDef, body: unknown): X[] {
  if (!Array.isArray(body)) throw new ViadereSdkError("invalid_response", `The response is not a list of ${schema.name}.`);
  return body.map((item) => assertResponse<X>(schema, item));
}

// ---- path and query parameters --------------------------------------------------------------------------------------------------------------

const PATH_RULES = {
  /** A UUID path parameter; sent lowercase. */
  uuid: { pattern: schemas.UUID_PATTERN, what: "a UUID" },
  subjectRef: { pattern: schemas.SUBJECT_REF, what: "sub_ plus 43 base64url characters" },
  kid: { pattern: /^[A-Za-z0-9_-]{43}$/, what: "43 base64url characters" },
  /** Approve request ids, result references and freeze references: the identifier charset, at most 128 characters. */
  token: { pattern: /^[A-Za-z0-9_.:-]{1,128}$/, what: "1 to 128 characters of A-Z a-z 0-9 _ . : -" },
  verificationRequestId: { pattern: schemas.VERIFICATION_REQUEST_ID_PATTERN, what: "req_ plus 22 base64url characters" },
  verificationResultRef: { pattern: schemas.VERIFICATION_RESULT_REF_PATTERN, what: "res_ plus 43 base64url characters" },
  /** Connected Loop references (`loop.action.submitted` / `loop.instance.expired`): the prefix and a lowercase UUID. */
  loopEventRef: { pattern: /^lev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, what: "lev_ plus a lowercase UUID" },
  loopInstanceRef: { pattern: /^lin_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, what: "lin_ plus a lowercase UUID" },
} as const;

/**
 * A path parameter, checked against its charset before it is put in a URL (so `../` or a query can never be smuggled into a path), and
 * percent-encoded. Throws `invalid_path`.
 */
export function pathParameter(kind: keyof typeof PATH_RULES, name: string, value: unknown): string {
  const rule = PATH_RULES[kind];
  if (typeof value !== "string" || !rule.pattern.test(value)) throw new ViadereSdkError("invalid_path", `${name} must be ${rule.what}.`);
  return encodeURIComponent(kind === "uuid" ? value.toLowerCase() : value);
}

export function assertIdempotencyKey(key: string): string {
  if (!isValidIdempotencyKey(key)) throw new ViadereSdkError("invalid_idempotency_key", "The idempotency key must match [A-Za-z0-9_.:-]{1,128}.");
  return key;
}
