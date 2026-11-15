import { ViadereValidationError } from "./errors.js";
import {
  CHANNELS,
  CODE_KINDS,
  CREATE_REQUEST_MEMBERS,
  CREATE_REQUEST_REQUIRED,
  LINK_MODES,
  METHODS,
  PURPOSES,
  type AuthDeliveryCreateRequest,
} from "./types.js";

export const DELIVERY_ID_PATTERN = /^adl_[A-Za-z0-9_-]{22}$/;
export const SUBJECT_REF_PATTERN = /^sub_[A-Za-z0-9_-]{43}$/;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const SESSION_HANDLE_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const OTP_CODE_PATTERN = /^[0-9A-Z]{4,10}$/;
const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
/** Body limit of the create route (16 KiB). */
export const MAX_CREATE_BODY_BYTES = 16 * 1024;

type Problem = { field: string; code: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function oneOf(value: unknown, allowed: readonly string[]): boolean {
  return typeof value === "string" && allowed.includes(value);
}

function closed(object: Record<string, unknown>, allowed: readonly string[], prefix: string, problems: Problem[]): void {
  for (const key of Object.keys(object)) {
    if (!allowed.includes(key)) problems.push({ field: prefix + key, code: "unknown_member" });
  }
}

function checkString(object: Record<string, unknown>, key: string, prefix: string, problems: Problem[], options: { max?: number; pattern?: RegExp } = {}): void {
  const value = object[key];
  if (value === undefined) return;
  if (typeof value !== "string") return void problems.push({ field: prefix + key, code: "invalid_type" });
  if (options.max !== undefined && value.length > options.max) problems.push({ field: prefix + key, code: "too_long" });
  if (options.pattern && !options.pattern.test(value)) problems.push({ field: prefix + key, code: "invalid_format" });
}

/**
 * Checks a create request against the contract before anything is sent, with the same field names and codes the server answers (`422
 * validation_failed`). The tenant is the API key's business: `tenant_id` and `audience` are refused, like every other unknown member.
 * Returns the problems; `assertValidCreateRequest` throws.
 */
export function validateCreateRequest(input: unknown): Problem[] {
  const problems: Problem[] = [];
  if (!isRecord(input)) return [{ field: "(body)", code: "invalid_type" }];
  closed(input, CREATE_REQUEST_MEMBERS, "", problems);
  for (const key of CREATE_REQUEST_REQUIRED) {
    if (input[key] === undefined) problems.push({ field: key, code: "required" });
  }
  if (input.method !== undefined && !oneOf(input.method, METHODS)) problems.push({ field: "method", code: "invalid_value" });
  if (input.purpose !== undefined && !oneOf(input.purpose, PURPOSES)) problems.push({ field: "purpose", code: "invalid_value" });
  checkString(input, "request_id", "", problems, { pattern: REQUEST_ID_PATTERN });
  checkString(input, "subject_ref", "", problems, { pattern: SUBJECT_REF_PATTERN });
  if (typeof input.template === "string" && input.template.length === 0) problems.push({ field: "template", code: "required" });
  else checkString(input, "template", "", problems);
  checkString(input, "correlation_id", "", problems, { max: 128 });
  checkString(input, "client_transaction_ref", "", problems, { max: 128 });
  checkString(input, "session_handle", "", problems, { pattern: SESSION_HANDLE_PATTERN });

  if (input.variables !== undefined) {
    if (!isRecord(input.variables)) problems.push({ field: "variables", code: "invalid_type" });
    else {
      for (const [key, value] of Object.entries(input.variables)) {
        if (typeof value !== "string") problems.push({ field: `variables.${key}`, code: "invalid_type" });
        else if (value.length < 1 || value.length > 60) problems.push({ field: `variables.${key}`, code: "invalid_length" });
      }
    }
  }
  if (input.expires_in_seconds !== undefined) {
    const v = input.expires_in_seconds;
    if (typeof v !== "number" || !Number.isInteger(v) || v < 60 || v > 86400) problems.push({ field: "expires_in_seconds", code: "out_of_range" });
  }
  if (input.channels !== undefined) {
    if (!Array.isArray(input.channels)) problems.push({ field: "channels", code: "invalid_type" });
    else input.channels.forEach((channel, i) => {
      if (!oneOf(channel, CHANNELS)) problems.push({ field: `channels[${i}]`, code: "invalid_value" }); // there is no `sms`
    });
  }
  if (input.destination !== undefined) {
    const d = input.destination;
    if (!isRecord(d)) problems.push({ field: "destination", code: "invalid_type" });
    else {
      closed(d, ["link_mode", "url", "signature", "link_client_id", "return_url", "code_challenge", "code_challenge_method"], "destination.", problems);
      if (d.link_mode === undefined) problems.push({ field: "destination.link_mode", code: "required" });
      else if (!oneOf(d.link_mode, LINK_MODES)) problems.push({ field: "destination.link_mode", code: "invalid_value" });
      checkString(d, "url", "destination.", problems, { max: 2048 });
      checkString(d, "signature", "destination.", problems, { max: 2048 });
      checkString(d, "link_client_id", "destination.", problems);
      checkString(d, "return_url", "destination.", problems);
      checkString(d, "code_challenge", "destination.", problems);
      if (d.code_challenge_method !== undefined && d.code_challenge_method !== "S256") problems.push({ field: "destination.code_challenge_method", code: "invalid_value" });
    }
  }
  if (input.otp !== undefined) {
    const o = input.otp;
    if (!isRecord(o)) problems.push({ field: "otp", code: "invalid_type" });
    else {
      closed(o, ["code", "code_kind"], "otp.", problems);
      if (o.code === undefined) problems.push({ field: "otp.code", code: "required" });
      else checkString(o, "code", "otp.", problems, { pattern: OTP_CODE_PATTERN });
      if (o.code_kind === undefined) problems.push({ field: "otp.code_kind", code: "required" });
      else if (!oneOf(o.code_kind, CODE_KINDS)) problems.push({ field: "otp.code_kind", code: "invalid_value" });
    }
  }
  if (input.fallback !== undefined) {
    const f = input.fallback;
    if (!isRecord(f)) problems.push({ field: "fallback", code: "invalid_type" });
    else {
      closed(f, ["email"], "fallback.", problems);
      if (f.email !== undefined) {
        if (!isRecord(f.email)) problems.push({ field: "fallback.email", code: "invalid_type" });
        else {
          closed(f.email, ["address"], "fallback.email.", problems);
          if (typeof f.email.address !== "string") problems.push({ field: "fallback.email.address", code: "required" });
        }
      }
    }
  }
  if (input.callback !== undefined) {
    const c = input.callback;
    if (!isRecord(c)) problems.push({ field: "callback", code: "invalid_type" });
    else {
      closed(c, ["webhook_id"], "callback.", problems);
      if (typeof c.webhook_id !== "string" || !UUID_PATTERN.test(c.webhook_id)) problems.push({ field: "callback.webhook_id", code: "invalid_format" });
    }
  }
  return problems;
}

export function assertValidCreateRequest(input: unknown): asserts input is AuthDeliveryCreateRequest {
  const problems = validateCreateRequest(input);
  if (problems.length > 0) throw new ViadereValidationError(problems);
  if (Buffer.byteLength(JSON.stringify(input), "utf8") > MAX_CREATE_BODY_BYTES) throw new ViadereValidationError([{ field: "(body)", code: "too_large" }]);
}
