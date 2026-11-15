import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  CHANNELS,
  COMPLETE_OUTCOMES,
  CREATE_REQUEST_MEMBERS,
  CREATE_REQUEST_REQUIRED,
  CODE_KINDS,
  ENVELOPE_VERSION,
  LINK_MODES,
  METHODS,
  VIEW_METHODS,
  PURPOSES,
  ROUTES,
  STATUSES,
  WEBHOOK_EVENT_TYPES,
} from "../src/index.js";
import { readRepoFile, readRepoJson } from "./helpers.js";

// The OpenAPI contract is hand-written YAML with a very regular layout. These tests read it without a YAML dependency (dev tooling stays minimal):
// they slice the document by indentation and pull out enums, required lists, property names and operations. They fail when the SDK drifts from
// `contracts/openapi/auth-delivery-v1.yaml` or `contracts/schemas/*.json`, and the extraction itself is pinned by sanity assertions.

const yaml = readRepoFile("contracts/openapi/auth-delivery-v1.yaml").split("\n");

/** The lines of the block under `header` (a line at `indent` spaces), up to the next line at that indent or less. */
function block(lines: string[], header: RegExp, indent: number): string[] {
  const start = lines.findIndex((l) => header.test(l) && l.length - l.trimStart().length === indent);
  assert.ok(start >= 0, `block ${header} not found`);
  const out: string[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim() !== "" && line.length - line.trimStart().length <= indent) break;
    out.push(line);
  }
  return out;
}

function schema(name: string): string[] {
  const schemas = block(yaml, /^ {2}schemas:$/, 2);
  return block(schemas, new RegExp(`^ {4}${name}:$`), 4);
}

function inlineList(text: string): string[] {
  return text.split(",").map((s) => s.trim().replace(/^["']|["']$/g, "")).filter((s) => s !== "");
}

function enumOf(lines: string[]): string[] {
  const inline = lines.find((l) => /\benum: \[/.test(l));
  if (inline) return inlineList(/enum: \[(.*)\]/.exec(inline)![1]!);
  const i = lines.findIndex((l) => /^\s*enum:$/.test(l));
  assert.ok(i >= 0, "no enum");
  const out: string[] = [];
  for (let j = i + 1; j < lines.length && /^\s*- /.test(lines[j]!); j++) out.push(lines[j]!.replace(/^\s*- /, "").trim());
  return out;
}

function propertyNames(lines: string[], indent: number): string[] {
  const props = block(lines, /^\s*properties:$/, indent);
  return props.filter((l) => l.length - l.trimStart().length === indent + 2 && /^\s*[A-Za-z_][A-Za-z0-9_]*:/.test(l)).map((l) => /^\s*([A-Za-z_][A-Za-z0-9_]*):/.exec(l)![1]!);
}

function required(lines: string[]): string[] {
  const line = lines.find((l) => /^\s*required: \[/.test(l));
  assert.ok(line, "no required list");
  return inlineList(/required: \[(.*)\]/.exec(line)![1]!);
}

describe("contract parity: enums", () => {
  it("Method, Purpose, Channel, Status", () => {
    assert.deepEqual(enumOf(schema("Method")), [...METHODS]);
    assert.deepEqual(enumOf(schema("ViewMethod")), [...VIEW_METHODS]);
    assert.deepEqual(enumOf(schema("Purpose")), [...PURPOSES]);
    assert.deepEqual(enumOf(schema("Channel")), [...CHANNELS]);
    assert.deepEqual(enumOf(schema("Status")), [...STATUSES]);
  });
  it("there is no sms channel and no verify route", () => {
    assert.ok(!(CHANNELS as readonly string[]).includes("sms"));
    assert.ok(!yaml.some((l) => /\/verify|verify-code|totp\/verify/.test(l) && !/verify_contact|destination_unverified/.test(l)));
  });
  it("complete outcomes, code kinds, link modes", () => {
    assert.deepEqual(enumOf(schema("AuthDeliveryCompleteRequest")), [...COMPLETE_OUTCOMES]);
    const create = schema("AuthDeliveryCreateRequest");
    assert.deepEqual(enumOf(block(create, /^\s*destination:$/, 8)).slice(0, 2), [...LINK_MODES]);
    assert.deepEqual(enumOf(block(create, /^\s*otp:$/, 8).filter((l) => /code_kind/.test(l))), [...CODE_KINDS]);
  });
  it("webhook test event types", () => {
    assert.deepEqual(enumOf(schema("AuthWebhookTestRequest")), [...WEBHOOK_EVENT_TYPES]);
  });
});

describe("contract parity: create request", () => {
  it("members and required list match the OpenAPI schema", () => {
    const create = schema("AuthDeliveryCreateRequest");
    assert.deepEqual(required(create), [...CREATE_REQUEST_REQUIRED]);
    assert.deepEqual(propertyNames(create, 6), [...CREATE_REQUEST_MEMBERS]);
    assert.ok(create.some((l) => /additionalProperties: false/.test(l)));
  });
  it("members match the JSON Schema (and its required list)", () => {
    const json = readRepoJson<{ required: string[]; properties: Record<string, unknown>; additionalProperties: boolean }>("contracts/schemas/auth-delivery-create-request-v1.schema.json");
    assert.equal(json.additionalProperties, false);
    assert.deepEqual(Object.keys(json.properties), [...CREATE_REQUEST_MEMBERS]);
    assert.deepEqual(json.required, [...CREATE_REQUEST_REQUIRED]);
  });
});

describe("contract parity: routes", () => {
  it("every business operation in the OpenAPI file is a route of the SDK, with the same method and path", () => {
    const found: Record<string, { method: string; path: string }> = {};
    let path = "";
    let method = "";
    for (const line of yaml) {
      const p = /^ {2}(\/\S+):$/.exec(line);
      if (p) path = p[1]!;
      const m = /^ {4}(get|post|patch|put|delete):$/.exec(line);
      if (m) method = m[1]!.toUpperCase();
      const o = /^ {6}operationId: (\w+)$/.exec(line);
      if (o) found[o[1]!] = { method, path };
    }
    const business = Object.fromEntries(Object.entries(found).filter(([, v]) => v.path.startsWith("/v1/business/")));
    assert.deepEqual(business, { ...ROUTES });
    // The device routes are Viadere's app side and deliberately absent from a business SDK.
    assert.ok(Object.values(found).some((v) => v.path.startsWith("/v1/auth-deliveries")));
  });
  it("the Idempotency-Key parameter matches the SDK's key charset and length", () => {
    const line = yaml.find((l) => /pattern: "\^\[A-Za-z0-9_\.:-\]\+\$"/.test(l) && /maxLength: 128/.test(l));
    assert.ok(line);
  });
});

describe("contract parity: webhook envelope", () => {
  const event = readRepoJson<{ required: string[]; properties: Record<string, { enum?: string[]; const?: string }>; additionalProperties: boolean }>("contracts/schemas/auth-delivery-event-v1.schema.json");
  it("event types, version and closed members", () => {
    assert.deepEqual(event.properties.type!.enum, [...WEBHOOK_EVENT_TYPES]);
    assert.equal(event.properties.version!.const, ENVELOPE_VERSION);
    assert.equal(event.additionalProperties, false);
    assert.deepEqual(event.required, ["id", "type", "version", "tenant_id", "request_id", "occurred_at"]);
  });
  it("the display schema lists the same statuses", () => {
    const display = readRepoJson<{ properties: { status: { enum: string[] } } }>("contracts/schemas/auth-delivery-display-v1.schema.json");
    assert.deepEqual(display.properties.status.enum, [...STATUSES]);
  });
});

// =============================================================================================================================================
// The business API of `docs/openapi.yaml`, and coverage of the Swift SDK.

import { readdirSync } from "node:fs";
import { join } from "node:path";
import {
  ACTION_ROLES,
  ADDITIONAL_WEBHOOK_EVENT_TYPES,
  APPROVAL_CAPABILITIES,
  APPROVAL_ENROLLMENT_STATUSES,
  APPROVAL_REQUEST_STATUSES,
  APPROVE_DEVICE_POLICIES,
  BUSINESS_RISK_TIERS,
  BUSINESS_ROUTES,
  BUSINESS_WEBHOOK_EVENT_TYPES,
  CAPABILITIES,
  DECISIONS,
  DECISION_ASSURANCES,
  INTERACTION_CHANNELS,
  INTERACTION_KINDS,
  INTERACTION_PRIORITIES,
  INTERACTION_PURPOSES,
  INTERACTION_STATUSES,
  LINKABLE_CAPABILITIES,
  LINK_SESSION_STATUSES,
  MESSAGE_ATTACHMENT_MAX_PER_MESSAGE,
  MESSAGE_ATTACHMENT_MAX_STORED_BYTES,
  MESSAGE_ATTACHMENT_MAX_UPLOAD_BYTES,
  MESSAGE_ATTACHMENT_MEDIA_TYPES,
  MESSAGE_ATTACHMENT_STATES,
  OPAQUE_ENVELOPE_EVENT_TYPES,
  OPERATIONS_NOT_OFFERED,
  REWARD_KINDS,
  SENSITIVITIES,
  VERIFICATION_CAPABILITIES,
  VERIFICATION_SESSION_STATUSES,
  ViadereClient,
  WALLET_PASS_KINDS,
  schemas,
} from "../src/index.js";
import { REPO_ROOT } from "./helpers.js";

const api = readRepoFile("docs/openapi.yaml").split("\n");
const apiSchemas = block(api, /^ {2}schemas:$/, 2);

function apiSchema(name: string): string[] {
  return block(apiSchemas, new RegExp(`^ {4}${name}:$`), 4);
}

function operations(lines: string[]): Record<string, { method: string; path: string }> {
  const found: Record<string, { method: string; path: string }> = {};
  let path = "";
  let method = "";
  let inPaths = false;
  for (const line of lines) {
    if (/^[a-z]+:$/.test(line)) inPaths = line === "paths:"; // `webhooks:` entries are deliveries to you, not operations
    if (!inPaths) continue;
    const p = /^ {2}(\/\S+):$/.exec(line);
    if (p) path = p[1]!;
    const m = /^ {4}(get|post|patch|put|delete):$/.exec(line);
    if (m) method = m[1]!.toUpperCase();
    const o = /^ {6}operationId: (\w+)$/.exec(line);
    if (o) found[o[1]!] = { method, path };
  }
  return found;
}

/** The client method that implements each operation. An operation without an entry here fails the test below. */
const METHOD_OF: Record<keyof typeof BUSINESS_ROUTES | keyof typeof ROUTES, string> = {
  getCapabilities: "getCapabilities",
  createProfileRequest: "createProfileRequest",
  getProfileRequest: "getProfileRequest",
  getProfile: "getProfile",
  issueInteraction: "issueInteraction",
  getInteractionOutcome: "getInteractionOutcome",
  cancelInteraction: "cancelInteraction",
  sendMessage: "sendMessage",
  uploadAttachment: "uploadAttachment",
  getAttachment: "downloadAttachment",
  updateStatus: "updateStatus",
  createSandboxRelationship: "createSandboxRelationship",
  createApprovalEnrollment: "createApprovalEnrollment",
  getApprovalEnrollment: "getApprovalEnrollment",
  confirmApprovalEnrollment: "confirmApprovalEnrollment", // and `confirmApprovalEnrollmentRaw`
  cancelApprovalEnrollment: "cancelApprovalEnrollment",
  listApprovalKeys: "listApprovalKeys",
  revokeApprovalKey: "revokeApprovalKey",
  createApprovalRequest: "createApprovalRequest",
  getApprovalRequest: "getApprovalRequest",
  cancelApprovalRequest: "cancelApprovalRequest",
  getApprovalResult: "getApprovalResult",
  freezeApprovals: "freezeApprovals",
  getApprovalFreeze: "getApprovalFreeze",
  getApproveSettings: "getApproveSettings",
  putApproveSettings: "putApproveSettings",
  createLinkSession: "createLinkSession",
  getLinkSession: "getLinkSession",
  confirmLinkSession: "confirmLinkSession", // and `confirmLinkSessionRaw`
  cancelLinkSession: "cancelLinkSession",
  createVerificationSession: "createVerificationSession",
  getVerificationSession: "getVerificationSession", // and `getVerifiedVerificationSession`
  cancelVerificationSession: "cancelVerificationSession",
  publishKeyEntry: "publishKeyEntry",
  listKeyEntries: "listKeyEntries",
  listWebhooks: "listWebhooks",
  createWebhook: "createWebhook",
  deleteWebhook: "deleteWebhook",
  rotateWebhookSecret: "rotateWebhookSecret",
  verifyWebhook: "verifyWebhook",
  sendWebhookTestEvent: "testWebhook",
  pauseWebhook: "pauseWebhook",
  resumeWebhook: "resumeWebhook",
  getLoyaltyProgram: "getLoyaltyProgram",
  saveLoyaltyProgram: "saveLoyaltyProgram",
  adjustLoyaltyPoints: "adjustLoyaltyPoints",
  listRewards: "listRewards",
  createReward: "createReward",
  revokeReward: "revokeReward",
  consumeRedemption: "consumeRedemption",
  issueWalletPass: "issueWalletPass",
  listWalletPasses: "listWalletPasses",
  updateWalletPass: "updateWalletPass",
  voidWalletPass: "voidWalletPass",
  scanWalletPass: "scanWalletPass",
  createVerificationRequest: "createVerificationRequest",
  getVerificationRequest: "getVerificationRequest",
  getVerificationResult: "getVerificationResult",
  createAuthDelivery: "createAuthDelivery",
  getAuthDelivery: "getAuthDelivery",
  cancelAuthDelivery: "cancelAuthDelivery",
  completeAuthDelivery: "completeAuthDelivery",
  updateWebhook: "updateWebhook",
  testAuthWebhook: "testAuthWebhook",
  createAuthApproval: "createAuthApproval",
  getAuthApproval: "getAuthApproval",
  redeemAuthLink: "redeemAuthLink",
  readDestinationKeyRegistrationNonce: "readDestinationKeyRegistrationNonce",
};

describe("business API parity: operations", () => {
  const documented = operations(api);

  it("the extraction sees the whole document", () => {
    assert.equal(Object.keys(documented).length, api.filter((l) => /^ {6}operationId: /.test(l)).length);
    assert.ok(Object.keys(documented).length >= 59);
    assert.deepEqual(documented.updateWalletPass, { method: "PATCH", path: "/v1/business/wallet/passes/{passId}" });
  });

  it("every operation of docs/openapi.yaml is offered with the same method and path, or is on the commented allow-list", () => {
    // Fails when the document gains an operation the SDK does not have, when a method or path drifts, and when an allow-listed
    // operation disappears from the document (so the list cannot rot).
    assert.deepEqual(documented, { ...BUSINESS_ROUTES, ...OPERATIONS_NOT_OFFERED });
    assert.deepEqual(Object.keys(OPERATIONS_NOT_OFFERED).filter((op) => op in BUSINESS_ROUTES), []);
    // Everything deliberately not offered is public and unauthenticated: no API-key operation is ever skipped.
    for (const route of Object.values(OPERATIONS_NOT_OFFERED)) assert.ok(!route.path.startsWith("/v1/business/"), route.path);
  });

  it("every offered operation has a client method", () => {
    const routes = { ...BUSINESS_ROUTES, ...ROUTES };
    assert.deepEqual(Object.keys(METHOD_OF).sort(), Object.keys(routes).sort());
    for (const [operation, method] of Object.entries(METHOD_OF)) {
      assert.equal(typeof (ViadereClient.prototype as unknown as Record<string, unknown>)[method], "function", `${operation} -> ViadereClient.${method}`);
    }
  });

  it("every route the Swift SDK calls is a route of the Node SDK", () => {
    // The Swift SDK names its routes `APIRoutes.<name>.descriptor`; `ViadereCore` defines each as `Endpoint<...>("id", .METHOD, "/path", ...)`.
    const walk = (dir: string): string[] => readdirSync(join(REPO_ROOT, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(`${dir}/${e.name}`) : e.name.endsWith(".swift") ? [`${dir}/${e.name}`] : []));
    const defined: Record<string, { method: string; path: string }> = {};
    for (const file of walk("Packages/ViadereCore/Sources/ViadereCore")) {
      for (const m of readRepoFile(file).matchAll(/static let (\w+) = Endpoint<[^>]*(?:<[^>]*>[^>]*)*>\(\s*"[^"]+", \.(GET|POST|PUT|PATCH|DELETE), "([^"]+)"/g)) defined[m[1]!] = { method: m[2]!, path: m[3]! };
    }
    const used = new Set<string>();
    for (const file of walk("Packages/ViadereBusinessSDK/Sources/ViadereBusinessSDK")) {
      for (const m of readRepoFile(file).matchAll(/APIRoutes\.(\w+)\.descriptor/g)) used.add(m[1]!);
    }
    assert.ok(used.size >= 60, `the Swift SDK uses ${used.size} routes`);
    const offered = new Set(Object.values({ ...BUSINESS_ROUTES, ...ROUTES }).map((r) => `${r.method} ${r.path}`));
    const missing: string[] = [];
    for (const name of used) {
      const route = defined[name];
      assert.ok(route, `APIRoutes.${name} is not defined in ViadereCore (the extraction is stale)`);
      if (!offered.has(`${route.method} ${route.path}`)) missing.push(`${name}: ${route.method} ${route.path}`);
    }
    assert.deepEqual(missing, []);
  });
});

describe("business API parity: schemas", () => {
  const topLevel = (lines: string[], pattern: RegExp) => lines.find((l) => pattern.test(l));

  for (const schema of schemas.OPENAPI_SCHEMAS) {
    it(`${schema.name}: members, required list and additionalProperties`, () => {
      const lines = apiSchema(schema.name);
      assert.deepEqual(Object.keys(schema.properties).sort(), propertyNames(lines, 6).sort());
      const requiredLine = topLevel(lines, /^ {6}required: \[/);
      assert.deepEqual([...schema.required].sort(), (requiredLine ? inlineList(/required: \[(.*)\]/.exec(requiredLine)![1]!) : []).sort());
      assert.equal(schema.closed, topLevel(lines, /^ {6}additionalProperties: false$/) !== undefined, "additionalProperties: false");
      const anyOf = lines.filter((l) => /^ {8}- required: \[/.test(l)).map((l) => /required: \[(.*)\]/.exec(l)![1]!);
      if (anyOf.length > 0) assert.deepEqual(schema.oneOfRequired, anyOf);
      else if (schema.name !== "BusinessIssueWalletPassRequest") assert.equal(schema.oneOfRequired, undefined); // prose only in the document
    });
  }

  it("the table covers every object schema of the document, except the ones listed here", () => {
    const names = apiSchemas.filter((l) => /^ {4}[A-Za-z0-9]+:$/.test(l)).map((l) => l.trim().slice(0, -1));
    const objects = names.filter((n) => apiSchema(n).some((l) => /^ {6}(properties|allOf):$/.test(l)));
    const covered = new Set(schemas.OPENAPI_SCHEMAS.map((s) => s.name));
    const notInTable = objects.filter((n) => !covered.has(n));
    assert.deepEqual(notInTable.sort(), [
      "BusinessLoyaltyProgram", // an `allOf`, checked below
      "ConsistencyProofResponse", // answer of a public route that is not offered (`OPERATIONS_NOT_OFFERED`)
      "ErrorResponse", // `ViadereApiError`
      "SignedDecision", // never sent to a business ("there is no `signedDecision`")
    ]);
  });

  it("BusinessLoyaltyProgram is the upsert request plus memberCount and updatedAt", () => {
    const lines = apiSchema("BusinessLoyaltyProgram");
    assert.ok(lines.some((l) => /\$ref: "#\/components\/schemas\/UpsertLoyaltyProgramRequest"/.test(l)));
    const extra = inlineList(/required: \[(.*)\]/.exec(lines.find((l) => /required: \[/.test(l))!)![1]!);
    assert.deepEqual([...schemas.BusinessLoyaltyProgram.required].sort(), [...schemas.UpsertLoyaltyProgramRequest.required, ...extra].sort());
    assert.deepEqual(Object.keys(schemas.BusinessLoyaltyProgram.properties).sort(), [...Object.keys(schemas.UpsertLoyaltyProgramRequest.properties), ...extra].sort());
  });

  it("the inline redeem body and the prose auth-approval body of the auth-delivery contract", () => {
    const redeem = block(yaml, /^ {2}\/v1\/business\/auth-links\/redeem:$/, 2);
    const requestBody = block(redeem, /^ {6}requestBody:$/, 6);
    assert.deepEqual(propertyNames(requestBody, 14), Object.keys(schemas.AuthLinkRedeemRequest.properties));
    assert.deepEqual(required(requestBody), [...schemas.AuthLinkRedeemRequest.required]);
    const response = block(redeem, /^ {6}responses:$/, 6);
    assert.deepEqual(required(response), [...schemas.AuthLinkRedeemResponse.required]);
    // The contract names the extra members of the approval body in prose; `ViadereCore` is the definition.
    const prose = block(yaml, /^ {2}\/v1\/business\/auth-approvals:$/, 2).join(" ");
    for (const member of ["number_match", "match_tag", "match_prefix_tag", "risk", "session_handle"]) assert.ok(prose.includes("`" + member), member);
    const swift = readRepoFile("Packages/ViadereCore/Sources/ViadereCore/AuthDelivery/AuthApprovalDTOs.swift");
    const codingKeys = /enum CodingKeys: String, CodingKey, CaseIterable \{([\s\S]*?)\n {4}\}/.exec(swift)![1]!;
    const wire = [...codingKeys.matchAll(/(\w+)(?: = "(\w+)")?(?=,|\n|$)/g)].map((m) => m[2] ?? m[1]!).filter((n) => n !== "case");
    assert.deepEqual(wire.sort(), Object.keys(schemas.AuthApprovalCreateRequest.properties).sort());
  });
});

describe("business API parity: enums", () => {
  const inline = (lines: string[], property?: string) => {
    const line = lines.find((l) => (property === undefined ? /^\s*enum: \[/.test(l) : new RegExp(`^\\s*${property}: \\{.*enum: \\[`).test(l)));
    assert.ok(line, `enum ${property ?? ""}`);
    return inlineList(/enum: \[([^\]]*)\]/.exec(line)![1]!);
  };
  it("the named enums", () => {
    const named: Record<string, readonly string[]> = {
      InteractionKind: INTERACTION_KINDS, InteractionPurpose: INTERACTION_PURPOSES, InteractionPriority: INTERACTION_PRIORITIES, Sensitivity: SENSITIVITIES, Channel: INTERACTION_CHANNELS,
      ActionRole: ACTION_ROLES, Decision: DECISIONS, DecisionAssurance: DECISION_ASSURANCES, InteractionStatus: INTERACTION_STATUSES, RewardKind: REWARD_KINDS, WalletPassKind: WALLET_PASS_KINDS,
      Capability: CAPABILITIES, BusinessRiskTier: BUSINESS_RISK_TIERS, WebhookEventType: BUSINESS_WEBHOOK_EVENT_TYPES,
    };
    for (const [name, values] of Object.entries(named)) assert.deepEqual(inline(apiSchema(name)), [...values], name);
  });
  it("the inline enums of the snake_case schemas", () => {
    assert.deepEqual(inline(apiSchema("CreateApprovalRequest"), "capability"), [...APPROVAL_CAPABILITIES]);
    assert.deepEqual(inline(apiSchema("CreateApprovalEnrollmentRequest"), "capability"), [...APPROVAL_CAPABILITIES]);
    assert.deepEqual(inline(apiSchema("ApprovalEnrollmentView"), "status"), [...APPROVAL_ENROLLMENT_STATUSES]);
    assert.deepEqual(inline(apiSchema("ApprovalRequestView"), "status"), [...APPROVAL_REQUEST_STATUSES]);
    assert.deepEqual(inline(apiSchema("ApproveBusinessSettings"), "device_policy"), [...APPROVE_DEVICE_POLICIES]);
    assert.deepEqual(inline(apiSchema("CreateLinkSessionRequest"), "capabilities"), [...LINKABLE_CAPABILITIES]);
    assert.deepEqual(inline(apiSchema("LinkSessionView"), "status"), [...LINK_SESSION_STATUSES]);
    assert.deepEqual(inline(apiSchema("CreateVerificationSessionRequest"), "capability"), [...VERIFICATION_CAPABILITIES]);
    assert.deepEqual(inline(apiSchema("CreateVerificationRequest"), "capability"), [...VERIFICATION_CAPABILITIES]);
    assert.deepEqual(inline(apiSchema("VerificationSessionView"), "status"), [...VERIFICATION_SESSION_STATUSES]);
    assert.deepEqual(inline(apiSchema("WebhookEnvelopeV2"), "type"), [...OPAQUE_ENVELOPE_EVENT_TYPES]);
  });
  it("the event types the Swift SDK defines beyond the document's enum exist in ViadereCore", () => {
    const core = ["Verify/VerificationDTOs.swift", "Profile/ProfileDTOs.swift", "Approve/ApproveDTOs.swift"].map((f) => readRepoFile(`Packages/ViadereCore/Sources/ViadereCore/${f}`)).join("\n");
    for (const type of ADDITIONAL_WEBHOOK_EVENT_TYPES.filter((t) => t !== "webhook.test")) {
      assert.ok(core.includes(`WebhookEventType(rawValue: "${type}")`), type);
      assert.ok(!(BUSINESS_WEBHOOK_EVENT_TYPES as readonly string[]).includes(type));
    }
  });
});

describe("message attachment limits parity (SECURITY.md 2.113)", () => {
  const core = readRepoFile("Packages/ViadereCore/Sources/ViadereCore/Models/MessageAttachments.swift");
  const brand = readRepoFile("Packages/ViadereCore/Sources/ViadereCore/BrandKits/BrandAssetPolicy.swift");
  /** `a * b * c` or a plain integer, as ViadereCore writes these constants. */
  const product = (text: string) => text.split("*").map((f) => Number(f.trim())).reduce((a, b) => a * b, 1);
  const constant = (source: string, name: string) => {
    const line = source.split("\n").find((l) => l.trim().startsWith(`public static let ${name} = `));
    assert.ok(line, name);
    return line.split(" = ").slice(1).join(" = ").trim();
  };
  const listOf = (text: string) => text.split(",").map((t) => t.trim());

  it("the upload cap is ViadereCore's MessageAttachmentPolicy.maxUploadBytes and the OpenAPI maxLength of both image bodies", () => {
    assert.equal(constant(core, "maxUploadBytes"), "BrandAssetPolicy.maxUploadBytes");
    assert.equal(product(constant(brand, "maxUploadBytes")), MESSAGE_ATTACHMENT_MAX_UPLOAD_BYTES);
    assert.equal(MESSAGE_ATTACHMENT_MAX_UPLOAD_BYTES, 2 * 1024 * 1024);
    const upload = block(api, /^ {2}\/v1\/business\/conversations\/\{sessionId\}\/attachments:$/, 2);
    const caps = upload.filter((l) => /format: binary, maxLength: /.test(l)).map((l) => Number(/maxLength: (\d+)/.exec(l)![1]));
    assert.deepEqual(caps, [MESSAGE_ATTACHMENT_MAX_UPLOAD_BYTES, MESSAGE_ATTACHMENT_MAX_UPLOAD_BYTES]);
    const types = upload.filter((l) => /^ {10}image\/[a-z]+:$/.test(l)).map((l) => l.trim().slice(0, -1));
    assert.deepEqual(types, [...MESSAGE_ATTACHMENT_MEDIA_TYPES]);
    assert.ok(!upload.some((l) => /IdempotencyKey/.test(l)), "the upload takes no idempotency key, so the SDK never retries it");
  });

  it("per-message count, stored size, types and states match ViadereCore and the schemas", () => {
    assert.equal(Number(constant(core, "maxPerMessage")), MESSAGE_ATTACHMENT_MAX_PER_MESSAGE);
    assert.equal(product(constant(core, "maxStoredBytes")), MESSAGE_ATTACHMENT_MAX_STORED_BYTES);
    assert.deepEqual([...constant(core, "storedMediaTypes: Set<String>").matchAll(/"([^"]+)"/g)].map((m) => m[1]), [...MESSAGE_ATTACHMENT_MEDIA_TYPES]);
    const attachment = apiSchema("MessageAttachment").join("\n");
    assert.ok(attachment.includes(`byteSize: { type: integer, minimum: 1, maximum: ${MESSAGE_ATTACHMENT_MAX_STORED_BYTES} }`));
    assert.deepEqual(listOf(/mediaType: \{ type: string, enum: \[([^\]]*)\]/.exec(attachment)![1]!), [...MESSAGE_ATTACHMENT_MEDIA_TYPES]);
    assert.deepEqual(listOf(/state: \{ type: string, enum: \[([^\]]*)\]/.exec(attachment)![1]!), [...MESSAGE_ATTACHMENT_STATES]);
    const send = apiSchema("BusinessSendMessageRequest").join("\n");
    assert.match(send, new RegExp(`attachmentIds:\\n\\s+type: array\\n\\s+minItems: 1\\n\\s+maxItems: ${MESSAGE_ATTACHMENT_MAX_PER_MESSAGE}\\n\\s+uniqueItems: true`));
  });
});
