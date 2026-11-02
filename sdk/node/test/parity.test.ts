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
  return props.filter((l) => l.length - l.trimStart().length === indent + 2 && /^\s*[A-Za-z_]+:/.test(l)).map((l) => /^\s*([A-Za-z_]+):/.exec(l)![1]!);
}

function required(lines: string[]): string[] {
  const line = lines.find((l) => /^\s*required: \[/.test(l));
  assert.ok(line, "no required list");
  return inlineList(/required: \[(.*)\]/.exec(line)![1]!);
}

describe("contract parity: enums", () => {
  it("Method, Purpose, Channel, Status", () => {
    assert.deepEqual(enumOf(schema("Method")), [...METHODS]);
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
