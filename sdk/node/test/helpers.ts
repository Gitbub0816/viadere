import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { base64urlEncode, canonicalJson, p256PublicKeyOf, signEs256, softwareSigner, type Es256Signer, type JsonValue } from "../src/index.js";

export const BUSINESS_ID = "b0b1b2b3-c4c5-4d6d-8e7e-f8f9fafbfcfd";
export const UUID_1 = "11111111-2222-4333-8444-555555555555";
export const UUID_2 = "5a0e9c2b-3f41-4d6a-9b7c-0d1e2f3a4b5c";

/** A fresh P-256 key with its wire public key, key id and a signer. */
export function newKey(): { privateKey: KeyObject; publicKey: string; kid: string; signer: Es256Signer } {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pub = p256PublicKeyOf(privateKey);
  return { privateKey, publicKey: pub.base64url, kid: pub.kid, signer: softwareSigner(privateKey) };
}

/** Plays a device or Viadere: signs a canonical-JSON statement under `domain`. */
export async function signStatement(object: Record<string, JsonValue>, domain: string, signer: Es256Signer): Promise<{ kid: string; payload: string; signature: string }> {
  const bytes = Buffer.from(canonicalJson(object), "utf8");
  const { signature, key } = await signEs256(signer, Buffer.concat([Buffer.from(domain, "utf8"), bytes]));
  return { kid: key.kid, payload: base64urlEncode(bytes), signature };
}
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The repository root, found from this file (compiled to `sdk/node/dist/test/`). */
export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

export function readRepoFile(relative: string): string {
  return readFileSync(join(REPO_ROOT, relative), "utf8");
}

export function readRepoJson<T>(relative: string): T {
  return JSON.parse(readRepoFile(relative)) as T;
}

export const DELIVERY_ID = "adl_AAAAAAAAAAAAAAAAAAAAAA";
export const SUBJECT_REF = "sub_" + "A".repeat(43);
export const API_KEY = "vdk_test_0123456789abcdef";

export interface RecordedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  /** A JSON (string) body; `undefined` for none and for a raw body. */
  body: string | undefined;
  /** A raw (bytes) body, as sent. */
  bytes: Uint8Array | undefined;
  redirect: string;
}

/** `bytes` answers a raw body (an image download) instead of JSON. */
export type Scripted = { status: number; body?: unknown; bytes?: Uint8Array; headers?: Record<string, string> } | Error;

/** A fetch stand-in that answers from a script and records what was sent. */
export function scriptedFetch(script: Scripted[]) {
  const requests: RecordedRequest[] = [];
  const fetchFn = async (url: string, init: { method: string; headers: Record<string, string>; body?: string | Uint8Array; redirect: "manual"; signal: AbortSignal }) => {
    requests.push({ url, method: init.method, headers: init.headers, body: typeof init.body === "string" ? init.body : undefined,
                    bytes: init.body instanceof Uint8Array ? init.body : undefined, redirect: init.redirect });
    const next = script.shift();
    if (next === undefined) throw new Error("script exhausted");
    if (next instanceof Error) throw next;
    const headers = new Map(Object.entries(next.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    const text = next.body === undefined ? "" : JSON.stringify(next.body);
    return {
      status: next.status,
      headers: { get: (name: string) => headers.get(name.toLowerCase()) ?? null },
      text: async () => (next.bytes !== undefined ? Buffer.from(next.bytes).toString("latin1") : text),
      arrayBuffer: async () => {
        const bytes = next.bytes ?? Buffer.from(text, "utf8");
        return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
      },
    };
  };
  return { fetchFn, requests };
}

export function view(overrides: Record<string, unknown> = {}) {
  return {
    id: DELIVERY_ID,
    request_id: "req-1",
    method: "magic_link",
    purpose: "sign_in",
    status: "queued",
    expires_at: new Date(Date.now() + 600_000).toISOString(),
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

export function validCreate(overrides: Record<string, unknown> = {}) {
  return {
    method: "magic_link" as const,
    request_id: "req-1",
    subject_ref: SUBJECT_REF,
    purpose: "sign_in" as const,
    template: "auth.sign_in_link.v1",
    destination: { link_mode: "business" as const, url: "https://login.example.com/m/abc" },
    ...overrides,
  };
}
