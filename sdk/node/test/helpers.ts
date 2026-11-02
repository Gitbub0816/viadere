import { readFileSync } from "node:fs";
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
  body: string | undefined;
  redirect: string;
}

export type Scripted = { status: number; body?: unknown; headers?: Record<string, string> } | Error;

/** A fetch stand-in that answers from a script and records what was sent. */
export function scriptedFetch(script: Scripted[]) {
  const requests: RecordedRequest[] = [];
  const fetchFn = async (url: string, init: { method: string; headers: Record<string, string>; body?: string; redirect: "manual"; signal: AbortSignal }) => {
    requests.push({ url, method: init.method, headers: init.headers, body: init.body, redirect: init.redirect });
    const next = script.shift();
    if (next === undefined) throw new Error("script exhausted");
    if (next instanceof Error) throw next;
    const headers = new Map(Object.entries(next.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    return {
      status: next.status,
      headers: { get: (name: string) => headers.get(name.toLowerCase()) ?? null },
      text: async () => (next.body === undefined ? "" : JSON.stringify(next.body)),
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
