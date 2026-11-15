import { createHash, randomBytes } from "node:crypto";

/**
 * Idempotency keys for `POST /v1/business/*`. The server keeps one result per `(business, key)`: the same key with the same request replays the
 * original (`200`); the same key with another request is `409 idempotency_conflict`.
 */
export const MAX_IDEMPOTENCY_KEY_LENGTH = 128;

const KEY_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

export function isValidIdempotencyKey(key: string): boolean {
  return KEY_PATTERN.test(key);
}

function cleanPrefix(prefix: string): string {
  return prefix.replace(/[^A-Za-z0-9_.:-]/g, "").slice(0, 40);
}

/** A fresh random key (128 bits). Persist it before sending so a crash-and-retry reuses it. */
export function generateIdempotencyKey(prefix?: string): string {
  const random = randomBytes(16).toString("hex");
  const cleaned = prefix ? cleanPrefix(prefix) : "";
  return cleaned ? `${cleaned}-${random}` : random;
}

/**
 * A stable key derived from the business object being acted on (a request id, an order id), so every retry of the same logical operation, even
 * from another process, produces the same key without storing anything. Equal to the Swift SDK's `IdempotencyKey.deterministic`: the parts are
 * joined with a length-prefixed encoding, so `["ab","c"]` and `["a","bc"]` differ.
 */
export function deterministicIdempotencyKey(namespace: string, parts: readonly string[]): string {
  const hash = createHash("sha256");
  for (const part of [namespace, ...parts]) {
    hash.update(`${Buffer.byteLength(part, "utf8")}:`, "utf8");
    hash.update(part, "utf8");
  }
  const digest = hash.digest("hex").slice(0, 40);
  const ns = cleanPrefix(namespace);
  return ns ? `${ns}-${digest}` : digest;
}
