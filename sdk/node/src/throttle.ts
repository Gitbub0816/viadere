import { isIP } from "node:net";
import { ViadereThrottledError } from "./errors.js";
import { isTerminalStatus, type Status, type WebhookEventType } from "./types.js";

/**
 * Per-requester throttle (STAGE1_A2_REV3_CHECK condition C-14, ADR-0020 revision 3.1). Viadere never refuses or cancels anything because of a
 * per-customer count (that would hand a stranger a lockout lever), and it cannot see who started a sign-in. You can: the SDK therefore keeps at
 * most `maxOpen` (default 3) open deliveries per **account and client network prefix** (the `/24` of an IPv4 or the `/64` of an IPv6 address of the
 * browser that started the sign-in) and refuses the next one locally, before anything is sent.
 *
 * It is on by default in `ViadereClient`. The state is in process memory: with several server processes the cap is per process, so a multi-process
 * deployment that needs one cap supplies its own `OpenSlotStore`.
 */
export interface OpenSlotStore {
  /** The expiry times (epoch ms) of the open deliveries under `key`; entries at or before `now` are gone. */
  openExpiries(key: string, now: number): number[];
  add(key: string, deliveryId: string, expiresAt: number): void;
  remove(deliveryId: string): void;
  has(deliveryId: string): boolean;
}

export class InMemoryOpenSlotStore implements OpenSlotStore {
  readonly #byKey = new Map<string, Map<string, number>>();
  readonly #keyOf = new Map<string, string>();

  openExpiries(key: string, now: number): number[] {
    const slots = this.#byKey.get(key);
    if (!slots) return [];
    for (const [id, expiresAt] of slots) {
      if (expiresAt <= now) this.#drop(key, id);
    }
    return [...(this.#byKey.get(key)?.values() ?? [])];
  }

  add(key: string, deliveryId: string, expiresAt: number): void {
    let slots = this.#byKey.get(key);
    if (!slots) this.#byKey.set(key, (slots = new Map()));
    slots.set(deliveryId, expiresAt);
    this.#keyOf.set(deliveryId, key);
  }

  remove(deliveryId: string): void {
    const key = this.#keyOf.get(deliveryId);
    if (key !== undefined) this.#drop(key, deliveryId);
  }

  has(deliveryId: string): boolean {
    return this.#keyOf.has(deliveryId);
  }

  #drop(key: string, deliveryId: string): void {
    const slots = this.#byKey.get(key);
    slots?.delete(deliveryId);
    if (slots?.size === 0) this.#byKey.delete(key);
    this.#keyOf.delete(deliveryId);
  }
}

/** `/24` for IPv4, `/64` for IPv6 (an IPv4-mapped IPv6 address counts as its IPv4). `"unknown"` when no valid address is given. */
export function networkPrefix(address: string | undefined): string {
  if (!address) return "unknown";
  let a = address.trim();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(a);
  if (mapped?.[1]) a = mapped[1];
  const family = isIP(a);
  if (family === 4) {
    const parts = a.split(".");
    return `${parts.slice(0, 3).join(".")}.0/24`;
  }
  if (family === 6) {
    const zoneless = a.split("%")[0] ?? a;
    const [head = "", tail] = zoneless.split("::");
    const headGroups = head === "" ? [] : head.split(":");
    const tailGroups = tail === undefined ? [] : tail === "" ? [] : tail.split(":");
    const missing = 8 - headGroups.length - tailGroups.length;
    const groups = tail === undefined ? headGroups : [...headGroups, ...Array<string>(Math.max(missing, 0)).fill("0"), ...tailGroups];
    return `${groups.slice(0, 4).map((g) => g.toLowerCase().replace(/^0+(?=.)/, "")).join(":")}::/64`;
  }
  return "unknown";
}

export interface RequesterThrottleOptions {
  /** Open deliveries allowed per account and network prefix. Default 3. */
  maxOpen?: number;
  /** How long a slot is held before the delivery's own `expires_at` is known. Default 10 minutes. */
  provisionalSeconds?: number;
  store?: OpenSlotStore;
  now?: () => number;
}

export class RequesterThrottle {
  readonly maxOpen: number;
  readonly #provisionalMs: number;
  readonly #store: OpenSlotStore;
  readonly #now: () => number;
  #provisional = 0;

  constructor(options: RequesterThrottleOptions = {}) {
    this.maxOpen = options.maxOpen ?? 3;
    if (!Number.isInteger(this.maxOpen) || this.maxOpen < 1) throw new RangeError("maxOpen must be a positive integer");
    this.#provisionalMs = (options.provisionalSeconds ?? 600) * 1000;
    this.#store = options.store ?? new InMemoryOpenSlotStore();
    this.#now = options.now ?? Date.now;
  }

  /** The bucket key: the account (`subject_ref`) and the requester's network prefix. */
  static key(subjectRef: string, clientAddress: string | undefined): string {
    return `${subjectRef}|${networkPrefix(clientAddress)}`;
  }

  /**
   * Takes a slot before a create call. Throws `ViadereThrottledError` when `maxOpen` deliveries are already open for the key. Returns the
   * provisional slot id; settle it with `confirm` (success) or `release` (failure).
   */
  reserve(subjectRef: string, clientAddress: string | undefined): string {
    const now = this.#now();
    const key = RequesterThrottle.key(subjectRef, clientAddress);
    const open = this.#store.openExpiries(key, now);
    if (open.length >= this.maxOpen) {
      const soonest = Math.min(...open);
      throw new ViadereThrottledError(Math.max(1, Math.ceil((soonest - now) / 1000)));
    }
    const slot = `provisional:${++this.#provisional}`;
    this.#store.add(key, slot, now + this.#provisionalMs);
    return slot;
  }

  /** Binds a provisional slot to the delivery the API created (its `expires_at`). A replay of a known delivery does not take a second slot. */
  confirm(slot: string, deliveryId: string, expiresAt: string, subjectRef: string, clientAddress: string | undefined): void {
    this.#store.remove(slot);
    if (this.#store.has(deliveryId)) return;
    const parsed = Date.parse(expiresAt);
    this.#store.add(RequesterThrottle.key(subjectRef, clientAddress), deliveryId, Number.isNaN(parsed) ? this.#now() + this.#provisionalMs : parsed);
  }

  /** Frees a slot: a provisional one after a failed call, or a delivery that ended. */
  release(idOrSlot: string): void {
    this.#store.remove(idOrSlot);
  }

  /** Frees the slot of a delivery whose state you observed (a response of `getAuthDelivery`, `cancelAuthDelivery` or `completeAuthDelivery`). */
  observeStatus(deliveryId: string, status: Status): void {
    if (isTerminalStatus(status)) this.release(deliveryId);
  }

  /** Frees the slot when a verified webhook says the delivery ended. `auth.delivery.opened` does not end it: only your `complete` does. */
  observeEvent(type: WebhookEventType, deliveryId: string): void {
    if (type === "auth.delivery.completed" || type === "auth.delivery.failed" || type === "auth.delivery.denied" || type === "auth.delivery.cancelled" || type === "auth.delivery.expired") {
      this.release(deliveryId);
    }
  }
}
