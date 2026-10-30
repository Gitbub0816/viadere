# ADR-0014: Azure Service Bus queues with a transactional outbox, DLQ and idempotent consumers

- **Status:** proposed (2026-10-29)
- **Plan reference:** `docs/IMPLEMENTATION-PLAN-v3.md` decision PO-2; WP-B3; section 5.7 (decided by: Product owner, service and tier; Engineering, design)
- **Related:** `Server/Sources/ViadereServerKit/Jobs/BackgroundJobs.swift`, spec §9 ("Azure Service Bus + workers: durable queues, DLQ, idempotency"), SECURITY.md §2.27
- **Review:** revisit at each phase gate and when message volume or latency targets change

## Context

Every serving instance runs `BackgroundJobs.runOnce` every 5 seconds: SMS, channel, webhook and Wallet deliveries, expiries, recovery activation, retention, audit export and more, coordinated by compare-and-swap in PostgreSQL. It is safe but couples messaging work to the API process, polls the database constantly, has no dead-letter queue, and sends approval pushes inline in the request. The spec wants durable queues, DLQs, idempotency and separate workloads for the authorization core and messaging. Service Bus is not transactional with PostgreSQL, and there is no Azure Service Bus SDK for Swift. Private endpoints are Premium only; Standard supports IP firewall rules and Entra-only authentication (Microsoft Learn, 2026-05-02).

## Decision

1. **Transactional outbox:** work is recorded in an `outbox_messages` row inside the same database transaction as the state change; the worker publishes it to Service Bus with `MessageId` = outbox id (duplicate detection on, 10-minute window) and marks it published. Nothing is published for a transaction that rolled back.
2. **Queues:** `push`, `sms-outbound`, `channel-outbound`, `webhook-delivery`, `wallet-push`, `operator-notices`, `consumer-export`, plus scheduled messages for `interaction.expire`, `approve.expire` and identity holds. Messages carry a versioned envelope with ids only (`{"v":1,"type":…,"id":…,"ref":…}`), never personal data or secrets; consumers re-read state from PostgreSQL.
3. **Idempotent consumers:** the existing CAS state machines remain the source of truth, and a `processed_messages` row is written in the same transaction as the effect. Unknown types or versions are dead-lettered, never executed.
4. **DLQ:** per-queue `maxDeliveryCount` (3 to 10), retries as scheduled messages with the existing backoff, alerts on any DLQ message and on active-message age; webhook DLQ triggers the existing endpoint pause.
5. **Sweeps** (retention, purges, assurance, audit export, API-key lifecycle, safety-net expiries) run as Container Apps scheduled jobs, single execution at a time, still CAS-safe.
6. **Transport:** the Service Bus REST API (send, peek-lock, complete, unlock, scheduled enqueue) with Entra tokens from the worker's managed identity, behind a `QueueTransport` protocol. A database-backed transport implementing today's semantics stays for development, tests and an emergency fallback mode.
7. **Tier:** staging uses **Standard** with local (SAS) auth disabled and an IP rule allowing only the NAT gateway's egress IP. Production uses **Premium (1 messaging unit)** with a private endpoint and public access disabled, unless the product owner accepts Standard with the same controls to save about USD 665 per month.

## Consequences

- Messaging moves out of the API workload; the API needs only Data Sender, the worker Data Receiver and Sender.
- Approval wake-up pushes gain a queue hop (tens to hundreds of milliseconds); the publisher is woken right after commit and push messages have a short TTL.
- Writing and maintaining a REST transport is our responsibility (tests first: duplicate delivery, rollback, poison message, unknown type).
- Cost: Standard ≈ USD 10 per month; Premium ≈ USD 677 per month per messaging unit (Azure Retail Prices API, 2026-10-29).
- `RUN_BACKGROUND_JOBS` and `JOB_INTERVAL_SECONDS` are retired from the API workload; the in-process loop remains only for development.

## Implementation notes (2026-10-30, WP-B3)

- `QueueTransport` has two implementations with the same semantics: `ServiceBusRESTTransport` (send with `MessageId`, scheduled enqueue, peek-lock, complete, unlock, renew) and `DatabaseQueueTransport` (`queue_messages`, leases taken by compare-and-swap on the delivery count; the default on Fly, in development and in tests). The Service Bus REST API has no dead-letter operation: the consumer dead-letters on the last allowed delivery itself (recorded in `queue_dead_letters`, alert metric `queue_dead_lettered`) and completes the message; broker-side dead letters (expiry) alert through Azure Monitor.
- Migration `QueueOutbox.v1` adds `outbox_messages`, `processed_messages`, `queue_messages` and `queue_dead_letters`. The envelope is normative in SECURITY.md §2.91. Lean (Service Bus Basic) has no duplicate detection, so `processed_messages` is the deduplication, written in the same transaction as each handler's state transition.
- Moved onto queues (plan 5.7): `sms.send`, `channel.deliver`, `webhook.deliver`, `wallet.push`, `operator_notice.deliver`, `consumer_export.process`, and the scheduled `interaction.expire`. Each handler claims its row with the same compare-and-swap the sweep uses and then runs the unchanged per-row code; a reschedule by the row's backoff becomes a new scheduled message. `approve.expire` is scheduled when an approval request is created (at `expires_at`) and when a link session is created (at `expires_at` and at the end of the confirmation grace); its handler runs the Approve v2 expiry sweep, which also ends link sessions (merge of Milestones B and C). `identity.hold_due` is registered, but its enqueue sites (recovery) are left to the work package that owns those files; the maintenance sweep keeps doing that work meanwhile, and remains the safety net for every scheduled expiry. Inline approval pushes (`push.send`) stay inline for now (Milestone C owns the Approve path).
- Sweeps stay as the safety net (`ViadereServer maintenance maintenance|hourly|audit-export`); `BackgroundJobs.runOnce` runs all of them plus one queue pass for the single-process mode.
- Message types are a registry: future Loop action events, hosted-inbox deliveries and notification-orchestrator steps (FEATURE-EXPANSION-v4 A2, A3, A7) are new `(type, v)` entries with their own claims and inherit the outbox, idempotency, retry and DLQ guarantees.
