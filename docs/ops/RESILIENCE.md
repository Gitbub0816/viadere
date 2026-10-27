# Resilience: RTO/RPO, backup and restore, degraded operation (OPS-007, OPS-008)

**Status:** proposal v1, 2026-10-27. Targets below are **proposals for the product owner to approve**; nothing here has been measured yet. Each target
becomes a commitment only after the first restore test and failover drill produce evidence (section 3.4). Owner: SRE lead.

## 1. Targets per capability (proposed)

RTO = time to restore the capability; RPO = maximum acceptable data loss. "Fail mode" is what the system does while down.

| Capability | RTO | RPO | Fail mode | Dependencies |
|---|---|---|---|---|
| Sign-in approval, transaction approval (Approve) | 30 min | 5 min | Fail closed: no approval without a verified device signature; requests expire (<= 15 min for security kinds) | Fly, Neon, Cloudflare, APNs |
| API for businesses (create interaction, status, messages) | 30 min | 5 min | 503 with `Retry-After`; business retries with idempotency keys (required on POSTs that create state) | Fly, Neon, Cloudflare |
| Consumer app basics (auth, devices, relationships) | 1 h | 5 min | Cached read-only views in the app; no new sessions | Fly, Neon |
| SMS/RCS broker and handoff links | 1 h | 5 min | Inbound provider webhooks retried by the provider; outbound queued durably | Fly, Neon, Twilio/RCS |
| Webhook delivery to businesses | 4 h | 0 (queue is in the database) | Deliveries queue and retry (30 s, 2 min, 10 min, 1 h, 6 h, 12 h, 24 h, then dead letter) | Fly, Neon |
| Business dashboard | 4 h | 15 min | Unavailable; API keeps working | Fly, Neon |
| Operator console | 4 h | 15 min | Use edge/CLI emergency controls (KILL-SWITCHES.md) | Fly, Neon |
| Verification (Wallet/Didit) | 4 h | 15 min | Capability disabled, other capabilities unaffected | vendors |
| Audit chain integrity | n/a | head exported hourly: at most 1 h of unanchored events | Chain keeps appending; anchoring catches up | Neon, write-once storage |
| Marketing/developer site | 1 h | 0 (rebuilt from git) | Static assets on Cloudflare Workers; independent of the API | Cloudflare |
| Status page and out-of-band comms | 0 (independent) | n/a | Hosted separately from our stack | external |

Database durability: Neon PITR (history retention 7 days, `Infra/terraform/neon.tf`) gives an RPO of seconds to minutes within the window; the
daily snapshot (30 days) covers longer-range recovery. The 5-minute RPO above is the commitment, PITR is how we expect to beat it.

## 2. Backups and key escrow

| What | How | Where | Test |
|---|---|---|---|
| PostgreSQL | Neon PITR (7 days) + scheduled daily snapshot (30 days, `neon_branch_backup_schedule`) | Neon, region of the project | Restore test quarterly (3.3) |
| Logical export (defense against provider-level loss) | Weekly `pg_dump` of the production branch by a CI job running with `viadere_readonly`, encrypted (age/KMS), written to a bucket in a **different provider/account** | to be built (owner: ENG) | Restore of the dump into a scratch branch every six months |
| Secrets: `DATA_ENCRYPTION_KEY`, `SERVER_PEPPER`, `AUDIT_CHAIN_KEY`, `CONNECT_LINK_SIGNING_KEY` | Offline escrow: split (Shamir 2-of-3) between three named people, sealed, location recorded; separate from database backups (Server/README.md: back them up separately) | offline | Annual retrieval drill without using the secret |
| KMS keys | Not exportable by design; recovery = key versions remain in GCP (scheduled destroy is 30 days and reversible); IAM state is in Terraform | GCP | Rebuild of IAM from Terraform in a scratch project |
| Infrastructure | Terraform in git; state in an encrypted, versioned bucket | git + bucket | `tofu plan` shows no drift monthly |
| Fly app | Image digests in GHCR (signed); `fly.*.toml` in git | GHCR | Redeploy previous digest in staging monthly |
| Audit heads | Write-once bucket (object lock) | to be provisioned | `audit-verify --head` after each restore |

Losing the escrowed secrets makes encrypted columns (phones, message bodies, webhook secrets) and OTP/phone hashes unrecoverable even from a perfect database restore. That is the most important DR dependency.

## 3. Restore and restore test

### 3.1 Restore to a point in time (Neon)

1. Decide the target time `T` (just before the damaging event; use the audit log to find it) and a reason; record in the incident log. Open a **Neon branch from the production branch at timestamp `T`** (console: Branches -> Create branch -> Past data; API/provider: `neon_branch` with `parent_timestamp`). Never restore in place first.
2. Verify the branch: connect with `viadere_readonly`; run `ViadereServer audit-verify --env staging` against it by starting a staging machine with that `DATABASE_URL` (the chain must verify to the last event before `T`; compare against the exported head); sample the tables that were damaged.
3. Decide in place vs repoint: **repoint** (preferred): create the compute endpoint on the restored branch, put its connection string into `DATABASE_URL` with `fly secrets set --app viadere-server DATABASE_URL=...` (rolling restart), make the restored branch the default branch afterwards. **In-place** (Neon "restore branch to point in time"): only when the whole database is wrong; it rewrites the branch history and the previous state is kept as a backup branch for the retention window.
4. Replay protection and sessions: nonces issued after `T` are gone, so a request replayed from after `T` could be accepted once; all token families created after `T` vanish (users must sign in again); both are acceptable and noted in the incident.
5. Run `migrate` (release command) to ensure schema is current, `audit-verify`, `/readyz`, one end-to-end sign-in approval on staging-like traffic, then lift edge blocks.
6. Reconcile: webhooks and SMS sent after `T` were sent but are no longer recorded; consult provider logs (Twilio) and business webhook logs; notify per runbook.

### 3.2 Restore test procedure (quarterly, SRE lead, 2 hours)

1. Create a Neon branch of production from a timestamp 24 hours ago (read-only role only; never expose its connection string outside the drill).
2. Start a **staging** machine configured with that branch (`DATABASE_URL`), the **staging** secrets would not decrypt production data: use production `DATA_ENCRYPTION_KEY` retrieved from escrow with two custodians present (this is also the escrow drill) and run in an isolated app (`viadere-restore-drill`, no public hostname).
3. Run `ViadereServer audit-verify` (expect OK) and `audit-verify --head <stored head older than the branch time>` (expect OK).
4. Prove the escrowed `DATA_ENCRYPTION_KEY` opens restored data. No CLI does this today (`reencrypt-fields` opens only legacy `v1.` values, so it prints 0 rewritten on a healthy v2 database whether or not the key is right). Interim check: sign in to the drill app's operator/dashboard as a test user and open a page that decrypts a field (for example `/dashboard/team`, which shows decrypted member emails). **[GAP: add a `verify-keys` command that opens a sample of every encrypted column and the audit key; owner: ENG.]**
5. Check sample counts against production (`consumers`, `devices`, `interactions`, `audit_events` max seq).
6. Record: time to create the branch, time to a working app, data age, issues. Delete the branch and the drill app; shred the escrow material handled.
7. File findings as risks or tickets; update RTO/RPO if reality differs.

### 3.3 Evidence

Each drill leaves: date, participants, measured RTO/RPO, `audit-verify` output, issues. Link them from `RISK-REGISTER.md` (R-033).

### 3.4 Gate

Targets in section 1 are approved only after one successful restore test and one Fly redeploy drill meeting them.

## 4. Degraded-mode behavior per vendor outage

Principle: availability is never bought by weakening a control. Security-critical limiters fail closed; sensitive approvals are never moved to weaker channels.

| Outage | What keeps working | What degrades | User/business impact |
|---|---|---|---|
| **APNs** | In-app inbox, SMS/RCS handoff link for non-security kinds, API | Push alerts for approvals and Live Activities | Approvals are not announced; users open the app; interactions expire normally. Banner/status page |
| **Twilio SMS** | Push-based flows, in-app, email for dashboard | SMS fallback, link texts, OTP for phone linking | Phone linking and SMS threads stop; outbound queue retries with backoff, then fails with `error_code`; cannot send approvals by SMS anyway |
| **RCS provider** | SMS (automatic fallback), push | Rich messaging | Silent fallback recorded as `channel.*` events |
| **Didit** | Wallet verification, Approve, messaging | Verification for users without a Wallet ID | Capability disabled for that method [flag G2] |
| **Apple Wallet / PKI** | Everything else | New pass issuing; pass update pushes queue | Passes already in Wallet keep working (offline) |
| **Neon** | Static pages, `/healthz`, Cloudflare edge pages | Everything stateful: `/readyz` 503 pulls machines from rotation; security-critical limiters refuse | Full API outage; clients retry; no data loss (nothing accepted without a database write) |
| **Fly.io** | Static site, status page | API, dashboard | Outage; Cloudflare error page; DR: redeploy image elsewhere (3.4/drill) |
| **Cloudflare** | Origin unaffected | Edge, WAF, DNS, site | Break-glass DNS to Fly for <= 1 h, SEC-approved, since the edge controls and origin lock are bypassed |
| **GCP KMS** | Verification of existing signatures; cached unwrapped keys | New signatures (audit heads, connect links, webhook key ids); wrapped-key unwrap after process restart | Avoid restarts during the outage; queue head export; never switch to software keys in production |
| **Email provider** | API, app | Dashboard sign-up codes and invitations | Business onboarding delayed; consumer flows unaffected |

Dependencies shared by every machine (Neon, Cloudflare) are single points of failure today; this is why the RTOs are 30 to 60 minutes rather than seconds. Multi-region compute is cheap
to add later (Fly) but is pointless without a database plan: Neon read replicas or a second project with logical replication is a design decision for the RTO review.

## 5. Asynchronous delivery (OPS-008): what exists

| Property | Current behavior | Gap |
|---|---|---|
| Durable queues | State is rows, not memory: `sms_outbound`, `channel_outbound`, `webhook_deliveries`, `wallet_push_outbox`; claims by compare-and-swap, any number of instances | n/a |
| Idempotency | Business POSTs require `Idempotency-Key`; provider webhooks dedup by provider message id; decisions consume single-use challenges | n/a |
| Bounded retries | Webhooks: 30 s, 2 min, 10 min, 1 h, 6 h, 12 h, 24 h, then `dead`; SMS/channel: attempts with `next_attempt_at` | document SMS/channel schedule with the Server owner |
| Dead-letter | `webhook_deliveries.status = dead` plus `webhook_delivery_attempts`; audited `webhook.dead_lettered`; business can replay from the dashboard | alert on dead-letter growth (G13); SMS/channel dead-letter view |
| Delivery vs user-action states | Interaction status and delivery state are separate (`delivery_status` on messages, `status` on outbound rows, interaction `status`/`decided_at`) | signed delivery receipts are not implemented |
| Signed receipts | Decisions are device-signed; provider delivery receipts are stored (`RCS` receipts, Twilio status callbacks) | Viadere-signed receipts to businesses: not built |

## 6. Drills (OPS-009 link)

Quarterly: restore test (3.2). Twice a year: Fly redeploy to a clean app from a signed digest; Cloudflare break-glass DNS rehearsal (staging zone); escrow retrieval with custodians. Annual: full DR tabletop (`TABLETOP-EXERCISES.md` scenario 4).
