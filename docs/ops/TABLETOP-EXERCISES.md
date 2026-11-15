# Disaster-recovery and incident tabletop exercises (OPS-009)

**Status:** programme v1, 2026-10-27. Owner: Security lead. Cadence: one scenario per quarter, each scenario at least once a year, a full DR tabletop annually, and
one live drill (restore test) per quarter (`RESILIENCE.md` 3.2). A tabletop is a facilitated walk-through of the runbook by the people who would run it; the
output is findings, not a pass/fail grade.

## 1. Ground rules

* **Out-of-band contact paths** (OPS-009): the exercise starts by proving the IC can reach every role without Viadere systems or the company chat: a printed/offline contact sheet (phone numbers, personal email, the status-page provider login), a separate bridge line, and the escrow custodians. Keep the sheet in the sealed escrow envelope and in a password manager owned outside the production identity provider. Verify annually that every number works.
* Facilitator injects events on a timeline; participants state actions and cite the exact command or console path from `RUNBOOKS.md`/`KILL-SWITCHES.md`. If a step references a **[GAP]**, the exercise records it as a finding.
* No production changes during a tabletop. Live drills (restore, failover) use staging or isolated apps.
* Output within 5 business days: timeline, decisions, gaps (each linked to `KILL-SWITCHES.md` G-numbers or a ticket), runbook edits, updated risk ratings.

## 2. Roles

IC, SEC, ENG, OPS (operator console), COMMS, LEGAL, scribe, facilitator (not a participant). A business-liaison role joins for scenarios that involve a customer.

## 3. Scenario library

| # | Scenario | Objective | Key injects | Runbooks / expected findings |
|---|---|---|---|---|
| 1 | **Leaked live API key** found in a public repository; fraudulent interactions sent to 400 users | Revoke fast, scope impact, notify | Business unreachable for 2 h; the key had `webhooks:manage`; press inquiry | RB-1; G3 (operator revoke), G9 (consumer notice) |
| 2 | **Business admin account takeover** that points a webhook at an attacker URL and sends phishing through a verified handle | Suspend, restore the real owner, contain webhook | No operator-assisted business recovery; webhook deliveries contain message text | RB-2, RB-3; G5 (webhook pause) |
| 3 | **Signing/secret compromise**: an engineer's laptop with a Fly token is stolen; KMS alert "unexpected_use" fires | Contain, rotate, decide notification | `AUDIT_CHAIN_KEY` and `DATA_ENCRYPTION_KEY` possibly read; deploys made by the token | RB-4, RB-5; G8 (no rotation tooling) |
| 4 | **Region/provider loss**: Neon project unreachable for 6 h and Fly region degraded | Run the DR plan, meet RTO, communicate | Escrow custodians in two time zones; status page; business SLA calls | RESILIENCE.md sections 3 and 4; RTO/RPO validation |
| 5 | **Mass approval abuse**: credential-stuffing of a business login triggers prompt bombing; users approve by fatigue | Throttle, freeze, notify, protect users | Complaint rate spike; auto-throttle fires; support queue overloaded | KILL-SWITCHES.md E-2/E-3/E-13; G6, G7, G12 |
| 6 | **Fraudulent age verification**: a bypass of the vendor liveness check produces valid assertions | Identify, disable method, notify relying businesses | Vendor advisory arrives late; legal question on a regulated retailer | RB-6, RB-7; G2, G14 |
| 7 | **Supply chain**: a malicious release of a scanner or a Swift dependency is discovered | Determine exposure, roll back, rebuild | Provenance verification mismatch on one release | RB-4 step 4; SECURE-SDLC.md checksum pinning; R-026 |
| 8 | **Privacy incident**: a database export is posted online | Legal clocks, regulator and user notification, evidence | Field encryption holds; hashes only; phone last4 and display names exposed | RB-0, DATA-INVENTORY.md; LEGAL decision log |
| 9 | **Vendor outage combination**: APNs and Twilio degraded the same hour | Degraded mode, communication, no weakened controls | Pressure to widen OTP countries or send approvals by SMS | RB-9; RESILIENCE.md section 4 |

## 4. Run sheet (90 minutes)

0:00 brief and contact-path check; 0:10 inject 1, detection and declaration; 0:30 containment decisions; 0:50 inject 2 (complication), notification clocks; 1:10 recovery and communication; 1:20 hot wash (what surprised us, which step failed, which tool is missing).

## 5. Exercise log

| Date | Scenario | Participants | Findings (ticket/gap ids) | Runbook changes | Next exercise |
|---|---|---|---|---|---|
| (planned: before the Phase 1 gate) | 1 and 2 | | | | |
