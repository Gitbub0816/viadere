<!-- Source: Viadere_Security_Architecture_Expansion_v1.docx (product owner, 29 October 2026). Text extracted verbatim; tables rendered as Markdown. -->

# Viadere

**Identity, Device Trust, Business Enrollment & Azure Migration**

_Architecture expansion specification  |  Version 1.0  |  29 October 2026_

Prepared from the combined perspectives of a senior security architecture function and a principal software engineering function. This is a design proposal, not an assertion of review or authorship by named external professionals.

# Executive decision

Adopt a pseudonymous, device-first account model. Use independent, hardware-protected device credentials for approvals, optional portable recovery credentials, and per-business opaque connections. Target production infrastructure: Cloudflare public edge + Azure Container Apps / ASP.NET Core + Azure Database for PostgreSQL Flexible Server + Azure Service Bus + Key Vault / Managed HSM as justified. Current Cloudflare/Fly.io/Neon staging is transitional, not the production system of record.

# 1. Scope, assumptions and non-goals

- Scope: consumer iOS, iPadOS, macOS, watchOS companion and Android clients; business APIs and console; messaging, push-based MFA, age/identity claims and account recovery.
- Assumptions: project is early-stage; existing Cloudflare/Fly.io/Neon deployment can be replaced before production; existing users, secrets and integrations must be inventoried before any destructive migration.
- Non-goals: legal-identity proof at initial enrollment; mandatory email/phone/password; Apple ID enumeration; universal seamless enrollment without device authorization; treating app attestation as proof of a human identity.
- Security principle: pseudonymous does not mean anonymous to all parties. IP addresses, device signals, push tokens, business mappings and audit records may remain identifying or linkable and require privacy controls.

# 2. Trust model and invariants

- One Viadere account may contain many device registrations; each device has its own nonexportable approval key and independently revocable credential.
- A business connection is a unique, pairwise opaque identifier, not the global Viadere account ID. No business may query another business’s relationships.
- Business enrollment requires a fresh authorization from both an already-authenticated business session and the Viadere account/device.
- A push notification is a delivery signal only. It is never sufficient evidence of approval.
- Every sensitive approval must sign a canonical, server-generated challenge bound to relying party, action, nonce, expiry, device and transaction context.
- Recovery authority is weaker than existing trusted-device authority; recovery alone must not silently grant high-risk MFA privileges.
- All authorization decisions are made by the backend using verified signatures and policy, not solely by client claims.

# 3. Account and device data model

| Entity | Required fields (illustrative) |
|---|---|
| Account | account_id (random 128+ bit opaque ID), state, created_at, policy_version |
| Device | device_id, account_id, platform, public_key, key_algorithm, attestation metadata, trust_tier, last_seen, revoked_at |
| RecoveryCredential | credential_id, account_id, public_key or protected recovery verifier, type, status, created_at |
| BusinessConnection | connection_id, business_id, account_id (internal only), status, permissions, enrollment evidence, created_at |
| EnrollmentSession | session_id, business_id, authenticated_subject_ref (business-held), nonce, expiry, state, proof digest |
| ApprovalChallenge | challenge_id, connection_id, action_hash, display payload, nonce, expiry, status, policy, attempt count |
| ApprovalEvidence | challenge_id, device_id, signature, user-verification evidence, verification result, timestamp |
| AuditEvent | event_id, actor pseudonym, action, correlation_id, policy version, result, immutable log pointer |

Use distinct internal IDs and external pairwise IDs. Encrypt sensitive columns as warranted; minimize retention and prohibit logging of private keys, full tokens, identity documents, or recovery secrets.

# 4. First-run anonymous enrollment

1. User opens app; present concise consent/privacy and explain that a device will be registered; avoid unnecessary registration fields.

2. Client generates a hardware-protected signing key where supported; explicitly select access control requiring biometric or device passcode for sensitive signing.

3. Client requests a server challenge; attach platform-specific app/key integrity evidence where supported (iOS App Attest, Android Play Integrity plus key attestation as applicable).

4. Server validates challenge, attestation chain/policy, freshness and replay protections; creates account and device records; returns scoped session credentials.

5. Register APNs/FCM delivery token separately. Show readiness only after backend confirms enrollment; degraded integrity cases use risk policy rather than silently receiving full trust.

App Attest does not establish legal identity or prove biometric user presence. Secure Enclave-backed signing and LocalAuthentication/Keychain access controls must be designed and verified independently. Platform capability varies by device.

# 5. Business-to-user linking protocol

## 5.1 QR enrollment (baseline)

1. Business authenticates customer using its own approved account access/recovery procedure.

2. Business backend creates an expiring, single-use enrollment session with Viadere via mutually authenticated service API; session is scoped to business, requested permissions and a non-sensitive transaction reference.

3. Business UI displays QR containing only an opaque session reference / universal HTTPS URL. Never embed persistent account IDs, API credentials or reusable enrollment secrets.

4. Viadere app scans and retrieves signed business identity, requested scope, expiry and display context over authenticated TLS.

5. User confirms on Viadere; device signs enrollment challenge with appropriate local verification.

6. Viadere backend atomically consumes the session, creates a pairwise connection ID, and emits a signed/verified result to the business via authenticated callback or poll.

7. Business binds the connection ID to the authenticated local customer record; provide immediate enrollment confirmation and out-of-band notice where appropriate.

## 5.2 App-to-app and browser variants

Universal Links / Android App Links transport the same short-lived enrollment session. Browser flows may use cross-device QR or deep link. Standard WebAuthn/passkeys can complement Viadere but must not be conflated with its custom transaction-approval protocol. Implement anti-session-swapping protections, explicit business identity display, and a verified return channel.

# 6. Multi-device and Apple ecosystem

An Apple Account does not expose an API that allows arbitrary apps to enumerate all the user’s devices or silently provision trust. iCloud Keychain can synchronize eligible Keychain items, and CloudKit can synchronize app-specific private data where available; neither synchronizes Secure Enclave or App Attest private keys.

- Primary path: new device creates its own device-bound key, discovers the account via an optional synchronized recovery/bootstrap credential or authenticated pairing, then requests device enrollment.
- Trust elevation: an existing trusted device approves addition using a signed, short-lived, account/device-bound challenge; show device name, platform, approximate region and permissions.
- Same-ecosystem convenience: use iCloud Keychain for an optional portable discovery/recovery credential; CloudKit may hold encrypted non-authoritative account hints. Never equate iCloud presence with MFA approval authorization.
- Cross-platform: use QR-based device pairing or a portable passkey/recovery method; no Apple-only dependency in core account schema or protocol.
- Apple Watch: implement companion notification and approvals only after evaluating watchOS security and key-management capabilities; never assume parity with iPhone App Attest.
- Device lifecycle: user can view devices, revoke individually, rotate keys, and see recent approvals. Device loss or reset invalidates its device-bound key.

# 7. MFA challenge and approval

Business requests approval for an enrolled connection through authenticated API. Viadere creates a unique, short-lived challenge with canonical action details, relying-party identifier, expiry and nonce; stores pending state durably; dispatches push as a wake-up hint. Client fetches details directly, renders unambiguous transaction context, requires local user verification according to policy, signs a domain-separated challenge, and submits signature. Server verifies key status, connection, signature, nonce, expiry, challenge state and policy before atomically transitioning to approved/denied. Business receives only a signed/verified result. Include idempotency keys, replay rejection, push-fatigue limits, cancellation and timeout semantics.

Do not promise phishing resistance from push approval alone. Require explicit transaction binding and user-verifiable relying-party context; consider FIDO2/WebAuthn for standard sign-in and higher assurance use cases.

# 8. Recovery and assurance tiers

- Tier D0: registered pseudonymous account and device, suitable for basic messaging; no assertion of real-world identity.
- Tier D1: hardware-protected device key plus recent local user verification and validated app/key integrity where supported; eligible for MFA subject to business policy.
- Tier D2: independently verified age/identity attributes using approved credential providers; disclose minimum claims (e.g., age_over_21), not birth date, where legally and technically supportable.
- Recovery: prioritize trusted-device authorization. Optional synchronized passkey or offline high-entropy recovery code may restore account access but must trigger risk review before high-assurance device activation.
- High-risk replacement: step-up at relying business, configurable delay, notifications to existing devices, and revocation of lost device; avoid irreversible account takeover from a single compromised cloud account.

# 9. Target infrastructure architecture — formal decision

ADR-VDR-001 — Status: PROPOSED FOR ADOPTION. Replace Fly.io application runtime and Neon production database with Azure-managed services. Retain Cloudflare as public edge/DNS/WAF where appropriate. No assertion that Azure automatically satisfies compliance requirements.

| Layer | Target service | Security/operational requirement |
|---|---|---|
| Public edge | Cloudflare DNS, WAF, rate limits | Authenticated origin, DDoS controls, avoid edge secrets |
| API services | Azure Container Apps, ASP.NET Core (.NET LTS) | Separate identity, approval, messaging and business APIs |
| Data | Azure PostgreSQL Flexible Server | Private networking, HA, PITR, tested restore |
| Async jobs | Azure Service Bus + workers | Durable queues, DLQ, idempotency |
| Keys/secrets | Azure Key Vault; Managed HSM if warranted | Managed identity, rotation, audit, separation of duties |
| Workload auth | Microsoft Entra managed identities | No embedded long-lived cloud credentials |
| Telemetry | Azure Monitor / Application Insights | Redacted traces, security audit export, alerting |
| Build/deploy | GitHub Actions with OIDC federation | Environment approvals, IaC, artifact provenance |

Keep authorization core and messaging workers in separate workloads, identities, network policies, queues and databases/schemas where justified. Avoid unnecessary Kubernetes/AKS initially. Size capacity and regional topology using measured SLOs, not hypothetical peak claims.

# 10. Security boundaries and control baseline

- TLS 1.3 where feasible; mTLS or equivalent strong workload authentication for partner connections where supported; certificate/key rotation and authenticated callbacks.
- Use NIST-aligned cryptographic algorithms and audited libraries; choose P-256 ECDSA or Ed25519 based on platform hardware and verifier interoperability. Do not invent cryptographic primitives.
- Private DB connectivity, least-privilege managed identities, per-service authorization, network segmentation and egress restrictions.
- HSM-backed server keys protect server-held secrets/signatures, not users’ device private keys. Maintain key inventories and emergency revocation procedures.
- Rate limits, anti-enumeration, anti-bot checks, device integrity signals, anomaly detection and abuse controls that minimize privacy intrusion.
- Audit append-only events with integrity controls, defined retention, controlled access, alerting and independent backup/export.
- Business tenant isolation, scoped service credentials, RBAC, dual control for sensitive operations and security-tested admin recovery.
- Privacy impact review and regulatory counsel for biometric processing, age verification, data protection, banking use cases and cross-border storage.

# 11. Migration from Cloudflare / Fly.io / Neon

## Phase 0 — inventory and freeze

Map services, Neon schema, secrets, jobs, edge routes, app configuration, staging users and business integrations; preserve rollback artifacts. Do not delete resources yet.

## Phase 1 — Azure foundation

Create separate Viadere subscription/resource groups as appropriate, IaC, Container Apps environment, PostgreSQL, private network, Key Vault, identities, monitoring, CI/CD.

## Phase 2 — service port

Port Vapor endpoints to ASP.NET Core or implement protocol-compatible .NET services. Preserve versioned API contracts and test vectors; do not assume Swift code is mechanically portable.

## Phase 3 — data transition

Version schema and migrations; export/import Neon staging data where useful, validate row counts, constraints, key references and retention; rotate exposed/shared secrets.

## Phase 4 — dual-environment verification

Run contract, cryptographic, negative-path, concurrency, recovery, disaster recovery, load and security tests against Azure; compare functional behavior with staging.

## Phase 5 — controlled cutover

Move Cloudflare origin routes using staged traffic and health checks; monitor errors/latency/queue lag; maintain rollback window and write-freeze plan where required.

## Phase 6 — decommission

Revoke Fly/Neon credentials, remove unused routes and secrets, export required records, document deletion and verify no orphaned services remain.

# 12. Verification gates and acceptance criteria

- Enrollment: no mandatory personal fields; invalid/replayed attestations and challenges rejected; registration cannot silently elevate trust.
- Business linking: QR expires and is one-time; session swapping, tenant confusion and unauthorized linking rejected.
- Multi-device: iPhone→Mac, iPhone→Android and loss/recovery paths tested; new device receives independent key and does not inherit high-trust approval without policy authorization.
- MFA: replay, double approval, stale challenge, revoked key, spoofed business, notification tampering and concurrent race conditions rejected.
- Infrastructure: backup/restore exercise, regional failure exercise, key rotation, least-privilege review, secret scanning, SAST/DAST and external penetration test before sensitive production onboarding.
- Operations: define measurable availability/latency/recovery objectives, audit retention, breach response and on-call ownership before production launch.

# 13. Open architecture decisions

- Whether any recovered account can immediately restore low-risk messaging; default deny high-risk MFA until trusted-device or relying-party reauthorization.
- Whether multiple devices can approve the same business connection; recommend per-business configurable policy and independent device audit.
- Choice of portable recovery credential and platform compatibility, including behavior when iCloud Keychain is disabled.
- Regional residency, database topology and required recovery objectives based on initial customer jurisdictions.
- Exact cryptographic encoding and signing profile, standardized through versioned protocol documents and cross-language test vectors.
- Whether to use Cloudflare Workers for non-sensitive edge routing; prohibit authoritative approval decisions at the edge unless independently reviewed.

# 14. Implementation sequence

Milestone A: threat model, protocol schema and ADR approval. Milestone B: Azure landing zone and identity/device enrollment. Milestone C: business linking + signed approval flow. Milestone D: multi-device enrollment and recovery. Milestone E: native Apple/Android integrity adapters and console. Milestone F: load, security and operational readiness. Do not advertise financial-grade authentication before independent security evaluation and relying-party assurance requirements are met.

# Reference standards and platform documentation to validate

NIST SP 800-63B (digital authentication); W3C WebAuthn; FIDO Alliance passkey guidance; Apple DeviceCheck/App Attest, Keychain Services, CloudKit and LocalAuthentication documentation; Android Keystore, Key Attestation, Play Integrity and Credential Manager; Microsoft Azure Container Apps, Managed Identity, Key Vault, PostgreSQL Flexible Server and Service Bus documentation. Reconfirm platform limits and service pricing at implementation time.
