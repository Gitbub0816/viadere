# Viadere — Security, Trust, Business Platform & Compliance Specification

**Version:** 1.0 (architecture baseline)
**Date:** 27 October 2026
**Status:** Proposed product and engineering requirements; subject to threat modeling, legal review, and independent security assessment
**Classification:** Internal product specification (public-facing statements must be separately approved)

## 1. Executive summary

Viadere is a verified business-to-consumer communications network designed first to replace and extend conventional SMS short-code experiences with persistent verified business identities, interactive notifications, customer replies, and structured requests. Optional capabilities include customer authentication approvals, age-eligibility assertions, identity-attribute verification, and a third-party passkey/TOTP authenticator. Viadere shall not be a general-purpose sign-in identity provider or issue login sessions for relying-party businesses. The business remains the system of record for its customers and retains final authorization decisions.

The security objective is to provide cryptographically trustworthy, purpose-limited interactions while minimizing the sensitive information that Viadere can access or retain. Business onboarding must be simple for ordinary messaging integrations and support optional enhanced controls for regulated and enterprise deployments. No single security mechanism (VPN, API key, Face ID, TLS, or identity-document check) shall be represented as sufficient for all use cases.

### 1.1 Normative language

MUST/SHALL = mandatory before production; SHOULD = expected absent documented exception; MAY = optional. Every requirement shall have an owner, verification method, and release gate. Requirements tagged [POLICY] are proposed Viadere decisions; [LEGAL] require qualified jurisdiction-specific legal determination; [DEPENDENCY] require external platform or vendor capability.

### 1.2 Non-goals

- No "Sign in with Viadere" identity-provider product in the baseline scope.
- No replacement of a business's user directory, session management, password policy, KYC program, or access decisions.
- No blanket claim that Viadere verification satisfies every age-verification, banking, health, or financial regulation.
- No mandatory VPN or proprietary network protocol for standard business integration.
- No central repository of raw government IDs or reusable plaintext passkey private keys.
- No guarantee that Viadere infrastructure compromise can never affect a relying party; instead, minimize and independently constrain the blast radius.

## 2. Product boundaries and terminology

- **Verified business:** A business whose legal existence and control of a Viadere business identity have been checked under documented policy; this is not a guarantee of safety, regulatory licensing, or endorsement.
- **Identity proofing:** Establishing a person's claimed real-world identity from acceptable evidence and checks.
- **Attribute verification:** Validating a particular claim, such as age eligibility, without necessarily identifying the person to the requesting business.
- **Authentication:** Demonstrating control of an authenticator or registered credential.
- **Authorization:** Permission to perform an operation or disclose a field; the business makes its own account-access decisions.
- **Assurance:** Documented confidence in the identity evidence, authenticator, and federation/presentation mechanism, assessed separately.
- **Credential presentation:** A customer-approved proof or set of attributes delivered to a verifier.
- **Relying business:** A business using a Viadere message, verification, or approval result.
- **Pairwise subject reference:** Business-specific pseudonymous identifier not shared across unrelated businesses.
- **Viadere relay:** Infrastructure that routes messages and requests, ideally without plaintext access to sensitive end-to-end payloads.

### 2.1 Modules

1. **Messaging (core):** Verified business directory, persistent business handles and codes, interactive notifications, SMS fallback, routing, replies, templates, consent, delivery reporting.
2. **Approve (optional):** Transaction-specific and login-related MFA approval challenges; device-bound signatures; independent business validation.
3. **Verify (optional):** Age-threshold and identity-attribute assertions derived from validated evidence; purpose-limited disclosure.
4. **Authenticator (optional):** User-controlled storage/use of third-party passkeys and optionally TOTP; not a Viadere-issued business login identity.
5. **Business Platform:** Console, API, SDKs, webhooks, analytics, business verification, security and compliance administration.

## 3. Architecture and trust boundaries

### 3.1 Logical architecture

- **Consumer iOS app and extensions:** Local credential operations, biometric/user-presence gating, signed approvals, consent UX, Wallet credential presentations where supported, optional passkey credential-provider extension.
- **Public API gateway:** TLS termination, client authentication, rate limits, request schema enforcement, tenant isolation, abuse controls, routing.
- **Messaging and event services:** Queueing, delivery orchestration, retry/dead-letter handling, APNs dispatch, SMS gateway integration, webhook fan-out.
- **Business identity and policy service:** Business registration, verified directory, entitlements, requested-capability policy, purpose restrictions, risk decisions.
- **Trust and credential validation service:** Credential format/issuer trust validation, revocation/status checks, evidence provenance, assurance evaluation, signed-result construction as appropriate.
- **Key and secret management:** Azure Key Vault or managed HSM for service keys, key versions, credential issuance, rotation, and auditable access. Customer private keys remain device-side wherever feasible.
- **Business console:** Tenant administration, integrations, requests, analytics, billing, security posture, legal notices.
- **Public marketing/developer site:** Marketing content, product explanations, public trust and legal documentation, developer onboarding and API reference.

Boundary A: Customer device ↔ Viadere. Boundary B: Viadere ↔ business. Boundary C: Viadere ↔ external credential issuer/provider. Boundary D: Public website ↔ management console. Boundary E: Internal workloads ↔ production data/keys. Each boundary requires its own threat model and authentication controls.

### 3.2 Tenant isolation

- Every business resource MUST be bound to an immutable tenant ID and authorized in the service layer, not solely by UI filtering.
- API credentials MUST be tenant-bound, scope-bound, environment-bound, and individually revocable.
- No business may infer other businesses' customer relationships, identifiers, analytics, credentials, or messages.
- Pairwise subject identifiers SHOULD be generated with a cryptographically sound construction and be non-enumerable; age proofs SHOULD support nonpersistent or unlinkable presentations where available.

## 4. Cryptographic and transport security

### 4.1 Network transport

- **SEC-TR-001** All public API, console, and device connections MUST use HTTPS with TLS 1.3 wherever supported; modern TLS 1.2 may be supported only under an explicitly reviewed compatibility policy. Prohibit SSL, TLS 1.0/1.1, weak ciphers, and insecure renegotiation.
- **SEC-TR-002** Support TLS 1.3 AEAD cipher suites, including AES-256-GCM and ChaCha20-Poly1305. Do not claim that mandating AES-256 over all other secure TLS 1.3 suites necessarily improves security.
- **SEC-TR-003** Configure HSTS for applicable web origins; validate certificates and hostnames; use secure cookie settings, CSRF protections, and appropriate origin controls for browser sessions.
- **SEC-TR-004** Service-to-service traffic MUST use authenticated encrypted channels; use workload identity and mTLS where suitable.
- **SEC-TR-005** Enterprise business connections MAY use mTLS, private endpoints, site-to-site VPN/WireGuard, or dedicated connectivity; all must terminate at the same policy-enforcing API layer. Private networking MUST NOT bypass application authorization.
- **SEC-TR-006** The iOS app SHOULD use ordinary TLS with strong device authentication rather than requiring a persistent consumer VPN. APNs payloads MUST avoid raw identity evidence, sensitive credentials, and unnecessary personal data.

### 4.2 Application-level protection

- **SEC-CR-001** Sensitive identity disclosures and high-value approval payloads MUST be cryptographically bound to an intended recipient, business identity, request ID, nonce, purpose, and expiry.
- **SEC-CR-002** Where Viadere is not an intended plaintext recipient, use independently authenticated end-to-end encryption with a vetted standard such as HPKE (RFC 9180) and vetted algorithm suites. Do not invent a proprietary cipher, key exchange, or envelope.
- **SEC-CR-003** Customer approval signatures MUST use device-protected private keys, with independent validation by the business wherever practical. P-256 with Secure Enclave/Keychain integration is a practical Apple-platform baseline; other standardized algorithms require platform support and review.
- **SEC-CR-004** Every signed approval MUST bind the exact human-readable transaction parameters; a generic "approve" result cannot be reused to authorize a different transaction.
- **SEC-CR-005** Enforce replay protection using one-time nonces, request IDs, expiry, clock-skew policy, and atomic consumption of challenges.
- **SEC-CR-006** Authenticate business public-key discovery and rotation; a compromised relay MUST NOT be able to silently substitute an attacker's key without detection under the intended threat model.
- **SEC-CR-007** Cryptographic protocols MUST specify canonical encoding, algorithm identifiers, key identifiers, signature verification rules, revocation semantics, and version negotiation; reject unknown critical fields and algorithm downgrades.
- **SEC-CR-008** Use approved CSPRNGs; separate keys by purpose; use HKDF or vetted KDFs as required; never reuse AEAD nonces with the same key.
- **SEC-CR-009** Protect service private keys using managed key services/HSM where warranted; audit access and rotate according to risk. Never store secrets in source code, logs, telemetry, or client-distributed configuration.

### 4.3 API authentication and credential lifecycle

- **SEC-API-001** Issue 256-bit CSPRNG API secrets encoded as URL-safe strings with a recognizable environment prefix and nonsecret key identifier. Length alone is not a security control.
- **SEC-API-002** Show secret material only at creation; retain a secure verifier, not a retrievable plaintext API key. Store a separately indexed nonsecret key ID.
- **SEC-API-003** Support per-key scopes, tenant binding, environments, expiry options, immediate revocation, last-used metadata, and overlap-based rotation.
- **SEC-API-004** Require elevated reauthentication for secret creation, rotation, scope elevation, and administrative changes.
- **SEC-API-005** Sensitive operations SHOULD use short-lived scoped tokens or signed requests; optional mTLS or proof-of-possession for high-assurance tenants.
- **SEC-API-006** Signed webhooks MUST include timestamp, unique delivery ID, body-integrity signature, versioned key ID, retry semantics, and replay windows.
- **SEC-API-007** Rate-limit by tenant, credential, endpoint, device, and risk signal; apply abuse detection, quotas, circuit breakers, and anomaly alerts.
- **SEC-API-008** Publish an OpenAPI specification, SDKs, deterministic idempotency behavior, explicit error taxonomy, pagination, and backward-compatible versioning.

## 5. Consumer device security and credential custody

- **SEC-DEV-001** Use iOS Keychain and Secure Enclave where supported; private-key operations SHOULD be hardware-backed and require user presence for high-risk approvals. Document platform and accessibility limitations.
- **SEC-DEV-002** Face ID/Touch ID authenticates an enrolled device user; it MUST NOT be described as Apple verifying the person's legal identity.
- **SEC-DEV-003** Store the minimum viable local identity state; prefer references to issuer-held credentials or fresh Wallet presentations over copying identity documents.
- **SEC-DEV-004** Encrypted local storage MUST use device/platform protections; secrets MUST NOT appear in notifications, screenshots of sensitive screens where avoidable, analytics, crash reports, or backups without a reviewed protection model.
- **SEC-DEV-005** Define lost-device, stolen-device, device replacement, multi-device enrollment, and recovery workflows. Recovery MUST NOT silently recreate prior device-bound authentication keys or restore a passkey vault solely on presentation of a government ID.
- **SEC-DEV-006** Device registration and key changes MUST produce independently auditable security events and customer notifications; high-risk changes SHOULD have cooldowns or secondary verification.
- **SEC-DEV-007** Consider device integrity and attestation signals where available, but do not equate attestation with identity proofing or absolute resistance to compromised devices.
- **SEC-DEV-008** Protect against notification-prompt fatigue; display verified business identity and exact action, require fresh user interaction for high-risk operations, and prohibit unattended approval.

### 5.1 Third-party passkey vault

- Viadere MAY implement Apple's credential-provider extension for standard WebAuthn/FIDO passkeys and TOTP where supported.
- The relying website remains the authenticating party; Viadere does not issue its session or control its account.
- A passkey created for a website is not automatically importable from Apple Passwords or another manager; migration depends on supported interoperability.
- Private keys MUST be encrypted at rest, protected during use, and never transmitted to Viadere servers in plaintext.
- If cross-device synchronization is offered, use independently reviewed end-to-end encryption, robust recovery, anti-rollback protection, and explicit customer controls; do not imply that device-only storage automatically supports synchronization.
- Separate vault-unlock policy from government identity verification. Identity proofing alone MUST NOT unlock or recover a credential vault.

## 6. Identity proofing and attribute assurance

### 6.1 Assurance taxonomy

Implement separate recorded dimensions for: identity evidence/proofing, authenticator strength, credential issuer trust, attribute freshness, presentation binding, and transaction risk. Align terminology and evaluation with NIST SP 800-63-4 where applicable; do not self-certify compliance or claim IAL/AAL/FAL equivalence without evidence and assessment.

### 6.2 Verification methods

- **VER-001** Support unverified accounts for basic communications subject to abuse controls; elevated verified status is optional unless required by a specific feature or jurisdiction.
- **VER-002** Supported evidence MAY include eligible government-issued IDs in Apple Wallet, other standards-based mobile credentials, and approved third-party identity-proofing vendors. Availability depends on jurisdiction, entitlement, device, and provider capabilities.
- **VER-003** Where supported, the client MAY check whether an eligible Wallet presentation can be requested before showing that option; availability is not proofing, and the user must explicitly consent to a presentation.
- **VER-004** Validate issuer trust chain, signature, credential type, validity dates, revocation/status where available, requested attributes, challenge/nonce, audience, and freshness before asserting a verified result.
- **VER-005** Document which methods establish identity, age, address, or merely possession of a device; do not promote a weaker result to a stronger claim.
- **VER-006** If physical-document capture or selfie matching is offered, conduct vendor diligence covering document authenticity, liveness/presentation attack detection, bias, accessibility, retention, biometric processing, fraud, and appeals.
- **VER-007** Record provenance, method, verification time, expiry/revalidation requirement, confidence/assurance, revocation state, and policy version. Retain raw evidence only when strictly necessary and with explicit retention policy.
- **VER-008** Provide accessible alternative paths for customers without compatible Wallet IDs, biometric capability, or standard documentation.
- **VER-009** Distinguish 'verified identity', 'verified age threshold', 'registered authenticator', and 'reachable contact' in UI and API; do not use a single misleading universal badge.

### 6.3 Age assurance

- **AGE-001** Offer threshold-based claims such as age.minimum with a parameter (e.g., 18 or 21), rather than disclosing full birthdate by default.
- **AGE-002** Positive results MUST be backed by a verified birthdate or trusted threshold credential; self-entered birthdates cannot be labeled verified.
- **AGE-003** Prefer selective disclosure or unlinkable proofs where credential technology permits. Avoid disclosing actual age, name, birthdate, document number, or global identifier when only a threshold is required.
- **AGE-004** Results MUST specify verification provenance/assurance, validity period, relying-party audience, and unique challenge; do not make age proofs reusable across unrelated businesses.
- **AGE-005** Denial and error design SHOULD avoid unnecessarily revealing whether the user is underage versus unable/unwilling to verify.
- **AGE-006** [LEGAL] Jurisdiction-specific requirements for adult content, alcohol, gambling, and other restricted services must be assessed separately; Viadere shall not promise universal compliance based on a Boolean response.
- **AGE-007** [POLICY] Sensitive-industry access to full identity fields requires additional purpose justification, customer consent, and heightened review; the default is threshold-only disclosure.

### 6.4 Privacy-preserving business requests

- Use a typed capability catalog: contact.reachable, age.minimum, identity.name, identity.address, identity.verified, auth.challenge, transaction.approve, message.send, consent.request, etc.
- Every capability defines inputs, required evidence, sensitivity tier, policy, customer UX, output schema, maximum retention, audit fields, and revocation behavior.
- Apply business entitlement ceiling ∩ customer consent ∩ evidence sufficiency ∩ law/policy before disclosure.
- Do not expose global customer identifiers across unrelated businesses; support one-time proofs where feasible.
- High-risk personal-data releases require granular consent, purpose and recipient display, expiry, and an audit receipt; never use broad blanket consent to justify unrelated later disclosures.

## 7. MFA and transaction approval

- **APP-001** Businesses initiate a challenge against an established customer relationship; Viadere MUST NOT accept a raw phone number alone as sufficient proof of account binding.
- **APP-002** Initial enrollment MUST bind a verified business account to a customer-held cryptographic authenticator using a secure, business-authorized enrollment flow.
- **APP-003** Approval UI MUST show verified business, action, timestamp/expiry, and transaction details; require local authentication and explicit customer intent.
- **APP-004** Return a short-lived, signed, audience-bound result including request ID, nonce, decision, key ID, authentication method, and transaction digest.
- **APP-005** The business MUST independently verify the signature, bound details, expiry, challenge uniqueness, and enrolled key before granting access or executing a transaction.
- **APP-006** The business controls its own primary login and session; Viadere is an independent factor or approval channel, not the account identity provider.
- **APP-007** Provide explicit controls for decline, report suspicious request, revoke device, and freeze approvals.
- **APP-008** Design phishing-resistant flows when possible; a generic push-approval button without origin/request binding MUST NOT be marketed as phishing-resistant.

## 8. Business onboarding and verification

### 8.1 Onboarding stages

1. **Create business workspace:** Verified email, account security, organization and intended use.
2. **Prove organizational control:** Domain verification and legal-entity validation proportionate to risk; additional checks for regulated/sensitive categories.
3. **Assign public identity:** Permanent business handle and immutable public code per established product rules; prevent impersonation, lookalike abuse, reassignment, and unauthorized transfers.
4. **Accept contractual terms:** Business agreement, data processing terms as applicable, acceptable-use rules, messaging consent obligations, and capability-specific addenda.
5. **Configure integration:** Sandbox credentials, SDK examples, endpoints, webhook destination and signature verification, test customer, test events.
6. **Go-live review:** Production credential issuance, security posture, use-case approval, deliverability and abuse limits, operational contact.
7. **Ongoing assurance:** Periodic verification refresh, licensing checks where applicable, security alerts, suspension/reinstatement, and audit.

### 8.2 Risk-tiered business access

- **Tier M — Messaging:** Basic verified business and messaging policies.
- **Tier A — Approvals:** Stronger integration security, enrollment controls, incident response readiness, and approval-specific review.
- **Tier V — Verified attributes:** Purpose assessment, data minimization, consent UX, privacy/legal basis, retention rules, and additional review.
- **Tier E — Enterprise/regulated:** Optional mTLS/private connectivity, audit exports, contractual controls, key-management integration, data residency where supported, and enhanced support.

A category label (bank, retailer, adult site) MUST NOT be the sole access decision. Require documented lawful purpose and risk-based approval. A verified business badge MUST NOT imply approval for all Viadere capabilities.

## 9. Business management console specification

### 9.1 Information architecture

- **Dashboard:** Delivery/response metrics, active channels, incidents, pending approvals, quota usage, verification request volumes, system health, and actionable setup status. No sensitive attributes in default analytics.
- **Organization:** Legal entity profile, verified business status, domain ownership, public directory listing, handles/codes, subsidiaries/brands, team members, business contacts.
- **Developers:** Apps, sandbox/live environments, API credentials, scopes, key rotation, SDK quickstarts, OpenAPI explorer, request logs with redaction, webhook endpoints, test events, replay/retry, idempotency diagnostics.
- **Messaging:** Templates, approval workflow, inbox/agent assignment if offered, channel preferences, interactive actions, consent records, routing rules, delivery reports, opt-outs, SMS fallback configuration.
- **Verify:** Enabled attributes/capabilities, permitted purposes, evidence requirements, consent templates, verification result metrics, legal-policy restrictions, assurance thresholds. No searchable raw ID archive.
- **Approve:** MFA integration settings, enrolled-key references, transaction templates, challenge histories, suspicious-request reports, revocation and risk controls.
- **Security:** SSO for console administrators where available, MFA/passkeys, RBAC, service accounts, IP/network restrictions, mTLS certificates, session management, audit logs, alert subscriptions, security contacts, incident status.
- **Compliance:** Agreements and versions, retention configuration, DPA and subprocessors, export/delete requests, data-region settings if offered, verification policies, required industry attestations.
- **Billing:** Usage by capability, invoices, payment methods, quotas, enterprise contracts, spend alerts.
- **Support:** Documentation, tickets, integration health, incident notices, account appeals.

### 9.2 Roles and controls

Suggested roles: Owner, Organization Admin, Developer, Messaging Operator, Verification Compliance Admin, Security Admin, Analyst, Billing Admin, Read-only Auditor. Enforce least privilege and prevent any single low-privilege role from issuing credentials and widening its own scope. Sensitive operations require step-up authentication and audit trails. Provide separation of duties for enterprise accounts.

### 9.3 Console security and UX requirements

- Strong admin authentication, passkey/MFA support, device/session inventory, short inactivity timeouts for privileged operations, suspicious login alerts.
- Credential secrets displayed once, with copy/download warning and immediate revoke/rotate actions.
- Webhook endpoint ownership verification, signing-secret rotation, retry simulation, and event schema preview.
- Immutable or tamper-evident security audit records with actor, timestamp, action, target, before/after references, source, and outcome; avoid storing secrets or sensitive PII in logs.
- Clear separation of test/live and of business legal identity versus public display identity.
- Accessibility aligned to WCAG 2.2 AA target; mobile-responsive administration, but high-risk administrative changes may require stronger verification.
- No silent changes to customer-consent language or verification purposes; version and reapprove materially changed policies.

### 9.4 Business integration UX acceptance test

A legitimate low-risk messaging business should be able to: create workspace → verify control → obtain sandbox key → send test message → configure signed webhook → receive test reply → request production approval, without installing VPN software. Timing targets should be measured in usability testing rather than promised without evidence.

## 10. Public marketing website and developer portal

### 10.1 Sitemap

- **Home:** "A trusted way to connect." Verified, interactive business communication without traditional short-code friction; concise explanation of customer/business value.
- **Products:** Messaging, Approve, Verify, Authenticator; clearly identify what is live, beta, or planned.
- **For Businesses:** Use cases, integration walkthrough, capabilities, supported channels, pricing, onboarding.
- **For Consumers:** How to recognize verified businesses, notification controls, privacy, verification choices, accessibility, recovery, safety reporting.
- **Developers:** API docs, SDKs, sandbox, schemas, webhooks, auth, rate limits, error codes, changelog, status, migration guides.
- **Security & Trust:** Security overview, responsible disclosure, identity assurance explanation, verification-badge meaning, architecture overview, published attestations only if actually achieved.
- **Privacy Center:** Data categories, device-held vs server-held data, controls, retention, requests, subprocessors, regional rights.
- **Legal:** Terms, business agreement, privacy notice, DPA where applicable, acceptable use, messaging consent rules, age assurance disclosures, cookie policy, accessibility, law-enforcement request policy.
- **Company/Contact:** Organization, support, sales, press, security contact.
- **Status:** Service status, incident notices, maintenance notices, historical incidents where appropriate.

### 10.2 Marketing integrity requirements

- Do not state "unhackable," "anonymous," "zero knowledge," "government certified," "bank compliant," "HIPAA compliant," or "end-to-end encrypted" unless each claim is technically true for the named feature and independently supportable.
- Clearly distinguish verified business identity from trusted/endorsed business, and verified age from verified legal identity.
- State when SMS fallback is not end-to-end encrypted; distinguish platform relay metadata from encrypted payloads.
- Do not imply every Apple Wallet user can present an ID or that Face ID proves legal identity.
- Label demos and future capabilities honestly; provide a public security-contact and vulnerability-reporting process.
- Pricing and plan limits must disclose per-message, verification, carrier, provider, and overage fees where applicable.

### 10.3 Visual and content direction

Premium charcoal, ivory, and satin champagne metallic palette; understated lowercase "viadere" wordmark and continuous-ribbon monogram with floating dot. Use plain language and direct product demos. Avoid dark-pattern consent flows, gratuitous badges, or excessive claims of secrecy.

## 11. Privacy, legal, and regulatory workstreams

This section is an issue-spotting specification, not a determination of legal compliance. Counsel must assess launch jurisdictions, customers, processors, and use cases.

### 11.1 Privacy governance

- **LEG-PR-001** Publish consumer privacy notice identifying controller/business and processor/service-provider roles by processing activity; describe categories collected, purposes, disclosures, retention, rights, security, contact, and international transfers.
- **LEG-PR-002** Map data flows and record processing purposes, legal bases where required, recipients, subprocessors, retention, and deletion mechanics.
- **LEG-PR-003** Conduct privacy impact/risk assessments for government-ID processing, biometric verification, age assurance, sensitive-industry disclosures, and large-scale behavioral telemetry.
- **LEG-PR-004** Build rights workflows for access, correction, deletion, portability, consent withdrawal, appeals, and opt-out where applicable; distinguish deletion of server data from revocation of credentials retained by a third party.
- **LEG-PR-005** Define jurisdiction-specific applicability of US state privacy laws (including California), GDPR/UK GDPR, children's privacy rules, and international transfer requirements before market launch.
- **LEG-PR-006** Define retention by data class and legal obligation. Minimize and promptly delete temporary proofing artifacts; document audit-log retention and legal holds.
- **LEG-PR-007** Establish vendor DPAs, subprocessors list, security due diligence, breach notification obligations, and data transfer safeguards.
- **LEG-PR-008** Avoid unnecessary collection of sensitive biometric templates; if using a provider, document whether Viadere ever receives biometric data and assess biometric privacy laws separately.

### 11.2 Messaging and communications

- **LEG-MSG-001** Assess TCPA, FCC rules, state telemarketing laws, CAN-SPAM where applicable, carrier requirements, and SMS/RCS program rules for each channel and use case.
- **LEG-MSG-002** Maintain consent provenance, permitted purpose, opt-out instructions, suppression lists, quiet hours where applicable, and compliant STOP/HELP handling.
- **LEG-MSG-003** Clarify whether Viadere or the business is sender/initiator for each message type and allocate contractual responsibility; verify applicable registration/numbering rules with messaging providers.
- **LEG-MSG-004** Ensure promotional messages cannot be misrepresented as authentication or transactional messages to bypass consent requirements.

### 11.3 Identity, age, financial and health use cases

- **LEG-ID-001** Confirm government-ID presentation terms, platform entitlements, issuer/credential licensing, verifier requirements, and permitted storage/redisclosure for each supported credential.
- **LEG-ID-002** Map jurisdiction- and industry-specific age assurance requirements; assess whether threshold assertions are acceptable evidence, required retention, auditability, and privacy protections.
- **LEG-ID-003** For financial institutions, document that Viadere verification does not automatically fulfill customer identification, AML/KYC, sanctions, or bank regulatory requirements. Define reliance, evidence access, vendor oversight, and contractual responsibilities.
- **LEG-ID-004** For health-sector integrations, determine HIPAA covered-entity/business-associate status and required BAA/security controls before handling protected health information.
- **LEG-ID-005** For children/minors, evaluate COPPA and applicable state/international child privacy and age-appropriate design requirements; avoid collecting data not needed for age eligibility.
- **LEG-ID-006** Determine accessibility, consumer protection, unfair/deceptive practices, identity theft, data broker, and electronic-signature requirements as relevant to feature claims and markets.

### 11.4 Contracts and public disclosures

- Consumer Terms of Service and Privacy Notice.
- Business Services Agreement and Acceptable Use Policy.
- Data Processing Addendum, subprocessors list, and international transfer addenda when applicable.
- Messaging consent and content-policy addendum.
- Verification Services Addendum defining evidence sources, assurance limits, permitted purposes, retention, liability allocation, prohibited uses, and no universal regulatory sufficiency guarantee.
- MFA/Approval Services Addendum defining relying-party key enrollment, signature validation, fallback, dispute handling, and the business's final authorization responsibility.
- Credential Vault terms describing recovery, device loss, synchronization, and inability to recover nonexportable keys.
- Security Overview, vulnerability disclosure policy, incident notification policy, law-enforcement request policy, accessibility statement, cookie notice where applicable.
- Public explanations of business verification badges and age/identity assurance claims.

### 11.5 Suggested concise disclosure language (draft; counsel review required)

- **Business verification:** "A verified business has completed Viadere's business-identity checks. Verification does not constitute an endorsement, guarantee of legitimacy, or confirmation of regulatory licensing."
- **Identity verification:** "Viadere may verify selected identity attributes using supported credentials or verification providers. A verification result describes the attribute and assurance evaluated; it is not a universal guarantee of identity or eligibility."
- **MFA:** "Viadere delivers and records authentication approvals. The business remains responsible for account access decisions and for independently validating applicable approval evidence."
- **Age verification:** "Where supported, Viadere can confirm that a person meets a specified age threshold without disclosing their date of birth. Availability and legal sufficiency vary by jurisdiction and service."
- **Encryption:** "Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview."
- **Device custody:** "Some credentials are protected on your device. Losing access to a device or recovery method may require re-enrollment or re-verification; some nonrecoverable credentials may need to be recreated with the original service."

## 12. Operations, resilience, and incident response

- **OPS-001** Maintain a security risk register, architecture decision records, threat models (STRIDE or equivalent), and documented exceptions.
- **OPS-002** Secure SDLC: code review, dependency and container scanning, secret scanning, SAST/DAST, SBOM, pinned build provenance, infrastructure-as-code review, and staged rollout.
- **OPS-003** Commission independent penetration testing before launching sensitive verification or MFA at scale; assess mobile app, API, console, tenant boundaries, cryptographic enrollment, and business key rotation.
- **OPS-004** Centralize redacted security logs with tamper resistance, least-privilege access, alerting, retention, and incident correlation; avoid logging raw credentials and identity evidence.
- **OPS-005** Define detection and response playbooks for API-key compromise, business impersonation, webhook takeover, relay compromise, signing-key compromise, fraudulent verification, credential issuer revocation, device theft, and vendor outage.
- **OPS-006** Support safe kill switches, credential revocation, business suspension, replay cache enforcement, webhook pause, emergency messaging restrictions, and notification to affected parties.
- **OPS-007** Define RTO/RPO targets by capability, backups, restore tests, multi-region strategy where justified, and degraded operation when APNs, SMS providers, Wallet providers, or identity vendors are unavailable.
- **OPS-008** Design asynchronous delivery with durable queues, idempotency, bounded retries, dead-letter queues, signed receipts, and explicit delivery versus user-action states.
- **OPS-009** Perform disaster recovery and incident tabletop exercises; maintain contact paths independent of Viadere itself.
- **OPS-010** Implement a vulnerability disclosure policy, patch SLAs by severity, and coordinated disclosure handling.

## 13. Data classification and retention principles

| Data class | Examples | Preferred custody | Default treatment |
|---|---|---|---|
| Public | Verified business directory listing | Viadere | Public with review and correction |
| Operational | Message routing IDs, delivery state | Viadere | Minimize, tenant-isolate, time-bound |
| Security metadata | Public keys, nonces, audit events | Viadere/business | Integrity-protect, retain by policy |
| Identity assertions | Age threshold result, proof metadata | Device/business; minimal Viadere metadata | Purpose-bound, expiring, minimize correlation |
| Raw identity evidence | ID image, birthdate, selfie | Issuer/device/provider preferred | Avoid central collection; short retention if unavoidable |
| Passkey private keys | Third-party account credentials | Customer device / E2EE vault | Never server plaintext; independent recovery model |
| Sensitive message payloads | Health/financial details | Intended endpoints where feasible | E2EE; no plaintext relay logging |

Retention periods must be established through a documented data inventory and applicable law; do not hardcode a single universal duration for all categories.

## 14. Example API contracts (illustrative, not final)

### 14.1 Create an age-threshold request

```http
POST /v1/verification-requests
Authorization: Bearer <scoped-business-token>
Idempotency-Key: <unique-request-key>
Content-Type: application/json

{
  "subject_ref": "pairwise_customer_ref",
  "capability": "age.minimum",
  "parameters": {"years": 18},
  "purpose_code": "age_restricted_access",
  "callback_id": "registered_callback_01",
  "expires_in_seconds": 180
}
```

Requirements: Validate business entitlement and purpose, rate limits, customer binding, proof format, recipient/audience, and consent. Never accept arbitrary callback URLs from untrusted request bodies.

### 14.2 Create a transaction approval

```json
{
  "subject_ref": "pairwise_customer_ref",
  "capability": "transaction.approve",
  "challenge": "base64url_random_nonce",
  "transaction": {
    "currency": "USD",
    "amount_minor": 250000,
    "payee_display": "Example Merchant",
    "transaction_reference": "bank_tx_123"
  },
  "expires_in_seconds": 120
}
```

Requirements: Sign exact canonical transaction data; return verifiable key reference and decision; business validates independently. Never authorize merely because a relay database status says approved.

### 14.3 Event/webhook envelope

```json
{
  "id": "evt_opaque",
  "type": "verification.completed",
  "version": "2026-10-27",
  "tenant_id": "tenant_opaque",
  "request_id": "req_opaque",
  "occurred_at": "2026-10-27T18:00:00Z",
  "result_ref": "result_opaque"
}
```

Webhook transport uses a signature over canonical bytes plus timestamp and event ID; sensitive results SHOULD be retrieved or delivered using an explicitly authenticated and recipient-bound mechanism rather than embedded as unrestricted webhook plaintext.

## 15. Threat model and abuse scenarios

Threats to evaluate before launch include: API-key theft, cross-tenant IDOR, compromised business admin, fake business registration, directory spoofing, SIM swap, device theft, biometric fallback abuse, compromised mobile OS, passkey export/recovery compromise, malicious credential issuer, fake age assertion, request substitution, replay, notification fatigue, man-in-the-middle public-key substitution, malicious webhook endpoints, SSRF, supply-chain compromise, insider abuse, mass messaging/spam, phishing through verified businesses, coercion of customer consent, privacy correlation, and metadata inference.

Controls must be validated with concrete adversarial tests; defense-in-depth should not be described as eliminating all risk.

## 16. Security standards and external references to evaluate

- NIST SP 800-63-4 Digital Identity Guidelines (identity proofing, authenticators, federation; applicability and assurance mapping to be assessed).
- NIST SP 800-53 and NIST Cybersecurity Framework 2.0 for control/risk governance where appropriate.
- OWASP ASVS, OWASP API Security Top 10, OWASP MASVS/MSTG for app/API requirements and testing.
- RFC 8446 (TLS 1.3); RFC 9180 (HPKE); RFC 9421 (HTTP Message Signatures) where applicable.
- W3C WebAuthn and FIDO passkey specifications; Apple AuthenticationServices, PassKit/Verify with Wallet, Secure Enclave and Keychain documentation.
- SOC 2 Trust Services Criteria and ISO/IEC 27001 as potential independently assessed assurance programs, not presumed certifications.
- Applicable US state privacy laws, GDPR/UK GDPR, TCPA/FCC messaging rules, COPPA, biometric privacy rules, industry-specific age-verification laws, and sector requirements (e.g., financial and health) subject to counsel's analysis.

## 17. Release plan and gates

### Phase 0 — Foundation

Architecture review, data inventory, threat model, business identity model, key lifecycle, policy engine, privacy design, legal gap assessment, security baseline, incident runbooks.

**Gate:** No production release without tenant isolation tests, secret handling, abuse controls, and legal review of actual launch flows.

### Phase 1 — Messaging core

Verified business onboarding, directory, business console MVP, sandbox/live API, SDK, signed webhooks, interactive notifications, SMS fallback and opt-outs, operational telemetry, consumer controls, public marketing/developer site.

**Gate:** End-to-end delivery and opt-out tests, webhook replay protection, business impersonation controls, messaging consent review, accessibility testing, and incident drill.

### Phase 2 — Approve

Secure customer-to-business enrollment, device-bound keys, transaction-bound signatures, phishing-resistant patterns where supported, suspicious approval reporting, business independent verification SDK.

**Gate:** Independent security assessment of enrollment, key substitution, device loss, challenge binding, replay, and recovery.

### Phase 3 — Verify

Credential verifier integrations, Apple Wallet eligibility/presentation where authorized, age threshold capability, provenance and assurance metadata, customer consent receipts, capability entitlement review.

**Gate:** Legal validation by market/use case; privacy assessment; credential issuer/format validation tests; non-disclosure and unlinkability tests where claimed.

### Phase 4 — Authenticator and enterprise

Credential-provider extension, optional TOTP, optional E2EE vault sync, enterprise mTLS/private connectivity, audit exports, advanced compliance tooling.

**Gate:** Independent vault cryptography/recovery review, passkey interoperability tests, enterprise connectivity failover and key rotation tests.

## 18. Acceptance criteria and measurable evidence

1. A compromised messaging API credential cannot invoke age verification or transaction approval without corresponding scope and policy authorization.
2. A business cannot retrieve another tenant's message, verification result, subject reference, audit event, or credential by changing an identifier.
3. Replaying a signed approval or substituting its amount, payee, business, nonce, or expiry fails verification.
4. A relay-only compromise cannot decrypt properly end-to-end encrypted identity disclosures when endpoint keys remain uncompromised.
5. A business independently validates approval signatures using an enrolled public key; relay status alone is insufficient.
6. An age-only verification request discloses no birthdate, name, address, or government ID number in the standard result.
7. Device loss/recovery cannot silently authorize the replacement of an enrolled approval key or restoration of an entire passkey vault without its specified independent protections.
8. All production secrets are redacted from console logs, telemetry, crash reports, support exports, and routine API responses.
9. An ordinary business can integrate standard messaging without a VPN; an enterprise can select a private transport without changing business-level API semantics.
10. All user-visible verification labels and security claims map to documented evidence and approved public disclosures.
11. All public legal pages have versioning, effective dates, owner, counsel review status, and archival history.
12. The team can revoke a compromised business key, suspend a tenant, disable a capability, and notify affected parties using tested procedures.

## 19. Open decisions requiring product, engineering, and counsel approval

1. Which launch jurisdictions and industry categories will Viadere serve first?
2. Which identity evidence formats/providers are supported at launch, and what exact assurance labels are defensible?
3. Which claims can be derived locally from a credential without exporting underlying PII?
4. Should high-risk capabilities be available only to individually reviewed business tenants?
5. What metadata must Viadere retain for fraud, dispute, billing, and lawful requests without undermining privacy goals?
6. What is the customer recovery model for device-bound approval keys and the optional passkey vault?
7. Which channels provide true end-to-end payload confidentiality, and what is the fallback when they do not?
8. What business verification checks and renewal cadence apply by risk tier?
9. What evidence, contracts, and certifications will enterprise customers require before adopting the platform?
10. Which capabilities are generally available, invite-only, restricted, or prohibited by business use case?

---

**Design principle:** Viadere connects, delivers, and verifies. Businesses control their own accounts; customers control their credentials and disclosures; Viadere minimizes the information it must possess.
