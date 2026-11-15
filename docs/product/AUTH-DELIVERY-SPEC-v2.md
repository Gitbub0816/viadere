Revision 2.0 \| 01 November 2026 \| INTERNAL CODING-AGENT WORK ORDER

Status: proposed engineering requirements; agents must inspect the
actual repository, reconcile existing code, and validate platform
behavior before implementation.

This document assigns specialist AI coding/review agents to perform
work. It does not claim that external human experts have participated or
approved the design.

# Executive decision

Preserve Viadere's anonymous, device-linked consumer model and its
existing business messaging, MFA push, verification, and first-party
action capabilities. Add a transport-neutral Authentication Delivery
service that can deliver and route secure links, one-time codes, TOTP
enrollment prompts, and approval requests. Keep a full Viadere OpenID
Connect / SAML identity provider as a separately gated future option,
not a prerequisite for delivery or MFA.

The security objective is compromise containment: breach of one ordinary
production service must not independently permit arbitrary customer
impersonation, issuance of unauthorized grants, or extraction of
nonexportable signing keys. This is a testable goal, not a claim of
invulnerability.

# Document navigation

1\. Board and decision authority

2\. Baseline versus expansion

3\. Product model and supported methods

4\. Threat model and trust boundaries

5\. Reference architecture

6\. Protocols and transaction contracts

7\. Customer journeys and UX copy

8\. SDK and platform requirements

9\. Network, cloud and cryptographic controls

10\. Account recovery and assurance

11\. Privacy, compliance and governance

12\. Reliability, monitoring and operations

13\. Testing and release gates

14\. Rollout, decisions and open questions

Appendices: schemas, failure cases, references

# 1. Multidisciplinary architecture review board

The following are required review perspectives and decision
responsibilities, rather than a representation that actual individuals
have signed off.

  -----------------------------------------------------------------------
  Discipline                          Review mandate / veto
  ----------------------------------- -----------------------------------
  Identity architect (OIDC, SAML,     Protocol correctness, RP
  FIDO2)                              integration, assurance semantics,
                                      token issuance; veto insecure auth
                                      semantics

  Applied cryptographer / HSM         Key custody, algorithms, signing
  engineer                            authorization, lifecycle,
                                      anti-replay; veto bespoke
                                      cryptography

  Red-team / adversarial security     Threat modeling,
  lead                                attacker-controlled gateway
                                      scenarios, lateral movement,
                                      recovery abuse

  Cloud and infrastructure security   Workload isolation, IAM,
  architect                           attestation options, control-plane
                                      threats, tenant isolation

  Network security engineer           Private endpoints, mTLS,
                                      segmentation, DNS, egress
                                      restrictions, routing, certificate
                                      rotation

  Principal backend / distributed     Idempotency, transaction state,
  systems engineer                    concurrency, eventual consistency,
                                      failure handling

  iOS / watchOS engineer              APNs, notification launch,
                                      universal links, app extensions,
                                      passkey APIs, watch constraints

  Android / Wear OS engineer          FCM, app links, Credential Manager,
                                      background launch, wearable
                                      limitations

  Web / SDK / protocol engineer       Browser flows, CSP, CSRF, PKCE,
                                      redirect security, SDK
                                      interoperability

  Product design and UX research lead Comprehension, consent, error copy,
                                      anti-fatigue, accessibility,
                                      usability studies

  Behavioral psychology / abuse       Approval fatigue, deceptive
  specialist                          prompts, phishing resistance, habit
                                      formation

  Privacy counsel / data protection   Minimization, consent, retention,
  lead                                data subject rights, jurisdictional
                                      rules

  SRE / incident response lead        Operational controls, kill
                                      switches, logging, fail-closed
                                      behavior, recovery drills

  Developer relations / partner       Business onboarding, documentation,
  integrations                        test harness, compatibility,
                                      migration
  -----------------------------------------------------------------------

# 1.1 Governance and sign-off

Security, privacy, and platform leads have blocking approval on their
respective control categories. Product may choose among compliant
alternatives but may not waive mandatory controls without documented
risk acceptance and an expiry. Record an Architecture Decision Record
(ADR) for each material protocol or boundary decision. Independent
review is mandatory before external identity-provider launch.

# 2. Scope ledger: existing, expansion, and deferred

  ---------------------------------------------------------------------------
  Classification          Capabilities                Boundary
  ----------------------- --------------------------- -----------------------
  BASELINE --- prior      Anonymous device            Maintain existing
  scope                   recognition; device-linked  anonymous default; do
                          identity; cross-device      not silently require
                          linking; business           verified legal identity
                          connections; messaging; MFA 
                          push; age/identity          
                          verification options;       
                          first-party actions;        
                          business console; partner   
                          brand kits; optional Loops  

  BASELINE --- previously Business-issued secure MFA  Confirm implementation
  discussed               requests; actionable        status in repository;
                          notifications; device-local scope is not evidence
                          key material; no            of production readiness
                          third-party arbitrary code; 
                          partner theme assets only   

  NEW --- phase A         Secure-link delivery,       Delivery provider, not
                          magic-link routing, OTP     automatic identity
                          delivery, resend/expiry,    provider
                          request inbox, status       
                          callbacks, anti-phishing    
                          destination controls        

  NEW --- phase B         TOTP                        Only advertise
                          provisioning/verification   assurance supported by
                          service where contracted;   actual method
                          recovery delivery; adaptive 
                          delivery choice; unified    
                          auth SDKs; optional         
                          phone/email transport       
                          adapters                    

  NEW --- phase C,        Viadere-managed optional    Separate security and
  conditional             recoverable identity, OIDC  business approval; do
                          provider, SAML 2.0          not make required for
                          federation, token issuance  core
                          and dedicated grant         
                          authority                   

  EXPLICITLY OUT          Mandatory legal-name        Changes require new ADR
                          verification; arbitrary     and risk review
                          partner HTML/JS in Viadere; 
                          guaranteed silent external  
                          URL launch on iOS; homemade 
                          crypto; promises of         
                          invulnerability             
  ---------------------------------------------------------------------------

Implementation truth rule: "previously scoped" means product direction
from earlier design conversations, not confirmation that code has
shipped. The source repository and deployment must be audited to assign
Implemented / Partial / Planned / Absent to each baseline capability.

# 2.1 Non-goals

-   Replacing Apple/Google device passkey ecosystems with a proprietary
    authenticator in phase A.

-   Guaranteeing that SMS or email are phishing-resistant, or
    representing them as equivalent to FIDO2.

-   Creating an independent universal identity profile for every Viadere
    consumer.

-   Storing arbitrary business magic-link URLs or bearer credentials in
    notification bodies.

-   Allowing businesses to bypass Viadere-owned security decisions
    through partner themes or Loops.

# 3. Product model and authentication taxonomy

Separate DELIVERY, VERIFICATION, AUTHORIZATION, and IDENTITY FEDERATION.
A delivered message is not itself evidence that a user authenticated. A
notification tap is not proof of identity. An email link may prove
control of an email inbox, subject to its risks. An approved push
request can be an authentication factor only if device binding, user
verification, and transaction binding are enforced.

  -----------------------------------------------------------------------
  Method                  Viadere role            Assurance / caveat
  ----------------------- ----------------------- -----------------------
  Magic link              Deliver and route a     Bearer-link
                          short-lived             interception and
                          business-issued link or wrong-device risk;
                          Viadere-issued          single use
                          challenge               

  Email one-time code     Deliver via Viadere if  Mailbox compromise and
                          account-linked;         phishing exposure
                          optional email          
                          transport connector     

  SMS one-time code       Optional fallback via   SIM swap, interception,
                          contracted provider; do and phishing;
                          not make default        restricted assurance

  TOTP                    Provision, store        Shared secret
                          securely where          protection; phishing
                          applicable, or verify   possible
                          via MFA service         

  Push approve / deny     Transaction-bound       Number matching and
                          device approval with    origin/context binding;
                          local user verification fatigue controls

  Passkey / WebAuthn      Relying-party login or  Phishing-resistant when
                          optional Viadere        correctly implemented;
                          identity sign-in        synced versus
                                                  device-bound
                                                  distinction

  Recovery / device       Restore account         Never weaken
  transfer                continuity with         high-assurance
                          independent recovery    authentication silently
                          controls                
  -----------------------------------------------------------------------

# 3.1 Authentication service contracts

-   Business owns the primary customer account and authentication
    decision unless Viadere Identity Provider is explicitly enabled.

-   Every request has immutable tenant, user-handle, relying-party,
    transaction ID, requested action, expiry, and policy version.

-   Delivery success, link open, challenge completion, factor
    verification, and account login are distinct status events.

-   No universal fallback from strong MFA to weaker SMS/email; business
    policy must explicitly permit fallback and record assurance
    downgrade.

-   Partner can choose approved delivery methods and brand kit, but
    cannot alter security-critical copy, warning hierarchy, or approval
    semantics.

# 4. Threat model and security objectives

## 4.1 Assets and attacker objectives

Assets: consumer private keys and device bindings; business account
mappings; TOTP seeds; magic-link credentials; session tokens; grant
decisions; signing keys; recovery records; API credentials; tenant
configuration; notification metadata; operational audit trails. Attacker
goals include arbitrary account takeover, MFA fatigue, phishing, session
replay, lateral movement, malicious URL redirection, bulk data
exfiltration, unauthorized token minting, and denial of service.

## 4.2 Explicit attacker assumptions

-   Internet-facing gateway compromised with arbitrary code execution.

-   One workload identity, API key, or database read credential stolen.

-   An employee support account phished or session token stolen.

-   A business integration or tenant admin account malicious or
    compromised.

-   A consumer device stolen while locked, or separately stolen while
    unlocked.

-   An upstream push, email, or SMS provider unavailable or compromised.

-   Cloud control-plane or high-privilege administrator compromise as a
    separate severe threat class.

## 4.3 Non-negotiable invariants

-   One compromised ordinary workload must not issue arbitrary valid
    authentication grants.

-   The public gateway cannot export grant or token signing keys and
    cannot self-authorize signatures.

-   Grant decisions require independently authenticated, audience-bound,
    short-lived evidence; policy controls assurance requirements.

-   Tenant isolation must be enforced at the data, key, authorization,
    and message-routing layers.

-   Recovery and authenticator enrollment cannot bypass the effective
    assurance policy without explicit controlled downgrade.

-   Any failure to validate nonce, audience, origin, signature, state,
    time, policy version, or replay state results in denial.

-   A successful network tunnel or mTLS handshake is never itself
    sufficient authorization.

## 4.4 Residual risks

An HSM protects key extraction but may still sign malicious requests if
authorization is weak. A compromised legitimate device may produce valid
approvals. A compromised grant authority or cloud control plane can
defeat service isolation. Third-party RPs may mishandle tokens. Service
availability and privacy remain at risk even when account impersonation
is prevented. These are explicitly tracked rather than concealed behind
"unhackable" language.

# 5. Reference architecture and service responsibilities

-   Edge Gateway: public API, abuse throttling, business auth, request
    schema validation; holds no grant signing keys.

-   Delivery Orchestrator: routes approved message templates to
    APNs/FCM, in-app inbox, email/SMS adapters; does not decide
    successful authentication.

-   Device Binding Service: manages pseudonymous device identities,
    public keys, registrations, cross-device association, revocation.

-   Authentication Verification Service: validates WebAuthn/passkeys and
    credential evidence; stores no plaintext secrets.

-   MFA Authority: verifies push/TOTP/other factors and signs
    method-specific, transaction-bound evidence.

-   Policy / Grant Authority: private, independently permissioned
    decision point; checks evidence and relying-party policy.

-   Token Issuer (future IdP): tightly controlled signer; only accepts
    valid, nonreplayable grant artifacts; HSM-backed keys.

-   Recovery Authority: separate enrollment/recovery policy, holds
    independent credentials and approval rules.

-   Tenant & Consent Service: business-to-device mapping, subscriptions,
    permission scope, retention policy, branded display metadata.

-   Audit and Security Analytics: append-only security events, anomaly
    detection, administrative approvals, immutable incident evidence.

## 5.1 Logical data flow: secure magic-link delivery

1.  1\. Business backend creates a one-time authentication request and
    binds it to its customer session and intended destination.

2.  2\. Business authenticates to Viadere Delivery API with scoped
    workload credentials; Viadere validates tenant, destination
    ownership, expiry, user mapping, and rate limits.

3.  3\. Viadere persists only minimal request metadata and an opaque
    lookup reference; secret URL material is encrypted and tightly
    TTL-bound or, preferably, retained by the business.

4.  4\. APNs/FCM receives a nonsecret notification payload containing
    request ID and approved display text.

5.  5\. On tap, Viadere opens briefly, resolves the request over an
    authenticated API, and initiates the approved HTTPS universal/app
    link or browser URL.

6.  6\. The business verifies its own magic-link token and completes its
    session; Viadere does not infer login success from a tap.

7.  7\. Business posts an authenticated completion callback; Viadere
    closes the request and records coarse audit events.

## 5.2 Logical data flow: Viadere push MFA

8.  1\. Business creates an MFA challenge with transaction details and
    requested assurance.

9.  2\. Viadere checks enrolled device binding, consent, risk limits,
    and challenge integrity.

10. 3\. Customer sees business, action, approximate context, and a clear
    Approve / Deny decision.

11. 4\. Local biometric/device credential verifies user presence when
    required; cryptographic device proof binds approval to challenge ID,
    origin, and expiry.

12. 5\. MFA Authority validates signature, replay status, policy, and
    enrollment; issues short-lived signed evidence.

13. 6\. Business receives result via signed callback or polling. An
    OAuth grant, if present, requires a separate grant decision.

## 5.3 Future identity provider

If activated, Viadere must implement OAuth 2.0 Authorization Code with
PKCE and OpenID Connect for authentication; SAML 2.0 as a separately
tested federation protocol. OAuth alone is an authorization framework
and is not synonymous with user login. Use well-supported protocol
libraries and established metadata/discovery endpoints. Grant Authority
and signing infrastructure must be separated from the internet-facing
authorization endpoints. A public gateway cannot unilaterally mint valid
ID tokens or SAML assertions.

# 6. API and protocol specifications

## 6.1 Public partner API

  ---------------------------------------------------------------------------------
  Endpoint (illustrative)           Purpose                 Control
  --------------------------------- ----------------------- -----------------------
  POST /v1/auth-deliveries          Create secure link or   mTLS or signed client
                                    OTP delivery            authentication; scoped
                                                            tenant credentials;
                                                            idempotency key

  GET /v1/auth-deliveries/{id}      Status, no secret       Business-only scope and
                                    retrieval by default    audit

  POST /v1/mfa/challenges           Create push/TOTP        Signed request;
                                    challenge               user-binding check;
                                                            policy

  POST                              Revoke pending request  Owner authorization and
  /v1/auth-deliveries/{id}/cancel                           audit

  POST /v1/devices/link             Consumer-driven device  Out-of-band
                                    association             confirmation and proof
                                                            of possession

  POST /v1/webhooks/test            Partner validation      Sandbox-only, signed
                                                            sample events
  ---------------------------------------------------------------------------------

Actual URI names are proposed. Public APIs must use HTTPS, modern TLS,
strict validation, bounded request sizes, replay-resistant client
authentication where appropriate, and quotas. Return generic error
messages that do not disclose whether a consumer has Viadere or is
enrolled with a given business.

## 6.2 Event model

States: CREATED → VALIDATED → QUEUED → SENT → DELIVERED (if provider
confirms) → OPENED → COMPLETED, or EXPIRED / CANCELLED / DENIED /
FAILED. Delivery provider acknowledgments are not proof of human
receipt. OPENED is not authentication success. COMPLETED is
authoritative only from the verifier/business that owns the
authentication decision.

## 6.3 Webhooks and replay defense

Sign callbacks over method, path, timestamp, body digest, event ID, and
tenant context. Verify signatures with rotating asymmetric keys or
appropriately managed MAC secrets. Enforce a short freshness window,
persist event IDs for replay rejection, and deliver at least once with
idempotent consumption. Do not put magic links, OTPs, TOTP seeds, or
sensitive identity details in routine webhook payloads.

## 6.4 Magic-link requirements

-   Opaque, cryptographically random bearer tokens generated by the
    party responsible for authentication; do not construct tokens from
    user IDs.

-   TTL recommended 2--10 minutes by risk level; single use; revoke on
    completion, replacement, or cancellation.

-   Bind token to the intended relying party, transaction and action;
    optionally bind to initiating browser/device with a safe
    cross-device handoff.

-   Approved destination must be verified for the tenant, HTTPS-only,
    and protected from open redirects, URL rewriting and host confusion.

-   On cross-device use, prefer a confirmation or pairing flow rather
    than silently transferring a browser session to an unrelated device.

-   Treat URL logs, referrer headers, previews, analytics, screenshots,
    and push payloads as exfiltration surfaces; use no-referrer policies
    and avoid third-party assets on redemption pages.

## 6.5 OTP and TOTP

OTP verification must use server-side rate limits, bounded retries,
short expiry, per-challenge storage of a keyed hash rather than
plaintext, and constant-time comparison where applicable. TOTP must
follow RFC 6238; protect enrollment seeds with encryption and strict
access; prevent code replay within an accepted time step. Email and SMS
are delivery channels with lower assurance than origin-bound passkeys;
do not mislabel them as phishing resistant.

# 7. UX and behavioral-security specification

Design principles: plain language, identifiable business, explicit
action, neutral tone, no manufactured urgency, no deceptive success
state, minimal disclosure on lock screen, accessibility at 200% text
scaling, clear Deny/Report options, and consistent security copy
regardless of brand kit. "Approve" is not displayed for a passive
magic-link notification; a tap to open a link is distinct from an MFA
approval.

  -----------------------------------------------------------------------
  Flow                    Recommended customer    Interaction / rule
                          copy                    
  ----------------------- ----------------------- -----------------------
  Magic link ready        "Netflix sign-in link   Tap initiates external
                          is ready. Tap to        handoff; no "Approved"
                          continue."              claim

  Push approval           "Sign-in requested for  Review details; Approve
                          Netflix. Is this you?"  / Deny; require user
                                                  verification when
                                                  policy says

  Unrecognized request    "Didn't request this?   One-tap denial; no
                          Deny and report."       additional sign-in
                                                  required to deny when
                                                  safe

  Expired link            "This sign-in link has  Do not automatically
                          expired. Request a new  regenerate; return to
                          one from Netflix."      verified business

  Cross-device transfer   "Confirm that you're    Show both device names
                          moving your Viadere     and verification method
                          account to this         
                          device."                

  Recovery downgrade      "This recovery method   Explicit informed
                          offers less protection. choice, step-up or
                          Some actions will be    cooling-off
                          temporarily             
                          restricted."            

  SMS fallback            "Use a text message     Only if permitted by
                          instead? Text messages  policy; never silent
                          are less resistant to   fallback
                          interception."          

  Service outage          "We couldn't complete   Fail closed; never
                          verification right now. claim authentication
                          Try again."             success
  -----------------------------------------------------------------------

## 7.1 Magic-link tap behavior by platform

iOS: APNs tap ordinarily activates Viadere, which handles the
notification and requests an approved external URL via system APIs. A
fully invisible, direct push-to-arbitrary-website launch cannot be
guaranteed. The app may briefly appear, and platform rules govern
background behavior. Android: FCM notification tap uses a controlled
PendingIntent/deep-link routing flow; app links may hand off to the
partner app or browser. In both cases, never auto-redeem a credential
before explicit user interaction, and do not promise a universal
seamless redirect.

## 7.2 Behavioral abuse defenses

-   Collapse repeated prompts; throttle approval requests and provide a
    clear "This wasn't me" path.

-   Prefer transaction details and number matching for sensitive push
    approvals; avoid one-tap blind approval for high risk.

-   Make Deny visually equal in prominence to Approve; never use brand
    styling to conceal it.

-   Do not display sensitive login URLs, codes, or personal information
    on lock screens.

-   Do not let businesses write custom security warnings or turn
    approval prompts into marketing messages.

-   Usability testing must measure accidental approvals, completion
    rate, comprehension, phishing recognition, and accessibility.

# 8. Cross-platform SDK and surface requirements

  -----------------------------------------------------------------------
  Surface                 Required                Constraint
  ----------------------- ----------------------- -----------------------
  Swift iOS SDK           Push routing, universal No claim of universal
                          links, device binding,  third-party
                          secure local storage,   passkey-provider
                          biometric prompt,       entitlement
                          approval UI             

  Kotlin Android SDK      FCM, App Links,         Account for OEM
                          Credential Manager      background restrictions
                          integration, Keystore   
                          binding, approval UI    

  Web SDK                 Request initiation,     Never store secrets in
                          redirect state/nonce,   localStorage by default
                          PKCE (future IdP),      
                          status UI               

  Backend SDKs            Typed delivery and MFA  SDK must not hold
                          APIs, signed webhooks,  master signing secrets
                          idempotency, retries    

  watchOS companion       Display/approve         Watch is not
                          eligible low- to        automatically a
                          medium-risk requests    universal FIDO2
                          with paired-device      authenticator
                          trust                   

  Wear OS companion       Equivalent constrained  Device capabilities and
                          notification/approval   biometric policies vary
                          flows                   

  Business console        Emulator, templates,    No arbitrary partner
                          domain verification,    JS/HTML or
                          scopes, risk policy,    security-flow override
                          audit, sandbox          
  -----------------------------------------------------------------------

## 8.1 SDK principles

Provide OpenAPI specification, reference implementations, platform
capability matrix, test vectors, signed releases, semantic versioning,
deprecation policy, and reproducible build provenance. Business SDKs
must be optional for standard OIDC/SAML integration. Never require
businesses to decrypt proprietary 96-character composite tokens; use
interoperable signed standards.

## 8.2 Business onboarding

14. Verify business ownership and allowed destination domains; register
    signing keys and redirect URIs.

15. Configure supported auth methods, assurance requirements,
    user-handle mapping, callback endpoints, and permitted fallback.

16. Test in sandbox with replay, expired-link, cross-device, and
    unavailable-provider cases.

17. Complete security checklist and production approval; high-risk
    verticals require manual review.

18. Provide metrics for delivery, user completion, failures, and abuse
    without exposing sensitive contents.

# 9. Network and cloud security

## 9.1 Private connectivity

Azure implementation candidate: isolate policy/grant and signing
workloads in private network segments with no public inbound addresses;
use private endpoints/private ingress and workload identity; restrict
east--west traffic with explicit rules. Establish mTLS for authenticated
service-to-service calls. A private VNet address is not a cryptographic
security boundary and a tunnel does not prevent misuse by a compromised
authorized peer. No requirement to use IPv6; private IPv4 is sufficient.
Evaluate Azure Container Apps/AKS/VM isolation against actual threat
model, cost, and operational skill.

## 9.2 Egress and control plane

-   Deny outbound internet by default for Grant Authority; permit only
    named internal dependencies, telemetry sinks, and key operations.

-   Use separate Azure subscriptions or management boundaries for
    high-impact signing/policy infrastructure when justified.

-   Enforce least-privilege managed identities, conditional access,
    phishing-resistant admin authentication, privileged access
    management, and just-in-time elevation.

-   No shared CI/CD credential can deploy to gateway, MFA, grant, and
    signer simultaneously.

-   Require independent approvals for key policy changes, production
    break-glass, and recovery policy edits.

-   Monitor DNS changes, certificate issuance, routing policies, HSM
    permissions, and infrastructure-as-code drift.

## 9.3 Cryptography and keys

Use FIDO2/WebAuthn for passkeys, standard digital signatures such as
ECDSA P-256 or Ed25519 where ecosystem compatibility permits, and
managed HSM-backed keys for production token issuance. Use Argon2id only
for password hashing if passwords are supported; bcrypt is also a
password hash, not a signing mechanism. Do not split a token into halves
encrypted/hashed with unrelated password algorithms. Token signature
validity must be checked with public keys published via a controlled
JWKS endpoint (OIDC) or trusted federation metadata (SAML).

Keys must have defined ownership, use restrictions, rotation schedule,
revocation procedure, emergency rollover, backup/recovery strategy,
audit trails, and nonexportability where supported. HSM policies must
reject unauthorized signing even when the caller has network access; use
authorization artifacts with nonce, audience, expiry, and grant ID. If
hardware cannot enforce semantic policy, place a separately isolated
signer front end enforcing it.

## 9.4 Supply-chain security

Signed artifacts, pinned dependencies, SCA/SAST/DAST, SBOMs, code review
for security-critical changes, dependency update SLAs, artifact
provenance, restricted production deployments, and independent
vulnerability disclosure program. Test that compromised build
credentials cannot silently update all trust authorities.

# 10. Anonymous identity, enrollment and recovery

Baseline consumer identity remains a pseudonymous Viadere
device/installation relationship. Business-specific identifiers should
be pairwise where feasible to reduce correlation. Recognize-this-device
must not be presented as legal identity verification. A device can be
linked to additional devices only through authenticated user-mediated
ceremony or an approved recovery process.

## 10.1 Enrollment

19. Generate or register device-protected asymmetric key pair; store
    only public key and minimal metadata server-side.

20. Issue opaque installation identifier and pairwise business subject
    identifiers; do not expose global stable ID to all partners.

21. Require explicit user confirmation for high-risk new-device
    enrollment; log device change and notify existing devices.

22. Allow device revocation and lost-device reporting with clear
    consequences for pending MFA and delivery.

## 10.2 Recovery policy tiers

  -----------------------------------------------------------------------
  Tier                    Method                  Security condition
  ----------------------- ----------------------- -----------------------
  Standard anonymous      Existing trusted device Cannot guarantee
                          authorizes new device;  recovery if all
                          optional                authenticators are lost
                          platform-synced         
                          credential              

  Recoverable optional    Passkey plus            Explicit user opt-in;
  account                 independent recovery    separate account from
                          route; verified email   anonymous default
                          may be allowed at       
                          limited assurance       

  High assurance          Multiple independent    Cooling-off,
                          authenticators,         notifications,
                          recovery key and/or     restricted actions,
                          identity proofing       manual fraud review
                                                  where justified
  -----------------------------------------------------------------------

No recovery method can promise both guaranteed account restoration after
total loss of all recovery factors and zero possibility of unauthorized
recovery. Product copy must state that tradeoff. Government ID proofing
is optional, purpose-limited, and subject to legal/privacy review; it
does not automatically make a session phishing-resistant.

# 11. Privacy, consent, and compliance

-   Data minimization: avoid retaining magic-link credentials; use short
    TTLs and purpose-limited encrypted records.

-   Separate transactional security delivery from marketing consent and
    notification preferences.

-   Provide business-facing and consumer-facing data-flow disclosures,
    retention tables, deletion processes, and lawful-request procedures.

-   Define controller/processor roles per business relationship; review
    GDPR, CCPA/CPRA, COPPA and sector-specific obligations where
    applicable.

-   Limit device fingerprinting and cross-business tracking; use
    pairwise pseudonymous identifiers where possible.

-   Protect age/identity-verification outputs with selective disclosure;
    do not share date of birth when only an age threshold is needed.

-   Record administrative actions and authentication decisions without
    storing plaintext codes, bearer links, secrets, or unnecessary
    personal information.

## 11.1 Suggested retention defaults

Pending delivery secrets: until completion or expiry, normally minutes.
Security transaction metadata: short operational period (proposed 30--90
days), adjustable by legal and abuse needs. High-value audit evidence:
risk-based longer retention with access restrictions. Business message
content: governed by user/business retention and consent policy. Exact
periods require privacy and legal approval; no blanket seven-year
retention by default.

# 12. Reliability, observability and incident response

Target design: no single delivery-provider outage should compromise
authentication integrity. Delivery may fail closed or offer an
explicitly permitted alternative; never silently downgrade assurance.
Keep the grant path isolated from marketing and noncritical messaging.
Queue processing must be bounded, idempotent, and resistant to duplicate
approval. Avoid single-region dependencies for production-critical
services where business requirements justify multi-region resilience.

## 12.1 Operational objectives

-   Define SLOs separately for delivery acceptance, push latency,
    verification success, grant availability, and recovery turnaround.

-   Structured audit events include tenant, pseudonymous subject,
    challenge ID, evidence type, policy version, decision reason, key
    ID, and correlation ID---without secrets.

-   Alert on impossible travel indicators, anomalous MFA-denial rates,
    push bombing, new device surges, signing spikes, policy changes, and
    cross-tenant access attempts.

-   Provide incident controls: revoke device, suspend tenant, disable
    method, invalidate challenge family, rotate keys, block compromised
    destination, freeze account recovery.

-   Run periodic tabletop exercises and production-safe chaos tests for
    push outage, database compromise, HSM outage, signer isolation, and
    cloud administrator compromise.

# 13. Security verification and release gates

  -----------------------------------------------------------------------
  Gate                                Required evidence
  ----------------------------------- -----------------------------------
  Threat model                        STRIDE/attack trees for gateway,
                                      delivery, recovery, grant, signer,
                                      cloud control plane

  Protocol validation                 OIDC/FAPI and SAML conformance
                                      where applicable; WebAuthn
                                      verification tests

  Compromise test                     Red team owns gateway; cannot issue
                                      arbitrary valid grant or extract
                                      signer keys

  Cross-tenant test                   Tenant A cannot retrieve, route,
                                      revoke, or complete tenant B
                                      requests

  Replay test                         Duplicate, expired, reordered,
                                      cross-audience and cross-device
                                      evidence denied

  Recovery test                       Stolen email alone cannot override
                                      high-assurance recovery policy

  Mobile UX test                      Cold-launch handoff, locked screen,
                                      no app installed, denied
                                      notifications, lost connectivity

  Privacy test                        No secrets in push, URL analytics,
                                      crash reports, logs, webhooks, or
                                      ordinary database exports

  External review                     Independent penetration test and
                                      security design review before
                                      production IdP
  -----------------------------------------------------------------------

Formal success metric: given full arbitrary-code execution in one
ordinary public-facing production service, attacker cannot create a
valid login for an arbitrary customer without an independent
authenticator or compromising an additional separately controlled
authority. Define exceptions and environmental assumptions in the test
plan. Do not represent this as proof against all possible attacks.

# 14. Phased roadmap and decision record

  -----------------------------------------------------------------------
  Phase                   Deliverable             Release dependency
  ----------------------- ----------------------- -----------------------
  0 --- Inventory         Audit current Viadere   Repository,
                          implementation and      infrastructure and
                          reconcile scoped versus data-flow review
                          shipped                 

  A --- Delivery          Secure-link delivery,   Threat model, mobile UX
                          notification tap        test, abuse limits
                          routing, callbacks,     
                          business domain         
                          verification            

  B --- Broader MFA       TOTP, OTP transport     Assurance taxonomy and
                          adapters, step-up       independent factor
                          policies, recovery      security testing
                          guardrails, SDKs        

  C --- Hardened          Separate grant/policy   Compromise containment
  authorities             service and protected   exercises and HSM
                          signer where needed for operational readiness
                          Viadere-controlled auth 

  D --- Optional IdP      Recoverable accounts,   Commercial validation,
                          OIDC, SAML, federation  external security
                          onboarding              audit, compliance and
                                                  support readiness
  -----------------------------------------------------------------------

## 14.1 Explicit pending decisions

-   Whether to offer any SMS delivery at all, and which customer/tenant
    policies permit it.

-   Whether Viadere itself verifies TOTP or only delivers/initiates
    third-party verification.

-   Whether optional recoverable accounts use synced passkeys, multiple
    authenticators, or an external identity bootstrap.

-   Whether future IdP should support both OIDC and SAML at initial
    release; OIDC-first is simpler.

-   Which assurance tier is required for watch-originated approvals.

-   How to handle browser-to-phone magic-link continuation without
    account confusion.

-   Whether the private grant authority is needed in phase B or only
    when Viadere becomes the authoritative IdP.

-   Whether an independent infrastructure/security team can operate
    isolated signing authority at launch.

# Appendix A. Illustrative request contract

POST /v1/auth-deliveries

tenant_id: authenticated from client identity, not trusted from payload
alone

request_id: UUID or similarly collision-resistant identifier

type: MAGIC_LINK \| OTP \| PUSH_APPROVAL \| RECOVERY_NOTICE

subject_ref: tenant-scoped pseudonymous business mapping

display: Viadere-approved template ID and permitted variables

destination: verified HTTPS origin / approved deep-link association

expires_at: server-enforced short TTL

client_transaction_ref: opaque business correlation handle

idempotency_key: mandatory on create

callback: pre-registered signed webhook destination

# Appendix B. Example failure and misuse cases

-   Gateway compromise: attacker can submit arbitrary internal requests;
    downstream independent evidence verification still denies
    unauthorized grants.

-   Business admin compromise: attacker attempts to register phishing
    domain; require verification, risk checks, notification, and
    optional hold.

-   Push bombing: attacker creates hundreds of requests; per-subject and
    per-tenant throttles, grouping, deny/report, escalation.

-   Magic-link leakage: token accidentally included in notification log;
    design forbids storing token in push and limits token lifetime.

-   OTP brute force: attempts capped per challenge and account; server
    enforces cooldown and anomaly detection.

-   Replay of MFA approval: signed assertion bound to transaction ID,
    audience, nonce, and expiry; consumed once.

-   Stolen employee credentials: admin access uses phishing-resistant
    MFA and just-in-time privilege; sensitive changes require separate
    approval.

-   HSM signing misuse: signer requires grant proof and enforces
    per-tenant policy; raw sign access is not available to gateway.

-   Cloud control-plane breach: severe residual threat; separate
    subscriptions, access approval, independent logs and incident
    drills.

-   Compromised user device: revoke device and require separate
    recovery; local biometric cannot prove legal identity.

# Appendix C. Standards and primary technical references

W3C Web Authentication Level 3 --- https://www.w3.org/TR/webauthn-3/

FIDO Alliance passkeys and FIDO2 --- https://fidoalliance.org/passkeys/

OpenID Connect Core 1.0 ---
https://openid.net/specs/openid-connect-core-1_0.html

RFC 6749 OAuth 2.0 --- https://www.rfc-editor.org/rfc/rfc6749

RFC 7636 Proof Key for Code Exchange ---
https://www.rfc-editor.org/rfc/rfc7636

RFC 9700 OAuth 2.0 Security Best Current Practice ---
https://www.rfc-editor.org/rfc/rfc9700

RFC 9449 Demonstrating Proof-of-Possession ---
https://www.rfc-editor.org/rfc/rfc9449

RFC 6238 TOTP --- https://www.rfc-editor.org/rfc/rfc6238

NIST SP 800-63 Digital Identity Guidelines ---
https://pages.nist.gov/800-63-4/

NIST SP 800-207 Zero Trust Architecture ---
https://csrc.nist.gov/pubs/sp/800/207/final

OWASP ASVS ---
https://owasp.org/www-project-application-security-verification-standard/

OWASP Authentication Cheat Sheet ---
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

Apple Platform Security ---
https://support.apple.com/guide/security/welcome/web

Apple UserNotifications documentation ---
https://developer.apple.com/documentation/usernotifications

Android Credential Manager ---
https://developer.android.com/identity/sign-in/credential-manager

SAML 2.0 OASIS standard ---
https://docs.oasis-open.org/security/saml/v2.0/

References are standards and documentation starting points; verify
current revisions, platform entitlements, and provider-specific
constraints during implementation. This document is not a compliance
certification.

# PART II --- MANDATORY MULTI-AGENT BUILD & REVIEW DIRECTIVE

This part supersedes any implication in Part I that a single implementer
may design, implement, review, and approve the system. The orchestrating
agent must delegate implementation and independent review to specialized
agents with separate work products, evidence, and acceptance gates. No
agent may self-approve a security-critical change.

# 15. Roles, authority, and separation of duties

  ---------------------------------------------------------------------------
  Agent ID / discipline   Primary deliverable         Independent review
                                                      responsibility
  ----------------------- --------------------------- -----------------------
  A0 --- Principal        Repository inventory,       Coordinates; may not
  architect /             dependency graph, decision  waive security gates
  orchestrator            register, task DAG,         
                          integration sequencing      

  A1 --- Identity &       Authentication taxonomy,    Review A2 and A4
  protocol specialist     WebAuthn/FIDO2,             protocol assumptions
                          OIDC/OAuth2, optional SAML  
                          interface                   

  A2 --- Application      Threat model,               Reviews A1, A3, A5, A6
  security / threat       trust-boundary map, abuse   changes
  modeler                 cases, attack trees,        
                          security acceptance tests   

  A3 --- Cryptography /   Key lifecycle, signatures,  Reviews A1 and A5 proof
  key-management engineer JWK/JWKS, HSM policies,     semantics
                          replay controls             

  A4 --- Backend /        Domain models, idempotent   Reviews integration
  distributed systems     workflows, transactional    contracts and
  engineer                outbox, queues, APIs        resilience

  A5 --- Cloud / network  Azure/Fly/Cloudflare/Neon   Reviews A3 and A4
  security engineer       inventory; private routing, deployment boundaries
                          egress, workload identity,  
                          IaC                         

  A6 --- iOS / watchOS    APNs routing, universal     Reviews iOS UX
  engineer                links, notification         feasibility and
                          actions, device-bound       platform limitations
                          approvals                   

  A7 --- Android engineer FCM, Android App Links,     Reviews Android UX
                          credential manager          feasibility
                          integration, notification   
                          behavior                    

  A8 --- Web / SDK        TypeScript SDK, server      Reviews developer
  integration engineer    SDKs, signed webhook        experience and backward
                          verifier, partner examples  compatibility

  A9 --- UX writing /     Consent, phishing-resistant Reviews every
  behavioral security     copy, flow maps,            customer-facing
  designer                accessibility, dark-pattern security message
                          review                      

  A10 --- Privacy /       Data minimization,          Reviews logging and
  compliance specialist   retention, audit/access     recovery
                          requests, consent and legal 
                          checkpoints                 

  A11 --- SRE /           SLIs, SLOs, alerting,       Reviews release
  observability /         emergency key rotation,     readiness
  incident response       recovery drills             

  A12 --- Adversarial     Independent abuse testing,  Cannot implement the
  security reviewer / red exploit attempts in         feature under review
  team                    staging, attack evidence    

  A13 --- QA / test       Contract, platform,         Confirms all gates with
  automation engineer     accessibility, regression   reproducible evidence
                          and end-to-end suites       

  A14 --- Product scope   Maps existing capabilities  Reviews backward
  guardian                to proposed additions;      compatibility and
                          blocks unapproved expansion rollout
  ---------------------------------------------------------------------------

## 15.1 Agent working rules

-   All agents first read the repository, existing specs, deployment
    manifests, and active API contracts. They must not assume a service
    exists because this document names it.

-   Each agent produces an artifact: design note, code diff, tests,
    threat findings, or UX copy sheet. A0 records links and commit
    identifiers in an implementation ledger.

-   Each security-sensitive change requires one author and at least one
    different specialist reviewer. Cryptography, recovery, token
    issuance, and grant authorization require A2 plus A3 review.

-   Agents must identify unknowns explicitly, distinguish current
    implementation from proposed target, and avoid silently replacing
    current production behavior.

-   No agent deploys to production autonomously. Production promotion
    requires explicit owner approval after release gates pass.

-   Agents may propose architecture simplifications, but must document
    which threat assumptions change and obtain security review before
    reducing isolation.

# 16. Required discovery phase: do not code first

A0, A4, A5, A6, A7, and A8 must independently inspect the actual Viadere
repository and reconcile results. The previously discussed
Cloudflare/Fly/Neon stack is context, not proof of the current deployed
topology.

  -----------------------------------------------------------------------
  Discovery item                      Evidence required
  ----------------------------------- -----------------------------------
  Services and dependencies           Source paths, runtime/language,
                                      process entrypoints, external APIs,
                                      data stores, secrets references

  Current auth/account model          Device identifier lifecycle,
                                      anonymous enrollment, multi-device
                                      sync, loss/recovery behavior

  Current notification pipeline       APNs/FCM integrations, push
                                      payloads, click routing,
                                      deduplication, delivery status

  Business model                      Tenant isolation, routing
                                      identifiers, consent, brand kits,
                                      Loops, messaging versus actions

  Current deployment                  Terraform/Bicep/configs, Cloudflare
                                      Workers, Fly services, Neon
                                      schemas, IAM and networking

  Security baseline                   Key storage, logging, TLS/mTLS,
                                      audit events, dependency scans, CI
                                      permissions

  SDKs                                Existing native/web/server SDKs,
                                      versioning, backward compatibility
                                      and example applications
  -----------------------------------------------------------------------

Discovery output: CURRENT_STATE.md, GAP_ANALYSIS.md, THREAT_MODEL.md,
and ADR-0001 (implementation strategy). No migration or refactor begins
until these are reviewed.

# 17. Explicit scope ledger and anti-scope-creep rules

  -------------------------------------------------------------------------
  Classification          Capabilities              Build instruction
  ----------------------- ------------------------- -----------------------
  CURRENTLY SCOPED ---    Anonymous/device-linked   Inventory and preserve
  preserve                enrollment; cross-device  behavior; do not
                          linking concept; business rewrite unless a
                          messaging; push           documented defect or
                          approvals; age/identity   dependency requires it
                          assertions; partner brand 
                          kits; customer            
                          pages/widgets; optional   
                          business Loops; tenant    
                          separation                

  NEW --- Phase A         Business-originated       Implement behind flags
  delivery                magic-link delivery,      with partner API and
                          secure notification       clear business-owned
                          handoff, OTP delivery,    verification
                          authenticator/TOTP        responsibility
                          support where             
                          appropriate, verified     
                          domain registration,      
                          delivery status and       
                          callbacks                 

  NEW --- Phase B         Viadere-owned             Separate proof of
  assurance               verification of Viadere   delivery from proof of
                          push factors, signed      authentication
                          factor assertions,        
                          policy-based grant        
                          evaluation only for       
                          Viadere-managed sign-in   
                          flows, replay/abuse       
                          controls                  

  OPTIONAL FUTURE ---     Recoverable Viadere       Architecture-ready
  Phase C                 identity, OAuth 2.0/OIDC  interfaces only; do not
                          provider, SAML identity   ship without separate
                          provider, account         approval
                          recovery, grant authority 
                          and HSM-backed token      
                          issuance                  

  EXPLICITLY OUT OF SCOPE Mandatory government ID   Do not add without
                          for all users; replacing  approved change request
                          business IdPs by default; 
                          custom cryptographic      
                          protocols; SMS-first      
                          growth strategy;          
                          arbitrary partner         
                          HTML/code in native       
                          Viadere surfaces          
  -------------------------------------------------------------------------

# 18. Security model: evidence, not trust-by-network

The secure-delivery product and an eventual identity provider are
distinct trust domains. For delivery-only requests, Viadere transmits a
business-issued credential or action safely but does not claim to
authenticate the user on the business\'s behalf. For Viadere-verified
MFA, Viadere returns a signed, transaction-bound result. For a future
IdP, a grant authority evaluates authenticated evidence before a
separately controlled token issuer signs an OIDC token or SAML
assertion.

-   A private network or tunnel is an access restriction, not proof of
    correctness. Every service request must authenticate its workload
    identity and be authorized for a narrowly scoped action.

-   An HSM prevents key extraction but does not automatically prevent a
    compromised, authorized service from requesting malicious
    signatures. Enforce issuer-side policy, grant verification, least
    privilege and auditable authorization.

-   Do not concatenate Argon2/bcrypt outputs into authentication tokens.
    Those are password hashing functions, not signing protocols. Use
    standards-based asymmetric signatures and vetted libraries.

-   Passkeys can satisfy MFA when user verification and assurance policy
    support it; do not automatically assume all passkeys satisfy all
    business assurance levels.

-   Email links and SMS codes may be lower assurance; classify them as
    delivery/verification methods with clear limitations and risk-based
    restrictions.

-   Token binding and proof of possession should be considered where
    supported; do not claim that ordinary OIDC relying parties
    automatically verify multiple signatures or DPoP.

# 19. Canonical authentication and delivery contracts

A4 and A8 must implement versioned schemas with generated clients. All
operations carry tenant_id, request_id, correlation_id, expires_at,
audience, allowed destination, and explicit purpose. Enforce server-side
tenant authorization rather than trusting client-provided tenant_id.

  -------------------------------------------------------------------------------------------------
  Operation                          Input / output                         Invariants
  ---------------------------------- -------------------------------------- -----------------------
  POST /v1/auth-deliveries           method=magic_link\|otp\|push_action;   Never return bearer
                                     business request reference; verified   secret in logs, push
                                     destination; template; TTL;            body, analytics, or
                                     idempotency key                        webhook

  GET /v1/auth-deliveries/{id}       Status: accepted, queued, delivered,   Delivery/open is not
                                     opened, expired, canceled, failed      proof of identity

  POST /v1/auth-approvals            Signed challenge metadata, intended    No approval solely from
                                     user/device, contextual action details unauthenticated push
                                                                            tap

  POST                               Authenticated device proof;            One-time decision;
  /v1/auth-approvals/{id}/decision   approve/deny; challenge binding        short TTL; risk checks;
                                                                            audit event

  POST /v1/webhooks/test             Registered endpoint; signed test event Signed delivery, retry
                                                                            limits, replay
                                                                            protection

  Future: /oidc/\*                   Standard authorization, token,         Only if separately
                                     discovery, JWKS, logout endpoints      approved; conform to
                                                                            protocol standards
  -------------------------------------------------------------------------------------------------

## 19.1 Magic-link data handling

-   Preferred: the business generates a short-lived single-use URL on
    its verified HTTPS domain; Viadere acts as transport and never logs
    or persists the bearer token in plaintext.

-   Where Viadere must temporarily store a link, encrypt it at rest with
    per-purpose access controls, minimize retention, and remove it
    promptly after use or expiration.

-   Push payload contains a non-sensitive opaque notification
    identifier, not the bearer URL. Fetch handoff data only after the
    authenticated app handles the tap.

-   On iOS, a notification tap may foreground Viadere before an external
    link opens; never promise a fully invisible handoff. On Android,
    validate task and intent behavior across versions.

-   Do not prefetch or automatically redeem a magic link. Opening a link
    can consume a one-time token; design a confirmation screen or
    server-side redemption flow where needed.

-   Verify business-controlled HTTPS host and prevent open redirects;
    partner-controlled redirect chains must be constrained by documented
    policy.

-   Support cross-device magic-link login carefully: link opening on the
    phone may not complete a browser login on a laptop unless the
    business uses a transaction-binding or polling handoff.

# 20. UX psychology, trust and wording specification

A9 owns user-visible language; A2 reviews susceptibility to phishing and
MFA fatigue; A6/A7 validate native affordances. All copy must identify
the requesting business, action, device/location context only when
reliably known, expiration and safe denial paths.

  -----------------------------------------------------------------------
  Scenario                Approved default copy   Behavior
  ----------------------- ----------------------- -----------------------
  Magic link              \[Business\] sign-in    Tap routes to verified
                          link is ready. Tap to   business URL; no
                          continue.               approval claim

  Unsolicited magic link  Didn\'t request this?   No forced action;
                          Ignore this message.    repeated requests
                                                  rate-limited

  Push MFA                Approve sign-in to      Approve and Deny; show
                          \[Business\]? Only      request details; user
                          approve if you started  verification for high
                          this.                   risk

  Approval denied         Sign-in request denied. Emit decision; do not
                          Your account has not    expose personal
                          been approved for this  information
                          attempt.                

  Expired link            This sign-in link has   No automatic repeated
                          expired. Request a new  delivery
                          link from \[Business\]. 

  New device recovery     Verify your existing    No unverified support
                          device or use an        override
                          approved recovery       
                          method.                 
  -----------------------------------------------------------------------

UX requirements: never show Approve as the visually dominant default
when context is missing; respect reduced motion, screen readers, large
text and localization; avoid panic language; use consistent business
attribution and recognizable Viadere security framing.

# 21. Cross-platform SDK ownership and compatibility matrix

  --------------------------------------------------------------------------
  Surface                 Agent                   Mandatory behaviors
  ----------------------- ----------------------- --------------------------
  iOS                     A6                      UNUserNotificationCenter
                                                  tap handling, APNs,
                                                  universal links, Face
                                                  ID/Touch ID via platform
                                                  APIs, secure local key
                                                  storage, no arbitrary
                                                  background browser launch

  watchOS                 A6                      Constrained companion
                                                  approval; require explicit
                                                  security classification;
                                                  no assertion that watchOS
                                                  is a generic FIDO2
                                                  authenticator

  Android                 A7                      FCM, verified App Links,
                                                  Credential Manager
                                                  integration as
                                                  appropriate, secure
                                                  keystore, notification
                                                  action authentication

  Web SDK                 A8                      TypeScript, PKCE for
                                                  future OIDC clients,
                                                  CSP-compatible
                                                  integration, verified
                                                  origins, typed events

  Server SDKs             A8                      At least one reference
                                                  SDK, webhook verification,
                                                  idempotency, retry
                                                  handling, secrets hygiene

  Partner test harness    A8/A13                  Mock business app, sign-in
                                                  flow simulator, replay
                                                  tests, simulated
                                                  expired/denied/error cases
  --------------------------------------------------------------------------

# 22. Network, workload identity and isolation plan

A5 must propose an Azure-target and a viable current-stack target, with
cost, isolation, operational complexity and documented service support.
Do not migrate solely because a private VNet sounds safer. The grant
authority must have no public inbound endpoint if deployed. Public
gateway and private services use independent workload identities,
least-privilege egress and service-level authorization.

-   Separate ingress, verification, MFA, grant and issuer roles
    logically; use separate deployments and identity boundaries where
    justified by threat model.

-   Prefer managed identity or workload identity federation over
    long-lived static service keys. Use mTLS when suitable, but verify
    authorization claims independently.

-   Protect administrative control plane: separate privileged
    identities, phishing-resistant admin MFA, just-in-time elevation,
    dual approval for critical key/policy changes.

-   Restrict egress by default, including metadata services and internal
    management interfaces; record and alert on denied attempts.

-   Test compromise of gateway credentials and service identity.
    Demonstrate they cannot call HSM signing operations directly or
    modify grant policy.

-   Plan private DNS, certificate rotation, regional failover, time
    synchronization, audit log immutability and incident isolation.

-   Treat cloud-provider administrators, CI/CD identities and signing
    workflows as part of the threat model; private IP addresses alone do
    not isolate those privileges.

# 23. Recovery, abuse and privacy safeguards

-   Anonymous core accounts remain usable without identity proofing.
    Distinguish device loss, device migration, account linking and
    verified-account recovery.

-   Recovery for future Viadere IdP must be a separate product design:
    multiple enrolled authenticators, optional hardware keys, recovery
    codes, delays/notifications for high-risk changes and explicit
    recovery policy.

-   Do not let email-only recovery silently downgrade a high-assurance
    account. Any downgrade must be visible and controlled by policy.

-   Rate-limit by tenant, account, destination, device and risk signals;
    avoid permanent lockout as an attacker-controlled denial-of-service
    mechanism.

-   Provide accessible abuse-reporting and opt-out controls. Protect
    against notification bombing, approval fatigue, link phishing and
    account enumeration.

-   Retain only minimum delivery metadata; keep content, authentication
    evidence and audit events in separate stores with documented
    retention periods.

-   Never collect government ID by default for basic messaging or
    delivery. Age/identity assertions require explicit consent and a
    separate assurance contract.

# 24. Implementation workstreams, dependencies and handoffs

  -----------------------------------------------------------------------------
  Stage             Owner(s)                Inputs            Exit gate
  ----------------- ----------------------- ----------------- -----------------
  0\. Discovery     A0/A4/A5/A6/A7/A8/A14   Repository and    Current-state
                                            deployment access inventory
                                                              approved

  1\. Threat        A1/A2/A3/A5/A10         Stage 0 outputs   Threat model,
  model + ADRs                                                trust boundaries,
                                                              ADRs signed by
                                                              reviewers

  2\. API + data    A4/A8/A10               Stage 1           Schema
  contracts                                                   compatibility and
                                                              privacy review

  3\. Delivery      A4/A8                   Stage 2           Magic link and
  engine                                                      OTP transport
                                                              with tests

  4\. Native        A6/A7/A9                Stage 2-3         Real-device click
  handoffs                                                    and error-path
                                                              validation

  5\. Viadere MFA   A1/A2/A3/A4             Stage 1-3         Independent
  proofs                                                      signed-evidence
                                                              tests

  6\. Cloud         A5/A11                  Stage 1-5         IaC, key
  hardening                                                   isolation, access
                                                              tests

  7\. Red-team + QA A12/A13                 Stage 3-6         Critical/high
                                                              issues resolved
                                                              or blocked

  8\. Controlled    A0/A11/A14              Stage 7           Owner-approved
  pilot                                                       feature flags and
                                                              rollback

  9\. Optional IdP  A0/A1/A2/A3             Pilot evidence +  Separate business
  discovery                                 explicit approval case and new
                                                              architecture
                                                              review
  -----------------------------------------------------------------------------

# 25. Deliverables coding agents must commit

-   /docs/architecture/CURRENT_STATE.md and GAP_ANALYSIS.md

-   /docs/architecture/THREAT_MODEL.md, TRUST_BOUNDARIES.md and
    ADR/\*.md

-   /docs/product/SCOPE_LEDGER.md, UX_COPY.md and FLOW_MATRIX.md

-   /contracts/openapi/auth-delivery-v1.yaml plus event and webhook
    schemas

-   /sdk/ (platform-specific SDKs or repository-consistent equivalents),
    sample apps and developer guides

-   /infra/ deployment definitions, least-privilege policies, network
    diagrams and secret inventory (no real secrets)

-   /tests/security/ replay, forged-proof, tenant-breakout, token-theft
    and recovery-abuse tests

-   /docs/operations/KEY_ROTATION.md, INCIDENT_RESPONSE.md, ROLLBACK.md
    and RUNBOOK.md

-   /docs/reviews/ agent review notes, sign-off matrix, findings,
    evidence and unresolved risks

# 26. Mandatory red-team acceptance scenarios

-   Compromise the public delivery gateway: cannot mint MFA success,
    alter grant policy, retrieve protected signing keys or read other
    tenants\' data.

-   Steal a webhook signing secret: cannot create an authentication
    grant or impersonate Viadere\'s HSM-backed issuer.

-   Replay a previously approved MFA assertion: rejected by challenge
    ID, audience, expiration and single-use state.

-   Swap business destination domain or follow open redirects: blocked
    before magic-link handoff.

-   Intercept a push payload: cannot redeem a bearer credential because
    the payload contains no bearer credential.

-   Compromise one business tenant: cannot send messages as another
    tenant or query another tenant\'s authentication status.

-   Compromise ordinary admin account: cannot change signing policy or
    enroll a new privileged issuer without independent authorization.

-   Use email/SMS recovery against a high-assurance account: cannot
    silently replace a passkey without required recovery controls.

-   Flood a user with MFA prompts: rate limits and user reporting
    contain fatigue attacks without creating indefinite
    attacker-controlled lockout.

-   Crash during delivery or callback: idempotency and outbox ensure no
    duplicate authorization and bounded retries.

# 27. Acceptance criteria and stop-ship conditions

Release must be blocked if any single ordinary public service can
independently issue a successful authentication grant, if a link token
appears in push payloads/logs, if a verified business domain can be
bypassed, if cross-tenant access is possible, if critical keys are
exportable to application processes, or if account recovery bypasses the
configured assurance level.

A12 must produce a signed-off adversarial findings report (agent review
record, not a third-party certification); A13 must provide reproducible
CI results; A11 must demonstrate rollback and emergency revocation; A9
must validate customer-facing copy on real devices. A0 records
unresolved findings and requests explicit owner approval before any
production rollout.

# 28. Questions requiring owner decision before coding

-   Should Viadere ever deliver SMS directly, or only integrate optional
    SMS fallback providers when a business explicitly enables them?

-   Will businesses supply their own magic-link URLs, or should Viadere
    offer an optional link-generation and redemption service?

-   Which authentication assurance levels and business verticals are in
    the first pilot?

-   Should TOTP be a Viadere-managed authenticator feature or merely a
    transport for partner-generated codes?

-   Which current cloud services are actually deployed and which
    migrations are authorized?

-   Should Viadere\'s future IdP require a recoverable account, and what
    recovery mechanisms are acceptable?

-   What retention and regional residency policies apply to
    authentication events and user-linked metadata?

# 29. Reference standards and implementation verification

Agents must verify current revisions and platform API support against
primary sources before coding: NIST SP 800-63 digital identity guidance;
W3C WebAuthn; FIDO2/CTAP; RFC 6749 and current OAuth security BCP (RFC
9700); OpenID Connect Core and Discovery; RFC 7636 PKCE; RFC 9449 DPoP;
RFC 6238 TOTP; RFC 7515 JWS; RFC 7517 JWK; RFC 7519 JWT; RFC 8725 JWT
best practices; OWASP ASVS and MASVS; Apple UserNotifications and
Universal Links documentation; Android FCM/App Links/Credential Manager
documentation.

Source-of-truth rule: when a proposal conflicts with a platform
restriction or published protocol, the responsible specialist agent must
cite the official specification, open an ADR, and amend the design
rather than silently implementing a workaround.
