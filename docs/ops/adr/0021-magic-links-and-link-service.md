# ADR-0021: Magic links — business-supplied URLs on verified domains and the optional Viadere link service

- **Status:** proposed (2026-11-02); revision 2 (2026-11-02): §3.4 replaced by ADR-0031 (A2 R-07 ruling), §4 and §5 amended for S1-A2-4, A6/A7 findings 4, 12, 13 and A9 findings
- **Spec reference:** §5.1, §6.4, §7, §7.1, §19.1, §20, §26 (destination swap, push interception); owner decision 2
- **Related:** ADR-0019, ADR-0020, ADR-0023 (factor evidence and grants), ADR-0026; `Platform/DomainControl.swift`; SECURITY §2.7, §2.8; finding F-08
- **Review:** A2, A1 (link service as an assertion), A6/A7 (handoff feasibility), A9 (copy)

## Context

Decision 2 asks for both: business-supplied single-use URLs on verified domains (default) and an optional Viadere link generation and redemption service. Domain control exists for onboarding only (`DomainControl.swift`: DNS TXT or `/.well-known/viadere-verification.txt`) and is not tied to any destination policy. The existing `/h/` handoff redeems as soon as the universal link is handled (F-08). iOS cannot open an arbitrary website silently from a push (spec §7.1); the app comes to the foreground first.

## Decision

### 1. Two modes

| Mode | Who creates and verifies the bearer token | What Viadere asserts | Authority |
|---|---|---|---|
| `link_mode: "business"` (default) | the business, on its verified host | nothing (delivery only) | not involved |
| `link_mode: "viadere"` (link service) | the device generates a one-time code; the authority verifies and signs the result | "the person holding a key in account A approved opening this link for tenant T" (`viadere-grant+jwt`) | required |

### 2. Domain verification and destination policy

1. A tenant's `business_domains` row gains `purposes` (set; `auth_links` new) and an exact `allowed_hosts` list (each an A-label host equal to the verified domain or a subdomain of it). Adding a host or the `auth_links` purpose needs a fresh dashboard passkey step-up (existing re-authentication) by an Owner or Security Admin.
2. Verification is re-checked every 7 days (existing DNS/well-known method); a failed re-check suspends `auth_links` for that domain (deliveries to it are refused with `422 destination_not_allowed`) and notifies Owners.
3. Phishing-domain defenses (spec App. B): adding a host notifies every Owner by console notice and email; a tenant verified less than 30 days ago gets a 24 h hold before the host is usable; hosts whose registrable domain is on Viadere's reserved list (look-alikes of `viadere` and of other verified tenants' registrable domains by the existing confusable skeleton, SECURITY §2.9) are refused and flagged to operators.

### 3. URL validation (`AuthDestinationValidator`, in Core so the app and server share it)

1. Parsed with a strict RFC 3986 parser (the existing strict link parser style): scheme exactly `https`; no userinfo; no port, or `:443` which is removed; host lowercase A-labels only (any U-label, mixed script or non-ASCII byte refused); no IP literal; no trailing dot; no empty labels; no backslash anywhere; total length ≤ 2048; path and query must be valid percent-encoded ASCII; fragment allowed.
2. Host must be **exactly** one of the tenant's `allowed_hosts` for purpose `auth_links`.
3. Open-redirect check: every query parameter value, raw and after one percent-decode, that starts with `http:`, `https:`, `//`, `\\` or `/\` must itself be a URL whose host passes rule 2; otherwise refused. Viadere never fetches or follows the URL.
4. **Gateway compromise (AS-1).** A compromised api can rewrite a stored URL before handoff. Revision 1's narrowed reading of §27 was **rejected by A2** and is withdrawn. Control (normative, ADR-0031): every business-mode URL carries a business-signed `viadere-destination+jws` committing to the URL's SHA-256 and host; the device verifies it against an authority-signed tenant destination-key record before Continue is enabled, and checks the URL bytes against the digest before opening. Business mode fails closed without a signature in the pilot (`AUTH_DESTINATION_SIGNATURE_REQUIRED=true`). Residual R-07' (login-CSRF with a genuine signed URL for the attacker's own account) replaces R-07.
5. **How the host is shown (S1-A9-11).** The link screen shows the full host with the registrable domain in strong type, never truncated (it wraps); a host containing any `xn--` label is shown in its A-label form with "This address uses unusual characters"; the VoiceOver label of Continue is "Continue to {host}". Business name and host come from the authority tenant record and the signed statement (ADR-0031 §4), never from api display fields.

### 4. Handoff: confirm before open (fixes F-08 for all new handoffs)

1. Push carries only the delivery id (ADR-0020 §6). The NSE fetches the display object: verified business name, purpose, destination host, expiry. It never sees the URL.
2. Tapping the notification opens the app on the **link screen** (UX_COPY S-LINK-01): business, "Sign-in link", destination host, expiry time ("Expires at {time}", no live countdown), buttons **This wasn't me** and **Continue** (one component, equal weight, This wasn't me first in layout and reading order; UX_COPY §0 rule 5). Nothing is fetched that consumes the token. Continue stays disabled until the ADR-0031 §4 checks pass.
3. **Continue** calls `POST /v1/auth-deliveries/{id}/open` (device-signed) and receives the URL once; after the digest check (ADR-0031 §4) the app opens it with the system API (`UIApplication.open` on iOS without `universalLinksOnly`, so a business universal link opens the business app; Android `startActivity(Intent(ACTION_VIEW))` **from the foreground link activity after the tap**, never from a receiver or service). No in-app web view, no Viadere page in between, no referrer. On Android the system opens the business app only if that app is verified for the host (`assetlinks.json`, business guidance) or the user chose it; otherwise the default browser (A6/A7 finding 13a).
4. The existing `/h/` handoff gets the same confirm step before `redeemHandoff` (F-08 fix, Stage 4) until it is retired by ADR-0027; the "This link is no longer used" screen for `/l/` and `/h/` never calls `redeemHandoff` (test ST-ML-14), and `AppModel.open(url:)` never redeems on handling.
5. **Notification actions** (A6/A7 findings 1, 4; S1-A9-4): category `viadere.auth.link` has **Open** (iOS `.foreground`, which makes iOS unlock first) and **This wasn't me** (iOS no `.authenticationRequired`, no `.foreground`; signed reduce-only deny with `report: true`). Android: Open = `PendingIntent.getActivity(…, FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT)` to an `exported="false"` activity with an explicit component and only the opaque delivery id as extra (no URL); This wasn't me = immutable `getBroadcast` to an `exported="false"` receiver that signs in `goAsync()` or expedited WorkManager and starts no activity; neither action sets `setAuthenticationRequired(true)`. A CI lint check refuses `FLAG_MUTABLE` and exported components in the app and SDK manifests.
6. Business guidance (developer docs + harness check): the redemption page sends `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, loads no third-party assets, consumes the token only on an explicit POST from the page (not on GET, so link scanners and previews cannot burn it), and binds the token to the initiating browser session (spec §6.4).

### 5. Viadere link service (`link_mode: "viadere"`)

1. **Link clients.** A tenant that uses the service has one or more link clients held **in the authority** (`authority_link_clients {client_id ("lcl_…"), tenant_id, display_name, return_urls[] exact, status}`), registered and changed only through the authority admin job (ADR-0019 §5) after the return URLs pass §3 validation against the tenant's verified hosts and the reviewer checks `display_name`. The api can suspend a client (reduce-only) but cannot add one or a URL.
2. **Create.** Business sends `destination {link_mode: "viadere", link_client_id, return_url, code_challenge, code_challenge_method: "S256"}`; `code_challenge` is the S256 hash of a `code_verifier` the business keeps in the initiating browser's session (RFC 7636 pattern). The api asks the authority for a challenge (`purpose: link_open`) passing only references; the authority refuses unless `return_url` equals a registered URL of that client byte for byte, **builds the display itself** (ADR-0033 §1) and returns a signed `viadere-challenge+jws` that the api relays unchanged.
3. **Approve on device.** The app verifies the challenge statement (ADR-0033 §2) and renders exactly its display. The link screen offers **Continue on this phone** and **I'm signing in on another device**. On this phone: the device generates `link_code` (32 random bytes, base64url), signs a `viadere-factor+jws` with its `approvalUserPresence` key (user presence required; biometric when policy says) containing `code_hash = base64url(SHA-256(link_code))` and the exact `return_url` from the statement, and posts it via the api. The authority verifies (ADR-0023 §3, including the byte-for-byte `return_url` check) and records `{ach, code_hash, client_id, code_challenge, expires_at = now + 120 s}` in `authority_link_codes`. Only after the authority's acceptance does the device open **the `return_url` it signed**, with the code in the **fragment** (`#vdr_code=<link_code>`), so the code is not sent to the business server on the first request, not written to its access logs and not in a `Referer`; the business page's own script posts it to its backend (A6/A7 finding 12a). If AS-1 fakes the acceptance, no code hash is registered and the code is useless.
4. **Redeem.** The business backend calls `POST /v1/business/auth-links/redeem {code, code_verifier}`; the authority checks the hash, that the client's tenant equals the **authenticated caller's** tenant as recorded in the client record (the api-passed tenant is compared for equality only and never used as a source), `S256(code_verifier) == code_challenge`, single use (CAS), expiry, then returns a `viadere-grant+jwt` (ADR-0023 §5) whose `aud` and `tid` come from the client record. The delivery becomes `completed`.
5. The authority computes `sub` itself (the tenant's `subject_ref` for the account that owns the signing key, after the account binding check of ADR-0032 §2), so a mismatched `subject_ref` or `accountId` in the request cannot redirect the grant to another customer (THREAT_MODEL T-GW-4).

### 6. Cross-device

- **Business mode:** Viadere does not transfer sessions. The link screen's copy is "Continue on this device". If the business detects that the opening browser is not the initiating one, it must either refuse ("Open this link on the device where you started") or run its own pairing, preferably push MFA with number matching (ADR-0022). Viadere's harness tests both behaviors.
- **Link service:** "I'm signing in on another device" asks the person to type the number shown on the initiating screen (the business displays the `match_code` returned in the create response; 2 digits, ADR-0022 §2). The evidence carries `match`; no code is opened on the phone; the business's initiating session redeems by polling `GET /v1/business/auth-deliveries/{id}` and then calling redeem with `{code: null, ach_ref, code_verifier}` — the authority accepts a code-less redemption only for evidence that carried a correct `match`.

## Consequences

- Fixes F-08's pattern: no new handoff consumes anything before an explicit tap.
- The link service makes Viadere an asserting party for that flow; it inherits every authority control and its outage behavior (fails closed).
- Businesses using the link service need a link-client registration through a reviewed admin change; that is slower onboarding by design.
- Domain verification gains a maintenance job (weekly re-check).

## Threat assumptions changed

- Link prefetch, previews and push interception can no longer consume or reveal a token (T-ML-4, T-DO-1).
- The api becomes untrusted for link-service results (AS-1 contained) and for business-mode URL integrity (ADR-0031; residual R-07' only).

## Reviewers required

A2 (destination policy, R-07 decision), A1 and A3 (link-service grant semantics), A6 and A7 (handoff on iOS and Android), A9 (link screen copy).
