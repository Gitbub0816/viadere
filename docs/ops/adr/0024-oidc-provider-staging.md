# ADR-0024: OIDC provider in staging (authorization code + PKCE); SAML design only

- **Status:** proposed (2026-11-02); revision 3 (2026-11-02): authority challenge only after a user action, edge limits and signing bulkhead (S2-A2-6); R-17 narrowed to single-session binding, passkey origin allow-list (S2-A2-2); `amr` for unattested keys (S2-A2-11 item 3); key-inventory channel and monitor scope (S1-A3-R06 item 5, -R08); revision 2 (2026-11-02): confidential clients only, issuer-only assertion audience, RFC 9207 `iss`, residual R-17 (S1-A2-5); JWKS publication as protected as the signing key (S1-A3-01, -16); `sub` binding and encoding (S1-A3-04, -14); authority-built display (S1-A3-06); consent copy and revoke (S1-A9-7); `login_hint` exposure (S1-A10-2)
- **Implementation (Stage 6 application, 2026-11-03):** app-approval method, code + PKCE, `private_key_jwt`, authority-signed id_token (RS256 default, ES256 per client) and RFC 9068 access token, userinfo, RP-initiated logout, flags off by default and refused in production (SECURITY §2.103). Added 2026-11-03: the passkey method verified by the authority, consent records with the app's list and revoke (§8), the QR universal link and the `login_hint` push (ledger S6-01 to S6-03). Not yet: static discovery/JWKS publication and the conformance run (ledger S6-10).
- **Spec reference:** §5.3, §8.1, §13 (protocol validation), §14 Phase D, §19 (`/oidc/*`), §24 stage 9; owner decision 6; OpenID Connect Core 1.0, Discovery 1.0, RP-Initiated Logout 1.0, RFC 6749, RFC 7636, RFC 9700, RFC 9068, RFC 8176, RFC 8725, W3C WebAuthn Level 3
- **Related:** ADR-0019, ADR-0022 §6, ADR-0023, ADR-0028; ADR-0004 (static site on Workers Static Assets)
- **Review:** A1 (author role), A2, A3; external review before any production IdP (spec §13)

## Context

Decision 6: build OIDC in staging behind a staging-only flag; SAML stays design only; production needs explicit owner approval after release gates. Spec §5.3: the public gateway cannot mint ID tokens; grant authority and signer are separated from internet-facing endpoints. Spec §24 puts the IdP after pilot evidence; decision 6 brings a staging build forward — this ADR keeps it behind its own flag and outside the pilot's release gate.

## Decision

### 1. Flag and hosts

- `OIDC_PROVIDER_ENABLED` (api) and `AUTHORITY_OIDC_ENABLED` (authority), default off; **both refuse to start with the flag on when `ENVIRONMENT=production`** until a new ADR and owner approval change that line.
- Issuer `https://id.<staging domain>` (exact string, no trailing slash). Cloudflare routes on that host: `/.well-known/openid-configuration` and `/oidc/jwks.json` → Workers Static Assets (§7); `/oidc/authorize`, `/oidc/token`, `/oidc/userinfo`, `/oidc/logout` → tunnel → api.

### 2. Supported protocol surface (everything else refused)

| Item | Value |
|---|---|
| `response_types_supported` | `["code"]` (no implicit, no hybrid) |
| `response_modes_supported` | `["query"]` |
| `grant_types_supported` | `["authorization_code"]` (no refresh tokens in staging, no ROPC, no client credentials, no device code) |
| `code_challenge_methods_supported` | `["S256"]`; PKCE **required for every client** (RFC 9700 §2.1.1); `plain` refused |
| `scopes_supported` | `["openid"]` (only the pairwise `sub` is released; no profile, email or phone exist for anonymous accounts) |
| `subject_types_supported` | `["pairwise"]` |
| `id_token_signing_alg_values_supported` | `["RS256","ES256"]` — RS256 is included because OpenID Connect Discovery 1.0 requires it; the client registration's `id_token_signed_response_alg` (default `RS256` per OIDC Registration) selects the key |
| `token_endpoint_auth_methods_supported` | `["private_key_jwt"]` — **confidential clients only** (client JWKS held in the authority registration). Public clients (`none`) are refused until a separate A2 and A3 review (S1-A2-5) |
| `token_endpoint_auth_signing_alg_values_supported` | `["ES256","RS256","PS256"]`; the algorithm is resolved from the registered client JWK, never from the assertion header alone |
| `authorization_response_iss_parameter_supported` | `true`: `iss` is returned in every authorization response, success and error (RFC 9207, mix-up defense) |
| `claims_parameter_supported`, `request_parameter_supported`, `request_uri_parameter_supported` | `false` |
| `acr_values_supported` | `["urn:viadere:acr:passkey","urn:viadere:acr:app"]` |
| `end_session_endpoint` | `/oidc/logout` (RP-Initiated Logout 1.0) |
| `nonce` | required on every authorization request |

Spec-vs-standard conflict recorded: the spec's crypto guidance names ES256/Ed25519; OIDC Discovery requires RS256 support. Decision: hold both an RS256 (RSA 3072) and an ES256 key in the authority; RS256 is the default for clients that do not choose. Ed25519 (`EdDSA`) is not offered: the Key Vault key types used here (EC P-256, RSA) do not include it (A3 re-checks against the current Key Vault key-type list in Stage 6).

### 3. Clients (relying parties)

Registered in the authority only (`authority_oidc_clients {client_id ("ocl_…"), tenant_id, display_name, client_type: "confidential", redirect_uris[] exact, post_logout_redirect_uris[] exact, sector_identifier, jwks (private_key_jwt), id_token_signed_response_alg, default_acr_values, require_acr, status}`), created and changed only through the authority admin job (ADR-0019 §5). Link-client ids use `lcl_` and OIDC client ids `ocl_`; registration enforces the prefixes so the namespaces are disjoint (S1-A3-15). `display_name` is reviewed at registration against the tenant's verified name and is always shown together with the redirect host (S1-A9-7). Redirect URIs: exact string match, `https` (or a claimed `https` app link / universal link for native; no custom schemes, no loopback in staging), no wildcards, no fragments. `sector_identifier` is the lowercase A-label host of the redirect URIs; LF and non-A-label characters are refused. Multiple hosts need a `sector_identifier_uri` reviewed at registration, and the reviewer confirms common ownership of every host, because one sector lets those relying parties correlate a person (OIDC Core §8.1, S1-A10-11).

### 4. Authentication at the authorize endpoint

The api renders the authorize page (strict CSP, `frame-ancestors 'none'`, `__Host-` cookies, CSRF token on every form). Loading the page validates the client and the exact redirect URI through the authority's neutral `GET oidc/clients/{client_id}/check?redirect_uri=…` (a database lookup that returns only `{valid, display_name}`, both already public on the RP's own sign-in page; no Key Vault call; an invalid client or redirect URI shows an error page and never redirects, RFC 6749 §4.1.2.1) but **creates no authority challenge** (S2-A2-6). The challenge (`purpose: oidc_login`, client id, exact redirect URI; **no display object**: the authority builds and signs the display itself, ADR-0033 §1, and re-validates client and redirect URI) is created only when the person **chooses a method** on the page (a CSRF-protected `POST`), behind two fail-closed api-edge limits, `oidc-authorize-ip` (per client IP: 10 per minute, 60 per hour) and `oidc-authorize-client` (per OIDC client, plan-dependent), plus Cloudflare rate rules on the `id.` host. These are new namespaces of the `DatabaseRateLimitStore` fail-closed list; they belong to the OIDC routes (Stage 9 flag) and do not change ADR-0020 §8. At the authority, challenge signing runs in its own per-tenant bulkhead (ADR-0033 §2): a flood degrades only that tenant's OIDC challenges, never heads, tenant records, grants or other tenants. Over budget the page shows OIDC-11 ("Too many sign-in attempts. Wait a minute and try again."), never a lockout of other flows. Tests ST-OIDC-17 (unauthenticated authorize loads create no authority challenge) and ST-AUTH-24.

**Residual R-17 (S1-A2-5), narrowed in revision 3 (S2-A2-2).** The authorize endpoint and the WebAuthn origin `https://id.<domain>` are served by the api. A compromised api can therefore bind a victim's *genuine*, *in-progress* login to the **attacker's** RP session: it creates the authority challenge with the attacker's `code_challenge` and `state`, runs the victim's real passkey or app ceremony against it, and delivers the code to the attacker's browser, so the RP logs the attacker in as the victim **for that one session**. Passkey origin binding does not help because the origin is the compromised component. R-17 covers **only** this single-session binding. A **lasting** key addition through the same origin is excluded by design: a passkey assertion is accepted only for `oidc_login` and the reduce-only `recovery_cancel`, never for `device_added`, `passkey_added`, `recovery_codes_set` or `enrollment_confirmed` (ADR-0023 §3a), so no passkey ceremony the person performs here can be redirected into an attacker key in the log. R-17 needs the victim to be actively signing in, and it is a **named exception to the §13 formal metric** for the staging OP. Owner A2. Removal condition: before any production IdP, the browser-facing authorization endpoint and passkey origin run in a component outside the ordinary tier with its own identity and deploy path, plus the external review of spec §13 (condition C-10).

Methods, in the order offered (passkey bias, decision 4):

1. **Passkey** (WebAuthn L3): discoverable credential, `rpId = RP_ID` (the existing Viadere RP id, so existing account passkeys work), allowed origin `https://id.<domain>`, `userVerification: "required"`, challenge = authority nonce. The authority verifies the assertion itself (it links webauthn-swift) against a grant-capable passkey in its key log (ADR-0023 §4), and checks `clientDataJSON.origin` against the `oidc_login` allow-list (exactly `https://id.<domain>`; ADR-0023 §3a).
2. **App approval**: if the request has `login_hint` equal to that client's tenant `subject_ref`, the authority resolves the account and the api pushes an approval to its devices; these pushes count against the ADR-0022 §5 fatigue counters per (client, account) and are alert-limited like every other prompt (S1-A2-5, -6). Otherwise the page shows a QR code containing a Viadere universal link with the `ach`, which the Viadere app handles with its confirm screen; the system camera opening it lands on the same in-app screen, never a web page (A6/A7 matrix note F13). Either way the page shows a 2-digit number and the app requires it to be typed (ADR-0022 §2); the phone screen is "Sign in to {Client}?" with the row "Website {redirect host}" from the signed challenge (UX_COPY OIDC-08); evidence is a `viadere-factor+jws` (`purpose: oidc_login`).
3. **`login_hint` exposure (S1-A10-2).** `login_hint` (a pairwise per-tenant identifier) travels in the authorize query string, which reaches browser history and could reach edge logs. Controls in staging: `login_hint` is optional; the `id.` host's Cloudflare Logpush and analytics exclude query strings; the api logs only the allow-listed fields (ADR-0020 §9). Carrying it in a signed request object or PAR is a later phase (deferred, owner A1, Stage 9).

No SSO session is kept at the OP in staging: every authorization requires fresh evidence, so a stolen api session cannot be turned into a token; `max_age` and `prompt=login` are trivially satisfied, `prompt=none` returns `login_required`.

### 5. acr and amr (what a token may claim)

| Evidence | `acr` | `amr` (RFC 8176) | Phishing resistant? |
|---|---|---|---|
| Passkey assertion, UV, origin `https://id.<domain>` | `urn:viadere:acr:passkey` | `["user","mfa"]` plus `"hwk"` only when the credential's attestation shows a device-bound authenticator, otherwise `"swk"` (RFC 8176 has no passkey-specific value) | yes (origin-bound) |
| App approval with number match, `uv = biometric` | `urn:viadere:acr:app` | `["hwk","user","mfa"]` | **no** (relay possible, R-12) |
| App approval with number match, `uv = user_presence` (biometric or passcode, modality unknown) | `urn:viadere:acr:app` | `["hwk","mfa"]` (no `pin` claim; S1-A3-21) | no |
| App approval as above, key **not** attested as hardware-bound | `urn:viadere:acr:app` | `swk` in place of `hwk`: `["swk","user","mfa"]` or `["swk","mfa"]` (S2-A2-11 item 3, S1-A3-R06 item 3; ADR-0023 §5) | no |

No NIST AAL is claimed in tokens; documentation describes the passkey path as comparable to a phishing-resistant multi-factor authenticator and the app path as a non-phishing-resistant one (NIST SP 800-63B-4 terms), without certification claims. A client with `require_acr = urn:viadere:acr:passkey` can never be satisfied by app approval (`acr_values` is enforced, not advisory).

### 6. Tokens are issued only by the isolated signer

- Authorization code: generated by the authority, 256-bit, stored as a hash with client, redirect URI, PKCE challenge, nonce, `acr`, `amr`, `auth_time`, `account_ref`, 60 s lifetime, single use; the api only carries it in the redirect.
- `POST /oidc/token` at the api forwards the form body to the authority's `oidc/token`; the authority authenticates the client (`private_key_jwt`: `iss`/`sub` = client id; **`aud` a single string exactly equal to the issuer identifier**; arrays and the token endpoint URL are refused with `invalid_client` (S1-A2-5, S1-A3-15); algorithm resolved from the registered JWK; `iat` required; `jti` single use until `exp` + 60 s; `exp` ≤ 5 min), checks PKCE and code, then signs:
  - id_token: `iss`, `sub`, `aud` = client id, `azp`, `nonce`, `auth_time`, `acr`, `amr`, `iat`, `exp = iat + 300`, `jti`; header `typ: JWT`, `kid` thumbprint. `sub = base64url(HMAC-SHA256(OIDC_PAIRWISE_KEY, "oidc-sub\n" ‖ sector_host_lowercase_alabel ‖ "\n" ‖ accountId_lowercase_uuid))`, **no truncation** (43 characters), with a vector (S1-A3-14). `accountId` is used only after the binding check against the `account_ref` of the passkey or key that produced the evidence (ADR-0032 §2); `OIDC_PAIRWISE_KEY` serves only this derivation (ADR-0032 §4);
  - access token: RFC 9068 `at+jwt`, `aud = https://id.<domain>/oidc/userinfo`, `exp = iat + 300`, scope `openid`.
- `/oidc/userinfo` (api) verifies the access token with the authority's public keys (the api may verify, never sign) and returns `{sub}` only.
- Every issuance is recorded in `authority_grants` (jti, kid, client, acr, sub hash).

### 7. Discovery and JWKS are not served by the api

Publishing a key is equivalent to holding the signing key (S1-A3-01), so publication gets the same protection as an authority deploy:

1. The discovery document and both JWKS documents (`/oidc/jwks.json`, `/grant/jwks.json`) are static files under `Site/content/id/`, deployed **only** by a dedicated workflow `authority-publish.yml` in GitHub environment `authority-publish-<env>` with the same required reviewers as authority deploys, deployment branch `main` only, and its own Cloudflare token scoped to the `id.` host's static assets only. The general site token loses every `id.` scope; the site workflow refuses to deploy `Site/content/id/**`.
2. CODEOWNERS covers `Site/content/id/**` and branch protection requires code-owner review on it (ADR-0028 §6).
3. A JWK is admitted to a published set only if its RFC 7638 thumbprint equals a public key that the authority admin job printed from `kv-vdr-auth` in an **attested** key-inventory artifact (GitHub artifact attestation by `authority-admin.yml` on `main`); `authority-publish.yml` verifies the attestation and compares thumbprints; a hand-pasted value fails. **Channel (S1-A3-R06 item 5; revised 2026-11-03, ledger S6-06):** no log is read. The admin job holds no Key Vault role, so the inventory is a reviewed change file (public JWKs with `name/version` read by the crypto-officer group through PIM; for `recovery-seal`, the public half and `kid` of an `authority_seal_keys` row) recorded by `key-inventory-record`; the serving authority verifies each entry against Key Vault at exactly that version (or against the seal-key row); `authority-admin.yml` waits for the exit status of `key-inventory-check`, which succeeds only when every entry is verified, then builds the inventory from the change file, re-derives each thumbprint, and attests it. `id-gh-authority-admin-<env>` holds no Log Analytics role. The same inventory supplies the app-pinned constants for `device-statement-signing` and `recovery-seal` (ADR-0033 §3, ADR-0034 §5).
4. A scheduled monitor that holds no Azure or Cloudflare write credential (a read-only GitHub scheduled workflow, separate from both tiers' deploy identities) fetches the live documents every 15 minutes and alerts the owner on any `kid` not in the attested inventory or any change outside an `authority-publish` run. It also compares `issuer`, `jwks_uri` and the `alg` lists of the discovery document with the committed copy, alerts when a document is unreachable, and has a dead-man check that pages when the monitor itself has not reported for 45 minutes (S1-A3-R08, adopted).
5. Content and caching (S1-A3-16): every JWK carries `kid`, `use: "sig"` and `alg` (`RS256` or `ES256`); the grant JWKS and the OIDC JWKS never share a key; served with `Cache-Control: max-age=3600` or less, and the edge cache is purged on publication; SDK verifiers refetch on an unknown `kid` at most once per 5 minutes; maximum RP exposure after an emergency rollover is the cache TTL plus the token lifetime (≤ 3600 s + 300 s), documented.
6. Key rotation: the admin job prints the new public JWK into the attested inventory; `authority-publish` publishes it at least 24 h before the authority switches to it (explicit version pin, ADR-0028 §2); the old key stays published for 24 h after the switch. Cloudflare route and DNS changes are IaC-only with change alerts (ADR-0028 §8).

A compromised api cannot publish a key, and neither can a compromised site credential or a single merged PR (THREAT_MODEL T-OIDC-2, T-CP-8).

### 8. Consent and logout

- Consent: first use of a client by an account shows UX_COPY OIDC-05 ("{Client} wants to confirm it's you. It gets an ID that only {Client} can use. It doesn't get your name, email or phone number, and other apps can't match it. You'll return to {redirect host}."). The display is authority-built and signed (ADR-0033), so the device-signed `display_digest` proves what the person saw. Consent records (client, `account_ref`, granted at, last used) are kept by the authority (class T while active, deleted on revoke). The app lists them under Settings → "Apps you've signed in to with Viadere" with "Stop {Client} recognizing me" (revokes consent through a reduce-only `revocations` call; UX_COPY OIDC-09, OIDC-10).
- Logout: `end_session_endpoint` accepts `id_token_hint` (verified), `post_logout_redirect_uri` (exact registered), `state`; since no OP session exists, logout only redirects. Back-channel and front-channel logout are not offered in staging.

### 9. SAML 2.0: design only

Not built (decision 6). If approved later: IdP-initiated SSO refused; SP-initiated with signed `AuthnRequest` required; assertions signed by a dedicated authority key `saml-signing` (RSA 3072, RSA-SHA256) in `kv-vdr-auth`, never by the api; metadata published statically like JWKS; `NameID` format persistent pairwise per SP; audience restriction and `InResponseTo` enforced; one-time assertion ids replay-cached; XML signature handled by a vetted library with signature-wrapping tests (OASIS SAML 2.0 core and profiles). Requires its own ADR, library choice and CLAUDE.md row.

### 10. Conformance

Stage 9 (or the staging build) runs the OpenID Foundation conformance suite for the "Basic OP" profile with PKCE against staging and records results; DPoP (RFC 9449) and PAR are considered and deferred (no RP in the pilot needs sender-constrained tokens).

## Consequences

- RPs integrate with standard OIDC libraries; no Viadere SDK is required (spec §8.1).
- No refresh tokens and no SSO means more prompts; acceptable for staging.
- A new library dependency is not needed for OIDC itself (JOSE handled by swift-crypto and the existing JWS code); webauthn-swift is linked into the authority.

## Threat assumptions changed

- Token minting moves entirely out of the internet-facing process; JWKS integrity moves to a reviewer-gated publication path tied to an attested key inventory (AS-7 class for Cloudflare account compromise).
- Under AS-1 a genuine login can be bound to an attacker's RP session (R-17, named exception to the §13 metric until the authorize front end leaves the ordinary tier).
- App-approval tokens are explicitly labelled non-phishing-resistant.

## Reviewers required

A1 (protocol), A2 (redirect, CSRF, relay), A3 (keys, JOSE), A5 (Cloudflare routes and static publication); external review before production (spec §13).
