# ADR-0024: OIDC provider in staging (authorization code + PKCE); SAML design only

- **Status:** proposed (2026-11-02)
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
| `token_endpoint_auth_methods_supported` | `["private_key_jwt","none"]` — confidential clients use `private_key_jwt` (client JWKS held in the authority registration); public clients (`none`) are allowed only with PKCE and only for native/SPA redirect URIs |
| `claims_parameter_supported`, `request_parameter_supported`, `request_uri_parameter_supported` | `false` |
| `acr_values_supported` | `["urn:viadere:acr:passkey","urn:viadere:acr:app"]` |
| `end_session_endpoint` | `/oidc/logout` (RP-Initiated Logout 1.0) |
| `nonce` | required on every authorization request |

Spec-vs-standard conflict recorded: the spec's crypto guidance names ES256/Ed25519; OIDC Discovery requires RS256 support. Decision: hold both an RS256 (RSA 3072) and an ES256 key in the authority; RS256 is the default for clients that do not choose. Ed25519 (`EdDSA`) is not offered: the Key Vault key types used here (EC P-256, RSA) do not include it (A3 re-checks against the current Key Vault key-type list in Stage 6).

### 3. Clients (relying parties)

Registered in the authority only (`authority_oidc_clients {client_id, tenant_id, client_type, redirect_uris[] exact, post_logout_redirect_uris[] exact, sector_identifier, jwks (private_key_jwt), id_token_signed_response_alg, default_acr_values, require_acr, status}`), created and changed only through the authority admin job (two reviewers, ADR-0019 §5). Redirect URIs: exact string match, `https` (or a claimed `https` app link / universal link for native; no custom schemes, no loopback in staging), no wildcards, no fragments. `sector_identifier` defaults to the redirect URIs' common host; multiple hosts need a `sector_identifier_uri` reviewed at registration (OIDC Core §8.1).

### 4. Authentication at the authorize endpoint

The api renders the authorize page (strict CSP, `frame-ancestors 'none'`, `__Host-` cookies, CSRF token on every form) and calls the authority to create a challenge (`purpose: oidc_login`, client, exact redirect URI, display object). The authority validates the client and redirect URI before any user interaction; an invalid client or redirect URI shows an error page and never redirects (RFC 6749 §4.1.2.1).

Methods, in the order offered (passkey bias, decision 4):

1. **Passkey** (WebAuthn L3): discoverable credential, `rpId = RP_ID` (the existing Viadere RP id, so existing account passkeys work), allowed origin `https://id.<domain>`, `userVerification: "required"`, challenge = authority nonce. The authority verifies the assertion itself (it links webauthn-swift) against a passkey in its key log (ADR-0023 §4).
2. **App approval**: if the request has `login_hint` equal to that client's tenant `subject_ref`, the authority resolves the account and the api pushes an approval to its devices; otherwise the page shows a QR code containing the `ach` (the person scans it in the Viadere app). Either way the page shows a 2-digit number and the app requires it to be typed (ADR-0022 §2); evidence is a `viadere-factor+jws` (`purpose: oidc_login`).

No SSO session is kept at the OP in staging: every authorization requires fresh evidence, so a stolen api session cannot be turned into a token; `max_age` and `prompt=login` are trivially satisfied, `prompt=none` returns `login_required`.

### 5. acr and amr (what a token may claim)

| Evidence | `acr` | `amr` (RFC 8176) | Phishing resistant? |
|---|---|---|---|
| Passkey assertion, UV, origin `https://id.<domain>` | `urn:viadere:acr:passkey` | `["user","mfa"]` plus `"hwk"` only when the credential's attestation shows a device-bound authenticator, otherwise `"swk"` (RFC 8176 has no passkey-specific value) | yes (origin-bound) |
| App approval with number match, `uv = biometric` | `urn:viadere:acr:app` | `["hwk","user","mfa"]` | **no** (relay possible, R-12) |
| App approval with number match, `uv = device_passcode` | `urn:viadere:acr:app` | `["hwk","pin","mfa"]` | no |

No NIST AAL is claimed in tokens; documentation describes the passkey path as comparable to a phishing-resistant multi-factor authenticator and the app path as a non-phishing-resistant one (NIST SP 800-63B-4 terms), without certification claims. A client with `require_acr = urn:viadere:acr:passkey` can never be satisfied by app approval (`acr_values` is enforced, not advisory).

### 6. Tokens are issued only by the isolated signer

- Authorization code: generated by the authority, 256-bit, stored as a hash with client, redirect URI, PKCE challenge, nonce, `acr`, `amr`, `auth_time`, `account_ref`, 60 s lifetime, single use; the api only carries it in the redirect.
- `POST /oidc/token` at the api forwards the form body to the authority's `oidc/token`; the authority authenticates the client (`private_key_jwt`: `iss`/`sub` = client id, `aud` = the token endpoint URL, `jti` single use, `exp` ≤ 5 min), checks PKCE and code, then signs:
  - id_token: `iss`, `sub` (pairwise: `base64url(HMAC-SHA256(OIDC_PAIRWISE_KEY, "oidc-sub\n" ‖ sector_identifier ‖ "\n" ‖ accountId))` truncated to 32 bytes), `aud` = client id, `azp`, `nonce`, `auth_time`, `acr`, `amr`, `iat`, `exp = iat + 300`, `jti`; header `typ: JWT`, `kid` thumbprint;
  - access token: RFC 9068 `at+jwt`, `aud = https://id.<domain>/oidc/userinfo`, `exp = iat + 300`, scope `openid`.
- `/oidc/userinfo` (api) verifies the access token with the authority's public keys (the api may verify, never sign) and returns `{sub}` only.
- Every issuance is recorded in `authority_grants` (jti, kid, client, acr, sub hash).

### 7. Discovery and JWKS are not served by the api

The discovery document and both JWKS documents (`/oidc/jwks.json`, `/grant/jwks.json`) are static files committed under `Site/content/id/` and deployed by the site workflow to Cloudflare Workers Static Assets with its own Cloudflare token. A compromised api cannot publish a key (THREAT_MODEL T-OIDC-2). Key rotation: the admin job prints the new public JWK; a reviewed commit publishes it at least 24 h before the authority switches to it; the old key stays published for 24 h after the switch (longer than any token lifetime). Cloudflare route and DNS changes are IaC-only with change alerts (ADR-0028 §8).

### 8. Consent and logout

- Consent: first use of a client by an account shows "{Client} wants to confirm it's you. It will receive a private identifier for this app only." The device-signed display (`display_digest`) includes the client display name, so the evidence proves what the person saw. Consent records (client, `account_ref`, granted at) are kept by the authority (class T while active, deleted on revoke).
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

- Token minting moves entirely out of the internet-facing process; JWKS integrity moves to the reviewed static publication path (AS-7 class for Cloudflare).
- App-approval tokens are explicitly labelled non-phishing-resistant.

## Reviewers required

A1 (protocol), A2 (redirect, CSRF, relay), A3 (keys, JOSE), A5 (Cloudflare routes and static publication); external review before production (spec §13).
