# ADR-0030: SDKs — TypeScript web and server, Kotlin Android, Swift; packaging, zero runtime dependencies, versioning and deprecation

- **Status:** proposed (2026-11-02); revision 2 (2026-11-02): Android manifest and platform rules (A6/A7 findings 13, 14), downgrade-proof verifiers (S1-A3-08), destination signing (ADR-0031)
- **Spec reference:** §8, §8.1, §19, §21, §25 (`/sdk/`); owner decision 8; post-Stage-0 ruling **O-1** (Kotlin allowed; CLAUDE.md rule 4 updated)
- **Related:** ADR-0020 (contract, RFC 9421 signing), ADR-0022 (`ApprovalResult` v2), ADR-0023 (grant verification), ADR-0025 (webhook v2); `Packages/ViadereBusinessSDK`; `Server/Public/connect-button/v1/`
- **Review:** A8 (author of Stage 3 SDKs), A7 (Android), A6 (iOS), A3 (verifiers), A2

## Context

Only a Swift business SDK exists, unpublished (CURRENT_STATE §10). No TypeScript, no Android code on main (a Kotlin package is on an unmerged branch). CLAUDE.md rule 4 allows TypeScript for browser code and web/JavaScript SDKs and Kotlin for Android SDKs, both with zero runtime dependencies unless justified and with pinned, never-shipped dev tooling. The Connect button path `v1` is immutable.

## Decision

### 1. Repository layout

```
sdk/web/          @viadere/web      TypeScript, browser: request initiation, status UI, link-service PKCE helper, (future) OIDC PKCE client
sdk/node/         @viadere/server   TypeScript, server-side JS runtimes: typed client, RFC 9421 signing, webhook v2 verify, ApprovalResult/grant verify
sdk/android/      com.viadere:viadere-android (core) and com.viadere:viadere-android-fcm (optional)
Packages/ViadereBusinessSDK/   Swift server-side SDK (existing), extended
Packages/ViadereConnectKit/    Swift iOS SDK for partner apps (new, thin): open Viadere for enrollment/approval, receive return links
contracts/                     OpenAPI and JSON Schemas (ADR-0020 §10)
docs/protocol/vectors/         shared cross-language vectors (webhook v2, RFC 9421, ApprovalResult v2, factor JWS, grant JWT, destination validator corpus)
```

### 2. Zero runtime dependencies (how each SDK meets it)

| SDK | Runtime dependencies | Crypto | Dev tooling (never shipped) |
|---|---|---|---|
| `@viadere/web` | none | WebCrypto (`crypto.subtle`, `getRandomValues`) | TypeScript compiler, pinned exactly with a committed lockfile; browser tests reuse the existing Python browser-test approach; no bundler unless `tsc` output is insufficient (then one bundler, pinned, recorded in CLAUDE.md) |
| `@viadere/server` | none | WebCrypto / `node:crypto` webcrypto | as above; tests with the runtime's built-in test runner |
| `viadere-android` | AndroidX only where a platform API requires it, justified in its README. Credential Manager (`androidx.credentials`) is **not required for push MFA** (passkeys run in the business's app or browser); it is added only if Viadere's own account passkeys move into the app (Stage 7 scope) | Android Keystore (StrongBox when available), `java.security` | Gradle Kotlin DSL, version catalog with exact versions, Gradle wrapper with checksum |
| `viadere-android-fcm` | Firebase Messaging (required to receive FCM), justified in README; separate artifact so the core stays dependency-light | — | as above |
| `ViadereBusinessSDK` | `ViadereCore` → swift-crypto (existing) | swift-crypto | SwiftPM |
| `ViadereConnectKit` | none beyond Foundation/UIKit | none (no keys) | SwiftPM |

Android library manifests (A6/A7 finding 14): the core and FCM artifacts declare **no** `POST_NOTIFICATIONS`, `SEND_SMS` or exported components (partner apps merge manifests, so any exported library component is attack surface); `<queries>` entries live only in the app. The Viadere app targets API 30 as its minimum, uses Play Integrity as the App Attest equivalent and key attestation at enrollment (ADR-0022 §9.4).

iOS `ViadereConnectKit`: launch-only, opens Viadere through universal links, never probes with `canOpenURL` (no `LSApplicationQueriesSchemes` needed); partner apps cannot read Viadere's keychain.

Verifier APIs: `ApprovalExpectation.numberMatch` is non-optional with no default in all three languages (ADR-0022 §3); backend SDKs gain `signAuthDestination` (ADR-0031 §6); grant and OIDC verifiers refetch JWKS on an unknown `kid` at most once per 5 minutes (ADR-0024 §7.5).

Rules for all: no `localStorage`/`sessionStorage` for secrets by default (web keeps PKCE verifiers in memory or a `__Host-` cookie set by the business backend, spec §8); CSP-compatible (no `eval`, no inline styles injected; works under `script-src 'self'` with SRI); typed events; verifiers implement exactly the checks in ADR-0022 §3, ADR-0023 §5 and ADR-0025 §2 and pass every shared vector; SDKs never hold master signing secrets (spec §8).

### 3. Packaging and provenance

| SDK | Channel | Provenance |
|---|---|---|
| `@viadere/web`, `@viadere/server` | npm registry via trusted publishing (OIDC from the release workflow, no long-lived npm token); `@viadere/web` also at an immutable versioned path on the developer site (`/sdk/web/v1.2.3/viadere.js`) with published SRI hashes | npm provenance attestation + the existing SLSA attestation and SBOM |
| Android | Maven Central (`com.viadere`), PGP-signed as Central requires | GitHub build-provenance attestation, SBOM |
| Swift SDKs | SwiftPM needs the package at a repository root: CI mirrors `Packages/ViadereBusinessSDK` (and `ViadereCore` as its dependency) and `ViadereConnectKit` to read-only mirror repositories with signed semver tags | signed tags, SLSA attestation, SBOM |

Mirror repositories and npm/Maven publishing identities are separate from deploy identities (ADR-0028); publishing runs only on signed release tags with a reviewer-gated environment `sdk-release`.

### 4. Versioning and deprecation

- SDKs: Semantic Versioning 2.0; a major bump for any removed API or changed verification default; verification may only get stricter in minor versions when the change fixes a security defect (documented in the changelog).
- HTTP API: path major `/v1`, plus the existing date version (`info.version`) for additive changes; breaking changes need `/v2`.
- Deprecation: ≥ 6 months' notice for SDK APIs and HTTP endpoints; deprecated endpoints send `Deprecation` (RFC 9745) and `Sunset` (RFC 8594) headers and a `Link` to the migration guide; the console shows tenants which deprecated calls they still make. Security-forced removals (for example webhook v1 for `auth.*`, ADR-0025 M2) can be shorter with owner approval.
- Support window: latest major plus the previous major for 12 months.
- CLAUDE.md "Current versions" table gains rows for TypeScript, the Node-based dev toolchain, Kotlin, Gradle, Android Gradle Plugin and every justified runtime dependency in the stage that adds them (rules 1, 5, 9).

### 5. Partner test harness (spec §21)

`sdk/harness/` (Python, CLAUDE.md tooling default) runs a mock business against staging: magic link (same/cross device), link service, OTP, push MFA with number matching, payment step-up, replay, expired, denied, wrong number, webhook v2 verification and dedup, provider outage (simulated), and records results as Stage 7 evidence.

## Consequences

- Five SDK artifacts to maintain; shared vectors keep them consistent.
- Swift distribution needs mirror repositories (SwiftPM limitation), adding a sync job.
- The Kotlin package on the unmerged branch is reviewed against this ADR before merge (A7). The A6/A7 Stage 1 review could not perform this review (no Kotlin source on the branch); it is a tracked item (ledger L-6, owner A7, before the Android merge in Stage 4).

## Threat assumptions changed

- Business-side verification becomes the main defense for push MFA and grants; SDK verifier defects become security defects (A3 reviews verifier code; vectors gate releases).
- Supply chain: trusted publishing removes long-lived registry tokens; dev tooling stays out of shipped artifacts.

## Reviewers required

A8 (packaging, DX), A7 (Android specifics), A6 (iOS kit), A3 (verifier conformance), A2.
