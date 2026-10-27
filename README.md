# viadere

**A trusted way to connect.** Viadere connects consumers once to verified businesses, then lets them handle sign-in approvals, payment authorizations, messages, orders, rewards and passes mostly from actionable notifications — rarely opening the app.

This repository is Swift end to end: an iOS 17 app, a Vapor backend, and shared packages.

| Path | What it is |
|---|---|
| [`docs/COMPLETE-PRODUCT-SPEC.md`](docs/COMPLETE-PRODUCT-SPEC.md), [`docs/MESSAGING-GATEWAY-SPEC.md`](docs/MESSAGING-GATEWAY-SPEC.md) | Product requirements (phases P0–P5) |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Components and data flows |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model, residual risks, and the normative wire formats |
| [`docs/openapi.yaml`](docs/openapi.yaml), [`docs/BUSINESS-INTEGRATION.md`](docs/BUSINESS-INTEGRATION.md) | Business API and integration guide |
| [`Packages/ViadereCore`](Packages/ViadereCore) | Shared contract: identifiers and business codes, typed interaction protocol, assurance policy, request/decision/webhook signing, SMS state machine, DTOs and the route catalog (Linux + Apple) |
| [`Packages/ViadereKit`](Packages/ViadereKit) | iOS app logic: API client, Secure Enclave keys, Keychain, pinning, passkeys, approvals, view models (logic tested on Linux) |
| [`Packages/ViadereBusinessSDK`](Packages/ViadereBusinessSDK) | Swift SDK for business integrations |
| [`Server`](Server) | Vapor 4 backend, business dashboard and operator console — see [`Server/README.md`](Server/README.md) |
| [`App`](App) | XcodeGen project: app, notification extensions, Live Activities, App Clip, watchOS — see [`App/README.md`](App/README.md) |
| [`Design`](Design) | Brand mark, lockups, app icons, palette and brand guide (`Design/brand-guide.html`) |

## Running

```sh
# Shared packages and backend (Swift 6.x; swift-crypto must stay < 5.0)
(cd Packages/ViadereCore && swift test)
(cd Packages/ViadereKit && swift test)
(cd Packages/ViadereBusinessSDK && swift test)
(cd Server && swift test)                              # SQLite in memory
(cd Server && TEST_DATABASE_URL=postgres://… swift test) # same suite on PostgreSQL
(cd Server && docker compose up)                       # local Postgres + server; see Server/README.md for env

# iOS app (macOS + Xcode)
brew install xcodegen
cd App && xcodegen && open Viadere.xcodeproj
```

Before any release, see the configuration checklists in [`App/README.md`](App/README.md) (team ID, certificate pins, App Attest) and [`Server/README.md`](Server/README.md) (secrets, `ENVIRONMENT`, audit chain key, pass certificates).
