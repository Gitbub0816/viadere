# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## Project context

Viadere — *A trusted way to connect* — is a verified, privacy-conscious business↔consumer connection layer: sign-in approvals (MFA), transaction authorization, messaging, orders, rewards and Wallet passes, delivered mostly through actionable notifications. Requirements live in `docs/COMPLETE-PRODUCT-SPEC.md` and `docs/MESSAGING-GATEWAY-SPEC.md`; architecture in `docs/ARCHITECTURE.md`; the threat model, residual risks and **normative wire formats** in `docs/SECURITY.md`.

The stack is Swift end to end:

| Path | Role |
|---|---|
| `Packages/ViadereCore` | Shared contract (Linux + Apple): identifiers, interaction protocol, assurance policy, signing, SMS state machine, DTOs, route catalog |
| `Packages/ViadereKit` | iOS app logic (tested on Linux) and Apple-only security code |
| `Packages/ViadereBusinessSDK` | Swift SDK for business integrations |
| `Server` | Vapor backend, business dashboard, operator console (PostgreSQL; SQLite in tests) |
| `App` | XcodeGen project: app, notification extensions, Live Activities, App Clip, watchOS |
| `Design` | Brand assets and brand guide |

Security is the top priority. Never weaken a control from `docs/SECURITY.md` to make something build or pass; never put model identifiers in commits, PRs or code.

## Versioning policy

### Context

Viadere handles authentication and payment approvals. Outdated runtimes, SDKs and libraries are the most common source of unpatched vulnerabilities, and falling several versions behind turns routine upgrades into risky migrations. The policy is therefore **stay on the current stable release of everything, continuously**, and treat any deviation as a tracked exception — not a default.

### Rules

1. **Current stable, always.** Every toolchain, runtime, SDK, framework, library, database, base image and OS used to build, test or run Viadere ("nodes": every piece of the build and runtime chain) must be on the **latest stable release**. Before adding or changing a dependency, check the upstream release list — never rely on memory or on the version already in the repo.
2. **Partners too.** Third-party services and providers (APNs, Apple Wallet/PassKit, App Attest, SMS/RCS providers, the email provider, hosting/cloud services) must be integrated on their **current API version** and current SDKs. When a partner announces a deprecation, migrating is a priority task, not a backlog item.
3. **Stable, not pre-release.** "Current" means the newest *stable* release. Betas, release candidates and alphas are not allowed unless no stable release of a required component exists — then it is an exception (see below).
4. **No Node.js and no PHP — anywhere.** Not in the product, not in the server, not in build scripts, design tooling, CI, code generation or local dev utilities. Use Swift first; Python (current stable) is acceptable for tooling and scripts. JavaScript that runs **in the browser** (e.g. the embeddable Connect button, the passkey ceremony script) is allowed only as plain, dependency-free files that need no Node-based build step.
5. **Pin precisely, upgrade promptly.** Use `from:` (up-to-next-major) requirements in `Package.swift` with the floor set to the current release, and commit `Package.resolved`. Run `swift package update` and refresh base images at least monthly and whenever a security release appears; adopt a new major version within one release cycle unless it is blocked (then record an exception).
6. **Upgrades are verified, never blind.** An upgrade is done only when every suite passes: `Packages/ViadereCore`, `Packages/ViadereKit`, `Packages/ViadereBusinessSDK`, and `Server` on **both** SQLite and PostgreSQL (`TEST_DATABASE_URL=… TEST_RATE_LIMIT_STORE=database swift test`), with no new warnings. The app is built in the current Xcode before release.
7. **Build with the newest Apple SDK.** Always build the app with the latest stable Xcode and SDK. The *minimum deployment target* (currently iOS 17 / watchOS 10) is a product decision and changes only deliberately — record it in the exceptions table.
8. **Exceptions are explicit and temporary.** Any component not on its current stable release must have a row in the table below with the reason and the condition for removing it. No silent version caps (`..<` upper bounds) without a matching row.
9. **Keep this file true.** When you upgrade or add a component, update the "Current versions" table and the date in the same commit.

### Current versions (checked 2026-10-29; rows marked 2026-10-30 re-checked then)

| Component | Required | Notes |
|---|---|---|
| Swift toolchain | 6.4.1 | `swift-tools-version` stays at the lowest version that supports the features used; the toolchain itself is current |
| Vapor | 4.122.3 | Vapor 5 is pre-release (see exceptions) |
| Fluent / postgres driver / sqlite driver | 4.13.0 / 2.14.0 / 4.9.0 | fluent-postgres-driver 2.14.0 re-checked 2026-10-30 (latest tag) |
| PostgresNIO / postgres-kit | 1.33.2 / 2.17.0 | Latest tags 2026-10-30; both still take a static password only, so Entra token auth is the server's own connection source (`Core/TokenAuthPostgres.swift`, ADR-0011) |
| swift-crypto | 5.0.3 | |
| swift-certificates / swift-asn1 / swift-nio-ssl | 1.21.1 / 1.7.3 / 2.37.5 | |
| async-http-client | 1.36.2 | |
| APNSwift | 8.0.0 | |
| swift-png / swift-jpeg | 4.5.2 / 2.1.0 | Brand Kit image ingestion (WP-2.2, ADR-0017): pure-Swift PNG decode/encode and JPEG decode, no C codec. Latest tags checked 2026-10-31 (git tags; Swift Package Index lists both building on Swift 6.4, Linux). Transitive: rarestype/h 1.0.1 |
| PostgreSQL | 18.6 | Docker Compose (`postgres:18-alpine`) and production; server suite verified on 18.6 |
| Container base | `swift:6.4.1-resolute` (build) / `ubuntu:26.04` (runtime) | Ubuntu 26.04 LTS is the newest LTS the Swift image supports; both stages on the same LTS |
| Python (tooling only) | 3.15.x | |
| MailerSend API (partner) | v1 (`/v1/email`, `/v1/sms`) | Staging and production email and SMS (US/CA); Twilio remains a supported alternative |
| Xcode / iOS SDK | Xcode 27.1 (latest stable; 27.2 is RC) | `App/project.yml` `xcodeVersion: "2710"` |
| OpenTofu | 1.13.2 | `Infra/terraform`, `Infra/azure`; CI downloads it checksum-pinned (`get.opentofu.org/tofu/api.json`) |
| hashicorp/azurerm / azure/azapi (OpenTofu providers) | 5.12.0 / 2.13.0 | `Infra/azure/versions.tf`, exact pins; both served by `registry.opentofu.org` on 2026-10-29 |
| Azure API versions (control plane) | Key Vault `2026-02-01`, Container Apps environment `2026-01-01`, Consumption budgets `2024-08-01` | Newest GA in the azapi 2.13.0 schema set; `Infra/azure`, `docs/ops/AZURE-SETUP.md` |
| Azure data-plane REST (server, WP-B2/B3) | managed identity `api-version=2019-08-01`; Key Vault keys `2025-07-01`; Blob `x-ms-version: 2026-10-06`; Service Bus runtime REST (no api-version) | Checked 2026-10-30 on Microsoft Learn: Key Vault keys default moniker `rest-keyvault-keys-2025-07-01`; Blob `2026-10-06` is the GA Storage SDKs' default, deployed in every region except two canary regions (`eastus` included). Pinned in `AzureManagedIdentity`, `AzureKeyVaultKMS`, `AzureBlobObjectStore`, `Infra/azure/kv_tool.py` |
| Azure CLI (CI deploy, owner) | ≥ 2.91.0 | Preinstalled on GitHub runners; `.github/workflows/azure.yml` fails below this floor and disables dynamic extension installs |
| Azure Database for PostgreSQL Flexible Server | 18 (Azure creates 18.6; minors applied by Azure in monthly maintenance) | `Infra/azure/postgres.tf`; CI keeps testing the community `postgres:18` image |
| cloudflared (Cloudflare Tunnel connector) | 2026.10.6, digest-pinned | `Infra/azure` variable `cloudflared_image`; Go binary image |

### Exceptions

| Component | Allowed version | Why | Remove when |
|---|---|---|---|
| Vapor | 4.x (not 5) | Vapor 5 is still beta | Vapor 5 has a stable release — plan the migration |
| webauthn-swift (revision pin) | `main` @ `030acd1e` (after 1.0.0-beta.1) | The latest tagged release (1.0.0-beta.1) caps swift-crypto below 5.0.0; only an untagged main commit allows swift-crypto 5. `Server/Package.swift` pins that exact revision | A stable 1.x (or a tag allowing swift-crypto 5) ships — switch to `from:` the same week |
| iOS / watchOS deployment target | iOS 17 / watchOS 10 | Product decision for device reach | The product owner raises the minimum |
| GitHub-hosted JavaScript actions (`actions/checkout`, `upload-artifact`, `download-artifact`, `attest-build-provenance`, `github/codeql-action/upload-sarif`) | Current stable, pinned to full commit SHAs | GitHub's own platform actions run on the Node runtime bundled with GitHub-hosted runners — GitHub infrastructure, not our code or tooling. No third-party JavaScript actions; scanners are checksum-pinned Go/Rust binaries | GitHub ships non-Node equivalents, or CI moves to a self-hosted runner without them |
| TLS 1.2 client compatibility | Minimum TLS 1.2 at Cloudflare, ECDHE + AEAD suites only; TLS 1.3 preferred | SEC-TR-001 allows modern TLS 1.2 under a reviewed compatibility policy (`docs/ops/TLS-COMPATIBILITY-POLICY.md`) | That policy's telemetry gate shows TLS 1.2 traffic can be dropped |
| Azure lean profile: public endpoints for Service Bus and Key Vault | Service Bus **Basic** (no private networking exists below Premium) with local SAS auth disabled; Key Vault **Standard** with RBAC only, purge protection and a firewall that admits only the Container Apps subnet (+ listed admin IPs) and trusted Azure services (`bypass = AzureServices`, needed for ARM key creation; network layer only, no data-plane role is granted to them). Entra tokens are the only way in | Testing budget of about USD 30/month (plan 5.8a): private endpoints cost USD 7.30/month each and Service Bus Premium USD 677/month. `Infra/azure/policy_check.py` records them as `SB-PUBLIC` / `KV-PUBLIC` and fails them in `standard` | The lean environment is replaced by the `standard` profile (private endpoints, public access disabled), before any real customer data |
| Azure lean profile: software-protected keys | Key Vault Standard keys (EC P-256, RSA 3072) instead of HSM-backed keys (ADR-0012) | Same budget; same REST API and key types, so the server code does not change | The `standard` profile (Key Vault Premium, EC-HSM / RSA-HSM) is applied; lean keys are never reused |
| Azure lean profile: PostgreSQL without HA | Burstable B1ms, no standby, 7-day PITR, locally redundant backup (standard: zone-redundant HA, 35 days, geo-redundant) | Same budget; Burstable has no HA; no production data in lean | The `standard` profile is applied |
| Azure lean profile: brand-asset storage on a public endpoint | Storage account `stvdrbrand…` with public network access on, firewall Deny by default with only the Container Apps subnet (Microsoft.Storage service endpoint), no IP rules, no bypass; shared keys disabled, Entra only, container private. `policy_check.py` records it as `ST-BRAND-PUBLIC` and fails it in `standard` | Same budget as the other lean rows (a private endpoint is USD 7.30/month); customers never reach the account (the api serves assets through the tunnel) | The `standard` profile (private endpoint, public access disabled) is applied |
| OpenTofu state storage on a public endpoint (Azure, both profiles) | Storage account with shared keys disabled, Entra auth only, versioning, soft delete, lock | GitHub-hosted runners have no fixed address or VNet path | CI runs OpenTofu from a VNet-integrated runner (then disable public access) |

## Working in this repo

- Toolchain: `export PATH=/opt/swift/usr/bin:$PATH` in the cloud container (keep `/opt/swift` on the current release).
- Shared logic belongs in `ViadereCore` — never duplicate it in the server or the app. Core changes stay additive unless both sides are updated in the same change.
- Every security fix starts with a test that reproduces the exploit path.
- The app cannot be compiled on Linux: keep platform-neutral logic in `ViadereKit` with tests, guard Apple-only code with `#if canImport(…)`, and run `swiftc -parse` on touched app files.
- UI follows the brand (`Design/brand-guide.html`): custom design-system components, charcoal/ivory/champagne, no shield imagery, stock Apple controls only when necessary.
