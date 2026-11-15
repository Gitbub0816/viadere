# ADR-0010: Swift/Vapor server on Azure Container Apps behind Cloudflare Tunnel

- **Status:** proposed (2026-10-29)
- **Plan reference:** `docs/IMPLEMENTATION-PLAN-v3.md` decisions PO-1, PO-2, PO-4; WP-B1, WP-B2 (decided by: Product owner, runtime and platform; Engineering, origin design)
- **Supersedes:** 0001 (Fly.io behind Cloudflare)
- **Related:** `docs/SECURITY-ARCHITECTURE-EXPANSION-v1.md` §9 (ADR-VDR-001), §11 Phase 2; `Infra/azure/` (new); `.github/workflows/release.yml`; ADR-0009
- **Review:** revisit at each phase gate, or if a Swift-only adapter (Key Vault, Service Bus, Entra PostgreSQL auth) becomes a recurring source of defects

## Context

The Security Architecture Expansion (§9, ADR-VDR-001) moves production off Fly.io to Azure-managed services behind Cloudflare, and names "Azure Container Apps, ASP.NET Core (.NET LTS)" for the API services. §11 Phase 2 allows either porting the Vapor endpoints to ASP.NET Core or "protocol-compatible .NET services", and warns that Swift code is not mechanically portable.

The protocol and its cryptography live in one shared Swift package, `ViadereCore`, used by the server, the iOS app and the business SDK: canonical JSON, `VIADERE-SIG-V1` request signing, `VIADERE-ENROLL-V1` and App Attest bindings, approval statements and the ES256 result JWS, the enrollment binding tag and SAS, HPKE envelopes, the key directory and `subject_ref`. The server is about 35,000 lines with roughly 680 tests on SQLite and PostgreSQL, and its Approve, Verify, Authenticator and platform gates were independently reviewed and fixed (`docs/HANDOFF.md`). A port would create a second implementation of every security-critical encoding, reset those reviews, and contradict CLAUDE.md ("Swift end to end"). Fly.io's proxy also cannot verify client certificates, so the origin is protected only by a shared header (SECURITY.md §2.74, gap G-11).

## Decision

1. **Deviation, recorded:** keep the Swift/Vapor server and `ViadereCore`. It is the "protocol-compatible service" §11 Phase 2 permits: the contract is the versioned wire formats in SECURITY.md §2 plus cross-language test vectors (WP-A1), not the implementation language. No ASP.NET Core port is planned.
2. Run it on **Azure Container Apps** in a workload-profile environment (Consumption profile), VNet-integrated, ingress **internal only**, peer-to-peer encryption on, multiple-revision mode. Workloads: `ca-viadere-api` (HTTP), `ca-viadere-worker` (queues, ADR-0014), `ca-cloudflared`; Container Apps Jobs for migrations (`migrate` under a dedicated migrator identity) and scheduled maintenance. One image, roles chosen by configuration; each workload has its own user-assigned managed identity and least-privilege role assignments. No Kubernetes/AKS.
3. **Origin authentication:** Cloudflare Tunnel (`cloudflared`, a Go binary) inside the environment is the only path from Cloudflare to the app, so there is no public origin. The `EDGE_TOKEN` header check stays enforced as a second layer and keeps gating trust in Cloudflare-set headers. Fallback while the tunnel is being proven: public ingress restricted to Cloudflare's IPv4 ranges plus `EDGE_TOKEN`. Tier E mTLS stays at Cloudflare API Shield.
4. Images are built, scanned, signed and attested as today (GHCR, cosign keyless, SLSA provenance), verified in CI, copied by digest to Azure Container Registry and pulled with a managed identity. GitHub Actions authenticates with **Entra workload-identity federation** using the Azure CLI (`az login --federated-token`); the third-party `azure/login` JavaScript action is not used (CLAUDE.md rule 4).
5. Infrastructure as code stays **OpenTofu** (1.13.2) with `hashicorp/azurerm` 5.x (5.12.0 upstream, 5.11.0 on the OpenTofu registry on 2026-10-29) and the existing Cloudflare provider.
6. Fly.io (`viadere-server-staging`) remains the transitional staging runtime until cutover (plan section 4), then is decommissioned.

## Consequences

- There is no Azure SDK for Swift: the server owns small REST clients for the managed-identity endpoint, Key Vault, Blob Storage, Service Bus and the Entra token used for PostgreSQL. They are security-relevant code: tests first, outbound SSRF guards must refuse the identity endpoint, and api-versions are pinned and tracked in CLAUDE.md.
- Cross-language vectors become mandatory; they also unblock a future Android (Kotlin) client and non-Swift business SDKs.
- The health-check exemption of the origin lock moves from Fly's `fdaa::/16` to the Container Apps infrastructure subnet (`HEALTH_PEER_NETWORKS`); `FLY_PRIVATE_IP`, `release_command` and `FLY_API_TOKEN` go away; `TRUSTED_PROXY_COUNT` must be re-measured (client, Cloudflare, cloudflared, Envoy).
- Container Apps does not verify image signatures at pull time; signature and provenance verification stays a CI gate before the image is copied to ACR.
- The tunnel connector is a new availability dependency (min 2 replicas in production) and its token a new secret (Key Vault).
- The spec's "separate identity, approval, messaging and business APIs" is met first by separate workloads and identities for HTTP and messaging; further splitting of the HTTP surface is deferred until measured need.

## Implementation notes (2026-10-30, WP-B2)

- Process roles by configuration: `ROLE=api` (HTTP; publishes the transactional outbox right after commits), `ROLE=worker` (queue consumers and the publisher; serves only `/healthz` and `/readyz`), `ROLE=migrate` (a database-only configuration with no service secret, refused for anything but `ViadereServer migrate`); unset `ROLE` keeps the single combined process for Fly and development. Scheduled jobs run `ViadereServer maintenance <maintenance|hourly|audit-export>`.
- The managed-identity client is the only code that may reach `IDENTITY_ENDPOINT`; every other outbound client goes through `OutboundDestinationGuard` (SECURITY.md §2.95). REST api-versions are pinned in code and in CLAUDE.md: identity `2019-08-01`, Key Vault keys `2025-07-01`, Blob `x-ms-version 2026-10-06`; the Service Bus runtime REST operations take no api-version.
- `HEALTH_PEER_NETWORKS` replaces the hard-coded Fly health peers (default kept until cutover); `METRICS_BIND_HOST` replaces `FLY_PRIVATE_IP` (still read on Fly). The server never reads the `Host` header, so cloudflared's `Host: ca-viadere-api` changes nothing (a test scans the sources). `TRUSTED_PROXY_COUNT` still has to be re-measured on Azure staging (owner task, needs the running environment).
