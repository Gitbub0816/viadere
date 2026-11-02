# ADR-0019: Authentication delivery implementation strategy and the private authority

- **Status:** proposed (2026-11-02); revision 2 (2026-11-02): worker app role (S1-A2-8), reviewer separation stated honestly (S1-A2-9), new authority tables (ADR-0031, 0032, 0033)
- **Spec reference:** `docs/product/AUTH-DELIVERY-SPEC-v2.md` §5, §9, §16 ("ADR-0001 implementation strategy"), §18, §22; owner decisions 4, 5, 6, 11, 12
- **Related:** ADR-0010 (Container Apps), ADR-0011 (PostgreSQL), ADR-0012 (Key Vault), ADR-0014 (outbox and queues), ADR-0020 to ADR-0030; `docs/architecture/TRUST_BOUNDARIES.md`, `THREAT_MODEL.md`
- **Numbering note:** the spec calls this "ADR-0001". The repository already has ADR-0001 to ADR-0018 in `docs/ops/adr/`; this series continues there (0019 onward) instead of starting a second series under `docs/architecture/ADR/`.
- **Review:** A2 and A3 (grant authorization, key custody), A5 (network and identity), A4 (layering), A0 (consistency)

## Context

The server is one Swift/Vapor codebase with roles `api`, `worker`, `migrate` selected by `ROLE` (`Server/Sources/ViadereServer/main.swift`, `ViadereServerKit/App.swift`). The internet-facing api holds every service secret and four signing keys (F-01). The spec requires that one compromised ordinary workload cannot issue grants (§4.3), that the grant authority has no public inbound endpoint and least-privilege egress (§9.2, §22), and that no shared CI credential can deploy gateway and signer (§9.2). Decision 5 builds the authority in staging as a private Container App with its own managed identity and Key Vault key. Stage 0 found no service-to-service authentication and a shared subnet for api and cloudflared (F-13).

Options considered for the authority:

1. A new `ROLE=authority` of the existing `ViadereServer` executable, same image.
2. A separate executable target in the `Server` package, separate image, same repository.
3. A separate repository and language.

## Decision

1. **New services are layered onto the existing server as modules, not rewrites.** Delivery API, delivery orchestrator, consumer handoff routes and the OIDC front end live in `ViadereServerKit` (folders `AuthDelivery/`, `OIDC/`), run in `ROLE=api` and `ROLE=worker`, reuse the outbox (ADR-0014), rate limiter, audit chain, field encryption and idempotency. Shared wire types (requests, states, JWS claim sets, verification rules) live in `ViadereCore` (`AuthDelivery/`, `Authority/`) so the app, the SDKs and both server executables use one definition (CLAUDE.md "shared logic belongs in ViadereCore").
2. **The authority is option 2: a separate executable `ViadereAuthority`** in the `Server` package (`Server/Sources/ViadereAuthority/main.swift`, logic in a new library target `ViadereAuthorityKit`), depending on `ViadereCore`, Vapor (HTTP), Fluent + PostgreSQL driver, swift-crypto, async-http-client and webauthn-swift only. It does **not** link `ViadereServerKit`, APNs, email, SMS, Wallet, Didit or Service Bus code. It is built into its own image `viadere-authority` by the release workflow and deployed by its own workflow and identity (ADR-0028 §6). Reasons: smaller attack surface, no provider credentials can be configured, a separate image digest is what the separate deploy approval pins. Option 1 was rejected because one image would carry every adapter and make "same artifact deploys both" the default; option 3 because it duplicates verification code that must stay byte-identical with Core.
3. **Placement (staging, lean).** `ca-viadere-authority` in a separate internal Container Apps environment `cae-viadere-<env>-auth` on a new subnet `snet-auth` (`10.40.4.0/27`), resource group `rg-viadere-<env>-auth`, identity `id-viadere-authority`, vault `kv-vdr-auth-<env>`, database `viadere_authority`. No public ingress, no tunnel route, no Cloudflare hostname. Details in TRUST_BOUNDARIES §9. A separate subscription is the `standard` profile decision (spec §9.2 "when justified"); lean records the same-subscription exception (ADR-0028 §7).
4. **Service-to-service authentication and evidence.**
   1. Transport: HTTPS to the authority's internal FQDN (`allow_insecure_connections = false` on its ingress). mTLS is not required in lean (spec §9.1 "use mTLS when suitable"); it adds no authorization because any compromised ordinary workload would hold the client certificate too.
   2. Access control: an Entra access token for the authority's Entra application (`api://viadere-authority-<env>`). App role `Authority.Evidence.Submit` is assigned only to `id-viadere-api`; the worker gets only `Authority.Revocations`, which reaches nothing but `POST revocations` (S1-A2-8). The authority validates issuer, audience, `exp`/`nbf`, signature (Entra JWKS), the role per route, and that `oid` is on its configured allow-list. A token is necessary, never sufficient.
   3. Authorization: the request must carry evidence the authority can verify **without trusting the api**: a device `viadere-factor+jws` or a WebAuthn assertion, signed over an authority-issued challenge nonce, audience `urn:viadere:authority:<env>`, `exp − iat ≤ 120 s`, verified against the authority's own key log, consumed once (ADR-0023). The api is a relay; it is not asked to sign anything, because a signature by a compromised api proves nothing.
   4. Egress: NSG deny-by-default with named service tags, plus the app-level outbound guard in allow-list mode (TRUST_BOUNDARIES §9).
   5. Data: separate database `viadere_authority` (lean: same Flexible Server, separate role, no CONNECT for api roles; standard: decided in Stage 6 between a separate server and a separate subscription). Tables: `authority_accounts`, `authority_challenges`, `authority_replay`, `authority_keylog_entries`, `authority_keylog_heads`, `authority_keylog_imports`, `authority_recovery_verifiers`, `authority_tenant_keys`, `authority_link_clients`, `authority_link_codes`, `authority_oidc_clients`, `authority_oidc_codes`, `authority_oidc_consents`, `authority_grants`, `authority_policy_versions`, `authority_audit_events`. Key log, grants and audit are append-only (trigger), same pattern as `audit_events`.
5. **Administration path.** Changes that increase authority (lower a policy floor, register or change an OIDC client, link client or tenant destination key or host, import pre-migration keys, rotate a signing key's active version, restore grant capability after a legacy recovery) are commands of `ViadereAuthority admin <command> --change-file <path>`, run only as `job-viadere-authority-admin`. The job is started by the workflow `authority-admin.yml` in GitHub environment `authority-admin-<env>` with required reviewers and "Prevent self-review"; the change file is a reviewed commit on protected `main` under CODEOWNERS; the job writes an authority audit event naming the commit and reviewers. **Staging has one human reviewer (the owner), so this path is a single owner approval in staging** (residual R-21, ADR-0028 §6.6); production requires two human reviewers, neither the requester. There is no web console for the authority. Raise-only and reduce-only operations are exposed to the api (TRUST_BOUNDARIES §4.3).
6. **Feature flags.** `AUTH_DELIVERY_ENABLED`, `AUTH_LINK_SERVICE_ENABLED`, `AUTH_NUMBER_MATCHING_REQUIRED` (default on when approvals are on), `OIDC_PROVIDER_ENABLED` (staging only, refused in production), all default off; listed in the `Infra/azure` env allow-list and `ServerConfig`. The authority has its own `AUTHORITY_ENABLED`; when off, the api fails closed for link service and OIDC.
7. **What stays unchanged.** Existing interaction, Approve v2, link sessions, messaging, Loops, Brand Kits, profiles, household and recovery flows keep their routes and wire formats. New work is additive in Core (CLAUDE.md "Core changes stay additive").

## Consequences

- Two images, two deploy identities, two GitHub environments; a release that changes shared Core code needs two deploys. Compatibility rule: the authority accepts the previous and current versions of every Core wire type it verifies.
- The authority needs Vapor and Fluent like the api; no new dependency is added for it except linking webauthn-swift (already an exception row in CLAUDE.md).
- Cost (lean, to be confirmed by A5): workload-profile environment with only the Consumption profile has no fixed environment charge; the internal load balancer and ACR Basic registry add a small monthly amount; the authority runs `min_replicas = 1` at the smallest size.
- An Entra application registration and app role are needed (AzureAD provider or bootstrap; A5 decides in Stage 6). Until it exists, `AUTHORITY_ENABLED` stays off.
- Business-verified push MFA (ADR-0022) and delivery-only flows (ADR-0020) do not depend on the authority, so an authority outage does not stop them.

## Threat assumptions changed

- Before: the api is trusted for every security decision. After: the api is an untrusted relay for Viadere-asserted results; THREAT_MODEL AS-1 applies to it.
- New trusted component: the authority. Its compromise is a separate, severe class (spec §4.4); it is not contained by this design.
- The VNet path from `snet-cae` to the authority is reachable by cloudflared as well as the api; the Entra role check compensates (F-13).

## Reviewers required

A2 (security) and A3 (crypto) — grant authorization and evidence model; A5 — network, identities, cost; A4 — module layering and outbox reuse; A0 — consistency with Stage 0.
