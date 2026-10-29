# ADR-0001: Server on Fly.io behind Cloudflare

- **Status:** superseded by 0010 (proposed 2026-10-29; stays in force for the transitional Fly.io staging environment until 0010 is accepted and cutover completes)
- **Plan reference:** ADR-01 in `docs/IMPLEMENTATION-PLAN-v2.md` (decided by: Product owner, 2026-10-27)
- **Related:** Infra/fly/, Infra/terraform/cloudflare.tf
- **Review:** revisit at each phase gate or when a stated assumption changes

## Context

Viadere's API approves sign-ins and payments, so it must be always on, horizontally scalable and deployable without Node tooling (CLAUDE.md rule 4). The edge needs DNS, a WAF, a TLS policy and static hosting for the website. Cloudflare Containers were evaluated: they sleep after 10 minutes of inactivity, have ephemeral disk, and the Worker that fronts them has only Node-based deploy tooling today.

## Decision

Run the Vapor server as always-on Fly.io machines (minimum two in production, auto-stop off), deployed with `flyctl` from CI by image digest. Put Cloudflare in front for DNS, WAF, rate limits, TLS policy (TLS 1.3, reviewed 1.2 compatibility) and the static site. The origin is reachable only through Cloudflare (shared header, Authenticated Origin Pulls; see `Infra/fly/README.md`).

## Consequences

- Two vendors in the request path: both are in the vendor-outage runbook and RESILIENCE.md.
- The Fly proxy cannot verify client certificates, so true origin mTLS needs either an app-terminated TLS port or Cloudflare Tunnel (open gaps G-10/G-11 in KILL-SWITCHES.md).
- Deploys are by digest from CI only; staging precedes production; rollbacks redeploy a previous signed digest (migrations are forward-only).
- Single Fly region initially; multi-region is a later decision driven by RTO targets.
