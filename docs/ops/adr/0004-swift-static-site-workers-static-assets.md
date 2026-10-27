# ADR-0004: Swift static site on Cloudflare Workers Static Assets

- **Status:** accepted
- **Plan reference:** ADR-04 in `docs/IMPLEMENTATION-PLAN-v2.md` (decided by: Product owner)
- **Related:** Site/, .github/workflows/site.yml, Infra/terraform/cloudflare.tf
- **Review:** revisit at each phase gate or when a stated assumption changes

## Context

The marketing and developer site must be isolated from the API (Boundary D) and must not require a Node toolchain. Cloudflare's usual deploy tool (wrangler) is Node-based.

## Decision

Generate the site with a Swift static generator and upload it to Cloudflare Workers Static Assets through the REST direct-upload API using a Python standard-library uploader (`Site/deploy/upload.py`). Terraform binds the hostnames but does not own the script content.

## Consequences

- The uploader must track the Cloudflare upload API; a breaking change there blocks site deploys but not the API.
- The site has no server-side code path to the API database or secrets.
- Site changes ship through the `site.yml` workflow with its own protected environment and a Cloudflare token scoped to Workers Scripts only.
