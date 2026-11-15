# Secure software development lifecycle (OPS-002)

**Status:** v1, 2026-10-27. Describes what exists in this repository and what is still manual. Owner: Engineering lead. Companion: `docs/ops/VULNERABILITY-DISCLOSURE.md`, `docs/ops/RISK-REGISTER.md`, CLAUDE.md (versioning policy).

## 1. Controls, and where they are enforced

| OPS-002 element | Control | Implementation | Status |
|---|---|---|---|
| Code review | Every change through a pull request, one reviewer minimum; two for crypto, authentication, tenant isolation, IaC and workflows (CODEOWNERS, to be added with named owners); security fixes start with a reproducing test | Branch protection on `main`: required reviews, required status checks, no force-push, signed commits recommended | Policy; **settings must be applied in GitHub** |
| Build and test | All packages and the Server on SQLite **and** PostgreSQL 18 with the database rate limiter; warnings-as-errors for packages | `.github/workflows/ci.yml` (Swift 6.4.1 container, Postgres 18 service) | Built |
| Dependency scanning | grype on the SBOM, osv-scanner on lockfiles (includes Swift `Package.resolved`), daily and per PR; Dependabot for Swift, Actions, Docker, compose, Terraform | `security.yml`, `.github/dependabot.yml` | Built |
| Secret scanning | gitleaks over full history on every push/PR/day; GitHub secret scanning and push protection to be enabled | `security.yml`; repo setting | Built / setting |
| Container scanning | trivy on the built Server image (gate on fixable HIGH/CRITICAL) before publish and on PRs | `security.yml`, `release.yml` | Built |
| SAST | semgrep (official container) with security-audit, secrets, GitHub-actions, Dockerfile and Swift rule packs, SARIF to code scanning. CodeQL is unavailable for Swift on Linux | `security.yml` | Built; Swift rule coverage is thin (R-036) |
| DAST | Authenticated scan of staging with a self-hosted scanner (OWASP ZAP in a container, a Java tool: allowed, not Node) before each release candidate; part of the pen test scope | `TODO` workflow against `api-staging` | **Gap** |
| IaC review | `tofu fmt/validate` in CI, trivy config scan, plan reviewed by a human before apply, state in an encrypted backend | `ci.yml`, `security.yml`, Infra/terraform/README.md | Built; apply is manual |
| SBOM | SPDX of the repository per scan; SPDX of the Server image per release, attested (cosign) and stored 365 days | `security.yml`, `release.yml` | Built |
| Pinned build provenance | Keyless cosign signature + SLSA provenance (`actions/attest-build-provenance`) pushed to GHCR; deploy verifies both and deploys by digest; actions pinned to commit SHAs; scanner binaries by SHA-256; images by digest | `release.yml`, `.github/scripts/install-tools.sh` | Built |
| Staged rollout | Tag -> build -> staging deploy (migrations in the release command, smoke tests) -> production behind a protected environment (2 reviewers, wait timer) -> rolling deploy with health checks | `release.yml`, `Infra/fly/fly.*.toml` | Built; environment rules must be configured |
| Threat modelling | STRIDE per component in `docs/SECURITY.md`; updated in the same PR as any trust-boundary change; spec §15 reviewed each phase gate | PR checklist | Policy |
| Pen testing (OPS-003) | Independent test before launching sensitive verification or MFA at scale; scope: app, API, console, tenant boundaries, enrollment crypto, key rotation | Phase gates in spec §17 | Planned |

## 2. Workflow hardening rules

* Workflow `permissions:` default to `contents: read`; jobs request more only where needed (`packages: write`, `id-token: write`, `attestations: write`, `security-events: write`).
* `actions/checkout` runs with `persist-credentials: false`. Secrets are used only in the deploy jobs, scoped to environments; there are no repository-wide cloud keys. Deploy tokens are per Fly app. Signing is keyless (OIDC).
* Third-party actions: none beyond GitHub's own (`checkout`, `upload-artifact`, `download-artifact`, `attest-build-provenance`, `codeql-action/upload-sarif`), every one pinned to a full commit SHA with a version comment. Dependabot updates the SHAs; review the diff.
* No `curl | sh`. Tool binaries are downloaded from the vendor's release URL and verified against a SHA-256 recorded in `install-tools.sh`; a mismatch aborts the job. Update monthly (below).
* No Node.js in our workflows or scripts. **GitHub-hosted exception:** GitHub's own JavaScript actions execute on the runner's bundled Node. That is GitHub platform infrastructure, not our code or toolchain; we use only the actions above and avoid third-party JavaScript actions where a binary or container exists.
* Pull requests from forks never receive secrets; `pull_request_target` is not used.
* `workflow_dispatch` on `release.yml` builds from the selected ref but production deploy still requires a `v*` tag identity (cosign verification in the production job).

## 3. Monthly dependency and tool refresh (CLAUDE.md rule 5)

First working day of the month (and on any security release):
1. `swift package update` in each package, verify all suites (SQLite and PostgreSQL), commit `Package.resolved`.
2. Merge Dependabot PRs for Actions (SHA bumps), Docker base images and Terraform providers; read each diff.
3. Bump the checksum-pinned tools in `.github/scripts/install-tools.sh` (`gitleaks`, `syft`, `grype`, `trivy`, `cosign`, `flyctl`, `osv-scanner`, `actionlint`), the OpenTofu version/hash in `ci.yml`, and the `semgrep` image digest in `security.yml`: check the upstream release list, download once, record `sha256sum`, run CI.
4. Update the "Current versions" table and date in CLAUDE.md.
5. Record the refresh in the risk register review log.

## 4. Repository settings required (not expressible in files)

`main` protected (reviews, status checks `CI`, `Security`; linear history; no bypass); tag protection for `v*`; environments `staging`, `production` (required reviewers, wait timer, tag rule), `site-production`, `infrastructure`; Actions allowed list limited to GitHub-owned actions; private vulnerability reporting, secret scanning, push protection, Dependabot alerts enabled; default workflow token read-only; fork PR approval required.
