# ADR-0009: Infrastructure as code with OpenTofu and `fly.toml`; CI on GitHub Actions with Go/Swift/Python tools

- **Status:** accepted
- **Plan reference:** ADR-09 in `docs/IMPLEMENTATION-PLAN-v2.md` (decided by: Engineering)
- **Related:** Infra/, .github/
- **Review:** revisit at each phase gate or when a stated assumption changes

## Context

Manual console configuration of the edge, KMS and database cannot be reviewed or reproduced, and CLAUDE.md forbids Node.js in build and CI tooling.

## Decision

Manage Cloudflare, Google Cloud KMS and Neon with OpenTofu (Terraform-compatible) and Fly with `fly.toml`. CI runs on GitHub Actions: SHA-pinned actions, checksum-pinned Go/Rust release binaries for scanners (gitleaks, syft, grype, trivy, osv-scanner, cosign, flyctl), semgrep from its official container for SAST, keyless cosign signing and SLSA provenance for the Server image. GitHub's own JavaScript actions (checkout, upload-artifact, attest, upload-sarif) are an accepted platform exception.

## Consequences

- State holds sensitive values (Neon role passwords): the backend must be encrypted, access-logged and restricted.
- Provider and tool versions must be bumped monthly (Dependabot covers Actions, Swift, Docker and Terraform; the checksum-pinned tool table in `.github/scripts/install-tools.sh` is a manual monthly step).
- CodeQL does not analyze Swift on Linux runners, so semgrep is the SAST tool; coverage for Swift rules is thinner than for other languages and is tracked as a risk (RISK-REGISTER.md).
