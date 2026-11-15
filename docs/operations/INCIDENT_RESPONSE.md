# Incident response for the authentication delivery program (spec section 25)

**Status:** v1, 2026-11-02. Extends `docs/ops/RUNBOOKS.md` (RB-0 common procedure, RB-1 to RB-n) with the authority tier. Roles: **IC**, **SEC**, **ENG**, **COMMS**, **LEGAL**
as in RB-0; staging has one human, the owner, who holds every role (R-21). Kill switches: `docs/ops/KILL-SWITCHES.md`. Rollback: `ROLLBACK.md`. Keys: `docs/ops/KEY-ROTATION.md`.

## 1. Severity (authority specific)

| SEV | Examples |
|---|---|
| 1 | Any sign of authority process/memory compromise; unmatched `sign`/`unwrap`/`decrypt` in `kv-vdr-auth`; unknown `kid` in a published JWKS; a grant or id_token accepted that the authority did not mint; key-log head fork or rollback; seal-key or signing-key exposure |
| 2 | Authority outage (link service/OIDC fail closed); reconciliation job or JWKS monitor silent for 45 min; admin-job run nobody requested; role-assignment change in `rg-viadere-<env>-auth` nobody made |
| 3 | Alert noise, single failed deploy, cap reached on the authority workspace (blind spot: treat as SEV2 until logs resume) |

## 2. First 15 minutes (authority)

1. Open the incident record; use the out-of-band channel of RB-0.
2. **Contain with the narrowest switch:** set `AUTHORITY_ENABLED=false` (ROLLBACK.md section 3 step 1); the api then refuses link service and OIDC. Push MFA and delivery-only flows continue.
3. **Preserve evidence** before changing anything else: export the authority workspace (`log-viadere-<env>-auth`: Key Vault `AuditEvent`, Container Apps console logs for the window),
   the Activity Log of `rg-viadere-<env>-auth`, the GitHub run log of any `authority-*` run in the window, and a database snapshot point (PITR time).
4. **Do not** open a shell: there is none (no exec role, no shell in the image). Evidence comes from logs and the database through the read-only `viadere_readonly`-style role of the incident.
5. Classify with the table below; run the matching procedure.

## 3. Procedures

| Trigger | Procedure |
|---|---|
| Unmatched Key Vault `sign` / `unwrap` / `decrypt` | SEV1. Flag off. Compare the operation's caller oid and time with authority replica starts and grant/statement records. Caller is not `id-viadere-authority`: the identity or vault is compromised: disable the key version, rotate per KEY-ROTATION.md section 8 (emergency rollover). Caller is the authority but no record exists: treat the process as compromised: KEY-ROTATION.md section 11 (seal key exposed) and rotate every signing key; restart only after a clean deploy of a verified digest |
| Unknown `kid` in a published set | SEV1. The JWKS monitor alerted. Re-run `authority-publish.yml` from main with the last attested inventory to overwrite; investigate who held the Cloudflare `id.` token and which workflow run (or none) published; rotate that token; check CODEOWNERS and branch protection for the bypass |
| Authority image suspicion | Verify signature and provenance (`cosign verify`, `gh attestation verify`); deploy the last good digest through `authority-deploy.yml`; residual R-11 (a signed image from a malicious merged commit) is judged by reading the commit |
| Admin job run nobody requested | SEV1/SEV2 by effect. Read the run's change file and reviewer record; `authority_audit_events` names commit and reviewers. Reverse by the reviewer-gated opposite command; lower the GitHub environment's reviewers' access if an account is suspected |
| Deploy identity misuse | Disable the federated credential on `id-gh-deploy-auth-<env>` (az portal or CLI), re-create after review. A token for it exists only inside a reviewer-gated run of `authority-deploy.yml` on main (when `oidc_subject_workflow_ref` is on) |
| Key-log fork / rollback | SEV1. Compare the database head hash with the last signed head (ROLLBACK.md section 5). Freeze grants (flag off). Do not sign a new head until a consistency check passes |
| Ordinary api compromised (AS-1) | The authority treats the api as an untrusted relay: forged grants are impossible without evidence it verifies itself. Follow RB-4 for the api; additionally check the authority's rate/lock counters, the per-account device-add caps and that the revocation route saw no unexpected worker calls |
| Subscription Owner / Entra admin misuse | AS-7 class: Activity Log and role-assignment alerts only. Rotate every credential reachable, re-verify every role assignment against `Infra/azure-authority` (a `tofu plan` must be empty) |

## 4. Notification and review

LEGAL decides notification the moment personal data exposure is plausible (RB-0 step 5). After containment: root cause in `docs/reviews/`, update THREAT_MODEL and this file, add or fix the
policy rule or alert that would have caught it. Every SEV1 gets a tabletop entry (`TABLETOP-EXERCISES.md`).

## 5. Alerts that start these procedures

Authority workspace: query alert `kv-unexpected-principal` (any Key Vault data operation by a caller other than `id-viadere-authority`; officer operations alert by design), Activity Log alerts for
role assignments and NSG changes, the reconciliation job (C-11), the JWKS monitor (`jwks-monitor.yml`) and its external dead-man heartbeat, authority workspace cap reached. Receivers: `alert_email`.
