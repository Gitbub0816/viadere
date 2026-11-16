# Feature decisions by the owner (2026-11-02)

Product decisions on the features merged in `7a726b6` (Verify with Viadere, installable Loops). Authentication decisions live in
`docs/product/AUTH-OWNER-DECISIONS.md`.

| # | Question | Decision |
|---|---|---|
| F-1 | Does verifying through a business's "Verify with Viadere" button connect the customer to that business? | **Yes.** Accepting a verification session connects the account (shown explicitly on the review screen before the customer continues), as implemented; disclosure keeps requiring an active relationship. |
| F-2 | Production link domain for the web button and links | **viadere.io** (owner decision 2026-11-16; the earlier `.com` placeholder does not exist and is not Viadere's). Replaced everywhere in one change (Core `LinkDomain`, server defaults, AASA and associated domains, the web buttons' allowed hosts, SDKs, Infra, Site, docs, vectors regenerated); staging moved from **cksites.dev** to `staging.viadere.io` (F-7). Only the frozen verify-button `v1` (SRI-pinned) keeps the placeholder pending a ruling on it. |
| F-3 | Install cap | **100 active installed Loops per account** (as implemented). |
| F-4 | Alerts for Loops installed without connecting | **Yes, but only the Loop's own alerts, and only if the customer allows them.** An install never subscribes the customer to the business's other alerts, offers or messages. Implemented: a per-installed-Loop "Alerts from this Loop" choice (off unless chosen; install sheet and Your Loops), SECURITY.md §2.98 "Alerts from an installed Loop". |
| F-5 | Directory listing default | **Provisional (owner said "build it all" without ruling):** a newly published Loop stays out of the public directory until an operator lists it; it is still reachable from the business page and install links. Reversible. |
| F-6 | Verify on staging | **Enabled on staging with Didit** (owner set up a Didit account, 2026-11-03). Gate reference `owner-2026-11-03-staging-verify`. Production stays off until a separate gate decision. Secrets live only in Key Vault (`didit-api-key`, `didit-webhook-secret`); the workflow id is passed to the apply as `DIDIT_WORKFLOW_ID`. |
| F-7 | Staging domain | **Subdomains of viadere.io** (owner decision 2026-11-16): `staging.viadere.io` (web, links, passkey RP), `api-staging.viadere.io` (API), `assets-staging.viadere.io` (Brand Kit assets), `site-staging.viadere.io` (marketing site); the `cksites.dev` names, including the Azure test host `viadere-api-az.cksites.dev`, are retired. Isolation from production and residual risks: SECURITY.md §2.116; owner steps: LAUNCH.md "Move staging to viadere.io". |
