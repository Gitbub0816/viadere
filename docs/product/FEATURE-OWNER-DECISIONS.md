# Feature decisions by the owner (2026-11-02)

Product decisions on the features merged in `7a726b6` (Verify with Viadere, installable Loops). Authentication decisions live in
`docs/product/AUTH-OWNER-DECISIONS.md`.

| # | Question | Decision |
|---|---|---|
| F-1 | Does verifying through a business's "Verify with Viadere" button connect the customer to that business? | **Yes.** Accepting a verification session connects the account (shown explicitly on the review screen before the customer continues), as implemented; disclosure keeps requiring an active relationship. |
| F-2 | Production link domain for the web button and links | **Not viadere.com.** The owner intends to buy **viadere.io**; until then only subdomains of **cksites.dev** are owned (staging). Keep accepting the staging host; when the production domain is bought, replace `viadere.com` with it everywhere (Core `LinkDomain`, the web button's allowed hosts, AASA, docs) in one change. |
| F-3 | Install cap | **100 active installed Loops per account** (as implemented). |
| F-4 | Alerts for Loops installed without connecting | **Yes, but only the Loop's own alerts, and only if the customer allows them.** An install never subscribes the customer to the business's other alerts, offers or messages. (Today install-only instances do not appear in Alerts at all — gap to close.) |
| F-5 | Directory listing default | **Provisional (owner said "build it all" without ruling):** a newly published Loop stays out of the public directory until an operator lists it; it is still reachable from the business page and install links. Reversible. |
