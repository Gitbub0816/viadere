# Apple Wallet passes

Status of Apple Wallet support against the product spec (`COMPLETE-PRODUCT-SPEC.md` §10 loyalty, rewards and Wallet; §11 events,
appointments, travel). The normative wire formats and threat rows are in `SECURITY.md` (Wallet rows, §2.13 and §2.14); owner
setup is in `ops/AZURE-SETUP.md` §7.1. Apple documentation was checked on **2026-10-31**: "Adding a Web Service to Update
Passes" and its five endpoint pages, `Pass` (incl. `relevantDates`, `sharingProhibited`), `PassFieldContent`, `Pass.Barcodes`,
"Creating the source for a pass" (localization, UTF-16), and `PKPassLibrary.pass(withPassTypeIdentifier:serialNumber:)` /
the `com.apple.developer.pass-type-identifiers` entitlement.

## Gap analysis

"Before" is the state of `claude/inspiring-cannon-t5hxfw` at `2dd6df6`; "Now" is this change.

| Area | Spec | Before | Now |
|---|---|---|---|
| Pass types | Loyalty cards, coupons, event tickets, reservations "and similar" | `storeCard` (loyalty), `coupon` (reward), `eventTicket`, `boardingPass` and `generic` from ticket interactions | Same kinds. `generic` is the reservation/appointment style (label "RESERVATION"). `boardingPass` stays: §11 names travel and boarding, and a `ticket` interaction with `ticketType` "boarding_pass" maps to it; no airline-specific fields (gate, seat class) beyond venue/seat/start. |
| Signing | Server-only | Done: SHA-1 manifest, detached CMS with Pass Type ID cert + WWDR, validated at boot | Unchanged (existing `PassSigner` / `PASS_*` config). |
| PassKit web service | Apple's protocol | Done: register/unregister (`201`/`200`/`401`), serials since tag (`200`/`204`), latest pass with `If-Modified-Since` (`304`), `log`; per-pass `authenticationToken` hashed at rest, constant-time compare, one `401` for every failure, failures rate-limited per IP+serial, IP limits on the whole service | Re-verified against Apple's pages (paths, headers, codes). Added tests: one pass's token cannot register for or fetch another; updates reach only devices registered for that pass. |
| Update pushes | When a reward, ticket or reservation changes | Points changes, coupon redemption/revocation | Also business schedule/venue changes, code rotation, check-in, cancelled tickets and disconnects. Durable outbox, APNs pass push (production), dead devices dropped. |
| Not a marketing channel | §10 | No free-text update path existed | Updates accept only venue, seat, start time and code rotation, six per pass per day; only those three fields carry a `changeMessage`; no other text can be changed on a pass. Tested. |
| Redemption / validation | One-tap claim/redeem, business validation, fraud prevention | Pass QR was the **serial number** (the PassKit lookup key) and no business endpoint read it; coupons were redeemed only with the 2-minute app code | QR is a **signed presentation code** (`VQ1.`, HMAC, 128-bit tag). `POST /v1/business/wallet/scan`: coupon → redeemed (same single-use reservation and compare-and-swap as codes, auto-claim, webhook, metering) and the pass is voided; ticket/reservation → checked in once, inside its validity window; loyalty card → member + balance. One `404` for forged/altered/foreign/rotated/test-key/disconnected; per-business budget. Code rotation kills copied QRs. No NFC/VAS (needs an Apple NFC entitlement). |
| Voiding / expiry | | Revoked/redeemed coupons voided; `expirationDate` from reward/ticket | Plus business void endpoint, disconnect voids the business's passes, cancelled ticket voids its pass; a void pass has no barcode and its code is refused at once. |
| Relevance | Without leaking data | `relevantDate` for tickets | Plus iOS 18 `relevantDates` interval. **No `locations`**: businesses have no published places yet; adding them would put store coordinates in the pass (public data, but a decision for later). |
| Localization | | English labels only | `en`, `es`, `fr` `pass.strings` (UTF-16, keys = English text so unlisted languages read English). Business text untouched. |
| Accessibility | | Implicit | Pass `description` per kind, date fields with date/time styles, number style for points; app rows and pass card have combined VoiceOver labels; QR has a spoken label. |
| Privacy of content | Data minimization | Points, titles, venue/seat | Asserted by test: only allowed top-level keys, no holder name, member reference, consumer/relationship id, `userInfo`, `nfc`, `locations`; `sharingProhibited`. The business never receives the `.pkpass`, the holder's code or whether the pass is in Wallet. |
| Business API | Issue/update/void for a connected customer, live keys, capability checks | Only `issueWalletPass` on reward creation (silently skipped for test keys) | `POST/GET /v1/business/wallet/passes`, `PATCH /v1/business/wallet/passes/{id}`, `POST …/{id}/void`, `POST /v1/business/wallet/scan`; scope `wallet:write` (baseline, Tier M), capability `message.send`, test keys refused (`403`) for anything that touches a pass, tenant-isolated (`404`), audited. In `docs/openapi.yaml` and the Business SDK (`issueWalletPass`, `listWalletPasses`, `updateWalletPass`, `voidWalletPass`, `scanWalletPass`). |
| App: add / already added | PKAddPassButton, PKPassLibrary | Add flow done; **"In Wallet" could never show**: `PKPassLibrary.pass(…)` returns nil without the pass-type entitlement, which was deliberately not requested | Entitlement `$(TeamIdentifierPrefix)$(VIADERE_PASS_TYPE_IDENTIFIER)` added (owner portal step). |
| App: pass list and detail | Benefits/Rewards | Wallet button on rewards, loyalty and activity rows only | Benefits → **Wallet passes**: current and used/ended passes, detail with the brand pass card, Apple's add button / "In Wallet", and the signed code as a QR (hidden once used or void). `WalletPassesViewModel` / `WalletPassPresentation` in ViadereKit, tested. |
| "Beta" label | Open owner decision | None | Configurable and **on** by default: server `WALLET_BETA_LABEL` (back of every pass), app `VIADERE_WALLET_BETA_LABEL` (badge on Wallet screens). |
| Brand kits on passes | Later task | Viadere colors and a champagne icon | Unchanged on purpose (a later task applies brand kits). |

## Remaining gaps and decisions

* **Owner decision: Beta label.** Keep or drop (two switches above). Default: keep.
* **Owner decision: location relevance.** Needs business places (and whether showing a pass near a store is wanted).
* **Owner decision: one Pass Type ID or one per environment.** A single ID is simplest; separate IDs keep staging passes from looking like production ones.
* **Not done: NFC (VAS) passes** (Apple entitlement and terminals), **brand-kit styling**, a dashboard UI for passes (API only), per-business pass images, an expiry metric for the pass certificate.
* **Residual risks** are listed in `SECURITY.md` (static QR between rotations; pepper rotation invalidates codes and tokens; voiding reaches the device only on refresh).

## Owner actions

1. Apple Developer portal: create the Pass Type ID (`pass.com.viadere.wallet`), its certificate (CSR from your machine), download the WWDR G4 intermediate; enable Wallet on the `com.viadere.app` App ID with that Pass Type ID and regenerate profiles. Details: `ops/AZURE-SETUP.md` §7.1.
2. Key Vault: `pass-certificate`, `pass-private-key`, `pass-wwdr-certificate` (mapped from `PASS_CERTIFICATE_PEM`, `PASS_PRIVATE_KEY_PEM`, `PASS_WWDR_CERTIFICATE_PEM`) and `PASS_TYPE_IDENTIFIER` in `app_env`; on Fly the same three as secrets.
3. Business API keys that should issue or scan passes need the `wallet:write` scope (new; existing keys do not have it).
4. Verify on a device (needs the real certificate; not testable on Linux): add, "In Wallet", update push, scan.
