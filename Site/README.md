# Viadere site (WP7)

The public marketing website and developer portal: a small in-house **Swift static site generator** (Foundation only,
no Node.js, no PHP, no third-party packages). Output is plain HTML and one CSS file with no scripts, no cookies and no
third-party requests, deployed to Cloudflare Workers Static Assets (ADR-04).

```
Site/
  Package.swift              viadere-site (executable) + SiteKit (library) + tests
  site.yaml                  base URL, allowed link hosts, security.txt values (placeholders)
  content/                   Markdown + front matter, one file per page (URL = path)
  static/assets/site.css     hand-written CSS (tokens match Design/README.md, light + dark)
  static/assets/fonts/       Outfit woff2 (OFL) from Design/tools/fonts
  static/assets/media/       mark reveal animation (Design/motion) and its final frame, rendered in Chromium
  static/brand/              brand SVGs copied from Design/svg (a test fails if they drift)
  legal-lock.json            optional: hashes of legal versions that took effect
  deploy/upload.py           Cloudflare direct-upload deploy (Python stdlib)
  dist/                      build output (gitignored)
```

## Build

```bash
export PATH=/opt/swift/usr/bin:$PATH
cd Site
swift build && swift test && swift run viadere-site          # same as: viadere-site build --out dist
swift run viadere-site lint --dist dist                       # what CI runs after build
```

`build` loads `content/`, generates the developer reference from `../docs/openapi.yaml`, runs the integrity lint,
renders `dist/`, then checks the output (no external resources, scripts or inline styles; every internal link and
anchor resolves) and exits non-zero on any problem. `lint --dist DIR` re-runs the content lint (integrity rules, legal
metadata, legal lock) and the link and output checks against an existing build. Other commands: `check-links` and
`update-legal-lock`. Flags: `--root`, `--out`/`--dist`, `--repo`.

## Preview

```bash
python3 -m http.server -d Site/dist 8000     # then open http://localhost:8000
```

`_headers` is applied only by Cloudflare, so the response headers are not visible in this preview (a CSP `<meta>` tag
is also in every page).

## Deploy

```bash
export CLOUDFLARE_API_TOKEN=...   # Workers Scripts: Edit
export CLOUDFLARE_ACCOUNT_ID=...
python3 Site/deploy/upload.py --dist Site/dist --script viadere-site --dry-run   # hash and list, no network
python3 Site/deploy/upload.py --dist Site/dist --script viadere-site
```

The script does the three documented steps (assets-upload-session with a manifest, bucket uploads with `base64=true`,
then `PUT .../workers/scripts/{name}` with `assets.jwt`) and never prints the token or the JWTs. `_headers` is sent in
`assets.config`. Request shapes and sources are in the script's docstring; see "Unverified". Before launch, replace the
placeholders in `site.yaml` (`security_contact`, `security_expires`): the build warns while `security.txt` has them.

## Add content

Create `content/<section>/<page>.md` (or `<dir>/index.md`); the URL follows the path. Front matter:

| Key | Use |
|---|---|
| `title`, `description` | `description` is the lede and meta description |
| `order`, `nav_title` | sidebar order and label |
| `status: live\|beta\|planned` | **required** on `/products/<name>/` pages; renders the badge |
| `disclosures: [key]` | the page must contain the spec section 11.5 text verbatim (`mfa`, `business_verification`, `identity_verification`, `age_verification`, `encryption`, `device_custody`) |
| `claims:` | approved exceptions to the lint: `phrase`, `feature`, `evidence` (repo path), `approved_by` |
| `pricing: true` | the page must disclose per-message, verification, carrier, provider and overage fees |
| `sms_fallback: true` | force the SMS rule (it is also detected from the text) |
| `layout: home`, `noindex`, `path`, `wide`, `toc` | layout switches |

Markdown subset: headings (`{#id}` sets an explicit id), lists (`- [ ]` task items), tables, fenced code, blockquotes,
links, bold/italic, `{badge:beta}`, `{icon:name}` (line icons from `Icons.swift`), link classes (`[Go](/x/){.btn .secondary}`,
`{.more}`), and containers (`::: card` ... `:::`, nestable: `grid grid-3`, `steps`, `callout`, `disclosure`, `band`, `wrap`,
`feature` / `feature flip` with `feature-copy` and `feature-art`, `section-head`, `kicker`, `statement`, `devsplit`,
`prose`). `::: section [classes]` renders a full-width band with a centred wrap (`alt`, `dark`, `cta`, `tight`). Fenced
code takes `lang [title]` (```` ```swift Approve.swift ````) and is rendered as a code window with a dependency-free
highlighter (Swift, JSON, shell, Python, HTTP). Raw HTML is escaped.

Generated blocks: `{{ generate: product-cards }}`, `api-index`, `api-tag <Tag>`, `webhook-events`, `api-errors`,
`schemas`, `info-section <OpenAPI info heading>`, `status-components`, `status-notices`, `legal-index`, and
`mockup <name>` (CSS-drawn product illustrations from `Showcase.swift`: `signin`, `payment`, `conversation`, `wallet`,
`verify`, `authenticator`, `lineup`, `contrast`, `flow`, `privacy`, `signed-result`, `stage`, `pillars`, `channels`,
`curl`). Every device mockup uses fictional businesses and is captioned as an illustration; its text is linted with the
page. `{{api-version}}` inserts the contract version. API tag pages (`/developers/api/<tag>/`) come from `openapi.yaml`.

Layouts: `layout: home` (the dark hero with `static/assets/media/viadere-mark-reveal.webp`, screen-blended on black,
and `viadere-mark-final.webp` for `prefers-reduced-motion`), `layout: marketing` (page hero, section sub-navigation,
full-width body built from `::: section` bands; front matter `headline` with `*emphasis*`, `hero_art: <mockup>`,
`actions`, `subnav: false`), and the default docs layout with sidebar and table of contents.

## Marketing integrity lint (spec 10.2, acceptance 10)

| Rule | Fails when |
|---|---|
| `banned-claim` | "unhackable", "anonymous", "zero knowledge", "government certified", "bank compliant", "HIPAA compliant" or "end-to-end encrypted" appears (any hyphen or case variant) outside a negating sentence, without an approved `claims:` entry |
| `unearned-attestation` | SOC 2, ISO 27001, PCI DSS, FedRAMP, HITRUST, "certified", "independently audited", GDPR/CCPA/SOX "compliant" appear the same way |
| `claim-evidence` | a `claims:` entry lacks phrase, feature, evidence or approver, or cites a missing file (unused claims warn) |
| `product-status` | a product page has no status, or a non-live product says "available now" and similar |
| `sms-not-e2ee` | a page mentioning SMS fallback does not state that SMS is not end-to-end encrypted |
| `fee-disclosure`, `disclosure-verbatim` | see front matter above |
| `legal-metadata`, `legal-version`, `legal-draft`, `legal-lock` | see below |

A negating sentence has "not", "never", "no", "n't", "without" or "nor" before the phrase, so "Ordinary SMS is not
end-to-end encrypted" passes. Everything a page renders is linted, including text generated from `openapi.yaml`.

## Legal pages (acceptance 11)

Each document is `content/legal/<slug>/index.md` (the current version) with `version`, `effective_date` (empty until
approved), `owner`, `counsel_review: pending|in-review|approved` and `change_summary`. All 15 are drafts with bracketed
counsel placeholders. The generator renders a DRAFT banner, a metadata table and a version history, and marks drafts
`noindex`.

- A document cannot have an `effective_date` unless `counsel_review: approved`.
- Every version keeps a stable URL `/legal/<slug>/versions/<version>/`; the current version gets one automatically.
- New version: copy `index.md` to `versions/<old-version>.md`, add `superseded_on`, then edit `index.md` with the higher
  `version`. The archived file takes over the old URL.
- After approval, run `swift run viadere-site update-legal-lock` and review `legal-lock.json`. From then on the build
  fails if a version that took effect is edited or removed.
- The draft disclosure language from spec section 11.5 is used verbatim through `disclosures:`.

## Unverified

- The Cloudflare calls in `deploy/upload.py` follow the public docs but were not run against an account: the metadata
  part name (`metadata`), an assets-only PUT with no script part, `_headers` via `assets.config`, and whether
  `.well-known/` is served. Use `--dry-run`, then a throwaway Worker name.
- Contact addresses, `security.txt` values, subprocessors, retention periods and every `[COUNSEL ...]` item are placeholders.
- No independent accessibility audit. Checked here: no horizontal scroll at 360 px on every page, skip link, focus
  styles, reduced motion, AA colour tokens by calculation.
