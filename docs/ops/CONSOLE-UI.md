# Console UI: building a page with the design system

The business console (`/dashboard`) and the operator console (`/operator`) share one design system:
`Server/Sources/ViadereServerKit/Dashboard/ConsoleDesignSystem.swift` (`enum ConsoleUI`) for components and the stylesheet, and
`Dashboard/DashboardUI.swift` for the page shells (`businessPage`, `operatorPage`, `authPage`, `errorPage`, `reauthPage`). New console pages,
including pages other teams add (Loop directory metadata, Verify with Viadere buttons), use these and nothing else.

## Security rules the design system keeps (do not work around them)

* **CSP.** Every console page carries `default-src 'none'`, a `style-src` pinned to the SHA-256 of `ConsoleUI.css`, `img-src 'self' data:`,
  `font-src 'none'`, `form-action 'self'`, `base-uri 'none'`, `frame-ancestors 'none'`. There is no `unsafe-inline`. Consequences:
  * no `style="…"` attributes and no `<style>` blocks of your own: add a class to `ConsoleUI.css` instead (the hash updates itself);
  * no `<script>` and no `on…=` handlers. The only script is the passkey ceremony (`DashboardUI.script`, hash-pinned, only on pages that pass
    `script: true`). Everything else works without script: links, forms, `<details>`;
  * no external fonts, images, stylesheets or CDNs. Icons are inline SVG (`ConsoleUI.icon`), colours are tokens.
* **Escaping.** Component parameters named for text (`title`, `label`, `help`, `message`, `description`, …) are escaped by the component.
  Parameters named `html` or ending in `HTML` are trusted markup: build them from other components, or escape every interpolated value with
  `DashboardUI.esc`. Business-, customer- and operator-supplied text is never interpolated raw.
* **Forms.** Every POST form carries `DashboardUI.csrf(p)` (use `ConsoleUI.form(action, csrf: DashboardUI.csrf(p), …)`). Pages keep
  `Referrer-Policy: same-origin` (set by `DashboardUI.response`) so the CSRF origin check works. Never add a GET route that changes state.
* **Authorization stays in the route and the service.** Hiding a button is presentation only; the route still checks the permission
  (`p.require(.x)`, `DashboardActions.require…`, `hasFreshReauth`, `OperatorPermission.holds`). Show controls only to people who may use them,
  and keep showing state to people who may read it.
* **Passkey and second-person steps** are enforced by the server (`requireReauth`, `ReauthRequired`, `PendingChanges`). The UI announces them:
  `ConsoleUI.button(…, passkey: true)` adds a key glyph and `ConsoleUI.passkeyNote()` says so in words.

## Anatomy of a page

```swift
private static func widgetsPage(_ req: Request) async throws -> Response {
    let (p, businessId) = try req.businessDashboard
    try p.require(.viewWidgets)                                   // authorization first, always
    let widgets = try await WidgetService(db: req.db, ctx: req.ctx).list(businessId: businessId)
    let rows = widgets.map { w -> [ConsoleUI.Cell] in
        [.text(w.name), ConsoleUI.Cell(html: DashboardFormat.badge(w.state, w.live ? "ok" : "mu"), sort: .text(w.state)), .date(w.createdAt),
         ConsoleUI.Cell(html: ConsoleUI.confirm("Delete", ariaLabel: "Delete \(w.name)",
             ConsoleUI.form("/dashboard/widgets/\(w.id)/delete", csrf: DashboardUI.csrf(p),
                 "<p>This cannot be undone.</p>" + ConsoleUI.button("Delete widget", .dangerSolid, small: true, passkey: true))))]
    }
    let table = ConsoleUI.card("Widgets", description: "What a widget is, in one sentence.",
        ConsoleUI.table([ConsoleUI.Column("Name", key: "name"), ConsoleUI.Column("State"), ConsoleUI.Column("Created", key: "created"),
                         ConsoleUI.Column("", actions: true)],
                        rows, caption: "Widgets", state: ConsoleUI.TableState(req, id: "w"),
                        empty: "No widgets yet", emptyMessage: "Create one to …"))
    let create = ConsoleUI.card("Create a widget", id: "create",
        ConsoleUI.form("/dashboard/widgets", csrf: DashboardUI.csrf(p),
            ConsoleUI.input("name", label: "Name", help: "Only your team sees it.", required: true, attrs: ["maxlength": "64"])
            + ConsoleUI.formActions(ConsoleUI.button("Create widget", passkey: true) + ConsoleUI.passkeyNote())))
    return DashboardUI.businessPage(p, title: "Widgets", active: "/dashboard/widgets", subtitle: "One line on what this page is for.",
                                    actions: ConsoleUI.linkButton("Create a widget", href: "#create", .primary, icon: .plus),
                                    flash: DashboardFormat.flash(req), body: table + create)
}
```

* `title` is the only `h1`. Cards use `h2`; sub-headings inside a card use `h3`. Never skip a level.
* `active` is the path that selects the sidebar section and the tab. To make a page a tab, add a `NavItem` to its section in
  `DashboardUI.sections` (the order there is the spec's §9.1 order; `group` only adds the sidebar heading). Operator pages are listed in
  `DashboardUI.operatorSections`.
* Breadcrumbs are derived from `active` and `title`. Pass `breadcrumbs:` for detail pages
  (`[Crumb("Dashboard", "/dashboard"), Crumb("Developers", "/dashboard/developers"), Crumb("Delivery", nil)]`).
* `actions` holds the page's primary action (one primary button, then secondary links).
* `flash` shows a toast; add messages to `DashboardFormat.flash` and redirect with `?m=key`. Use `flashTone:` for a warning.
* Pages that frame a sandboxed preview pass `frames: true`; pages with a passkey button pass `script: true`.

The operator console is the same with `DashboardUI.operatorPage` (charcoal sidebar, "Viadere staff"). Every operator mutation needs a fresh
passkey and, almost always, a recorded reason: use `ConsoleUI.reason(id:)` (8 to 300 characters, the server's rule).

## Components

| Need | Use |
|---|---|
| A section of a page | `card(title, description:, actions:, tone:, html)`; `panel(html)` without a header; `sectionTitle` above a group of cards |
| Layout | `<div class="cols">` (responsive columns), `<div class="split">` (main + 360 px side), `split wa` (wider side) |
| Key numbers | `stats([Stat(value, label, hint:, tone:, href:)])` (markup `<div class="n">…</div><div class="l">…</div>`) |
| Facts about one thing | `keyValues([(label, html)])` |
| Status | `pill(text, tone)` or `DashboardFormat.badge(text, "ok" / "dg" / "wa" / "mu" / "")`; always words, never colour alone |
| Lists of records | `table(columns, rows, caption:, state:, pageSize:, empty:, emptyMessage:, emptyAction:)` with `Column(title, key:, numeric:, actions:)` and `Cell.text/.number/.date/.html(…, sort:)` |
| Nothing to show | `empty(title, message, icon:, action:)` (tables do this for you) |
| Inputs | `input`, `textarea`, `select`/`selectHTML`, `checkbox`, `choices` (radio cards; `tone: .danger` for a destructive choice), `fieldset`, `reason`, `hidden` |
| Form buttons | `button(label, style, small:, name:, value:, ariaLabel:, passkey:)`, `formActions(html, sep:)`, `passkeyNote()` |
| Navigation buttons | `linkButton(label, href:, style)`, `segmented([(title, href, current)], label:)` for filters and periods |
| Messages | `callout(tone, title:, urgent:, html)` (role `status`, `alert` when urgent), `toast` (the shell does this for `flash`) |
| Progress | `checklist([Step(done, title, detailHTML)], label:)` |
| Destructive actions | `confirm(label, ariaLabel:, html)` (a `<details>` that reveals the real submit button), `dangerZone(title, description:, html)`, `ButtonStyle.dangerSolid` for the final button |
| Review and approval | `diff(before:, after:, beforeTitle:, afterTitle:)` side by side (with `jsonLines`), `preview(src:, title:, width:, height:)` for a sandboxed iframe, `timeline` for decision history, `choices` for the decision, `reason` |
| Colours of a brand | `swatch("#RRGGBB")` (SVG fill; anything else is shown as text) |
| Icons | `icon(.key)` etc. Decorative only (`aria-hidden`). No shield imagery (brand rule) |

Tones: `.neutral`, `.accent`, `.success`, `.warning`, `.danger`.

### Tables: sorting and paging

`TableState(req, id: "w", defaultSort:, defaultAscending:)` reads `w_sort`, `w_dir` and `w_page` from the query string. Sorting and paging
happen in memory over the rows the page already loaded (keep queries bounded with `.limit`). Links keep the page's other parameters and drop
one-time flash parameters (`m`, `im`, `lm`, `sm`). Unknown sort keys are ignored and every value is escaped, so a crafted query string cannot
inject markup or change behaviour. Give each table on a page its own `id`.

### Forms: labels, help and validation

Every control has a visible `<label for>` (or is wrapped in `<label class="ck">`). Put the rule in the help text ("8 to 300 characters"),
and the constraint on the control (`required`, `attrs: ["maxlength": …, "min": …, "pattern": …]`, `type: "email"/"url"/"number"`).
Browsers enforce the constraints and the stylesheet shows a short message under an invalid field (`:user-invalid`, no script). The server
validates again; a failed POST renders the error page with the fields to check and a "Go back and fix it" link to the form (taken from the
`Referer`, accepted only as a path inside the same console by `ConsoleUI.backPath`).

## Accessibility and theming

* Tokens (`--bg`, `--sf`, `--sr`, `--fg`, `--mu`, `--ac`, `--dg`, `--ok`, `--wa`, `--bd`, `--pf`, `--op`) meet WCAG AA in light and dark
  (`prefers-color-scheme`); `WP6ConsoleTests.testDesignTokensMeetContrastRatiosInLightAndDarkThemes` checks them. Use tokens, never raw colours.
* Targets are at least 24 CSS pixels (buttons 36, small buttons 29.6); focus is a 2 px accent outline; motion respects
  `prefers-reduced-motion`; forced-colours mode keeps borders.
* Layout reflows at 820 px (sidebar becomes a scrolling top bar) and 560 px (single column, full-width form buttons). Wide tables scroll
  inside their card, never the page. A scrolling table shows soft edge shadows where more content lies beyond (pure CSS, `background-attachment:
  local`), and at 820 px and below its `actions` column is pinned to the right edge so row actions are never off-screen. Section tabs
  (`.tabs`) scroll with the same fade edges and wrap onto several lines at 560 px and below, so no tab is clipped. A file input
  keeps the native `<input type=file>` and styles its `::file-selector-button` as a 36 px pill; the input itself is at least 40 px tall.
* `WP6ConsoleTests` audits every console page structurally (one `h1`, landmarks, labels, captions, names, no inline style or handler).
  `ConsoleDesignSystemTests` covers escaping, tables, back links and the stylesheet. Add your page's paths to those audits.

## Rendering check

`Server/Tests/browser/test_console_render.py` renders every console page in headless Chromium at 1440, 1024, 820, 560 and 390 px, light and
dark, under the real response headers (so a stylesheet change that is not covered by the CSP pin fails). It fails on CSP violations, page-level
horizontal overflow and text below WCAG AA contrast, and lists targets under 24 px (the file input passes at 24 px and above). The pages come from the test-only dump
`ConsoleRenderDump` (skipped unless `CONSOLE_DUMP_DIR` is set):

```sh
CONSOLE_DUMP_DIR=/tmp/console-dump swift test --package-path Server --filter ConsoleRenderDump
python Server/Tests/browser/test_console_render.py /tmp/console-dump --out /tmp/console-shots
```

Rules this found: a `.vh` (visually hidden) element is `position:absolute`, so every horizontal scroller (`.tw`, `.tabs`, the mobile nav
strip) must be `position:relative` or the hidden text widens the whole page; the operator sidebar in dark mode is a raised charcoal surface, not
the inverted ivory of light mode. The fixture also holds a hosted-inbox item and an operator Loop revision waiting for review, so those pages are rendered too. Before/after screenshots: `docs/ops/console-screenshots/` (`api-keys-390-pinned-actions.png` shows the pinned actions column and wrapped tabs).
