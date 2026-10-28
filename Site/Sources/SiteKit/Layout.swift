import Foundation

public enum Brand {
    /// Builds the SVG sprite from the brand files (copied verbatim from Design/svg). Gradient ids are unique per file.
    public static func sprite(brandDir: URL) throws -> String {
        func symbol(_ file: String, id: String) throws -> String {
            let text = try String(contentsOf: brandDir.appendingPathComponent(file), encoding: .utf8)
            guard let vb = text.range(of: "viewBox=\""), let vbEnd = text[vb.upperBound...].firstIndex(of: "\""),
                  let open = text.range(of: ">", range: vb.upperBound..<text.endIndex), let close = text.range(of: "</svg>", options: .backwards) else {
                throw SiteError("cannot parse brand SVG \(file)")
            }
            var inner = String(text[open.upperBound..<close.lowerBound])
            inner = inner.replacingOccurrences(of: "<title>[^<]*</title>", with: "", options: .regularExpression)
            return "<symbol id=\"\(id)\" viewBox=\"\(text[vb.upperBound..<vbEnd])\">\(inner)</symbol>"
        }
        return "<svg class=\"sprite\" aria-hidden=\"true\" focusable=\"false\" xmlns=\"http://www.w3.org/2000/svg\">"
            + (try symbol("viadere-mark.svg", id: "mark")) + (try symbol("viadere-mark-on-dark.svg", id: "mark-dark"))
            + (try symbol("viadere-lockup-horizontal.svg", id: "lockup")) + (try symbol("viadere-lockup-horizontal-on-dark.svg", id: "lockup-dark"))
            + "</svg>"
    }
}

public struct Layout {
    public static let sectionTitles: [String: String] = [
        "products": "Products", "businesses": "For Businesses", "consumers": "For Consumers", "developers": "Developers",
        "security": "Security & Trust", "privacy": "Privacy Center", "legal": "Legal", "company": "Company", "status": "Status",
    ]
    public static let csp = "default-src 'none'; img-src 'self' data:; style-src 'self'; font-src 'self'; script-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'; manifest-src 'self'; object-src 'none'"

    let config: SiteConfig
    let pages: [Page]
    let cssPath: String
    let sprite: String

    public init(config: SiteConfig, pages: [Page], cssPath: String, sprite: String) {
        self.config = config; self.pages = pages; self.cssPath = cssPath; self.sprite = sprite
    }

    func e(_ s: String) -> String { HTML.escape(s) }

    func isDraft(_ p: Page) -> Bool { p.isLegal && LegalCatalog.status(of: p) == "draft" }

    func lockup(_ cls: String = "") -> String {
        "<svg class=\"lockup-light \(cls)\" viewBox=\"0 0 892.39 228\" role=\"img\" aria-label=\"Viadere\"><use href=\"#lockup\"/></svg>"
            + "<svg class=\"lockup-dark \(cls)\" viewBox=\"0 0 892.39 228\" role=\"img\" aria-label=\"Viadere\"><use href=\"#lockup-dark\"/></svg>"
    }

    func lockupOnDark(_ cls: String = "") -> String {
        "<svg class=\"lockup-fixed \(cls)\" viewBox=\"0 0 892.39 228\" role=\"img\" aria-label=\"Viadere\"><use href=\"#lockup-dark\"/></svg>"
    }

    /// Marketing pages render their body full width (authored with `::: section` bands) under a page hero.
    func isMarketing(_ p: Page) -> Bool { p.layout == "marketing" }

    func sectionPages(_ section: String) -> [Page] {
        pages.filter { $0.section == section && !$0.legalIsArchive && !$0.legalPermalink }
            .sorted { ($0.order, $0.title) < ($1.order, $1.title) }
    }

    func primaryNav(current: Page) -> String {
        func item(_ t: (title: String, path: String)) -> String {
            let active = current.url == t.path || current.url.hasPrefix(t.path)
            return "<li><a href=\"\(t.path)\"\(active ? " aria-current=\"page\"" : "")>\(e(t.title))</a></li>"
        }
        let items = config.nav.map(item).joined()
        let cta = "<a class=\"btn btn-sm nav-cta\" href=\"/businesses/onboarding/\">Get started</a>"
        return "<nav class=\"primary\" aria-label=\"Primary\"><ul class=\"nav-list\">\(items)</ul>\(cta)"
            + "<details class=\"nav-mobile\"><summary><span class=\"burger\" aria-hidden=\"true\"></span>Menu<span class=\"visually-hidden\"> (site sections)</span></summary><ul>\(items)<li class=\"nm-cta\"><a href=\"/businesses/onboarding/\">Get started</a></li></ul></details></nav>"
    }

    func breadcrumbs(_ p: Page) -> String {
        guard p.url != "/" else { return "" }
        var crumbs = "<li><a href=\"/\">Home</a></li>"
        let comps = p.url.split(separator: "/").map(String.init)
        var path = "/"
        for (i, c) in comps.enumerated() {
            path += c + "/"
            let isLast = i == comps.count - 1
            let target = pages.first { $0.url == path }
            let label = isLast ? p.title : (Self.sectionTitles[c].flatMap { i == 0 ? $0 : nil } ?? target?.title ?? c.capitalized)
            if isLast { crumbs += "<li aria-current=\"page\">\(e(label))</li>" }
            else if target != nil { crumbs += "<li><a href=\"\(path)\">\(e(label))</a></li>" }
        }
        return "<nav class=\"crumbs\" aria-label=\"Breadcrumb\"><ol>\(crumbs)</ol></nav>"
    }

    func sidebar(_ p: Page) -> String {
        let siblings = sectionPages(p.section)
        guard siblings.count > 1 else { return "" }
        let title = Self.sectionTitles[p.section] ?? p.section.capitalized
        func list() -> String {
            "<ul>" + siblings.map { s in
                let active = s.url == p.url || (p.legalIsArchive && s.legalSlug == p.legalSlug && !s.legalIsArchive)
                return "<li><a href=\"\(s.url)\"\(active ? " aria-current=\"page\"" : "")>\(e(s.front["nav_title"]?.string ?? s.title))</a></li>"
            }.joined() + "</ul>"
        }
        return "<aside class=\"side\"><nav class=\"side-desktop\" aria-label=\"\(e(title))\"><h2>\(e(title))</h2>\(list())</nav>"
            + "<details class=\"side-mobile\"><summary>In this section: \(e(title))</summary><nav aria-label=\"\(e(title)) (menu)\">\(list())</nav></details></aside>"
    }

    func toc(_ headings: [Heading]) -> String {
        let hs = headings.filter { $0.level <= 3 }
        guard hs.filter({ $0.level == 2 }).count >= 3 else { return "" }
        return "<nav class=\"toc\" aria-labelledby=\"toc-h\"><h2 id=\"toc-h\">On this page</h2><ul>"
            + hs.map { "<li class=\"l\($0.level)\"><a href=\"#\($0.id)\">\(e($0.text))</a></li>" }.joined() + "</ul></nav>"
    }

    func footer() -> String {
        func col(_ title: String, _ links: [(String, String)]) -> String {
            "<div class=\"foot-col\"><h2>\(e(title))</h2><ul>" + links.map { "<li><a href=\"\($0.1)\">\(e($0.0))</a></li>" }.joined() + "</ul></div>"
        }
        return """
        <footer class="site-footer dark"><div class="wrap">
        <div class="foot-grid">
        <div class="foot-brand"><a href="/" class="foot-logo" aria-label="Viadere, home">\(lockupOnDark())</a><p class="caps">\(e(config.tagline))</p><p>Verified, privacy-conscious connections between businesses and the people they serve.</p></div>
        \(col("Products", [("Messaging", "/products/messaging/"), ("Approve", "/products/approve/"), ("Verify", "/products/verify/"), ("Authenticator", "/products/authenticator/"), ("All products", "/products/")]))
        \(col("Build", [("Developers", "/developers/"), ("Quickstart", "/developers/quickstart/"), ("API reference", "/developers/api/"), ("Webhooks", "/developers/webhooks/"), ("Changelog", "/developers/changelog/"), ("Status", "/status/")]))
        \(col("Trust", [("Security overview", "/security/"), ("Architecture", "/security/architecture/"), ("Report a vulnerability", "/security/disclosure/"), ("Verification badges", "/security/verification-badges/"), ("Privacy Center", "/privacy/")]))
        \(col("Company", [("About", "/company/"), ("Contact", "/company/contact/"), ("Legal", "/legal/"), ("Privacy Notice", "/legal/privacy-notice/"), ("Accessibility", "/legal/accessibility-statement/"), ("Cookie Notice", "/legal/cookie-notice/")]))
        </div>
        <div class="fine">
        <p>This site sets no cookies, runs no scripts and makes no third-party requests.</p>
        <p>Legal documents on this site are drafts pending counsel review unless a page states an effective date. Product status badges show what is live, in beta or planned. Product screens on this site are illustrations with fictional businesses.</p>
        </div>
        </div></footer>
        """
    }

    func actions(_ p: Page, onDark: Bool = false) -> String {
        let list = p.front["actions"]?.array ?? []
        guard !list.isEmpty else { return "" }
        return "<div class=\"actions\">" + list.enumerated().map { i, a in
            "<a class=\"btn\(i == 0 ? "" : " secondary")\" href=\"\(e(a["href"]?.string ?? "/"))\">\(e(a["label"]?.string ?? ""))\(i == 0 ? Icons.svg("arrow") : "")</a>"
        }.joined() + "</div>"
    }

    func homeHero(_ p: Page) -> String {
        let f = p.front
        let h1 = Markdown().inline(f["headline"]?.string ?? p.title)
        let lede = e(f["lede"]?.string ?? p.description)
        let caps = e(f["eyebrow"]?.string ?? config.tagline)
        let proof = (f["proof"]?.array ?? []).map { item in
            "<li>\(Icons.svg(item["icon"]?.string ?? "check"))\(e(item["label"]?.string ?? ""))</li>"
        }.joined()
        return """
        <section class="hero dark" aria-labelledby="hero-h"><div class="hero-glow" aria-hidden="true"></div>
        <div class="wrap hero-inner">
        <div class="hero-mark"><picture><source media="(prefers-reduced-motion: reduce)" srcset="/assets/media/viadere-mark-final.webp" type="image/webp"><img src="/assets/media/viadere-mark-reveal.webp" width="1008" height="567" alt="The Viadere mark: a satin ribbon that draws the letters v, i and a, then a floating dot settles above the i." decoding="async" fetchpriority="high"></picture></div>
        <p class="caps hero-caps">\(caps)</p>
        <h1 id="hero-h">\(h1)</h1>
        <p class="lede">\(lede)</p>
        \(actions(p))
        \(proof.isEmpty ? "" : "<ul class=\"hero-proof\">\(proof)</ul>")
        </div></section>
        """
    }

    func subnav(_ p: Page) -> String {
        guard p.front["subnav"]?.bool ?? true else { return "" }
        let siblings = sectionPages(p.section)
        guard siblings.count > 1 else { return "" }
        let title = Self.sectionTitles[p.section] ?? p.section.capitalized
        return "<nav class=\"subnav\" aria-label=\"\(e(title))\"><div class=\"wrap\"><ul>" + siblings.map { s in
            "<li><a href=\"\(s.url)\"\(s.url == p.url ? " aria-current=\"page\"" : "")>\(e(s.front["nav_title"]?.string ?? s.title))</a></li>"
        }.joined() + "</ul></div></nav>"
    }

    func pageHead(_ p: Page) -> String {
        var badges = ""
        if let s = p.status, p.isProductPage { badges = "<span class=\"badge badge-\(s.rawValue)\">\(s.label)</span>" }
        if isDraft(p) { badges += " <span class=\"badge badge-draft\">Draft</span>" }
        let eyebrow = p.front["eyebrow"]?.string ?? (p.section == "legal" ? "Legal" : Self.sectionTitles[p.section] ?? "")
        let art = p.front["hero_art"]?.string.flatMap(Showcase.render) ?? ""
        let headline = p.front["headline"]?.string.map { Markdown().inline($0) } ?? e(p.title)
        return """
        <div class="page-head\(art.isEmpty ? "" : " has-art")\(isMarketing(p) ? " is-marketing" : "")"><div class="wrap ph-grid"><div class="ph-copy">\(breadcrumbs(p))
        <p class="eyebrow">\(e(eyebrow))\(badges.isEmpty ? "" : " " + badges)</p>
        <h1>\(headline)</h1>
        \(p.description.isEmpty ? "" : "<p class=\"lede\">\(e(p.description))</p>")
        \(actions(p))
        </div>\(art.isEmpty ? "" : "<div class=\"ph-art\">\(art)</div>")</div></div>
        """
    }

    func legalBanner(_ p: Page, history: [LegalVersion]) -> String {
        let f = p.front
        let eff = f["effective_date"]?.string ?? ""
        let status = LegalCatalog.status(of: p)
        var out = ""
        if status == "draft" {
            out += "<div class=\"draft-notice\" role=\"note\"><p><strong>DRAFT. Not in effect.</strong> This document has not been approved by counsel and has no effective date. It is published for review and must not be relied on as a binding or final statement of Viadere's terms or practices. Bracketed text marks decisions that counsel and the product owner have not made.</p></div>"
        }
        if p.legalPermalink {
            out += "<div class=\"callout\" role=\"note\"><p>This is the permanent address of version \(e(f["version"]?.string ?? "")). It is the latest version at the time of publication. The main address, <a href=\"/legal/\(e(p.legalSlug ?? ""))/\">/legal/\(e(p.legalSlug ?? ""))/</a>, always shows the latest version.</p></div>"
        }
        if p.legalIsArchive {
            out += "<div class=\"callout\" role=\"note\"><p>This is an archived version (\(e(f["version"]?.string ?? ""))). It was superseded on \(e(f["superseded_on"]?.string ?? "")). <a href=\"/legal/\(e(p.legalSlug ?? ""))/\">Read the current version</a>.</p></div>"
        }
        func row(_ k: String, _ v: String) -> String { "<tr><th scope=\"row\">\(k)</th><td>\(v)</td></tr>" }
        out += "<div class=\"table-wrap\"><table><tbody>"
        out += row("Version", e(f["version"]?.string ?? ""))
        out += row("Effective date", eff.isEmpty ? "<span class=\"placeholder\">[none: not yet approved]</span>" : e(eff))
        out += row("Owner", e(f["owner"]?.string ?? ""))
        out += row("Counsel review", e(f["counsel_review"]?.string ?? "pending"))
        out += "</tbody></table></div>"
        return out
    }

    func legalHistory(_ p: Page, history: [LegalVersion]) -> String {
        guard let slug = p.legalSlug else { return "" }
        var out = "<h2 id=\"version-history\">Version history</h2>\n"
        if history.count <= 1 && !p.legalIsArchive {
            out += "<p>This is the first draft. There are no earlier versions, and no version has ever been in effect.</p>\n"
        }
        out += "<div class=\"table-wrap history\" role=\"region\" tabindex=\"0\" aria-label=\"Version history\"><table><thead><tr><th scope=\"col\">Version</th><th scope=\"col\">Effective date</th><th scope=\"col\">Counsel review</th><th scope=\"col\">Status</th><th scope=\"col\">Changes</th></tr></thead><tbody>"
        for v in history {
            let status = v.isCurrent ? (v.effectiveDate.isEmpty ? "Current draft" : "Current") : "Superseded \(e(v.supersededOn))"
            out += "<tr><td><a href=\"\(v.url)\">\(e(v.version))</a></td><td>\(v.effectiveDate.isEmpty ? "None" : e(v.effectiveDate))</td><td>\(e(v.counselReview))</td><td>\(status)</td><td>\(e(v.summary))</td></tr>"
        }
        out += "</tbody></table></div>\n<p class=\"muted\">Every version keeps a permanent address of the form <code>/legal/\(e(slug))/versions/{version}/</code>. Versions that took effect are never edited or removed.</p>\n"
        return out
    }

    public func render(page p: Page, body: String, headings: [Heading], history: [LegalVersion]) -> String {
        let isHome = p.layout == "home"
        let title = isHome ? "\(config.name): \(config.tagline)" : "\(p.title) | \(config.name)"
        let canonical = config.baseURL + p.url
        let robots = (p.noindex || isDraft(p) || p.legalIsArchive || p.legalPermalink) ? "<meta name=\"robots\" content=\"noindex\">" : ""
        let desc = p.description.isEmpty ? config.tagline : p.description
        let metaCSP = Self.csp
        var main: String
        let showToc = (p.front["toc"]?.bool ?? (p.section == "developers" || p.section == "legal" || p.section == "privacy" || p.section == "security")) && !isHome
        let legalExtra = p.isLegal && p.url != "/legal/" ? legalBanner(p, history: history) : ""
        let legalFoot = p.isLegal && p.url != "/legal/" ? legalHistory(p, history: history) : ""
        if isHome {
            main = homeHero(p) + body
        } else if isMarketing(p) {
            main = subnav(p) + pageHead(p) + "<div class=\"mk-body\">\(body)</div>"
        } else {
            let side = sidebar(p)
            let wide = (p.front["wide"]?.bool ?? (p.section == "developers")) ? " wide" : ""
            main = pageHead(p) + "<div class=\"wrap shell\(side.isEmpty ? "" : " has-side")\">\(side)<div class=\"content\(wide)\">\(legalExtra)\(showToc ? toc(headings + (legalFoot.isEmpty ? [] : [Heading(level: 2, id: "version-history", text: "Version history")])) : "")\(body)\(legalFoot)</div></div>"
        }
        return """
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="Content-Security-Policy" content="\(e(metaCSP))">
        <title>\(e(title))</title>
        <meta name="description" content="\(e(desc))">
        <meta name="color-scheme" content="light dark">
        <meta name="theme-color" media="(prefers-color-scheme: light)" content="#F5F2EC">
        <meta name="theme-color" media="(prefers-color-scheme: dark)" content="#121211">
        <meta name="referrer" content="no-referrer">
        \(robots)
        <link rel="canonical" href="\(e(canonical))">
        <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <link rel="preload" href="/assets/fonts/outfit-latin-600-normal.woff2" as="font" type="font/woff2" crossorigin>
        <link rel="preload" href="/assets/fonts/outfit-latin-300-normal.woff2" as="font" type="font/woff2" crossorigin>
        <link rel="stylesheet" href="\(cssPath)">
        <meta property="og:title" content="\(e(title))">
        <meta property="og:description" content="\(e(desc))">
        <meta property="og:type" content="website">
        <meta property="og:url" content="\(e(canonical))">
        </head>
        <body\(isHome ? " class=\"is-home\"" : "")>
        \(sprite)
        <a class="skip" href="#main">Skip to main content</a>
        <header class="site-header\(isHome ? " dark" : "")"><div class="wrap bar">
        <a class="brand" href="/" aria-label="Viadere, home">\(isHome ? lockupOnDark() : lockup())</a>
        \(primaryNav(current: p))
        </div></header>
        <main id="main" tabindex="-1">
        \(main)
        </main>
        \(footer())
        </body>
        </html>
        """
    }
}
