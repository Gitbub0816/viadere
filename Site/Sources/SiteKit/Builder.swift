import Foundation

public struct BuildOptions: Sendable {
    public var siteRoot: URL           // directory containing content/, static/, site.yaml
    public var outDir: URL
    public var repoRoot: URL?          // used to verify claim evidence files and the OpenAPI source
    public var updateLegalLock = false
    public init(siteRoot: URL, outDir: URL? = nil, repoRoot: URL? = nil) {
        self.siteRoot = siteRoot
        self.outDir = outDir ?? siteRoot.appendingPathComponent("dist")
        self.repoRoot = repoRoot ?? siteRoot.deletingLastPathComponent()
    }
}

public struct BuildReport: Sendable {
    public var pages: [String] = []
    public var findings: [LintFinding] = []
    public var outputProblems: [String] = []
    public var linkProblems: [String] = []
    public var warnings: [String] = []
    public var fileCount = 0
    public var errors: [String] {
        findings.filter { $0.severity == .error }.map { $0.description } + outputProblems.map { "output: \($0)" } + linkProblems.map { "link: \($0)" }
    }
    public var ok: Bool { errors.isEmpty }
}

public struct SiteBuilder {
    public let options: BuildOptions
    public init(options: BuildOptions) { self.options = options }

    // MARK: Pipeline

    public func loadPages(config: SiteConfig, openapi: OpenAPI?) throws -> [Page] {
        var pages = try ContentLoader(root: options.siteRoot.appendingPathComponent("content")).load()
        if let api = openapi {
            for (i, tag) in api.tags.enumerated() where !api.operations(tag: tag).isEmpty {
                let slug = OpenAPI.tagSlug(tag)
                if pages.contains(where: { $0.url == "/developers/api/\(slug)/" }) { continue }
                var p = Page(sourcePath: "(generated from openapi.yaml)", url: "/developers/api/\(slug)/",
                             front: .map([("title", .string("\(tag) endpoints")),
                                          ("description", .string("Reference for the \(tag.lowercased()) operations of the Viadere Business API, generated from the OpenAPI contract.")),
                                          ("nav_title", .string("API: \(tag)")), ("order", .int(30 + i)), ("eyebrow", .string("API reference"))]),
                             body: "{{ generate: api-tag \(tag) }}\n")
                p.generated = true
                pages.append(p)
            }
        }
        return pages
    }

    /// Every version keeps a stable address: the current version gets a permalink until an archive file takes it over.
    func permalinks(for pages: [Page]) -> [Page] {
        var out: [Page] = []
        for p in pages where p.isLegal && !p.legalIsArchive && p.url != "/legal/" {
            let version = p.front["version"]?.string ?? "0.0.0"
            let url = "/legal/\(p.legalSlug ?? "")/versions/\(version)/"
            if pages.contains(where: { $0.url == url }) { continue }
            var copy = p
            copy.url = url
            copy.legalPermalink = true
            out.append(copy)
        }
        return out
    }

    func loadOpenAPI(_ config: SiteConfig) throws -> OpenAPI? {
        let url = URL(fileURLWithPath: config.openapiPath, relativeTo: options.siteRoot).standardizedFileURL
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try OpenAPI(contentsOf: url)
    }

    /// Expands `{{ generate: … }}` directives. Generated HTML is stored as raw blocks addressed by placeholder.
    func expand(_ page: Page, pages: [Page], api: OpenAPI?, md: inout Markdown) throws -> String {
        var out: [String] = []
        var n = 0
        for line in page.body.replacingOccurrences(of: "{{api-version}}", with: api?.version ?? "unversioned").components(separatedBy: "\n") {
            let t = line.trimmed
            guard t.hasPrefix("{{ generate:"), t.hasSuffix("}}") else { out.append(line); continue }
            let spec = String(t.dropFirst(12).dropLast(2)).trimmed
            let name = spec.split(separator: " ").first.map(String.init) ?? ""
            let arg = String(spec.dropFirst(name.count)).trimmed
            func raw(_ html: String) { n += 1; let k = "\(page.url)#\(n)"; md.rawBlocks[k] = html; out.append("{{raw:\(k)}}") }
            switch name {
            case "info-section":
                guard let api else { throw SiteError("\(page.sourcePath): openapi.yaml is required for info-section") }
                guard let s = api.infoSections.first(where: { $0.title == arg }) else { throw SiteError("\(page.sourcePath): no OpenAPI info section \"\(arg)\"") }
                out.append(s.markdown)
            case "api-index": raw(try need(api, page).renderIndex())
            case "api-tag": raw(try need(api, page).renderTagPage(arg))
            case "webhook-events": raw(try need(api, page).renderWebhooks())
            case "api-errors": raw(try need(api, page).renderErrors())
            case "schemas": raw(try need(api, page).renderSchemas())
            case "product-cards": raw(productCards(pages, md))
            case "status-components": raw(statusComponents(page))
            case "status-notices": raw(statusNotices(page))
            case "legal-index": raw(legalIndex(pages))
            default: throw SiteError("\(page.sourcePath): unknown generate directive \"\(name)\"")
            }
        }
        return out.joined(separator: "\n")
    }

    func need(_ api: OpenAPI?, _ p: Page) throws -> OpenAPI {
        guard let api else { throw SiteError("\(p.sourcePath): docs/openapi.yaml was not found; the developer portal is generated from it") }
        return api
    }

    func productCards(_ pages: [Page], _ md: Markdown) -> String {
        let products = pages.filter { $0.isProductPage }.sorted { ($0.order, $0.title) < ($1.order, $1.title) }
        var out = "<div class=\"grid grid-2\">\n"
        for p in products {
            let s = p.status
            out += "<div class=\"card\">" + (s.map { "<span class=\"badge badge-\($0.rawValue)\">\($0.label)</span>" } ?? "")
                + "<h3><a href=\"\(p.url)\">\(HTML.escape(p.title))</a></h3><p>\(HTML.escape(p.front["tagline"]?.string ?? p.description))</p>"
                + "<a class=\"more\" href=\"\(p.url)\">Learn more<span class=\"visually-hidden\"> about \(HTML.escape(p.title))</span></a></div>\n"
        }
        return out + "</div>"
    }

    func statusComponents(_ page: Page) -> String {
        var out = "<ul class=\"status-list\">\n"
        for c in page.front["components"]?.array ?? [] {
            let state = c["state"]?.string ?? "placeholder"
            out += "<li><span class=\"name\">\(HTML.escape(c["name"]?.string ?? ""))</span><span class=\"badge badge-planned\">\(HTML.escape(state == "placeholder" ? "Not yet monitored" : state))</span><span class=\"desc\">\(HTML.escape(c["description"]?.string ?? ""))</span></li>\n"
        }
        return out + "</ul>"
    }

    func statusNotices(_ page: Page) -> String {
        func block(_ key: String, _ empty: String) -> String {
            let items = page.front[key]?.array ?? []
            if items.isEmpty { return "<p>\(HTML.escape(empty))</p>" }
            return "<ul>" + items.map { "<li><strong>\(HTML.escape($0["date"]?.string ?? ""))</strong> \(HTML.escape($0["title"]?.string ?? "")): \(HTML.escape($0["detail"]?.string ?? ""))</li>" }.joined() + "</ul>"
        }
        return "<h2 id=\"incidents\">Incident notices</h2>\n" + block("incidents", "No incidents have been published. This list is empty because no service is live yet, not because monitoring found nothing.")
            + "\n<h2 id=\"maintenance\">Maintenance notices</h2>\n" + block("maintenance", "No maintenance is scheduled.")
    }

    func legalIndex(_ pages: [Page]) -> String {
        let docs = pages.filter { $0.isLegal && !$0.legalIsArchive }.sorted { ($0.order, $0.title) < ($1.order, $1.title) }
        var out = "<div class=\"table-wrap\" role=\"region\" tabindex=\"0\" aria-label=\"Legal documents\"><table class=\"history\"><thead><tr><th scope=\"col\">Document</th><th scope=\"col\">Version</th><th scope=\"col\">Status</th><th scope=\"col\">Effective date</th><th scope=\"col\">Owner</th></tr></thead><tbody>\n"
        for p in docs {
            let draft = LegalCatalog.status(of: p) == "draft"
            let eff = p.front["effective_date"]?.string ?? ""
            out += "<tr><td><a href=\"\(p.url)\">\(HTML.escape(p.title))</a></td><td>\(HTML.escape(p.front["version"]?.string ?? ""))</td><td><span class=\"badge \(draft ? "badge-draft" : "badge-live")\">\(draft ? "Draft" : "In effect")</span></td><td>\(eff.isEmpty ? "None" : HTML.escape(eff))</td><td>\(HTML.escape(p.front["owner"]?.string ?? ""))</td></tr>\n"
        }
        return out + "</tbody></table></div>"
    }

    static func stripTags(_ html: String) -> String {
        html.replacingOccurrences(of: "<[^>]+>", with: " ", options: .regularExpression)
            .replacingOccurrences(of: "&quot;", with: "\"").replacingOccurrences(of: "&#39;", with: "'")
            .replacingOccurrences(of: "&amp;", with: "&").replacingOccurrences(of: "&lt;", with: "<").replacingOccurrences(of: "&gt;", with: ">")
    }

    /// Content-level checks only (integrity lint, legal metadata and lock): what `viadere-site lint` runs before the output checks.
    public func lintContent() throws -> [LintFinding] {
        let config = try SiteConfig.load(from: options.siteRoot.appendingPathComponent("site.yaml"))
        let api = try loadOpenAPI(config)
        let pages = try loadPages(config: config, openapi: api)
        var findings: [LintFinding] = []
        if let text = try? String(contentsOf: options.siteRoot.appendingPathComponent("legal-lock.json"), encoding: .utf8) {
            findings += LegalLock.check(lock: LegalLock.decode(text), pages: pages)
        }
        let lint = IntegrityLint(repoRoot: options.repoRoot)
        for p in pages {
            var md = Markdown()
            let expanded = try expand(p, pages: pages, api: api, md: &md)
            findings += lint.check(p, assembledText: Self.assembledText(p, expanded: expanded, md: md), allPages: pages)
        }
        return findings
    }

    static func assembledText(_ p: Page, expanded: String, md: Markdown) -> String {
        var assembled = expanded
        for (k, v) in md.rawBlocks where expanded.contains("{{raw:\(k)}}") { assembled += "\n" + stripTags(v) }
        for key in ["headline", "lede", "tagline"] { if let v = p.front[key]?.string { assembled += "\n" + v } }
        for a in p.front["components"]?.array ?? [] { assembled += "\n" + (a["description"]?.string ?? "") }
        return assembled
    }

    // MARK: Build

    @discardableResult
    public func build() throws -> BuildReport {
        var report = BuildReport()
        let fm = FileManager.default
        let config = try SiteConfig.load(from: options.siteRoot.appendingPathComponent("site.yaml"))
        let api = try loadOpenAPI(config)
        let pages = try loadPages(config: config, openapi: api)

        // Duplicate URLs.
        var seenURLs = Set<String>()
        for p in pages where !seenURLs.insert(p.url).inserted { report.findings.append(LintFinding(rule: "duplicate-url", page: p.url, message: "two pages map to this URL", severity: .error)) }

        // Legal lock.
        let lockURL = options.siteRoot.appendingPathComponent("legal-lock.json")
        if options.updateLegalLock {
            try LegalLock.encode(LegalLock.entries(pages: pages)).write(to: lockURL, atomically: true, encoding: .utf8)
        } else if let text = try? String(contentsOf: lockURL, encoding: .utf8) {
            report.findings += LegalLock.check(lock: LegalLock.decode(text), pages: pages)
        }

        // Expand, lint.
        let lint = IntegrityLint(repoRoot: options.repoRoot)
        var rendered: [(Page, RenderedMarkdown)] = []
        for p in pages + permalinks(for: pages) {
            var md = Markdown()
            let expanded = try expand(p, pages: pages, api: api, md: &md)
            let assembled = Self.assembledText(p, expanded: expanded, md: md)
            if !p.legalPermalink { report.findings += lint.check(p, assembledText: assembled, allPages: pages) }
            rendered.append((p, md.render(expanded)))
        }

        // Fresh output directory.
        if fm.fileExists(atPath: options.outDir.path) { try fm.removeItem(at: options.outDir) }
        try fm.createDirectory(at: options.outDir, withIntermediateDirectories: true)

        // Static assets (CSS is fingerprinted).
        let staticDir = options.siteRoot.appendingPathComponent("static")
        let cssSource = try String(contentsOf: staticDir.appendingPathComponent("assets/site.css"), encoding: .utf8)
        let cssName = "site.\(SHA256.hex(cssSource).prefix(10)).css"
        try write(cssSource, to: "assets/\(cssName)")
        try copyTree(staticDir.appendingPathComponent("assets/fonts"), to: "assets/fonts")
        try copyTree(staticDir.appendingPathComponent("brand"), to: "brand")
        try fm.copyItem(at: staticDir.appendingPathComponent("brand/app-icon-light.svg"), to: options.outDir.appendingPathComponent("favicon.svg"))
        let sprite = try Brand.sprite(brandDir: staticDir.appendingPathComponent("brand"))

        // Pages.
        let layout = Layout(config: config, pages: pages + permalinks(for: pages), cssPath: "/assets/\(cssName)", sprite: sprite)
        for (p, r) in rendered {
            let html = layout.render(page: p, body: r.html, headings: r.headings,
                                     history: p.legalSlug.map { LegalCatalog.history(slug: $0, pages: pages) } ?? [])
            let rel = p.url.hasSuffix("/") ? String(p.url.dropFirst()) + "index.html" : String(p.url.dropFirst())
            try write(html, to: rel)
            report.pages.append(p.url)
        }

        // Deployment and discovery files.
        try write(DeployFiles.headers(), to: "_headers")
        try write(DeployFiles.securityTxt(config), to: ".well-known/security.txt")
        try write(DeployFiles.robots(config), to: "robots.txt")
        let indexable = pages.filter { !$0.noindex && !$0.url.hasSuffix(".html") && !(layout.isDraft($0)) && !$0.legalIsArchive && !$0.legalPermalink }.map { $0.url }
        try write(DeployFiles.sitemap(config, urls: indexable), to: "sitemap.xml")
        if DeployFiles.securityTxt(config).contains("PLACEHOLDER") { report.warnings.append("security.txt still contains placeholders (set security_contact and security_expires in site.yaml before launch)") }

        // Output policy checks.
        report.outputProblems = OutputChecker.check(dist: options.outDir, config: config)
        report.linkProblems = LinkChecker.check(dist: options.outDir)
        var count = 0
        if let en = fm.enumerator(at: options.outDir, includingPropertiesForKeys: [.isRegularFileKey]) { for case let u as URL in en where (try? u.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true { count += 1 } }
        report.fileCount = count
        return report
    }

    func write(_ text: String, to rel: String) throws {
        let url = options.outDir.appendingPathComponent(rel)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try text.write(to: url, atomically: true, encoding: .utf8)
    }

    func copyTree(_ src: URL, to rel: String) throws {
        let fm = FileManager.default
        let dst = options.outDir.appendingPathComponent(rel)
        try fm.createDirectory(at: dst.deletingLastPathComponent(), withIntermediateDirectories: true)
        try fm.copyItem(at: src, to: dst)
    }
}
