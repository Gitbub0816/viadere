import Foundation
import Testing
@testable import SiteKit

/// Site root = the directory above Tests/.
let siteRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

func page(_ url: String, _ front: String, _ body: String) throws -> Page {
    let (y, b) = try FrontMatter.split("---\n\(front)\n---\n\(body)")
    return Page(sourcePath: "t.md", url: url, front: y, body: b)
}

func rules(_ p: Page, _ text: String? = nil, all: [Page] = []) -> [String] {
    IntegrityLint(repoRoot: nil).check(p, assembledText: text ?? p.body, allPages: all).filter { $0.severity == .error }.map(\.rule)
}

@Suite("Front matter and YAML")
struct FrontMatterTests {
    @Test func parsesFrontMatter() throws {
        let (y, body) = try FrontMatter.split("---\ntitle: Hi\norder: 3\nlist: [a, b]\nnested:\n  - name: x\n    v: \"q\"\n---\nBody\n")
        #expect(y["title"]?.string == "Hi")
        #expect(y["order"]?.int == 3)
        #expect(y["list"]?.strings == ["a", "b"])
        #expect(y["nested"]?.array?.first?["v"]?.string == "q")
        #expect(body == "Body\n")
    }
    @Test func emptyStringStaysAnEmptyString() throws {
        let (y, _) = try FrontMatter.split("---\neffective_date: \"\"\n---\n")
        #expect(y["effective_date"]?.string == "")
    }
    @Test func unclosedFrontMatterFails() {
        #expect(throws: SiteError.self) { try FrontMatter.split("---\ntitle: x\n") }
    }
    @Test func blockScalarsAndFlowMaps() throws {
        let y = try YAMLParser.parse("a: |\n  one\n  two\nb: { x: 1, y: it's ok, z: [1, 2] }\nc:\n  - 1\n  - two\n")
        #expect(y["a"]?.string == "one\ntwo\n")
        #expect(y["b"]?["x"]?.int == 1)
        #expect(y["b"]?["y"]?.string == "it's ok")
        #expect(y["c"]?.array?.count == 2)
    }
}

@Suite("Markdown")
struct MarkdownTests {
    @Test func escapesRawHTMLAndBlocksUnsafeLinks() {
        let html = Markdown().render("<script>alert(1)</script> [x](javascript:alert(1)) [ok](/a/)").html
        #expect(!html.contains("<script>"))
        #expect(!html.contains("javascript:"))
        #expect(html.contains("href=\"/a/\""))
    }
    @Test func rendersHeadingsTablesContainers() {
        let r = Markdown().render("## Title\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n::: card\nHi **there**\n:::\n")
        #expect(r.headings == [Heading(level: 2, id: "title", text: "Title")])
        #expect(r.html.contains("<table>"))
        #expect(r.html.contains("<div class=\"card\">"))
        #expect(r.html.contains("<strong>there</strong>"))
    }
}

@Suite("Rich components")
struct RichComponentTests {
    @Test func sectionContainerIsAFullWidthBand() {
        let html = Markdown().render("::: section dark cta\n## Hi\n:::\n").html
        #expect(html.contains("<section class=\"band dark cta\"><div class=\"wrap\">"))
        #expect(html.contains("</div></section>"))
    }
    @Test func linkClassesAndIcons() {
        let html = Markdown().render("[Go](/a/){.btn .secondary} {icon:key} {icon:nope}").html
        #expect(html.contains("<a href=\"/a/\" class=\"btn secondary\">Go</a>"))
        #expect(html.contains("class=\"ic ic-key\""))
        #expect(!html.contains("{icon:key}"))
        #expect(Markdown.plainText("{icon:key} Keys") == "Keys")
    }
    @Test func taskListItems() {
        let html = Markdown().render("- [ ] open\n- [x] done\n").html
        #expect(html.contains("<li class=\"task\"><span class=\"tick\" aria-hidden=\"true\"></span>open</li>"))
        #expect(html.contains("<li class=\"task done\">"))
    }
    @Test func codeWindowWithTitleAndHighlighting() {
        let html = Markdown().render("```swift Demo.swift\nlet s = \"<b>\" // note\n```\n").html
        #expect(html.contains("code-window titled"))
        #expect(html.contains("<span class=\"code-title\">Demo.swift</span>"))
        #expect(html.contains("<span class=\"tok-k\">let</span>"))
        #expect(html.contains("<span class=\"tok-s\">&quot;&lt;b&gt;&quot;</span>"))
        #expect(html.contains("<span class=\"tok-c\">// note</span>"))
        #expect(!html.contains("<b>"))
    }
    @Test func highlighterEscapesEverythingAndKeepsText() {
        for lang in ["swift", "json", "bash", "python", "http", "unknown"] {
            let src = "<script>alert('x')</script> & \"q\" 12 # c"
            let out = Highlighter.highlight(src, language: lang)
            #expect(!out.contains("<script>"), "\(lang)")
            let text = out.replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
            #expect(text == HTML.escape(src), "\(lang)")
        }
    }
    @Test func everyMockupRendersAndIsLabelledAsAnIllustration() {
        for name in Showcase.names {
            let html = Showcase.render(name)
            #expect(html != nil, "\(name)")
            #expect(!(html ?? "").contains("style="), "\(name)")
            #expect(!(html ?? "").contains("<script"), "\(name)")
        }
        for name in ["signin", "payment", "conversation", "wallet", "verify", "authenticator", "lineup", "contrast"] {
            #expect(Showcase.render(name)!.lowercased().contains("illustration"), "\(name)")
        }
        #expect(Showcase.render("verify")!.contains("Planned"))
        #expect(Showcase.render("authenticator")!.contains("Planned"))
        #expect(Showcase.render("nope") == nil)
    }
    @Test func mockupTextIsLinted() throws {
        let p = try page("/x/", "title: T\nhero_art: channels", "Body.")
        let text = SiteBuilder.assembledText(p, expanded: p.body, md: Markdown())
        #expect(text.contains("Ordinary SMS is not end-to-end encrypted"))
        #expect(rules(p, text).isEmpty)
    }
    @Test func unknownMockupFailsTheBuild() throws {
        var md = Markdown()
        let p = try page("/x/", "title: T", "{{ generate: mockup nope }}\n")
        let b = SiteBuilder(options: BuildOptions(siteRoot: siteRoot))
        #expect(throws: SiteError.self) { _ = try b.expand(p, pages: [p], api: nil, md: &md) }
    }
}

@Suite("Marketing integrity lint")
struct LintTests {
    @Test func catchesEveryBannedClaim() throws {
        for phrase in IntegrityLint.bannedClaims {
            let p = try page("/x/", "title: T", "Our product is \(phrase) today.")
            #expect(rules(p).contains("banned-claim"), "\(phrase) should be banned")
        }
    }
    @Test func hyphenatedAndCasedVariantsAreCaught() throws {
        #expect(rules(try page("/x/", "title: T", "It is Zero-Knowledge and HIPAA-compliant.")).filter { $0 == "banned-claim" }.count == 2)
    }
    @Test func negatedUseIsAllowed() throws {
        #expect(rules(try page("/x/", "title: T", "We do not claim anything is unhackable. Ordinary SMS is not end-to-end encrypted.")).isEmpty)
    }
    @Test func approvedClaimWithEvidencePasses() throws {
        let ok = try page("/x/", "title: T\nclaims:\n  - phrase: end-to-end encrypted\n    feature: Identity disclosures\n    evidence: docs/SECURITY.md\n    approved_by: Security lead", "Identity disclosures are end-to-end encrypted.")
        #expect(rules(ok).isEmpty)
        let missingEvidence = try page("/x/", "title: T\nclaims:\n  - phrase: end-to-end encrypted\n    feature: f\n    evidence: \"\"\n    approved_by: me", "It is end-to-end encrypted.")
        #expect(rules(missingEvidence).contains("claim-evidence"))
        #expect(rules(missingEvidence).contains("banned-claim"))
    }
    @Test func evidenceFileMustExist() throws {
        let p = try page("/x/", "title: T\nclaims:\n  - phrase: anonymous\n    feature: f\n    evidence: docs/does-not-exist.md\n    approved_by: me", "It is anonymous.")
        let findings = IntegrityLint(repoRoot: siteRoot.deletingLastPathComponent()).check(p, assembledText: p.body)
        #expect(findings.contains { $0.rule == "claim-evidence" && $0.severity == .error })
    }
    @Test func attestationsNeedEvidence() throws {
        #expect(rules(try page("/x/", "title: T", "We are SOC 2 certified.")).contains("unearned-attestation"))
    }
    @Test func productPagesNeedAStatusBadge() throws {
        #expect(rules(try page("/products/thing/", "title: T", "Text.")).contains("product-status"))
        #expect(rules(try page("/products/thing/", "title: T\nstatus: planned", "Text.")).isEmpty)
        #expect(rules(try page("/products/thing/", "title: T\nstatus: planned", "It is now available.")).contains("product-status"))
    }
    @Test func smsFallbackMustStateNotE2EE() throws {
        #expect(rules(try page("/x/", "title: T", "Requests can use SMS fallback.")).contains("sms-not-e2ee"))
        #expect(rules(try page("/x/", "title: T", "Requests can use SMS fallback. Ordinary SMS is not end-to-end encrypted.")).isEmpty)
    }
    @Test func pricingMustDiscloseFees() throws {
        #expect(rules(try page("/x/", "title: T\npricing: true", "Cheap.")).contains("fee-disclosure"))
        #expect(rules(try page("/x/", "title: T\npricing: true", "Per-message, verification, carrier, provider and overage fees apply.")).isEmpty)
    }
    @Test func disclosuresMustBeVerbatim() throws {
        #expect(rules(try page("/x/", "title: T\ndisclosures: [mfa]", "Something else.")).contains("disclosure-verbatim"))
        #expect(rules(try page("/x/", "title: T\ndisclosures: [mfa]", "> \(Disclosures.all["mfa"]!)")).isEmpty)
    }
}

@Suite("Legal documents")
struct LegalTests {
    func legal(_ extra: String = "") throws -> Page {
        var p = try page("/legal/doc/", "title: Doc\nversion: 1.0.0\neffective_date: \"\"\nowner: Me\ncounsel_review: pending\n\(extra)", "Body")
        p.legalSlug = "doc"
        return p
    }
    @Test func draftsAreValidWithoutEffectiveDate() throws {
        let p = try legal()
        #expect(rules(p, all: [p]).isEmpty)
        #expect(LegalCatalog.status(of: p) == "draft")
    }
    @Test func cannotTakeEffectWithoutCounselApproval() throws {
        var p = try page("/legal/doc/", "title: D\nversion: 1.0.0\neffective_date: 2027-01-01\nowner: Me\ncounsel_review: pending", "x")
        p.legalSlug = "doc"
        #expect(rules(p, all: [p]).contains("legal-draft"))
    }
    @Test func missingMetadataFails() throws {
        var p = try page("/legal/doc/", "title: D", "x")
        p.legalSlug = "doc"
        #expect(rules(p, all: [p]).contains("legal-metadata"))
    }
    @Test func archiveRendersVersionHistoryAtStableURLs() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("vd-\(UUID().uuidString)")
        let fm = FileManager.default
        try fm.copyItem(at: siteRoot.appendingPathComponent("static"), to: tmp.appendingPathComponent("static"))
        try fm.createDirectory(at: tmp.appendingPathComponent("content/legal/doc/versions"), withIntermediateDirectories: true)
        try "---\ntitle: Home\n---\nHi\n".write(to: tmp.appendingPathComponent("content/index.md"), atomically: true, encoding: .utf8)
        try "---\ntitle: Legal\n---\nIndex\n".write(to: tmp.appendingPathComponent("content/legal/index.md"), atomically: true, encoding: .utf8)
        try "---\ntitle: Doc\nversion: 2.0.0\neffective_date: 2027-02-01\nowner: Me\ncounsel_review: approved\nchange_summary: Second\n---\nNew text\n".write(to: tmp.appendingPathComponent("content/legal/doc/index.md"), atomically: true, encoding: .utf8)
        try "---\ntitle: Doc\nversion: 1.0.0\neffective_date: 2026-12-01\nsuperseded_on: 2027-02-01\nowner: Me\ncounsel_review: approved\n---\nOld text\n".write(to: tmp.appendingPathComponent("content/legal/doc/versions/1.0.0.md"), atomically: true, encoding: .utf8)
        var opts = BuildOptions(siteRoot: tmp, outDir: tmp.appendingPathComponent("dist"), repoRoot: nil)
        opts.repoRoot = nil
        let report = try SiteBuilder(options: opts).build()
        #expect(report.findings.filter { $0.severity == .error }.isEmpty, "\(report.findings)")  // footer links to pages this mini-site lacks are ignored
        let current = try String(contentsOf: tmp.appendingPathComponent("dist/legal/doc/index.html"), encoding: .utf8)
        #expect(current.contains("/legal/doc/versions/1.0.0/"))
        #expect(current.contains("/legal/doc/versions/2.0.0/"))
        #expect(current.contains("Version history"))
        let old = try String(contentsOf: tmp.appendingPathComponent("dist/legal/doc/versions/1.0.0/index.html"), encoding: .utf8)
        #expect(old.contains("Old text"))
        #expect(old.contains("archived version"))
        #expect(fm.fileExists(atPath: tmp.appendingPathComponent("dist/legal/doc/versions/2.0.0/index.html").path))
        try? fm.removeItem(at: tmp)
    }
    @Test func lockDetectsEditedOrRemovedVersions() throws {
        var p = try page("/legal/doc/", "title: D\nversion: 1.0.0\neffective_date: 2027-01-01\nowner: Me\ncounsel_review: approved", "Text")
        p.legalSlug = "doc"
        let lock = LegalLock.entries(pages: [p])
        #expect(LegalLock.check(lock: lock, pages: [p]).isEmpty)
        var edited = p; edited.body = "Changed"
        #expect(!LegalLock.check(lock: lock, pages: [edited]).isEmpty)
        #expect(!LegalLock.check(lock: lock, pages: []).isEmpty)
    }
}

@Suite("OpenAPI rendering")
struct OpenAPITests {
    @Test func rendersEveryPathAndMethod() throws {
        let url = siteRoot.deletingLastPathComponent().appendingPathComponent("docs/openapi.yaml")
        let api = try OpenAPI(contentsOf: url)
        let source = try String(contentsOf: url, encoding: .utf8)
        let sourcePaths = source.components(separatedBy: "\n").filter { $0.hasPrefix("  /") && $0.hasSuffix(":") }.map { String($0.dropFirst(2).dropLast()) }
        #expect(!sourcePaths.isEmpty)
        let rendered = Set(api.operations.map(\.path))
        for path in sourcePaths { #expect(rendered.contains(path), "\(path) not rendered") }
        let html = api.tags.map { api.renderTagPage($0) }.joined()
        for op in api.operations { #expect(html.contains("id=\"op-\(op.id)\""), "\(op.id) missing") }
        // Every webhook declared in the contract is rendered (counted from the source, so adding one cannot be missed).
        let declared = try String(contentsOf: url, encoding: .utf8).components(separatedBy: "\nwebhooks:\n").last?
            .components(separatedBy: "\n").prefix { $0.isEmpty || $0.hasPrefix(" ") }.filter { $0.hasPrefix("  ") && !$0.hasPrefix("   ") }.count ?? 0
        #expect(api.webhooks.count == declared && declared > 0)
        let hooks = api.renderWebhooks()
        for (name, _) in api.webhooks { #expect(hooks.contains("event-\(slugify(name))")) }
        let schemas = api.renderSchemas()
        for (name, _) in api.spec["components"]?["schemas"]?.entries ?? [] { #expect(schemas.contains("id=\"schema-\(name)\""), "\(name)") }
    }
}

@Suite("Whole site")
struct SiteBuildTests {
    static let outDir = FileManager.default.temporaryDirectory.appendingPathComponent("vd-site-\(UUID().uuidString)")
    static let report: BuildReport = {
        var o = BuildOptions(siteRoot: siteRoot, outDir: outDir)
        o.repoRoot = siteRoot.deletingLastPathComponent()
        return try! SiteBuilder(options: o).build()
    }()

    @Test func buildsWithoutProblems() { #expect(Self.report.errors.isEmpty, "\(Self.report.errors)") }

    @Test func containsTheSitemapPages() {
        let urls = Set(Self.report.pages)
        for u in ["/", "/products/", "/products/messaging/", "/products/approve/", "/products/verify/", "/products/authenticator/",
                  "/businesses/", "/consumers/", "/developers/", "/developers/api/", "/developers/webhooks/", "/developers/errors/",
                  "/security/", "/security/disclosure/", "/privacy/", "/legal/", "/company/", "/status/"] { #expect(urls.contains(u), "\(u)") }
    }

    @Test func productStatusesAreHonest() throws {
        _ = Self.report
        let want = ["messaging": "beta", "approve": "beta", "verify": "planned", "authenticator": "planned"]
        for (slug, status) in want {
            let html = try String(contentsOf: Self.outDir.appendingPathComponent("products/\(slug)/index.html"), encoding: .utf8)
            #expect(html.contains("badge badge-\(status)"), "\(slug)")
        }
    }

    @Test func everyLegalDocumentIsADraftWithArchiveURLs() throws {
        _ = Self.report
        let slugs = ["consumer-terms", "privacy-notice", "business-services-agreement", "acceptable-use-policy", "data-processing-addendum", "subprocessors",
                     "messaging-consent-content-policy-addendum", "verification-services-addendum", "mfa-approval-services-addendum", "credential-vault-terms",
                     "vulnerability-disclosure-policy", "incident-notification-policy", "law-enforcement-request-policy", "accessibility-statement", "cookie-notice"]
        for s in slugs {
            let html = try String(contentsOf: Self.outDir.appendingPathComponent("legal/\(s)/index.html"), encoding: .utf8)
            #expect(html.contains("DRAFT. Not in effect."), "\(s)")
            #expect(html.contains("Version history"), "\(s)")
            let source = try String(contentsOf: siteRoot.appendingPathComponent("content/legal/\(s)/index.md"), encoding: .utf8)
            let version = try FrontMatter.split(source).0["version"]?.string ?? "?"
            #expect(FileManager.default.fileExists(atPath: Self.outDir.appendingPathComponent("legal/\(s)/versions/\(version)/index.html").path), "\(s) \(version)")
        }
    }

    @Test func noExternalURLsInResourcesAndNoScripts() {
        #expect(OutputChecker.check(dist: Self.outDir, config: SiteConfig()).isEmpty)
    }

    @Test func noBrokenInternalLinks() { #expect(LinkChecker.check(dist: Self.outDir).isEmpty) }

    @Test func linkCheckerCatchesBreakage() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("vd-lc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        try "<html lang=\"en\"><h1 id=\"a\">x</h1><a href=\"/nope/\">n</a><a href=\"#zzz\">z</a><a href=\"https://evil.example/x.js\">e</a><img src=\"https://evil.example/p.png\"><script>1</script></html>".write(to: tmp.appendingPathComponent("index.html"), atomically: true, encoding: .utf8)
        #expect(LinkChecker.check(dist: tmp).count == 2)
        let policy = OutputChecker.check(dist: tmp, config: SiteConfig())
        #expect(policy.contains { $0.contains("script element") })
        #expect(policy.filter { $0.contains("external reference") }.count == 2)
    }

    @Test func deploymentFiles() throws {
        _ = Self.report
        let headers = try String(contentsOf: Self.outDir.appendingPathComponent("_headers"), encoding: .utf8)
        for h in ["Strict-Transport-Security", "Content-Security-Policy", "frame-ancestors 'none'", "X-Content-Type-Options: nosniff", "Referrer-Policy", "Permissions-Policy"] { #expect(headers.contains(h), "\(h)") }
        let sec = try String(contentsOf: Self.outDir.appendingPathComponent(".well-known/security.txt"), encoding: .utf8)
        #expect(sec.contains("Contact:") && sec.contains("Expires:") && sec.contains("PLACEHOLDER"))
        let home = try String(contentsOf: Self.outDir.appendingPathComponent("index.html"), encoding: .utf8)
        #expect(home.contains("Content-Security-Policy") && home.contains("Skip to main content"))
    }

    @Test func homeHeroUsesTheRevealWithAReducedMotionStill() throws {
        _ = Self.report
        let home = try String(contentsOf: Self.outDir.appendingPathComponent("index.html"), encoding: .utf8)
        #expect(home.contains("<source media=\"(prefers-reduced-motion: reduce)\" srcset=\"/assets/media/viadere-mark-final.webp\""))
        #expect(home.contains("src=\"/assets/media/viadere-mark-reveal.webp\""))
        for f in ["viadere-mark-reveal.webp", "viadere-mark-final.webp"] {
            #expect(FileManager.default.fileExists(atPath: Self.outDir.appendingPathComponent("assets/media/\(f)").path), "\(f)")
        }
    }

    @Test func brandAssetsMatchDesignSource() throws {
        let design = siteRoot.deletingLastPathComponent().appendingPathComponent("Design/svg")
        guard FileManager.default.fileExists(atPath: design.path) else { return }
        for f in try FileManager.default.contentsOfDirectory(atPath: siteRoot.appendingPathComponent("static/brand").path) {
            let a = try Data(contentsOf: siteRoot.appendingPathComponent("static/brand/\(f)"))
            let b = try Data(contentsOf: design.appendingPathComponent(f))
            #expect(a == b, "\(f) drifted from Design/svg")
        }
    }

    @Test func sha256KnownAnswer() {
        #expect(SHA256.hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }
}
