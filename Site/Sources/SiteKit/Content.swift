import Foundation

public struct SiteConfig: Sendable {
    public var name = "Viadere"
    public var tagline = "A trusted way to connect."
    public var baseURL = "https://viadere.com"
    /// Hosts that may appear in `<a href>` (never in resource attributes).
    public var allowedLinkHosts: [String] = ["www.rfc-editor.org"]
    public var openapiPath = "../docs/openapi.yaml"
    public var securityContact = "mailto:[SECURITY-CONTACT-PLACEHOLDER]"
    public var securityExpires = "[EXPIRES-PLACEHOLDER: RFC 3339 date-time within 12 months]"
    public var securityPolicyURL = "https://viadere.com/legal/vulnerability-disclosure-policy/"
    public var securityCanonical = "https://viadere.com/.well-known/security.txt"
    public var nav: [(title: String, path: String)] = [
        ("Products", "/products/"), ("Businesses", "/businesses/"), ("Consumers", "/consumers/"),
        ("Developers", "/developers/"), ("Security & Trust", "/security/"), ("Privacy", "/privacy/"),
    ]

    public init() {}

    public static func load(from url: URL) throws -> SiteConfig {
        var c = SiteConfig()
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return c }
        let y = try YAMLParser.parse(text)
        if let v = y["name"]?.string { c.name = v }
        if let v = y["tagline"]?.string { c.tagline = v }
        if let v = y["base_url"]?.string { c.baseURL = v.hasSuffix("/") ? String(v.dropLast()) : v }
        if let v = y["allowed_link_hosts"]?.strings as [String]? { c.allowedLinkHosts = v }
        if let v = y["openapi"]?.string { c.openapiPath = v }
        if let v = y["security_contact"]?.string { c.securityContact = v }
        if let v = y["security_expires"]?.string { c.securityExpires = v }
        if let v = y["security_policy"]?.string { c.securityPolicyURL = v }
        if let v = y["security_canonical"]?.string { c.securityCanonical = v }
        return c
    }
}

public struct Claim: Sendable {
    public var phrase: String
    public var feature: String
    public var evidence: String
    public var approvedBy: String
}

public enum ProductStatus: String, Sendable, CaseIterable {
    case live, beta, planned
    public var label: String { rawValue.capitalized }
}

public struct Page: Sendable {
    public var sourcePath: String          // relative to content/
    public var url: String                 // "/products/messaging/"
    public var front: YAML
    public var body: String                // Markdown (directives expanded after load)
    public var generated = false
    public var legalSlug: String? = nil
    public var legalIsArchive = false
    /// The stable `/legal/{slug}/versions/{version}/` address of the current version (until an archive file replaces it).
    public var legalPermalink = false

    public var title: String { front["title"]?.string ?? "Untitled" }
    public var description: String { front["description"]?.string ?? "" }
    public var layout: String { front["layout"]?.string ?? "page" }
    public var order: Int { front["order"]?.int ?? 100 }
    public var section: String { url.split(separator: "/").first.map(String.init) ?? "" }
    public var status: ProductStatus? { front["status"]?.string.flatMap { ProductStatus(rawValue: $0.lowercased()) } }
    public var isProductPage: Bool { url.hasPrefix("/products/") && url.split(separator: "/").count == 2 }
    public var noindex: Bool { front["noindex"]?.bool ?? false }
    public var claims: [Claim] {
        (front["claims"]?.array ?? []).map {
            Claim(phrase: $0["phrase"]?.string ?? "", feature: $0["feature"]?.string ?? "",
                  evidence: $0["evidence"]?.string ?? "", approvedBy: $0["approved_by"]?.string ?? "")
        }
    }
    public var isLegal: Bool { legalSlug != nil }
}

public struct LegalVersion: Sendable {
    public var version: String
    public var effectiveDate: String
    public var counselReview: String
    public var url: String
    public var isCurrent: Bool
    public var supersededOn: String
    public var summary: String
}

public enum FrontMatter {
    /// Splits `---` delimited front matter from the body.
    public static func split(_ source: String, file: String = "") throws -> (YAML, String) {
        let text = source.replacingOccurrences(of: "\r\n", with: "\n")
        guard text.hasPrefix("---\n") else { return (.map([]), text) }
        let rest = text.dropFirst(4)
        guard let end = rest.range(of: "\n---\n") ?? (rest.hasSuffix("\n---") ? rest.range(of: "\n---", options: .backwards) : nil) else {
            throw SiteError("\(file): front matter is not closed with ---")
        }
        let yamlText = String(rest[..<end.lowerBound])
        let body = String(rest[end.upperBound...])
        do { return (try YAMLParser.parse(yamlText), body) }
        catch { throw SiteError("\(file): \(error)") }
    }
}

public struct ContentLoader {
    public let root: URL   // Site/content
    public init(root: URL) { self.root = root }

    public func load() throws -> [Page] {
        var pages: [Page] = []
        let fm = FileManager.default
        guard let en = fm.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]) else { return [] }
        var files: [URL] = []
        for case let u as URL in en where u.pathExtension == "md" { files.append(u) }
        files.sort { $0.path < $1.path }
        let rootPath = root.standardizedFileURL.path
        for f in files {
            let rel = String(f.standardizedFileURL.path.dropFirst(rootPath.count + 1))
            let (front, body) = try FrontMatter.split(try String(contentsOf: f, encoding: .utf8), file: rel)
            var comps = rel.dropLast(3).split(separator: "/").map(String.init)
            var page = Page(sourcePath: rel, url: "/", front: front, body: body)
            // Legal archives: legal/<slug>/versions/<version>.md  →  /legal/<slug>/versions/<version>/
            if comps.count == 4, comps[0] == "legal", comps[2] == "versions" {
                page.legalSlug = comps[1]; page.legalIsArchive = true
                let v = front["version"]?.string ?? comps[3]
                if v != comps[3] { throw SiteError("\(rel): front matter version \(v) must match the file name \(comps[3])") }
                page.url = "/legal/\(comps[1])/versions/\(comps[3])/"
            } else {
                if comps.last == "index" { comps.removeLast() }
                if comps.count == 2, comps[0] == "legal" { page.legalSlug = comps[1] }
                page.url = "/" + comps.map { $0 }.joined(separator: "/") + (comps.isEmpty ? "" : "/")
            }
            if let override = front["path"]?.string { page.url = override }
            pages.append(page)
        }
        return pages
    }
}

public enum LegalCatalog {
    /// Version history for one legal document: archived versions plus the current one, newest first.
    public static func history(slug: String, pages: [Page]) -> [LegalVersion] {
        var out: [LegalVersion] = []
        for p in pages where p.legalSlug == slug {
            out.append(LegalVersion(
                version: p.front["version"]?.string ?? "?", effectiveDate: p.front["effective_date"]?.string ?? "",
                counselReview: p.front["counsel_review"]?.string ?? "pending",
                url: p.legalIsArchive ? p.url : "/legal/\(slug)/versions/\(p.front["version"]?.string ?? "?")/",
                isCurrent: !p.legalIsArchive, supersededOn: p.front["superseded_on"]?.string ?? "",
                summary: p.front["change_summary"]?.string ?? ""))
        }
        return out.sorted { compareVersions($0.version, $1.version) > 0 }
    }

    public static func compareVersions(_ a: String, _ b: String) -> Int {
        let x = a.split(separator: ".").map { Int($0) ?? 0 }, y = b.split(separator: ".").map { Int($0) ?? 0 }
        for i in 0..<max(x.count, y.count) {
            let l = i < x.count ? x[i] : 0, r = i < y.count ? y[i] : 0
            if l != r { return l < r ? -1 : 1 }
        }
        return 0
    }

    public static func status(of p: Page) -> String {
        let eff = p.front["effective_date"]?.string ?? ""
        let review = p.front["counsel_review"]?.string ?? "pending"
        return (eff.isEmpty || review != "approved") ? "draft" : "approved"
    }
}
