import Foundation

/// Static-output policy checks: no third-party requests, no scripts, no inline styles, valid internal links.
public enum OutputChecker {
    static func htmlFiles(_ dist: URL) -> [URL] {
        var out: [URL] = []
        if let en = FileManager.default.enumerator(at: dist, includingPropertiesForKeys: nil) {
            for case let u as URL in en where u.pathExtension == "html" { out.append(u) }
        }
        return out.sorted { $0.path < $1.path }
    }

    static func matches(_ pattern: String, in text: String, group: Int = 1) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return [] }
        let ns = text as NSString
        return re.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { ns.substring(with: $0.range(at: group)) }
    }

    static func host(_ url: String) -> String? {
        var u = url
        if u.hasPrefix("//") { u = "https:" + u }
        return URL(string: u)?.host?.lowercased()
    }

    /// `config.baseURL` host and `allowedLinkHosts` may appear as navigational `<a href>`; nothing external may load.
    public static func check(dist: URL, config: SiteConfig) -> [String] {
        var problems: [String] = []
        let ownHost = host(config.baseURL) ?? "viadere.com"
        let allowedLinks = Set(config.allowedLinkHosts.map { $0.lowercased() } + [ownHost])
        let rootPath = dist.standardizedFileURL.path
        for f in htmlFiles(dist) {
            let rel = String(f.standardizedFileURL.path.dropFirst(rootPath.count))
            guard let text = try? String(contentsOf: f, encoding: .utf8) else { continue }
            for (pat, what) in [("<script\\b", "script element"), ("<style\\b", "style element"), ("<iframe\\b", "iframe"), ("<form\\b", "form"),
                                ("<object\\b", "object"), ("<embed\\b", "embed"), ("\\sstyle=\"", "inline style attribute"), ("\\son[a-z]+=\"", "inline event handler")] {
                if text.range(of: pat, options: [.regularExpression, .caseInsensitive]) != nil { problems.append("\(rel): contains \(what)") }
            }
            // Every attribute that can load or navigate.
            for tag in matches("<(a|link|img|source|video|audio|track|use|image|meta)\\b([^>]*)>", in: text, group: 0) {
                let isAnchor = tag.lowercased().hasPrefix("<a ")
                for url in matches("\\b(?:href|src|srcset|poster|content|xlink:href|data)=\"([^\"]*)\"", in: tag) {
                    guard url.hasPrefix("http://") || url.hasPrefix("https://") || url.hasPrefix("//") else { continue }
                    if tag.lowercased().hasPrefix("<meta") && !url.hasPrefix("http") { continue }
                    guard let h = host(url) else { continue }
                    if url.hasPrefix("http://") { problems.append("\(rel): insecure URL \(url)"); continue }
                    let isOwnMeta = (tag.contains("rel=\"canonical\"") || tag.contains("og:url")) && h == ownHost
                    if isOwnMeta { continue }
                    if tag.lowercased().hasPrefix("<meta") { if !(url.hasPrefix("https://\(ownHost)")) { problems.append("\(rel): external reference \(url)") }; continue }
                    if !(isAnchor && allowedLinks.contains(h)) { problems.append("\(rel): external reference \(url)") }
                }
            }
            if matches("<h1[ >]", in: text, group: 0).count != 1 { problems.append("\(rel): must contain exactly one <h1>") }
            if !text.contains("<html lang=\"en\">") { problems.append("\(rel): missing html lang") }
        }
        if let en = FileManager.default.enumerator(at: dist, includingPropertiesForKeys: nil) {
            for case let u as URL in en where u.pathExtension == "css" {
                let css = (try? String(contentsOf: u, encoding: .utf8)) ?? ""
                for url in matches("url\\(\\s*[\"']?([^)\"']+)", in: css) where url.hasPrefix("http") || url.hasPrefix("//") { problems.append("\(u.lastPathComponent): external url() \(url)") }
                if css.contains("@import") { problems.append("\(u.lastPathComponent): @import is not allowed") }
            }
        }
        return problems
    }
}

public enum LinkChecker {
    /// Verifies every internal `href`/`src` in `dist` resolves to a file, and every `#fragment` to an element id.
    public static func check(dist: URL) -> [String] {
        var problems: [String] = []
        let root = dist.standardizedFileURL
        var idCache: [String: Set<String>] = [:]
        func ids(_ file: URL) -> Set<String> {
            if let c = idCache[file.path] { return c }
            let text = (try? String(contentsOf: file, encoding: .utf8)) ?? ""
            let s = Set(OutputChecker.matches("\\sid=\"([^\"]+)\"", in: text))
            idCache[file.path] = s
            return s
        }
        func resolve(_ path: String) -> URL? {
            var p = path
            if let q = p.firstIndex(of: "?") { p = String(p[..<q]) }
            p = p.removingPercentEncoding ?? p
            let target = root.appendingPathComponent(p.hasPrefix("/") ? String(p.dropFirst()) : p)
            var isDir: ObjCBool = false
            if p.hasSuffix("/") || p.isEmpty {
                let idx = target.appendingPathComponent("index.html")
                return FileManager.default.fileExists(atPath: idx.path) ? idx : nil
            }
            if FileManager.default.fileExists(atPath: target.path, isDirectory: &isDir) { return isDir.boolValue ? nil : target }
            return nil
        }
        for f in OutputChecker.htmlFiles(dist) {
            let rel = String(f.standardizedFileURL.path.dropFirst(root.path.count))
            let text = (try? String(contentsOf: f, encoding: .utf8)) ?? ""
            let pageURL = rel.hasSuffix("/index.html") ? String(rel.dropLast("index.html".count)) : rel
            var seen = Set<String>()
            for url in OutputChecker.matches("\\b(?:href|src)=\"([^\"]*)\"", in: text) {
                let u = url.replacingOccurrences(of: "&amp;", with: "&")
                if u.hasPrefix("http") || u.hasPrefix("mailto:") || u.hasPrefix("//") || u.hasPrefix("data:") { continue }
                if u.hasPrefix("#") || u.isEmpty {
                    // `href="#"` alone is a dead link; `#main` etc. must exist on this page.
                    let frag = String(u.dropFirst())
                    if frag.isEmpty { if !u.isEmpty { problems.append("\(rel): empty fragment link") }; continue }
                    if !ids(f).contains(frag) { problems.append("\(rel): missing anchor #\(frag)") }
                    continue
                }
                if !seen.insert(u).inserted { continue }
                var path = u, frag: String? = nil
                if let h = u.firstIndex(of: "#") { path = String(u[..<h]); frag = String(u[u.index(after: h)...]) }
                if !path.hasPrefix("/") { path = pageURL + path }
                guard let file = resolve(path) else { problems.append("\(rel): broken link \(u)"); continue }
                if let fr = frag, !fr.isEmpty, file.pathExtension == "html", !ids(file).contains(fr) {
                    problems.append("\(rel): missing anchor \(u)")
                }
            }
        }
        return problems
    }
}
