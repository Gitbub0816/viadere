import Foundation

public struct Heading: Sendable, Equatable { public let level: Int; public let id: String; public let text: String }

public struct RenderedMarkdown: Sendable {
    public var html: String
    public var headings: [Heading]
}

/// A small, safe Markdown renderer. Raw HTML is never passed through (it is escaped), so content authors cannot
/// introduce scripts, inline styles or third-party resources.
///
/// Supported: ATX headings (with generated ids), paragraphs, `-`/`*`/`1.` lists with nesting, blockquotes, fenced code,
/// GFM tables, horizontal rules, `::: class` containers (nestable), inline code, links, bold, italic and `{badge:status}`.
public struct Markdown {
    public init() {}

    /// Generated HTML blocks addressed from Markdown by a placeholder paragraph, so they bypass escaping.
    public var rawBlocks: [String: String] = [:]

    public func render(_ source: String) -> RenderedMarkdown {
        var ctx = Context()
        let lines = source.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
        let html = blocks(lines, &ctx)
        return RenderedMarkdown(html: html, headings: ctx.headings)
    }

    struct Context {
        var headings: [Heading] = []
        var usedIDs: [String: Int] = [:]
        mutating func uniqueID(_ base: String) -> String {
            let n = usedIDs[base, default: 0]
            usedIDs[base] = n + 1
            return n == 0 ? base : "\(base)-\(n + 1)"
        }
    }

    // MARK: Blocks

    func blocks(_ lines: [String], _ ctx: inout Context) -> String {
        var out = ""
        var i = 0
        func indentOf(_ s: String) -> Int { s.prefix { $0 == " " }.count }
        while i < lines.count {
            let line = lines[i]
            let t = line.trimmed
            if t.isEmpty { i += 1; continue }

            // Raw generated block placeholder: `{{raw:KEY}}`
            if t.hasPrefix("{{raw:"), t.hasSuffix("}}") {
                let key = String(t.dropFirst(6).dropLast(2))
                out += (rawBlocks[key] ?? "") + "\n"
                i += 1; continue
            }
            // Fenced code
            if t.hasPrefix("```") {
                let lang = String(t.dropFirst(3)).trimmed
                var body: [String] = []
                i += 1
                while i < lines.count, !lines[i].trimmed.hasPrefix("```") { body.append(lines[i]); i += 1 }
                i += 1
                let cls = lang.isEmpty ? "" : " class=\"language-\(HTML.escape(slugify(lang)))\""
                out += "<pre tabindex=\"0\"><code\(cls)>\(HTML.escape(body.joined(separator: "\n")))</code></pre>\n"
                continue
            }
            // Container ::: name ... :::
            if t.hasPrefix(":::"), t.count > 3 {
                let name = String(t.dropFirst(3)).trimmed
                var depth = 1
                var inner: [String] = []
                i += 1
                while i < lines.count {
                    let tt = lines[i].trimmed
                    if tt == ":::" { depth -= 1; if depth == 0 { break } }
                    else if tt.hasPrefix(":::") && tt.count > 3 { depth += 1 }
                    inner.append(lines[i]); i += 1
                }
                i += 1
                let classes = name.split(separator: " ").map { slugify(String($0)) }.joined(separator: " ")
                let first = name.split(separator: " ").first.map { slugify(String($0)) } ?? ""
                let role = (first == "callout" || first == "draft-notice" || first == "note") ? " role=\"note\"" : ""
                out += "<div class=\"\(classes)\"\(role)>\n\(blocks(inner, &ctx))</div>\n"
                continue
            }
            // Heading
            if t.hasPrefix("#") {
                let hashes = t.prefix { $0 == "#" }.count
                if hashes <= 4, t.dropFirst(hashes).first == " " {
                    var text = String(t.dropFirst(hashes + 1)).trimmed
                    var explicit: String? = nil
                    if let r = text.range(of: " {#", options: .backwards), text.hasSuffix("}") {
                        explicit = String(text[r.upperBound...].dropLast())
                        text = String(text[..<r.lowerBound])
                    }
                    let plain = Self.plainText(text)
                    let id = ctx.uniqueID(explicit ?? slugify(plain))
                    if hashes >= 2 { ctx.headings.append(Heading(level: hashes, id: id, text: plain)) }
                    out += "<h\(hashes) id=\"\(id)\">\(inline(text))</h\(hashes)>\n"
                    i += 1; continue
                }
            }
            // Horizontal rule
            if t.count >= 3, t.allSatisfy({ $0 == "-" }) || t.allSatisfy({ $0 == "*" }) { out += "<hr>\n"; i += 1; continue }
            // Blockquote
            if t.hasPrefix(">") {
                var inner: [String] = []
                while i < lines.count, lines[i].trimmed.hasPrefix(">") {
                    var l = lines[i].trimmed.dropFirst()
                    if l.first == " " { l = l.dropFirst() }
                    inner.append(String(l)); i += 1
                }
                out += "<blockquote>\n\(blocks(inner, &ctx))</blockquote>\n"
                continue
            }
            // Table
            if t.contains("|"), i + 1 < lines.count, Self.isTableSeparator(lines[i + 1]) {
                let header = Self.cells(t)
                let aligns = Self.cells(lines[i + 1].trimmed)
                var rows: [[String]] = []
                i += 2
                while i < lines.count, lines[i].trimmed.contains("|"), !lines[i].trimmed.isEmpty { rows.append(Self.cells(lines[i].trimmed)); i += 1 }
                _ = aligns
                out += "<div class=\"table-wrap\" role=\"region\" tabindex=\"0\" aria-label=\"Table: \(HTML.escape(Self.plainText(header.first ?? "")))\"><table>\n<thead><tr>"
                for h in header { out += "<th scope=\"col\">\(inline(h))</th>" }
                out += "</tr></thead>\n<tbody>\n"
                for r in rows {
                    out += "<tr>"
                    for (ci, c) in r.enumerated() {
                        if ci == 0 && r.count > 1 { out += "<td>\(inline(c))</td>" } else { out += "<td>\(inline(c))</td>" }
                    }
                    out += "</tr>\n"
                }
                out += "</tbody></table></div>\n"
                continue
            }
            // List
            if Self.listMarker(line) != nil {
                let (html, next) = list(lines, from: i, &ctx)
                out += html; i = next
                continue
            }
            // Paragraph
            var para: [String] = [t]
            i += 1
            while i < lines.count {
                let n = lines[i]
                let nt = n.trimmed
                if nt.isEmpty || nt.hasPrefix("#") || nt.hasPrefix("```") || nt.hasPrefix(":::") || nt.hasPrefix(">")
                    || Self.listMarker(n) != nil || nt.hasPrefix("{{raw:") { break }
                if nt.contains("|"), i + 1 < lines.count, Self.isTableSeparator(lines[i + 1]) { break }
                para.append(nt); i += 1
            }
            out += "<p>\(inline(para.joined(separator: " ")))</p>\n"
        }
        return out
    }

    static func listMarker(_ line: String) -> (indent: Int, ordered: Bool, content: String)? {
        let indent = line.prefix { $0 == " " }.count
        let rest = line.dropFirst(indent)
        if rest.hasPrefix("- ") || rest.hasPrefix("* ") || rest.hasPrefix("+ ") {
            return (indent, false, String(rest.dropFirst(2)))
        }
        let digits = rest.prefix { $0.isNumber }
        if !digits.isEmpty, digits.count < 4, rest.dropFirst(digits.count).hasPrefix(". ") {
            return (indent, true, String(rest.dropFirst(digits.count + 2)))
        }
        return nil
    }

    func list(_ lines: [String], from start: Int, _ ctx: inout Context) -> (String, Int) {
        guard let first = Self.listMarker(lines[start]) else { return ("", start + 1) }
        let baseIndent = first.indent
        let tag = first.ordered ? "ol" : "ul"
        var out = "<\(tag)>\n"
        var i = start
        while i < lines.count {
            guard let m = Self.listMarker(lines[i]), m.indent == baseIndent, m.ordered == first.ordered else { break }
            var itemLines: [String] = [m.content]
            i += 1
            // Continuation lines: more indented than the marker (nested lists and wrapped text).
            while i < lines.count {
                let l = lines[i]
                if l.trimmed.isEmpty {
                    // A blank line continues the item only if the next non-blank line is indented deeper.
                    var j = i + 1
                    while j < lines.count, lines[j].trimmed.isEmpty { j += 1 }
                    if j < lines.count, lines[j].prefix(while: { $0 == " " }).count > baseIndent { itemLines.append(""); i += 1; continue }
                    break
                }
                let ind = l.prefix { $0 == " " }.count
                if ind > baseIndent { itemLines.append(String(l.dropFirst(min(ind, baseIndent + 2)))); i += 1 } else { break }
            }
            // If the item has nested blocks, render as blocks; otherwise inline.
            let hasNested = itemLines.dropFirst().contains { Self.listMarker($0) != nil || $0.trimmed.hasPrefix("```") || $0.trimmed.hasPrefix(":::") }
                || itemLines.contains("")
            if hasNested {
                let inner = blocks(itemLines, &ctx).replacingOccurrences(of: "<p>", with: "").replacingOccurrences(of: "</p>\n", with: "\n")
                out += "<li>\(inner.trimmed)</li>\n"
            } else {
                out += "<li>\(inline(itemLines.map { $0.trimmed }.joined(separator: " ")))</li>\n"
            }
        }
        out += "</\(tag)>\n"
        return (out, i)
    }

    static func isTableSeparator(_ s: String) -> Bool {
        let t = s.trimmed
        guard t.contains("-"), t.contains("|") || t.hasPrefix("-") || t.hasPrefix(":") else { return false }
        return t.allSatisfy { "|-: ".contains($0) } && t.contains("|")
    }

    static func cells(_ s: String) -> [String] {
        var t = s.trimmed
        if t.hasPrefix("|") { t.removeFirst() }
        if t.hasSuffix("|") && !t.hasSuffix("\\|") { t.removeLast() }
        var cells: [String] = []
        var cur = ""
        var inCode = false
        var prev: Character = " "
        for c in t {
            if c == "`" { inCode.toggle() }
            if c == "|" && !inCode && prev != "\\" { cells.append(cur.trimmed); cur = "" }
            else if c == "|" && prev == "\\" { cur.removeLast(); cur.append("|") }
            else { cur.append(c) }
            prev = c
        }
        cells.append(cur.trimmed)
        return cells
    }

    // MARK: Inline

    static func plainText(_ s: String) -> String {
        var t = s
        t = t.replacingOccurrences(of: "\\[([^\\]]+)\\]\\([^)]*\\)", with: "$1", options: .regularExpression)
        t = t.replacingOccurrences(of: "[`*]", with: "", options: .regularExpression)
        t = t.replacingOccurrences(of: "\\{badge:[a-z]+\\}", with: "", options: .regularExpression)
        return t.trimmed
    }

    public static func safeURL(_ u: String) -> String? {
        let t = u.trimmed
        if t.hasPrefix("/") || t.hasPrefix("#") || t.hasPrefix("https://") || t.hasPrefix("mailto:") { return t }
        if t.contains(":") { return nil }       // javascript:, data:, http: …
        return t                                 // relative
    }

    public func inline(_ source: String) -> String {
        var codes: [String] = []
        var s = source
        // Code spans
        if let re = try? NSRegularExpression(pattern: "(`+)(.+?)\\1") {
            let ns = s as NSString
            var result = ""
            var last = 0
            for m in re.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
                result += ns.substring(with: NSRange(location: last, length: m.range.location - last))
                codes.append("<code>\(HTML.escape(ns.substring(with: m.range(at: 2)).trimmed))</code>")
                result += "\u{E000}\(codes.count - 1)\u{E001}"
                last = m.range.location + m.range.length
            }
            result += ns.substring(from: last)
            s = result
        }
        // Backslash escapes for markdown punctuation
        var escapes: [Character] = []
        var tmp = ""
        var it = s.makeIterator()
        while let c = it.next() {
            if c == "\\", let n = it.next() {
                if "\\`*_{}[]()#+-.!|<>~:".contains(n) { escapes.append(n); tmp += "\u{E002}\(escapes.count - 1)\u{E003}" }
                else { tmp.append(c); tmp.append(n) }
            } else { tmp.append(c) }
        }
        s = HTML.escape(tmp)
        // Badges
        s = s.replacingOccurrences(of: "\\{badge:(live|beta|planned)\\}", with: "<span class=\"badge badge-$1\">$1</span>", options: .regularExpression)
        for (name, label) in [("live", "Live"), ("beta", "Beta"), ("planned", "Planned")] {
            s = s.replacingOccurrences(of: "badge badge-\(name)\">\(name)</span>", with: "badge badge-\(name)\">\(label)</span>")
        }
        // Links [text](url "title")
        if let re = try? NSRegularExpression(pattern: "\\[([^\\]]+)\\]\\(([^)\\s]+)(?:\\s+&quot;([^&]*?)&quot;)?\\)") {
            let ns = s as NSString
            var result = ""
            var last = 0
            for m in re.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
                result += ns.substring(with: NSRange(location: last, length: m.range.location - last))
                let text = ns.substring(with: m.range(at: 1))
                let rawURL = ns.substring(with: m.range(at: 2)).replacingOccurrences(of: "&amp;", with: "&")
                if let url = Self.safeURL(rawURL) {
                    result += "<a href=\"\(HTML.escape(url))\">\(text)</a>"
                } else { result += text }
                last = m.range.location + m.range.length
            }
            result += ns.substring(from: last)
            s = result
        }
        s = s.replacingOccurrences(of: "\\*\\*(?=\\S)(.+?)(?<=\\S)\\*\\*", with: "<strong>$1</strong>", options: .regularExpression)
        s = s.replacingOccurrences(of: "(?<![\\*\\w])\\*(?=[^\\s*])(.+?)(?<=[^\\s*])\\*(?![\\*\\w])", with: "<em>$1</em>", options: .regularExpression)
        s = s.replacingOccurrences(of: "(?<![\\w])_(?=[^\\s_])(.+?)(?<=[^\\s_])_(?![\\w])", with: "<em>$1</em>", options: .regularExpression)
        // Restore escapes and code
        for (n, ch) in escapes.enumerated() { s = s.replacingOccurrences(of: "\u{E002}\(n)\u{E003}", with: HTML.escape(String(ch))) }
        for (n, c) in codes.enumerated() { s = s.replacingOccurrences(of: "\u{E000}\(n)\u{E001}", with: c) }
        return s
    }
}
