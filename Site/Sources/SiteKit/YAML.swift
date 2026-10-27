import Foundation

/// A parsed YAML value. Maps keep their key order.
public indirect enum YAML: Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int)
    case string(String)
    case seq([YAML])
    case map([(key: String, value: YAML)])

    public static func == (a: YAML, b: YAML) -> Bool {
        switch (a, b) {
        case (.null, .null): return true
        case let (.bool(x), .bool(y)): return x == y
        case let (.int(x), .int(y)): return x == y
        case let (.string(x), .string(y)): return x == y
        case let (.seq(x), .seq(y)): return x == y
        case let (.map(x), .map(y)):
            return x.count == y.count && zip(x, y).allSatisfy { $0.key == $1.key && $0.value == $1.value }
        default: return false
        }
    }

    public subscript(key: String) -> YAML? {
        if case let .map(entries) = self { return entries.first { $0.key == key }?.value }
        return nil
    }
    public var string: String? {
        switch self {
        case let .string(s): return s
        case let .int(i): return String(i)
        case let .bool(b): return b ? "true" : "false"
        default: return nil
        }
    }
    public var int: Int? { if case let .int(i) = self { return i }; return nil }
    public var bool: Bool? { if case let .bool(b) = self { return b }; return nil }
    public var array: [YAML]? { if case let .seq(a) = self { return a }; return nil }
    public var entries: [(key: String, value: YAML)]? { if case let .map(m) = self { return m }; return nil }
    public var isNull: Bool { if case .null = self { return true }; return false }
    public var strings: [String] { (array ?? []).compactMap { $0.string } }
}

public struct YAMLError: Error, CustomStringConvertible, Sendable {
    public let line: Int
    public let message: String
    public var description: String { "YAML line \(line): \(message)" }
}

/// A deliberately small YAML subset parser (block maps and sequences, flow maps and sequences on one line,
/// plain/quoted scalars, `|` and `>` block scalars, comments). It covers `docs/openapi.yaml`, `site.yaml` and
/// page front matter. Anchors, tags, multi-document streams and multi-line flow collections are not supported.
public struct YAMLParser {
    struct Line { var indent: Int; var text: String; var number: Int; var raw: String }
    var lines: [Line] = []
    var pos = 0

    public static func parse(_ source: String) throws -> YAML {
        var p = YAMLParser(source)
        p.skipBlank()
        if p.pos >= p.lines.count { return .null }
        let v = try p.parseBlock(indent: p.lines[p.pos].indent)
        p.skipBlank()
        if p.pos < p.lines.count { throw YAMLError(line: p.lines[p.pos].number, message: "unexpected content") }
        return v
    }

    init(_ source: String) {
        for (i, raw) in source.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let r = String(raw)
            let indent = r.prefix { $0 == " " }.count
            lines.append(Line(indent: indent, text: String(r.dropFirst(indent)), number: i + 1, raw: r))
        }
    }

    mutating func skipBlank() {
        while pos < lines.count {
            let t = lines[pos].text
            if t.isEmpty || t.hasPrefix("#") { pos += 1 } else { break }
        }
    }

    static func stripComment(_ s: String) -> String {
        var inS = false, inD = false
        let chars = Array(s)
        for i in chars.indices {
            let c = chars[i]
            if c == "'" && !inD { inS.toggle() }
            else if c == "\"" && !inS && (i == 0 || chars[i - 1] != "\\") { inD.toggle() }
            else if c == "#" && !inS && !inD && (i == 0 || chars[i - 1] == " ") {
                return String(chars[..<i]).trimmingCharacters(in: .whitespaces)
            }
        }
        return s.trimmingCharacters(in: .whitespaces)
    }

    /// Splits `key: rest` where the colon is outside quotes/brackets. Returns nil when the text is not a map entry.
    static func splitKey(_ s: String) -> (key: String, rest: String)? {
        let chars = Array(s)
        guard let first = chars.first else { return nil }
        if first == "{" || first == "[" { return nil }
        if first == "\"" || first == "'" {
            guard let end = closingQuote(chars, 0), end + 1 < chars.count, chars[end + 1] == ":" else { return nil }
            if end + 2 < chars.count && chars[end + 2] != " " { return nil }
            let key = (try? scalar(String(chars[0...end]), line: 0)) ?? .null
            return (key.string ?? "", String(chars[(end + 2)...]).trimmingCharacters(in: .whitespaces))
        }
        var i = 0
        while i < chars.count {
            if chars[i] == ":" && (i + 1 == chars.count || chars[i + 1] == " ") {
                return (String(chars[..<i]).trimmingCharacters(in: .whitespaces),
                        String(chars[(i + 1)...]).trimmingCharacters(in: .whitespaces))
            }
            i += 1
        }
        return nil
    }

    /// Open `[`/`{` minus closed ones, ignoring brackets inside quotes (for flow collections that span lines).
    static func flowDepth(_ s: String) -> Int {
        var depth = 0
        var quote: Character? = nil
        var prev: Character = " "
        var significant: Character = "{"   // last non-space character outside quotes
        for c in s {
            if let q = quote {
                if c == q && !(q == "\"" && prev == "\\") { quote = nil; significant = c }
            } else if (c == "\"" || c == "'") && "{[,:".contains(significant) {
                quote = c   // quotes only open at the start of a token, so "currency's" does not count
            } else {
                if c == "[" || c == "{" { depth += 1 } else if c == "]" || c == "}" { depth -= 1 }
                if c != " " { significant = c }
            }
            prev = c
        }
        return depth
    }

    static func closingQuote(_ chars: [Character], _ start: Int) -> Int? {
        let q = chars[start]
        var i = start + 1
        while i < chars.count {
            if q == "\"" && chars[i] == "\\" { i += 2; continue }
            if chars[i] == q {
                if q == "'" && i + 1 < chars.count && chars[i + 1] == "'" { i += 2; continue }
                return i
            }
            i += 1
        }
        return nil
    }

    mutating func parseBlock(indent: Int) throws -> YAML {
        skipBlank()
        guard pos < lines.count else { return .null }
        let line = lines[pos]
        if line.text == "-" || line.text.hasPrefix("- ") { return try parseSeq(indent: line.indent) }
        if Self.splitKey(Self.stripComment(line.text)) != nil { return try parseMap(indent: line.indent) }
        // A lone scalar (or flow collection).
        pos += 1
        return try Self.value(Self.stripComment(line.text), line: line.number)
    }

    mutating func parseSeq(indent: Int) throws -> YAML {
        var items: [YAML] = []
        while true {
            skipBlank()
            guard pos < lines.count, lines[pos].indent == indent,
                  lines[pos].text == "-" || lines[pos].text.hasPrefix("- ") else { break }
            let line = lines[pos]
            let rest = String(line.text.dropFirst(1)).trimmingCharacters(in: .whitespaces)
            if rest.isEmpty {
                pos += 1
                skipBlank()
                if pos < lines.count, lines[pos].indent > indent { items.append(try parseBlock(indent: lines[pos].indent)) }
                else { items.append(.null) }
                continue
            }
            let offset = line.text.count - rest.count
            let stripped = Self.stripComment(rest)
            if Self.splitKey(stripped) != nil || stripped == "-" || stripped.hasPrefix("- ") {
                // Re-present the item content as a block indented to its own column.
                lines[pos] = Line(indent: indent + offset, text: rest, number: line.number, raw: line.raw)
                items.append(try parseBlock(indent: indent + offset))
            } else {
                pos += 1
                items.append(try Self.value(stripped, line: line.number))
            }
        }
        return .seq(items)
    }

    mutating func parseMap(indent: Int) throws -> YAML {
        var entries: [(key: String, value: YAML)] = []
        while true {
            skipBlank()
            guard pos < lines.count, lines[pos].indent == indent else { break }
            let line = lines[pos]
            if line.text == "-" || line.text.hasPrefix("- ") { break }
            guard let (key, restRaw) = Self.splitKey(Self.stripComment(line.text)) else {
                throw YAMLError(line: line.number, message: "expected `key: value`")
            }
            pos += 1
            let rest = restRaw
            if rest.hasPrefix("|") || rest.hasPrefix(">") {
                entries.append((key, .string(blockScalar(header: rest, parentIndent: indent))))
            } else if rest.isEmpty {
                skipBlank()
                if pos < lines.count, lines[pos].indent > indent {
                    entries.append((key, try parseBlock(indent: lines[pos].indent)))
                } else if pos < lines.count, lines[pos].indent == indent,
                          lines[pos].text == "-" || lines[pos].text.hasPrefix("- ") {
                    entries.append((key, try parseSeq(indent: indent)))
                } else {
                    entries.append((key, .null))
                }
            } else if rest.hasPrefix("{") || rest.hasPrefix("[") || rest.hasPrefix("\"") || rest.hasPrefix("'") {
                var text = rest
                while Self.flowDepth(text) > 0, pos < lines.count {
                    text += " " + Self.stripComment(lines[pos].text)
                    pos += 1
                }
                entries.append((key, try Self.value(text, line: line.number)))
            } else {
                // Plain scalar, possibly continued on deeper-indented lines.
                var text = rest
                while pos < lines.count, !lines[pos].text.isEmpty, lines[pos].indent > indent,
                      !lines[pos].text.hasPrefix("#") {
                    text += " " + Self.stripComment(lines[pos].text)
                    pos += 1
                }
                entries.append((key, try Self.value(text, line: line.number)))
            }
        }
        return .map(entries)
    }

    mutating func blockScalar(header: String, parentIndent: Int) -> String {
        let folded = header.hasPrefix(">")
        let strip = header.contains("-")
        var collected: [String] = []
        var blockIndent: Int? = nil
        while pos < lines.count {
            let l = lines[pos]
            if l.text.isEmpty { collected.append(""); pos += 1; continue }
            if l.indent <= parentIndent { break }
            if blockIndent == nil { blockIndent = l.indent }
            let bi = blockIndent!
            collected.append(l.indent >= bi ? String(l.raw.dropFirst(bi)) : l.text)
            pos += 1
        }
        while collected.last == "" { collected.removeLast() }
        // Blank lines consumed from beyond the block belong to the next entry; nothing to restore (we only dropped trailing blanks).
        var out: String
        if folded {
            var parts: [String] = []
            var para: [String] = []
            for l in collected {
                if l.isEmpty { parts.append(para.joined(separator: " ")); para = [] } else { para.append(l) }
            }
            parts.append(para.joined(separator: " "))
            out = parts.joined(separator: "\n")
        } else {
            out = collected.joined(separator: "\n")
        }
        return strip ? out : out + "\n"
    }

    // MARK: Scalars and flow collections

    static func value(_ s: String, line: Int) throws -> YAML {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("{") || t.hasPrefix("[") {
            var chars = Array(t)
            var i = 0
            let v = try flow(&chars, &i, line: line)
            return v
        }
        return try scalar(t, line: line)
    }

    static func scalar(_ t: String, line: Int) throws -> YAML {
        if t.hasPrefix("\"") {
            let chars = Array(t)
            guard let end = closingQuote(chars, 0), end == chars.count - 1 else { throw YAMLError(line: line, message: "unterminated string") }
            var out = ""
            var i = 1
            while i < end {
                let c = chars[i]
                if c == "\\", i + 1 < end {
                    i += 1
                    switch chars[i] {
                    case "n": out.append("\n")
                    case "t": out.append("\t")
                    case "\"": out.append("\"")
                    case "\\": out.append("\\")
                    case "/": out.append("/")
                    case "u":
                        let hex = String(chars[(i + 1)..<min(i + 5, end)])
                        if let n = UInt32(hex, radix: 16), let u = Unicode.Scalar(n) { out.unicodeScalars.append(u); i += 4 }
                    default: out.append(chars[i])
                    }
                } else { out.append(c) }
                i += 1
            }
            return .string(out)
        }
        if t.hasPrefix("'") {
            let chars = Array(t)
            guard let end = closingQuote(chars, 0), end == chars.count - 1 else { throw YAMLError(line: line, message: "unterminated string") }
            return .string(String(chars[1..<end]).replacingOccurrences(of: "''", with: "'"))
        }
        switch t {
        case "", "~", "null", "Null", "NULL": return .null
        case "true", "True": return .bool(true)
        case "false", "False": return .bool(false)
        default: break
        }
        if let n = Int(t), !(t.hasPrefix("0") && t.count > 1) { return .int(n) }
        return .string(t)
    }

    static func flow(_ c: inout [Character], _ i: inout Int, line: Int) throws -> YAML {
        func ws() { while i < c.count, c[i] == " " { i += 1 } }
        ws()
        guard i < c.count else { throw YAMLError(line: line, message: "unexpected end of flow collection") }
        if c[i] == "[" {
            i += 1
            var items: [YAML] = []
            while true {
                ws()
                guard i < c.count else { throw YAMLError(line: line, message: "unterminated [") }
                if c[i] == "]" { i += 1; break }
                items.append(try flow(&c, &i, line: line))
                ws()
                if i < c.count, c[i] == "," { i += 1 }
            }
            return .seq(items)
        }
        if c[i] == "{" {
            i += 1
            var entries: [(key: String, value: YAML)] = []
            while true {
                ws()
                guard i < c.count else { throw YAMLError(line: line, message: "unterminated {") }
                if c[i] == "}" { i += 1; break }
                let k = try flowScalarText(&c, &i, stops: [":", ",", "}"], line: line)
                ws()
                var v: YAML = .null
                if i < c.count, c[i] == ":" {
                    i += 1
                    ws()
                    v = try flow(&c, &i, line: line)
                }
                entries.append((try scalar(k, line: line).string ?? k, v))
                ws()
                if i < c.count, c[i] == "," { i += 1 }
            }
            return .map(entries)
        }
        let text = try flowScalarText(&c, &i, stops: [",", "]", "}"], line: line)
        return try scalar(text, line: line)
    }

    static func flowScalarText(_ c: inout [Character], _ i: inout Int, stops: Set<Character>, line: Int) throws -> String {
        guard i < c.count else { return "" }
        if c[i] == "\"" || c[i] == "'" {
            guard let end = closingQuote(c, i) else { throw YAMLError(line: line, message: "unterminated string") }
            let s = String(c[i...end]); i = end + 1
            return s
        }
        let start = i
        while i < c.count {
            if stops.contains(c[i]) {
                // A colon only ends a key when followed by a space or a stop; keep `https://` style text intact.
                if c[i] == ":" && !(i + 1 == c.count || c[i + 1] == " ") { i += 1; continue }
                break
            }
            i += 1
        }
        return String(c[start..<i]).trimmingCharacters(in: .whitespaces)
    }
}
