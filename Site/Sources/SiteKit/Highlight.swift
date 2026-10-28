import Foundation

/// A small, dependency-free syntax highlighter for the fenced code blocks on the site (Swift, JSON, shell, Python, HTTP).
///
/// It tokenizes the *raw* source and escapes every token itself, so the output can only contain the `<span class="tok-…">`
/// elements it emits. Unknown languages are escaped verbatim.
public enum Highlighter {
    static let keywords: [String: Set<String>] = [
        "swift": ["import", "let", "var", "func", "try", "await", "async", "throws", "return", "guard", "else", "if", "for", "in",
                  "struct", "enum", "case", "switch", "default", "public", "private", "static", "self", "nil", "true", "false", "do", "catch"],
        "python": ["import", "from", "def", "return", "if", "else", "elif", "not", "and", "or", "in", "for", "None", "True", "False",
                   "raise", "with", "as", "try", "except", "lambda", "class"],
        "json": ["true", "false", "null"],
        "bash": ["export", "curl", "cd", "swift", "python3", "echo"],
    ]

    static func normalize(_ lang: String) -> String {
        switch lang.lowercased() {
        case "swift": return "swift"
        case "json", "jsonc": return "json"
        case "bash", "sh", "shell", "zsh", "console", "curl": return "bash"
        case "python", "py": return "python"
        case "http": return "http"
        default: return ""
        }
    }

    public static func highlight(_ source: String, language: String) -> String {
        let lang = normalize(language)
        guard !lang.isEmpty else { return HTML.escape(source) }
        if lang == "http" { return source.components(separatedBy: "\n").map(httpLine).joined(separator: "\n") }
        let kw = keywords[lang] ?? []
        let chars = Array(source)
        var out = ""
        var i = 0
        func span(_ cls: String, _ text: String) { out += "<span class=\"tok-\(cls)\">\(HTML.escape(text))</span>" }
        let lineComment: String? = lang == "swift" ? "//" : (lang == "python" || lang == "bash") ? "#" : nil
        while i < chars.count {
            let c = chars[i]
            // Comments
            if let lc = lineComment, String(chars[i..<min(chars.count, i + lc.count)]) == lc,
               lang != "bash" || i == 0 || chars[i - 1] == " " || chars[i - 1] == "\n" {
                var j = i
                while j < chars.count, chars[j] != "\n" { j += 1 }
                span("c", String(chars[i..<j])); i = j; continue
            }
            // Strings
            if c == "\"" || (c == "'" && lang != "swift") {
                var j = i + 1
                while j < chars.count, chars[j] != c, chars[j] != "\n" || lang == "bash" {
                    if chars[j] == "\\" { j += 1 }
                    j += 1
                }
                j = min(j + 1, chars.count)
                let text = String(chars[i..<j])
                // JSON object keys are strings followed by a colon.
                var k = j
                while k < chars.count, chars[k] == " " { k += 1 }
                span(lang == "json" && k < chars.count && chars[k] == ":" ? "p" : "s", text)
                i = j; continue
            }
            // Numbers
            if c.isNumber, i == 0 || !(chars[i - 1].isLetter || chars[i - 1] == "_" || chars[i - 1].isNumber) {
                var j = i
                while j < chars.count, chars[j].isNumber || chars[j] == "." || chars[j] == "_" { j += 1 }
                if j < chars.count, chars[j].isLetter { out += HTML.escape(String(chars[i..<j])); i = j; continue }
                span("n", String(chars[i..<j])); i = j; continue
            }
            // Words
            if c.isLetter || c == "_" || c == "@" || (c == "-" && lang == "bash" && i + 1 < chars.count && chars[i + 1].isLetter && (i == 0 || chars[i - 1] == " ")) {
                var j = i + 1
                while j < chars.count, chars[j].isLetter || chars[j].isNumber || chars[j] == "_" || (lang == "bash" && chars[j] == "-") { j += 1 }
                let word = String(chars[i..<j])
                if kw.contains(word) { span("k", word) }
                else if lang == "bash" && word.hasPrefix("-") { span("a", word) }
                else if lang == "swift" && word.first!.isUppercase { span("t", word) }
                else if lang == "swift" && word.hasPrefix("@") { span("a", word) }
                else if j < chars.count, chars[j] == "(" , lang != "json" { span("f", word) }
                else { out += HTML.escape(word) }
                i = j; continue
            }
            if c == "$" && lang == "bash" {
                var j = i + 1
                while j < chars.count, chars[j].isLetter || chars[j].isNumber || chars[j] == "_" { j += 1 }
                span("v", String(chars[i..<j])); i = j; continue
            }
            out += HTML.escape(String(c))
            i += 1
        }
        return out
    }

    static func httpLine(_ line: String) -> String {
        if let r = line.range(of: "^(GET|POST|PUT|PATCH|DELETE|HEAD) ", options: .regularExpression) {
            return "<span class=\"tok-k\">\(HTML.escape(String(line[r].dropLast())))</span> \(HTML.escape(String(line[r.upperBound...])))"
        }
        if let colon = line.firstIndex(of: ":"), !line.hasPrefix(" "), !line.hasPrefix("{"), line[..<colon].allSatisfy({ $0.isLetter || $0 == "-" }) {
            return "<span class=\"tok-p\">\(HTML.escape(String(line[..<colon])))</span>\(HTML.escape(String(line[colon...])))"
        }
        return HTML.escape(line)
    }
}
