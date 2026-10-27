import Foundation

/// Renders the developer portal reference from `docs/openapi.yaml` so the docs cannot drift from the contract.
public struct OpenAPI: Sendable {
    public let spec: YAML
    public init(spec: YAML) { self.spec = spec }
    public init(contentsOf url: URL) throws { self.spec = try YAMLParser.parse(try String(contentsOf: url, encoding: .utf8)) }

    public struct Operation: Sendable {
        public let path: String
        public let method: String
        public let op: YAML
        public var id: String { op["operationId"]?.string ?? slugify(method + path) }
        public var tag: String { op["tags"]?.strings.first ?? "Other" }
        public var summary: String { op["summary"]?.string ?? id }
    }

    public var title: String { spec["info"]?["title"]?.string ?? "API" }
    public var version: String { spec["info"]?["version"]?.string ?? "" }
    public var serverURL: String { spec["servers"]?.array?.first?["url"]?.string ?? "" }
    public var tags: [String] { (spec["tags"]?.array ?? []).compactMap { $0["name"]?.string } }

    public var operations: [Operation] {
        var out: [Operation] = []
        for (path, item) in spec["paths"]?.entries ?? [] {
            for (m, op) in item.entries ?? [] where ["get", "post", "put", "patch", "delete"].contains(m) {
                out.append(Operation(path: path, method: m.uppercased(), op: op))
            }
        }
        return out
    }
    public func operations(tag: String) -> [Operation] { operations.filter { $0.tag == tag } }
    public static func tagSlug(_ tag: String) -> String { slugify(tag) }

    public var webhooks: [(name: String, op: YAML)] {
        (spec["webhooks"]?.entries ?? []).compactMap { k, v in v["post"].map { (k, $0) } }
    }

    /// `info.description` split on `## ` headings: [(title, markdown)]. The leading text has title "".
    public var infoSections: [(title: String, markdown: String)] {
        let text = spec["info"]?["description"]?.string ?? ""
        var out: [(String, String)] = [("", "")]
        for line in text.components(separatedBy: "\n") {
            if line.hasPrefix("## ") { out.append((String(line.dropFirst(3)).trimmed, "")) }
            else { out[out.count - 1].1 += line + "\n" }
        }
        return out
    }

    // MARK: Resolution

    func refName(_ y: YAML) -> String? { y["$ref"]?.string?.split(separator: "/").last.map(String.init) }

    func resolve(_ y: YAML) -> YAML {
        guard let ref = y["$ref"]?.string, ref.hasPrefix("#/") else { return y }
        var cur: YAML? = spec
        for part in ref.dropFirst(2).split(separator: "/") { cur = cur?[String(part)] }
        return cur ?? y
    }

    func md(_ s: String) -> String { Markdown().render(s).html }
    func inl(_ s: String) -> String { Markdown().inline(s.trimmed) }

    // MARK: Schema helpers

    func typeLabel(_ s: YAML) -> String {
        if let n = refName(s) { return "<a href=\"/developers/schemas/#schema-\(HTML.escape(n))\">\(HTML.escape(n))</a>" }
        if let all = s["allOf"]?.array { return all.map(typeLabel).joined(separator: " + ") }
        if let one = s["oneOf"]?.array ?? s["anyOf"]?.array { return one.map(typeLabel).joined(separator: " | ") }
        if let c = s["const"]?.string { return "<code>\(HTML.escape(c))</code>" }
        let type = s["type"]?.string ?? "object"
        if type == "array", let items = s["items"] { return "array of " + typeLabel(items) }
        var t = HTML.escape(type)
        if let f = s["format"]?.string { t += " (\(HTML.escape(f)))" }
        return t
    }

    func constraints(_ s: YAML) -> String {
        var parts: [String] = []
        if let e = s["enum"]?.array { parts.append("One of " + e.compactMap { $0.string }.map { "<code>\(HTML.escape($0))</code>" }.joined(separator: ", ")) }
        for (k, label) in [("minimum", "min"), ("maximum", "max"), ("minLength", "min length"), ("maxLength", "max length"), ("minItems", "min items"), ("maxItems", "max items")] {
            if let v = s[k]?.string { parts.append("\(label) \(HTML.escape(v))") }
        }
        if let p = s["pattern"]?.string { parts.append("pattern <code>\(HTML.escape(p))</code>") }
        if let d = s["default"]?.string { parts.append("default <code>\(HTML.escape(d))</code>") }
        return parts.joined(separator: "; ")
    }

    /// Flattens `allOf` and `$ref` to (properties, required).
    func flatten(_ s: YAML) -> (props: [(key: String, value: YAML)], required: Set<String>) {
        let r = resolve(s)
        var props: [(key: String, value: YAML)] = []
        var req = Set<String>(r["required"]?.strings ?? [])
        for sub in r["allOf"]?.array ?? [] {
            let f = flatten(sub)
            for p in f.props {
                if let i = props.firstIndex(where: { $0.key == p.key }) { props[i] = p } else { props.append(p) }
            }
            req.formUnion(f.required)
        }
        for p in r["properties"]?.entries ?? [] {
            if let i = props.firstIndex(where: { $0.key == p.key }) {
                // Later definitions (e.g. `type: {const: …}`) refine earlier ones.
                props[i] = p
            } else { props.append(p) }
        }
        return (props, req)
    }

    func propertyTable(_ s: YAML) -> String {
        let (props, req) = flatten(s)
        if props.isEmpty { return "" }
        var out = "<div class=\"table-wrap\" role=\"region\" tabindex=\"0\" aria-label=\"Fields\"><table>\n<thead><tr><th scope=\"col\">Field</th><th scope=\"col\">Type</th><th scope=\"col\">Required</th><th scope=\"col\">Description</th></tr></thead>\n<tbody>\n"
        for (k, v) in props {
            let target = resolve(v)
            let desc = (v["description"]?.string ?? target["description"]?.string).map(inl) ?? ""
            let cons = constraints(target)
            out += "<tr><td><code>\(HTML.escape(k))</code></td><td>\(typeLabel(v))</td><td>\(req.contains(k) ? "Yes" : "No")</td><td>\(desc)\(desc.isEmpty || cons.isEmpty ? "" : "<br>")\(cons.isEmpty ? "" : "<span class=\"muted\">\(cons)</span>")</td></tr>\n"
        }
        return out + "</tbody></table></div>\n"
    }

    // MARK: JSON examples

    func json(_ y: YAML, _ level: Int = 0) -> String {
        let pad = String(repeating: "  ", count: level + 1), end = String(repeating: "  ", count: level)
        switch y {
        case .null: return "null"
        case let .bool(b): return b ? "true" : "false"
        case let .int(i): return String(i)
        case let .string(s):
            let data = (try? JSONSerialization.data(withJSONObject: [s], options: [.withoutEscapingSlashes])) ?? Data()
            let arr = String(decoding: data, as: UTF8.self)
            return String(arr.dropFirst().dropLast())
        case let .seq(a):
            if a.isEmpty { return "[]" }
            if a.allSatisfy({ if case .map = $0 { return false }; if case .seq = $0 { return false }; return true }) {
                return "[" + a.map { json($0) }.joined(separator: ", ") + "]"
            }
            return "[\n" + a.map { pad + json($0, level + 1) }.joined(separator: ",\n") + "\n" + end + "]"
        case let .map(m):
            if m.isEmpty { return "{}" }
            return "{\n" + m.map { "\(pad)\(json(.string($0.key))): \(json($0.value, level + 1))" }.joined(separator: ",\n") + "\n" + end + "}"
        }
    }

    // MARK: Operations

    func scope(_ op: YAML) -> String? {
        let d = op["description"]?.string ?? ""
        guard let r = d.range(of: "Requires scope `") else { return nil }
        let rest = d[r.upperBound...]
        return rest.firstIndex(of: "`").map { String(rest[..<$0]) }
    }

    public func renderOperation(_ o: Operation) -> String {
        var out = "<section class=\"op\" id=\"op-\(HTML.escape(o.id))\" aria-labelledby=\"op-\(HTML.escape(o.id))-h\">\n"
        out += "<h3 id=\"op-\(HTML.escape(o.id))-h\">\(HTML.escape(o.summary))</h3>\n"
        out += "<p class=\"endpoint\"><span class=\"method method-\(o.method.lowercased())\">\(o.method)</span> <code>\(HTML.escape(o.path))</code>"
        if let s = scope(o.op) { out += " <span class=\"chip\">scope <code>\(HTML.escape(s))</code></span>" }
        out += "</p>\n"
        if let d = o.op["description"]?.string { out += md(d) }

        var params = o.op["parameters"]?.array ?? []
        params = params.map(resolve)
        if !params.isEmpty {
            out += "<h4>Parameters</h4>\n<div class=\"table-wrap\" role=\"region\" tabindex=\"0\" aria-label=\"Parameters\"><table>\n<thead><tr><th scope=\"col\">Name</th><th scope=\"col\">In</th><th scope=\"col\">Type</th><th scope=\"col\">Required</th><th scope=\"col\">Description</th></tr></thead>\n<tbody>\n"
            for p in params {
                let schema = p["schema"] ?? .map([])
                out += "<tr><td><code>\(HTML.escape(p["name"]?.string ?? ""))</code></td><td>\(HTML.escape(p["in"]?.string ?? ""))</td><td>\(typeLabel(schema))</td><td>\(p["required"]?.bool == true ? "Yes" : "No")</td><td>\(inl(p["description"]?.string ?? ""))</td></tr>\n"
            }
            out += "</tbody></table></div>\n"
        }
        if let rb = o.op["requestBody"] {
            let body = resolve(rb)
            if let json = body["content"]?["application/json"] {
                out += "<h4>Request body</h4>\n<p class=\"muted\"><code>application/json</code>\(body["required"]?.bool == true ? ", required" : "")</p>\n"
                if let schema = json["schema"] { out += propertyTable(schema) }
                if let ex = json["examples"]?.entries?.first {
                    out += "<p class=\"muted\">Example: \(inl(ex.value["summary"]?.string ?? ex.key))</p>\n<pre tabindex=\"0\"><code class=\"language-json\">\(HTML.escape(self.json(ex.value["value"] ?? .null)))</code></pre>\n"
                }
            }
        }
        out += "<h4>Responses</h4>\n<div class=\"table-wrap\" role=\"region\" tabindex=\"0\" aria-label=\"Responses\"><table>\n<thead><tr><th scope=\"col\">Status</th><th scope=\"col\">Meaning</th><th scope=\"col\">Body</th></tr></thead>\n<tbody>\n"
        for (code, r) in o.op["responses"]?.entries ?? [] {
            let res = resolve(r)
            let schema = res["content"]?["application/json"]?["schema"]
            out += "<tr><td><code>\(HTML.escape(code))</code></td><td>\(inl(res["description"]?.string ?? ""))</td><td>\(schema.map(typeLabel) ?? "")</td></tr>\n"
        }
        out += "</tbody></table></div>\n</section>\n"
        return out
    }

    public func renderTagPage(_ tag: String) -> String {
        let ops = operations(tag: tag)
        var out = "<ul class=\"op-list\">\n"
        for o in ops { out += "<li><a href=\"#op-\(HTML.escape(o.id))\"><span class=\"method method-\(o.method.lowercased())\">\(o.method)</span> <code>\(HTML.escape(o.path))</code></a> \(inl(o.summary))</li>\n" }
        out += "</ul>\n"
        for o in ops { out += renderOperation(o) }
        return out
    }

    public func renderIndex() -> String {
        var out = ""
        for tag in tags {
            let ops = operations(tag: tag)
            if ops.isEmpty { continue }
            out += "<h2 id=\"\(Self.tagSlug(tag))\">\(HTML.escape(tag))</h2>\n<div class=\"table-wrap\" role=\"region\" tabindex=\"0\" aria-label=\"\(HTML.escape(tag)) endpoints\"><table>\n<thead><tr><th scope=\"col\">Method</th><th scope=\"col\">Path</th><th scope=\"col\">Summary</th></tr></thead>\n<tbody>\n"
            for o in ops {
                out += "<tr><td><span class=\"method method-\(o.method.lowercased())\">\(o.method)</span></td><td><a href=\"/developers/api/\(Self.tagSlug(tag))/#op-\(HTML.escape(o.id))\"><code>\(HTML.escape(o.path))</code></a></td><td>\(inl(o.summary))</td></tr>\n"
            }
            out += "</tbody></table></div>\n"
        }
        return out
    }

    public func renderWebhooks() -> String {
        var out = "<ul class=\"op-list\">\n"
        for (name, op) in webhooks { out += "<li><a href=\"#event-\(slugify(name))\"><code>\(HTML.escape(name))</code></a> \(inl(op["summary"]?.string ?? ""))</li>\n" }
        out += "</ul>\n"
        for (name, op) in webhooks {
            out += "<section class=\"op\" id=\"event-\(slugify(name))\" aria-labelledby=\"event-\(slugify(name))-h\">\n<h3 id=\"event-\(slugify(name))-h\"><code>\(HTML.escape(name))</code></h3>\n<p>\(inl(op["summary"]?.string ?? ""))</p>\n"
            if let d = op["description"]?.string { out += md(d) }
            let body = resolve(op["requestBody"] ?? .map([]))
            if let schema = body["content"]?["application/json"]?["schema"] {
                out += "<h4>Payload</h4>\n" + propertyTable(schema)
                // `data` is the event-specific part; link its schema.
                let f = flatten(schema)
                if let data = f.props.first(where: { $0.key == "data" }), refName(data.value) != nil {
                    out += "<p>The <code>data</code> field is \(typeLabel(data.value)).</p>\n"
                    out += propertyTable(data.value)
                }
            }
            out += "</section>\n"
        }
        return out
    }

    public func renderErrors() -> String {
        var seen: [String: (String, String)] = [:]
        for o in operations {
            for (code, r) in o.op["responses"]?.entries ?? [] where r["$ref"] != nil {
                let name = refName(r) ?? ""
                if Int(code) != nil, Int(code)! >= 400 { seen[code] = (name, resolve(r)["description"]?.string ?? "") }
            }
        }
        var out = "<div class=\"table-wrap\" role=\"region\" tabindex=\"0\" aria-label=\"HTTP status codes\"><table>\n<thead><tr><th scope=\"col\">HTTP status</th><th scope=\"col\">Response</th><th scope=\"col\">Meaning</th></tr></thead>\n<tbody>\n"
        for code in seen.keys.sorted() { let (n, d) = seen[code]!; out += "<tr><td><code>\(code)</code></td><td>\(HTML.escape(n))</td><td>\(inl(d))</td></tr>\n" }
        out += "</tbody></table></div>\n"
        if let e = spec["components"]?["schemas"]?["ErrorResponse"] { out += "<h3 id=\"error-body\">Error body</h3>\n" + propertyTable(e) }
        return out
    }

    public func renderSchemas() -> String {
        var out = ""
        for (name, s) in spec["components"]?["schemas"]?.entries ?? [] {
            out += "<section class=\"schema\" id=\"schema-\(HTML.escape(name))\">\n<h3 id=\"schema-\(HTML.escape(name))-h\"><code>\(HTML.escape(name))</code></h3>\n"
            if let d = s["description"]?.string { out += md(d) }
            if let e = s["enum"]?.array, s["properties"] == nil {
                out += "<p>\(typeLabel(s)); one of " + e.compactMap { $0.string }.map { "<code>\(HTML.escape($0))</code>" }.joined(separator: ", ") + ".</p>\n"
            } else if flatten(s).props.isEmpty {
                out += "<p>\(typeLabel(s))\(constraints(s).isEmpty ? "" : "; " + constraints(s)).</p>\n"
            } else { out += propertyTable(s) }
            out += "</section>\n"
        }
        return out
    }

    public func renderChannelsNote() -> String { "" }
}
