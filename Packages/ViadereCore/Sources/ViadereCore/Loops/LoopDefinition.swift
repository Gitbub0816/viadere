import Foundation

/// Where a Loop may be opened from (spec A1.2).
public enum LoopEntryPoint: String, Sendable, Codable, CaseIterable, Hashable {
    case businessPage = "business_page"
    case message
    case alert
    case widget
}

/// How a Loop looks. Appearance is independent of authorship (spec A1): a business Loop in standard styling still says who built it.
public enum LoopAppearance: Sendable, Hashable {
    case standard
    /// A Brand Kit of the **same** business, by kit key.
    case brandKit(String)
}

public enum LoopStepType: String, Sendable, Codable, CaseIterable, Hashable {
    /// Collects fields, then offers actions.
    case form
    /// Shows a recap, then offers actions.
    case summary
    /// Terminal: shows the outcome.
    case result
    /// Terminal: hands the customer to a first-party module (reserved: `shop`, Phase 4, FX-5).
    case handoff
}

/// Handoffs a step may name. Data only in Phase 3: the validator refuses every handoff until the module ships (WP-4.6).
public enum LoopHandoffKind: String, Sendable, Codable, CaseIterable, Hashable {
    /// The Shopify checkout handoff of the `shop` module (FX-5). Never paired with an amount-bearing approval.
    case shop
}

/// The closed field-type allowlist (plan section 4.3). There is **no** type for secrets, payment card or bank data, government ids,
/// health or medical information, files, or long free text: such data cannot be expressed (FX-4, FX-5).
public enum LoopFieldType: String, Sendable, Codable, CaseIterable, Hashable {
    case singleChoice = "single_choice"
    case multiChoice = "multi_choice"
    case shortText = "short_text"
    case date
    case timeSlot = "time_slot"
    case yesNo = "yes_no"
    case acknowledgement

    var hasOptions: Bool { self == .singleChoice || self == .multiChoice || self == .timeSlot }

    /// Field types a hostile or confused definition may try, with the reason they are refused. A tripwire for clear messages; the
    /// control is the closed enum above (anything not in it is refused anyway).
    static let prohibited: [String: String] = [
        "password": "secret", "secret": "secret", "pin": "secret", "otp": "secret", "passcode": "secret", "security_answer": "secret",
        "card": "payment", "card_number": "payment", "credit_card": "payment", "cvv": "payment", "cvc": "payment", "bank_account": "payment",
        "iban": "payment", "routing_number": "payment", "payment": "payment",
        "ssn": "government_id", "government_id": "government_id", "passport": "government_id", "drivers_license": "government_id",
        "national_id": "government_id", "tax_id": "government_id", "date_of_birth": "government_id",
        "health": "health", "medical": "health", "diagnosis": "health", "symptoms": "health", "medication": "health",
        "allergies": "health", "insurance_member_id": "health", "health_condition": "health",
        "long_text": "free_text", "free_text": "free_text", "textarea": "free_text", "file": "upload", "photo": "upload", "upload": "upload",
        "signature": "upload", "html": "markup", "url": "link", "link": "link",
    ]
}

public struct LoopOption: Sendable, Hashable {
    public var id: String
    public var label: String

    public init(id: String, label: String) {
        self.id = id
        self.label = label
    }
}

public struct LoopField: Sendable, Hashable {
    public var id: String
    public var type: LoopFieldType
    /// Business text, sanitized and content-checked.
    public var label: String
    public var required: Bool?
    /// Choice and time-slot fields only.
    public var options: [LoopOption]?
    /// `short_text` only; at most `LoopLimits.maxShortTextLength`.
    public var maxLength: Int?

    public init(id: String, type: LoopFieldType, label: String, required: Bool? = nil, options: [LoopOption]? = nil, maxLength: Int? = nil) {
        self.id = id
        self.type = type
        self.label = label
        self.required = required
        self.options = options
        self.maxLength = maxLength
    }
}

public struct LoopRouting: Sendable, Hashable {
    public var mode: LoopRoutingMode
    /// Hosted inbox queue key.
    public var queue: String?

    public init(mode: LoopRoutingMode, queue: String? = nil) {
        self.mode = mode
        self.queue = queue
    }
}

/// A button bound to a registered action type.
public struct LoopActionBinding: Sendable, Hashable {
    public var id: String
    /// Registered action type (`LoopActionRegistry`). Kept as a string so an unregistered or reserved name is reported, not lost.
    public var action: String
    /// A label key from the action's allowed set.
    public var label: String
    /// Sanitized custom text, `low` risk actions only.
    public var customLabel: String?
    /// The step this action leads to.
    public var next: String?
    public var routing: LoopRouting?
    /// Values for the action's registered parameters.
    public var params: [String: JSONValue]?

    public init(id: String, action: String, label: String, customLabel: String? = nil, next: String? = nil, routing: LoopRouting? = nil,
                params: [String: JSONValue]? = nil) {
        self.id = id
        self.action = action
        self.label = label
        self.customLabel = customLabel
        self.next = next
        self.routing = routing
        self.params = params
    }
}

public struct LoopStep: Sendable, Hashable {
    public var id: String
    public var type: LoopStepType
    public var title: String?
    public var body: String?
    public var fields: [LoopField]
    public var actions: [LoopActionBinding]
    /// `result` steps: show the outcome status.
    public var showOutcome: Bool?
    /// `handoff` steps.
    public var handoff: LoopHandoffKind?

    public init(id: String, type: LoopStepType, title: String? = nil, body: String? = nil, fields: [LoopField] = [],
                actions: [LoopActionBinding] = [], showOutcome: Bool? = nil, handoff: LoopHandoffKind? = nil) {
        self.id = id
        self.type = type
        self.title = title
        self.body = body
        self.fields = fields
        self.actions = actions
        self.showOutcome = showOutcome
        self.handoff = handoff
    }
}

/// Platform caps (Viadere constants) and the business's declared expiry.
public struct LoopLimits: Sendable, Hashable {
    public static let maxSteps = 8
    public static let maxFieldsPerStep = 6
    public static let maxActionsPerStep = 3
    public static let minOptions = 2
    public static let maxOptions = 10
    public static let maxShortTextLength = 80
    public static let minExpiresInSeconds: Int64 = 300
    public static let maxExpiresInSeconds: Int64 = 30 * 24 * 3600
    /// Canonical JSON size cap of a whole definition.
    public static let maxDefinitionBytes = 32 * 1024
    public static let titleLength = 60
    public static let descriptionLength = 160
    public static let stepTitleLength = 60
    public static let bodyLength = 300
    public static let fieldLabelLength = 40
    public static let optionLabelLength = 40
    public static let customLabelLength = 24

    public var expiresInSeconds: Int64

    public init(expiresInSeconds: Int64) { self.expiresInSeconds = expiresInSeconds }
}

/// A declarative, business-authored Loop definition, schema version 1 (plan section 4.3; schema `docs/protocol/schemas/loop-definition-v1.schema.json`).
///
/// Closed data: `parse` reports every unknown member, and there is no field for code, markup, links, colors, security wording or
/// attribution. `jsonValue` is the canonical form; `definitionHash` (SHA-256 of its canonical JSON) is what review approves and what the
/// publication manifest signs.
public struct LoopDefinition: Sendable, Hashable {
    public static let schemaVersion: Int64 = 1

    public var schemaVersion: Int64
    public var key: String
    public var title: String
    public var description: String?
    public var entryPoints: [LoopEntryPoint]
    public var appearance: LoopAppearance
    public var steps: [LoopStep]
    public var limits: LoopLimits

    public init(schemaVersion: Int64 = LoopDefinition.schemaVersion, key: String, title: String, description: String? = nil,
                entryPoints: [LoopEntryPoint], appearance: LoopAppearance = .standard, steps: [LoopStep], limits: LoopLimits) {
        self.schemaVersion = schemaVersion
        self.key = key
        self.title = title
        self.description = description
        self.entryPoints = entryPoints
        self.appearance = appearance
        self.steps = steps
        self.limits = limits
    }

    public func step(_ id: String) -> LoopStep? { steps.first { $0.id == id } }

    // MARK: Canonical form

    public var jsonValue: JSONValue {
        var root: [String: JSONValue] = [
            "schema_version": .integer(schemaVersion), "key": .string(key), "title": .string(title),
            "entry_points": .array(entryPoints.map { .string($0.rawValue) }),
            "steps": .array(steps.map(\.jsonValue)),
            "limits": .object(["expires_in_seconds": .integer(limits.expiresInSeconds)]),
        ]
        if let description { root["description"] = .string(description) }
        switch appearance {
        case .standard: root["appearance"] = .object(["mode": .string("standard")])
        case .brandKit(let kit): root["appearance"] = .object(["mode": .string("brand_kit"), "kit": .string(kit)])
        }
        return .object(root)
    }

    public func canonicalJSON() throws -> Data { try CanonicalJSON.serialize(jsonValue) }

    /// `sha256:<hex>` of the canonical JSON: the value review approves and the publication manifest signs.
    public func definitionHash() throws -> String { try ContractHash.sha256(jsonValue) }

    // MARK: Strict parse

    static let rootMembers: Set<String> = ["schema_version", "key", "title", "description", "entry_points", "appearance", "steps", "limits"]
    static let stepMembers: Set<String> = ["id", "type", "title", "body", "fields", "actions", "show_outcome", "handoff"]
    static let fieldMembers: Set<String> = ["id", "type", "label", "required", "options", "max_length"]
    static let actionMembers: Set<String> = ["id", "action", "label", "custom_label", "next", "routing", "params"]

    /// Reads `value` strictly. Returns the typed definition (best effort: members that could not be read are dropped) and every
    /// structural issue. A definition with any issue must not be used; `LoopPolicyValidator` reports the issues as hard-gate failures.
    public static func parse(_ value: JSONValue) -> (definition: LoopDefinition?, issues: [ContractIssue]) {
        let sink = ContractIssueSink()
        guard let root = StrictObject(value, path: "", allowed: rootMembers,
                                      required: ["schema_version", "key", "title", "entry_points", "appearance", "steps", "limits"], sink: sink) else {
            return (nil, sink.issues)
        }
        let version = root.int("schema_version") ?? 0
        if root.has("schema_version"), version != schemaVersion { sink.add("unsupported_schema_version", "schema_version") }
        let key = root.string("key") ?? ""
        let title = root.string("title") ?? ""
        let description = root.string("description")

        var entryPoints: [LoopEntryPoint] = []
        for (i, item) in (root.array("entry_points") ?? []).enumerated() {
            guard let raw = item.stringValue else { sink.add(ContractIssue.wrongType, "entry_points[\(i)]"); continue }
            guard let point = LoopEntryPoint(rawValue: raw) else { sink.add(ContractIssue.invalidValue, "entry_points[\(i)]"); continue }
            entryPoints.append(point)
        }

        var appearance = LoopAppearance.standard
        if let a = root.object("appearance", allowed: ["mode", "kit"], required: ["mode"]) {
            switch a.string("mode") {
            case "standard"?:
                if a.has("kit") { sink.add(ContractIssue.unknownMember, "appearance.kit") }
            case "brand_kit"?:
                if let kit = a.string("kit") { appearance = .brandKit(kit) } else if !a.has("kit") { sink.add(ContractIssue.missingMember, "appearance.kit") }
            case nil: break
            default: sink.add(ContractIssue.invalidValue, "appearance.mode")
            }
        }

        var limits = LoopLimits(expiresInSeconds: 0)
        if let l = root.object("limits", allowed: ["expires_in_seconds"], required: ["expires_in_seconds"]) {
            limits.expiresInSeconds = l.int("expires_in_seconds") ?? 0
        }

        var steps: [LoopStep] = []
        for (i, item) in (root.array("steps") ?? []).enumerated() {
            if let step = parseStep(item, path: "steps[\(i)]", sink: sink) { steps.append(step) }
        }

        let definition = LoopDefinition(schemaVersion: version, key: key, title: title, description: description, entryPoints: entryPoints,
                                        appearance: appearance, steps: steps, limits: limits)
        return (definition, sink.issues)
    }

    /// Parses JSON bytes (floating point anywhere is refused).
    public static func parse(_ data: Data) -> (definition: LoopDefinition?, issues: [ContractIssue]) {
        guard data.count <= LoopLimits.maxDefinitionBytes * 2, let value = JSONValue.parseContract(data) else {
            return (nil, [ContractIssue(code: "malformed_json", path: "")])
        }
        return parse(value)
    }

    private static func parseStep(_ value: JSONValue, path: String, sink: ContractIssueSink) -> LoopStep? {
        guard let s = StrictObject(value, path: path, allowed: stepMembers, required: ["id", "type"], sink: sink) else { return nil }
        let id = s.string("id") ?? ""
        guard let rawType = s.string("type") else { return nil }
        guard let type = LoopStepType(rawValue: rawType) else { sink.add("unknown_step_type", s.child("type")); return nil }
        var step = LoopStep(id: id, type: type, title: s.string("title"), body: s.string("body"), showOutcome: s.bool("show_outcome"))
        if let raw = s.string("handoff") {
            if let kind = LoopHandoffKind(rawValue: raw) { step.handoff = kind } else { sink.add(ContractIssue.invalidValue, s.child("handoff")) }
        }
        for (i, item) in (s.array("fields") ?? []).enumerated() {
            if let field = parseField(item, path: "\(path).fields[\(i)]", sink: sink) { step.fields.append(field) }
        }
        for (i, item) in (s.array("actions") ?? []).enumerated() {
            if let action = parseAction(item, path: "\(path).actions[\(i)]", sink: sink) { step.actions.append(action) }
        }
        // Each member must belong to its step type: no fields outside forms, no actions on terminals, no outcome flag off results.
        if type != .form && s.has("fields") { sink.add("member_not_allowed_for_step_type", s.child("fields")) }
        if (type == .result || type == .handoff) && s.has("actions") { sink.add("member_not_allowed_for_step_type", s.child("actions")) }
        if type != .result && s.has("show_outcome") { sink.add("member_not_allowed_for_step_type", s.child("show_outcome")) }
        if type != .handoff && s.has("handoff") { sink.add("member_not_allowed_for_step_type", s.child("handoff")) }
        if type == .handoff && !s.has("handoff") { sink.add(ContractIssue.missingMember, s.child("handoff")) }
        return step
    }

    private static func parseField(_ value: JSONValue, path: String, sink: ContractIssueSink) -> LoopField? {
        guard let f = StrictObject(value, path: path, allowed: fieldMembers, required: ["id", "type", "label"], sink: sink) else { return nil }
        guard let rawType = f.string("type") else { return nil }
        guard let type = LoopFieldType(rawValue: rawType) else {
            sink.add(LoopFieldType.prohibited[rawType.lowercased()] != nil ? "prohibited_field_type" : "unknown_field_type", f.child("type"))
            return nil
        }
        var field = LoopField(id: f.string("id") ?? "", type: type, label: f.string("label") ?? "", required: f.bool("required"))
        if let options = f.array("options") {
            field.options = []
            for (i, item) in options.enumerated() {
                guard let o = StrictObject(item, path: "\(path).options[\(i)]", allowed: ["id", "label"], required: ["id", "label"], sink: sink) else { continue }
                field.options?.append(LoopOption(id: o.string("id") ?? "", label: o.string("label") ?? ""))
            }
        }
        if let max = f.int("max_length") { field.maxLength = Int(clamping: max) }
        return field
    }

    private static func parseAction(_ value: JSONValue, path: String, sink: ContractIssueSink) -> LoopActionBinding? {
        guard let a = StrictObject(value, path: path, allowed: actionMembers, required: ["id", "action", "label"], sink: sink) else { return nil }
        var binding = LoopActionBinding(id: a.string("id") ?? "", action: a.string("action") ?? "", label: a.string("label") ?? "",
                                        customLabel: a.string("custom_label"), next: a.string("next"))
        if let r = a.object("routing", allowed: ["mode", "queue"], required: ["mode"]) {
            if let raw = r.string("mode") {
                if let mode = LoopRoutingMode(rawValue: raw) { binding.routing = LoopRouting(mode: mode, queue: r.string("queue")) } else {
                    sink.add(ContractIssue.invalidValue, r.child("mode"))
                }
            }
        }
        if a.has("params") {
            if case .object(let params)? = a.members["params"] { binding.params = params } else { sink.add(ContractIssue.wrongType, a.child("params")) }
        }
        return binding
    }
}

extension LoopStep {
    var jsonValue: JSONValue {
        var o: [String: JSONValue] = ["id": .string(id), "type": .string(type.rawValue)]
        if let title { o["title"] = .string(title) }
        if let body { o["body"] = .string(body) }
        if type == .form || !fields.isEmpty { o["fields"] = .array(fields.map(\.jsonValue)) }
        if !actions.isEmpty || type == .form || type == .summary { o["actions"] = .array(actions.map(\.jsonValue)) }
        if let showOutcome { o["show_outcome"] = .bool(showOutcome) }
        if let handoff { o["handoff"] = .string(handoff.rawValue) }
        return .object(o)
    }
}

extension LoopField {
    var jsonValue: JSONValue {
        var o: [String: JSONValue] = ["id": .string(id), "type": .string(type.rawValue), "label": .string(label)]
        if let required { o["required"] = .bool(required) }
        if let options { o["options"] = .array(options.map { .object(["id": .string($0.id), "label": .string($0.label)]) }) }
        if let maxLength { o["max_length"] = .integer(Int64(maxLength)) }
        return .object(o)
    }
}

extension LoopActionBinding {
    var jsonValue: JSONValue {
        var o: [String: JSONValue] = ["id": .string(id), "action": .string(action), "label": .string(label)]
        if let customLabel { o["custom_label"] = .string(customLabel) }
        if let next { o["next"] = .string(next) }
        if let routing {
            var r: [String: JSONValue] = ["mode": .string(routing.mode.rawValue)]
            if let queue = routing.queue { r["queue"] = .string(queue) }
            o["routing"] = .object(r)
        }
        if let params { o["params"] = .object(params) }
        return .object(o)
    }
}
