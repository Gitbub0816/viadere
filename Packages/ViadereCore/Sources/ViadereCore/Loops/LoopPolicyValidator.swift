import Foundation

/// Who published a Loop: derived by the **server** from its own business record and the authenticated principal, never from the
/// definition, uploaded artwork or a client claim (spec A6a.3). It becomes the publication manifest's publisher fields.
public enum LoopPublisherType: String, Sendable, Codable, CaseIterable, Hashable {
    case viadere, business
}

public struct LoopPublisherIdentity: Sendable, Hashable {
    public var publisherType: LoopPublisherType
    /// Required for `business`; absent for `viadere`.
    public var businessId: BusinessID?
    public var verificationStatus: VerificationStatus
    public var category: BusinessCategory

    public init(publisherType: LoopPublisherType, businessId: BusinessID?, verificationStatus: VerificationStatus, category: BusinessCategory) {
        self.publisherType = publisherType
        self.businessId = businessId
        self.verificationStatus = verificationStatus
        self.category = category
    }

    /// A verified business publisher.
    public static func business(_ id: BusinessID, status: VerificationStatus = .verified, category: BusinessCategory = .retail) -> LoopPublisherIdentity {
        LoopPublisherIdentity(publisherType: .business, businessId: id, verificationStatus: status, category: category)
    }
}

/// Inputs of `LoopPolicyValidator` that come from the server's own records.
public struct LoopValidationContext: Sendable {
    /// The tenant submitting the definition (from the authenticated principal).
    public var submittingBusinessId: BusinessID
    /// Publisher identity for attribution; `nil` fails the gate (`attribution_missing`).
    public var publisher: LoopPublisherIdentity?
    public var phase: LoopPlatformPhase
    public var registry: LoopActionRegistry
    /// Brand Kit keys the business owns; `nil` skips that check (device-side re-validation).
    public var brandKitKeys: Set<String>?
    /// Handoffs whose module has shipped and is enabled. Empty until WP-4.6.
    public var enabledHandoffs: Set<LoopHandoffKind>
    /// Set only by `PresentationBuilder` for a verified first-party (`viadere`) manifest. Not public: no caller can switch the
    /// publisher rules off.
    var skipsPublisherRules = false

    public init(submittingBusinessId: BusinessID, publisher: LoopPublisherIdentity?, phase: LoopPlatformPhase = .hosted,
                registry: LoopActionRegistry = .v1, brandKitKeys: Set<String>? = nil, enabledHandoffs: Set<LoopHandoffKind> = []) {
        self.submittingBusinessId = submittingBusinessId
        self.publisher = publisher
        self.phase = phase
        self.registry = registry
        self.brandKitKeys = brandKitKeys
        self.enabledHandoffs = enabledHandoffs
    }
}

/// Rule codes of the hard gate and the review flags. Stable `snake_case` strings: they are shown to authors, stored in
/// `loop_reviews.rule_hits_json` and listed in the conformance vectors.
public enum LoopRule: String, Sendable, Codable, CaseIterable, Hashable {
    // Structure
    case malformedJSON = "malformed_json"
    case unknownMember = "unknown_member"
    case missingMember = "missing_member"
    case wrongType = "wrong_type"
    case invalidValue = "invalid_value"
    case unsupportedSchemaVersion = "unsupported_schema_version"
    case unknownStepType = "unknown_step_type"
    case memberNotAllowedForStepType = "member_not_allowed_for_step_type"
    case invalidIdentifier = "invalid_identifier"
    case duplicateId = "duplicate_id"
    case definitionTooLarge = "definition_too_large"
    case tooManySteps = "too_many_steps"
    case noSteps = "no_steps"
    case tooManyFields = "too_many_fields"
    case noFields = "no_fields"
    case tooManyActions = "too_many_actions"
    case invalidOptions = "invalid_options"
    case invalidLimit = "invalid_limit"
    case unknownBrandKit = "unknown_brand_kit"
    // Text
    case emptyText = "empty_text"
    case textTooLong = "text_too_long"
    case disallowedCharacters = "disallowed_characters"
    case impersonation
    case healthContent = "health_content"
    case sensitiveDataRequest = "sensitive_data_request"
    case attributionSpoofing = "attribution_spoofing"
    case linkNotAllowed = "link_not_allowed"
    // Fields
    case unknownFieldType = "unknown_field_type"
    case prohibitedFieldType = "prohibited_field_type"
    case freeTextInHighRisk = "free_text_in_high_risk"
    // Actions
    case unregisteredAction = "unregistered_action"
    case reservedAction = "reserved_action"
    case actionNotAvailable = "action_not_available"
    case labelNotAllowed = "label_not_allowed"
    case customLabelNotAllowed = "custom_label_not_allowed"
    case unknownParameter = "unknown_parameter"
    case missingParameter = "missing_parameter"
    case invalidParameter = "invalid_parameter"
    case missingRouting = "missing_routing"
    case routingNotAllowed = "routing_not_allowed"
    case routingModeNotAvailable = "routing_mode_not_available"
    case missingConfirmation = "missing_confirmation"
    case approvalWithCheckout = "approval_with_checkout"
    case handoffNotAvailable = "handoff_not_available"
    // Graph
    case missingNext = "missing_next"
    case unknownNextStep = "unknown_next_step"
    case cycle
    case unreachableStep = "unreachable_step"
    case noTerminalStep = "no_terminal_step"
    case entryIsTerminal = "entry_is_terminal"
    case deadEnd = "dead_end"
    case missingEntryPoint = "missing_entry_point"
    // Publisher and category
    case attributionMissing = "attribution_missing"
    case attributionMismatch = "attribution_mismatch"
    case publisherNotBusiness = "publisher_not_business"
    case publisherNotVerified = "publisher_not_verified"
    case categoryBanned = "category_banned"
    case categoryProhibited = "category_prohibited"
    // Review flags (never fail the gate; force a second reviewer)
    case healthAdjacentContent = "health_adjacent_content"
    case authorityClaim = "authority_claim"
    case highRiskAction = "high_risk_action"

    /// Review flags raise the review level; everything else is a hard-gate failure.
    public var isReviewFlag: Bool { self == .healthAdjacentContent || self == .authorityClaim || self == .highRiskAction }
}

public struct LoopRuleHit: Sendable, Hashable, Codable, CustomStringConvertible {
    public var rule: LoopRule
    public var path: String
    public var detail: String?

    public init(rule: LoopRule, path: String, detail: String? = nil) {
        self.rule = rule
        self.path = path
        self.detail = detail
    }

    public var description: String { "\(rule.rawValue) at \(path)" + (detail.map { " (\($0))" } ?? "") }
}

public enum LoopReviewLevel: String, Sendable, Codable, Hashable {
    /// One Viadere operator (every Loop and revision, FX-3).
    case single
    /// Two different operators: high risk, or any review flag (plan section 4.12 stage 3, section 4.13 layer 2).
    case twoPerson = "two_person"
}

/// A hard-gate failure. It has **no public initializer and no override**: only `LoopPolicyValidator` creates one, and nothing turns it
/// into a pass. A human reviewer cannot waive it; only a rule-set change (code + ADR) can (FX-3).
public struct LoopHardGateFailure: Error, Sendable, Hashable {
    public let hits: [LoopRuleHit]
    fileprivate init(hits: [LoopRuleHit]) { self.hits = hits }
}

public enum LoopHardGate: Sendable, Hashable {
    case passed
    case failed(LoopHardGateFailure)

    public var passed: Bool { if case .passed = self { true } else { false } }
}

/// The validator's output, used by Studio (live) and by the publication gate. Created only by `LoopPolicyValidator`.
public struct LoopValidationReport: Sendable, Hashable {
    public let hits: [LoopRuleHit]
    public let derivedRiskClass: LoopRiskClass
    public let requiredReview: LoopReviewLevel
    /// Canonical hash of the definition that was validated; `nil` when it could not be parsed.
    public let definitionHash: String?
    public let ruleSetVersion: Int
    public let registryVersion: Int

    fileprivate init(hits: [LoopRuleHit], derivedRiskClass: LoopRiskClass, requiredReview: LoopReviewLevel, definitionHash: String?,
                     ruleSetVersion: Int, registryVersion: Int) {
        self.hits = hits
        self.derivedRiskClass = derivedRiskClass
        self.requiredReview = requiredReview
        self.definitionHash = definitionHash
        self.ruleSetVersion = ruleSetVersion
        self.registryVersion = registryVersion
    }

    public var hardGateHits: [LoopRuleHit] { hits.filter { !$0.rule.isReviewFlag } }
    public var reviewFlags: [LoopRuleHit] { hits.filter { $0.rule.isReviewFlag } }
    public var rules: Set<LoopRule> { Set(hits.map(\.rule)) }

    public var gate: LoopHardGate {
        let hard = hardGateHits
        return hard.isEmpty && definitionHash != nil ? .passed : .failed(LoopHardGateFailure(hits: hard.isEmpty ? [LoopRuleHit(rule: .malformedJSON, path: "")] : hard))
    }
}

/// The automated hard gate of the Loop review pipeline (plan section 4.12 stage 1; FX-3, FX-4, FX-5). Runs on submit and again on
/// publish (server), and once more on the device before rendering (`PresentationBuilder`, defense in depth).
public enum LoopPolicyValidator {
    public static let ruleSetVersion = LoopContentRules.version

    /// Validates raw JSON bytes (the submitted document).
    public static func validate(_ data: Data, context: LoopValidationContext) -> LoopValidationReport {
        guard data.count <= LoopLimits.maxDefinitionBytes * 2, let value = JSONValue.parseContract(data) else {
            return LoopValidationReport(hits: [LoopRuleHit(rule: .malformedJSON, path: "")], derivedRiskClass: .low, requiredReview: .single,
                                        definitionHash: nil, ruleSetVersion: ruleSetVersion, registryVersion: context.registry.version)
        }
        return validate(value, context: context)
    }

    /// Validates a JSON value.
    public static func validate(_ value: JSONValue, context: LoopValidationContext) -> LoopValidationReport {
        let (definition, issues) = LoopDefinition.parse(value)
        var hits = issues.map { LoopRuleHit(rule: LoopRule(rawValue: $0.code) ?? .invalidValue, path: $0.path) }
        guard let definition else {
            return LoopValidationReport(hits: hits.isEmpty ? [LoopRuleHit(rule: .malformedJSON, path: "")] : hits, derivedRiskClass: .low,
                                        requiredReview: .single, definitionHash: nil, ruleSetVersion: ruleSetVersion, registryVersion: context.registry.version)
        }
        let (semantic, risk) = check(definition, context: context)
        hits += semantic
        let review: LoopReviewLevel = risk == .high || hits.contains(where: { $0.rule.isReviewFlag }) ? .twoPerson : .single
        return LoopValidationReport(hits: dedupe(hits), derivedRiskClass: risk, requiredReview: review,
                                    definitionHash: try? definition.definitionHash(), ruleSetVersion: ruleSetVersion,
                                    registryVersion: context.registry.version)
    }

    /// Validates a typed definition (round-trips through its canonical JSON so it gets exactly the same treatment as submitted bytes).
    public static func validate(_ definition: LoopDefinition, context: LoopValidationContext) -> LoopValidationReport {
        validate(definition.jsonValue, context: context)
    }

    private static func dedupe(_ hits: [LoopRuleHit]) -> [LoopRuleHit] {
        var seen = Set<LoopRuleHit>()
        return hits.filter { seen.insert($0).inserted }
    }

    // MARK: Semantic rules

    static func check(_ d: LoopDefinition, context: LoopValidationContext) -> ([LoopRuleHit], LoopRiskClass) {
        var hits: [LoopRuleHit] = []
        func hit(_ rule: LoopRule, _ path: String, _ detail: String? = nil) { hits.append(LoopRuleHit(rule: rule, path: path, detail: detail)) }

        /// Business text: sanitizer rules (identity mode: Loop text may not mention Viadere at all) and content rules.
        func text(_ value: String?, _ path: String, max: Int, required: Bool) {
            guard let value else {
                if required { hit(.emptyText, path) }
                return
            }
            if value.trimmingCharacters(in: .whitespaces).isEmpty {
                hit(.emptyText, path)
                if DisplayTextSanitizer.containsDisallowedScalars(value) { hit(.disallowedCharacters, path) }
                return
            }
            switch DisplayTextSanitizer.violation(of: value, maxCharacters: max, allowNewlines: false, identity: true) {
            case .disallowedCharacters?: hit(.disallowedCharacters, path)
            case .tooLong?: hit(.textTooLong, path)
            case .impersonation?: hit(.impersonation, path)
            case nil: break
            }
            for topic in LoopContentRules.topics(in: value) {
                switch topic {
                case .health: hit(.healthContent, path)
                case .sensitiveData: hit(.sensitiveDataRequest, path)
                case .attributionClaim: hit(.attributionSpoofing, path)
                case .link: hit(.linkNotAllowed, path)
                case .healthAdjacent: hit(.healthAdjacentContent, path)
                case .authorityClaim: hit(.authorityClaim, path)
                }
            }
        }
        func identifier(_ value: String, _ path: String, max: Int = 40) {
            if !ContractIdentifier.isValid(value, maxLength: max) { hit(.invalidIdentifier, path) }
        }

        // Size of the canonical form.
        if let bytes = try? d.canonicalJSON(), bytes.count > LoopLimits.maxDefinitionBytes { hit(.definitionTooLarge, "") }

        // Publisher and category (attribution metadata is required and must match the submitting tenant).
        if context.skipsPublisherRules {
            // First-party publication verified by the builder: publisher rules do not apply.
        } else if let publisher = context.publisher {
            if publisher.publisherType != .business { hit(.publisherNotBusiness, "publisher.publisher_type") }
            if publisher.businessId != context.submittingBusinessId { hit(.attributionMismatch, "publisher.publisher_business_id") }
            if publisher.verificationStatus != .verified { hit(.publisherNotVerified, "publisher.verification_status") }
            switch LoopCategoryPolicy.loops(publisher.category) {
            case .eligible: break
            case .refused(let reason): hit(reason == "healthcare_banned" ? .categoryBanned : .categoryProhibited, "publisher.category", publisher.category.rawValue)
            }
        } else {
            hit(.attributionMissing, "publisher")
        }

        // Root
        if !ContractIdentifier.isValid(d.key, maxLength: 48) { hit(.invalidIdentifier, "key") }
        text(d.title, "title", max: LoopLimits.titleLength, required: true)
        text(d.description, "description", max: LoopLimits.descriptionLength, required: false)
        if d.entryPoints.isEmpty { hit(.missingEntryPoint, "entry_points") }
        if Set(d.entryPoints).count != d.entryPoints.count { hit(.duplicateId, "entry_points") }
        if case .brandKit(let kit) = d.appearance {
            identifier(kit, "appearance.kit")
            if let owned = context.brandKitKeys, !owned.contains(kit) { hit(.unknownBrandKit, "appearance.kit") }
        }
        if !(LoopLimits.minExpiresInSeconds...LoopLimits.maxExpiresInSeconds).contains(d.limits.expiresInSeconds) {
            hit(.invalidLimit, "limits.expires_in_seconds")
        }

        // Steps
        if d.steps.isEmpty { hit(.noSteps, "steps") }
        if d.steps.count > LoopLimits.maxSteps { hit(.tooManySteps, "steps") }
        var stepIds = Set<String>()
        var actionIds = Set<String>()
        var risk = LoopRiskClass.low
        var hasShortText = false
        var hasAmountBearing = false
        var hasShopHandoff = false
        for (si, step) in d.steps.enumerated() {
            let sp = "steps[\(si)]"
            identifier(step.id, "\(sp).id")
            if !stepIds.insert(step.id).inserted { hit(.duplicateId, "\(sp).id") }
            text(step.title, "\(sp).title", max: LoopLimits.stepTitleLength, required: false)
            text(step.body, "\(sp).body", max: LoopLimits.bodyLength, required: false)

            switch step.type {
            case .form:
                if step.fields.isEmpty { hit(.noFields, "\(sp).fields") }
                if step.fields.count > LoopLimits.maxFieldsPerStep { hit(.tooManyFields, "\(sp).fields") }
            case .summary, .result, .handoff: break
            }
            if (step.type == .form || step.type == .summary) && step.actions.isEmpty { hit(.deadEnd, "\(sp).actions") }
            if step.actions.count > LoopLimits.maxActionsPerStep { hit(.tooManyActions, "\(sp).actions") }
            if step.type == .handoff {
                hasShopHandoff = hasShopHandoff || step.handoff == .shop
                if let kind = step.handoff, !(context.phase >= .connected && context.enabledHandoffs.contains(kind)) {
                    hit(.handoffNotAvailable, "\(sp).handoff", kind.rawValue)
                }
            }

            var fieldIds = Set<String>()
            for (fi, field) in step.fields.enumerated() {
                let fp = "\(sp).fields[\(fi)]"
                identifier(field.id, "\(fp).id")
                if !fieldIds.insert(field.id).inserted { hit(.duplicateId, "\(fp).id") }
                text(field.label, "\(fp).label", max: LoopLimits.fieldLabelLength, required: true)
                if field.type == .shortText { hasShortText = true }
                if field.type.hasOptions {
                    let options = field.options ?? []
                    if !(LoopLimits.minOptions...LoopLimits.maxOptions).contains(options.count) { hit(.invalidOptions, "\(fp).options") }
                    var optionIds = Set<String>()
                    for (oi, option) in options.enumerated() {
                        identifier(option.id, "\(fp).options[\(oi)].id")
                        if !optionIds.insert(option.id).inserted { hit(.duplicateId, "\(fp).options[\(oi)].id") }
                        text(option.label, "\(fp).options[\(oi)].label", max: LoopLimits.optionLabelLength, required: true)
                    }
                } else if field.options != nil {
                    hit(.invalidOptions, "\(fp).options")
                }
                if let max = field.maxLength, field.type != .shortText || !(1...LoopLimits.maxShortTextLength).contains(max) {
                    hit(.invalidValue, "\(fp).max_length")
                }
            }

            for (ai, action) in step.actions.enumerated() {
                let ap = "\(sp).actions[\(ai)]"
                identifier(action.id, "\(ap).id")
                if !actionIds.insert(action.id).inserted { hit(.duplicateId, "\(ap).id") }
                if let next = action.next {
                    if !d.steps.contains(where: { $0.id == next }) { hit(.unknownNextStep, "\(ap).next") }
                } else {
                    hit(.missingNext, "\(ap).next")
                }
                switch context.registry.resolve(action.action) {
                case .reserved(let reason):
                    hit(.reservedAction, "\(ap).action", reason.rawValue)
                case .unregistered:
                    hit(.unregisteredAction, "\(ap).action")
                case .registered(let def):
                    risk = max(risk, def.riskClass)
                    if def.amountBearing { hasAmountBearing = true }
                    if !def.isAvailable(in: context.phase) { hit(.actionNotAvailable, "\(ap).action", action.action) }
                    if def.riskClass == .high {
                        hit(.highRiskAction, "\(ap).action", action.action)
                        if def.confirmation == nil { hit(.missingConfirmation, "\(ap).action") }
                    }
                    if !def.allowedLabelKeys.contains(action.label) { hit(.labelNotAllowed, "\(ap).label") }
                    if let custom = action.customLabel {
                        if def.customLabelAllowed { text(custom, "\(ap).custom_label", max: LoopLimits.customLabelLength, required: true) } else {
                            hit(.customLabelNotAllowed, "\(ap).custom_label")
                        }
                    }
                    // Parameters: registered names only, required ones present, typed values.
                    let params = action.params ?? [:]
                    for name in params.keys.sorted() where !def.parameters.contains(where: { $0.name == name }) {
                        hit(.unknownParameter, "\(ap).params.\(name)")
                    }
                    for parameter in def.parameters {
                        let pp = "\(ap).params.\(parameter.name)"
                        guard let value = params[parameter.name] else {
                            if parameter.required { hit(.missingParameter, pp) }
                            continue
                        }
                        switch parameter.kind {
                        case .money:
                            if LoopParameterValue.money(value) == nil { hit(.invalidParameter, pp) }
                        case .text:
                            if let s = value.stringValue { text(s, pp, max: parameter.maxLength, required: true) } else { hit(.invalidParameter, pp) }
                        case .reference:
                            let ok = value.stringValue.map { s in
                                !s.isEmpty && s.utf8.count <= parameter.maxLength
                                    && s.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "_.:-".unicodeScalars.contains($0)) }
                            } ?? false
                            if !ok { hit(.invalidParameter, pp) }
                        }
                    }
                    // Routing: delivering actions must route, to a mode the action allows and the phase offers.
                    if def.deliversToBusiness {
                        if let routing = action.routing {
                            if !def.routing.contains(routing.mode) { hit(.routingNotAllowed, "\(ap).routing.mode") }
                            if routing.mode == .connected && context.phase < .connected { hit(.routingModeNotAvailable, "\(ap).routing.mode") }
                            if let queue = routing.queue { identifier(queue, "\(ap).routing.queue") }
                        } else {
                            hit(.missingRouting, "\(ap).routing")
                        }
                    } else if action.routing != nil {
                        hit(.routingNotAllowed, "\(ap).routing")
                    }
                }
            }
        }

        // FX-5: an amount-bearing approval can never share a flow with a checkout handoff.
        if hasAmountBearing && hasShopHandoff { hit(.approvalWithCheckout, "steps") }
        // Free text is refused in high-risk flows.
        if risk == .high && hasShortText { hit(.freeTextInHighRisk, "steps") }

        hits += graphHits(d)
        return (hits, risk)
    }

    /// Step graph: entry is `steps[0]` and not terminal; terminal steps (`result`, `handoff`) exist; every step is reachable; no cycles.
    static func graphHits(_ d: LoopDefinition) -> [LoopRuleHit] {
        guard let entry = d.steps.first else { return [] }
        var hits: [LoopRuleHit] = []
        let terminal: (LoopStep) -> Bool = { $0.type == .result || $0.type == .handoff }
        if terminal(entry) { hits.append(LoopRuleHit(rule: .entryIsTerminal, path: "steps[0]")) }
        if !d.steps.contains(where: terminal) { hits.append(LoopRuleHit(rule: .noTerminalStep, path: "steps")) }
        var edges: [String: [String]] = [:]
        for step in d.steps { edges[step.id, default: []] += step.actions.compactMap(\.next) }

        // Iterative DFS with colors: gray on the stack, black finished. A gray successor is a back edge (cycle).
        var color: [String: Int] = [:]
        var cycle = false
        var stack: [(String, Int)] = [(entry.id, 0)]
        color[entry.id] = 1
        while let (node, index) = stack.last {
            let successors = edges[node] ?? []
            if index < successors.count {
                stack[stack.count - 1].1 += 1
                let next = successors[index]
                guard edges[next] != nil else { continue }
                switch color[next] ?? 0 {
                case 0: color[next] = 1; stack.append((next, 0))
                case 1: cycle = true
                default: break
                }
            } else {
                color[node] = 2
                stack.removeLast()
            }
        }
        if cycle { hits.append(LoopRuleHit(rule: .cycle, path: "steps")) }
        for (i, step) in d.steps.enumerated() where color[step.id] == nil {
            hits.append(LoopRuleHit(rule: .unreachableStep, path: "steps[\(i)]"))
        }
        return hits
    }
}

/// Typed reads of action parameter values.
public enum LoopParameterValue {
    /// A `MoneyAmount` from exactly `{"value":"<decimal>","currency":"<ISO 4217>"}` (no other member).
    public static func money(_ value: JSONValue?) -> MoneyAmount? {
        guard case .object(let o)? = value, Set(o.keys) == ["value", "currency"], let raw = o["value"]?.stringValue,
              let code = o["currency"]?.stringValue, code == code.uppercased(), let currency = CurrencyCode(code) else { return nil }
        return try? MoneyAmount(string: raw, currency: currency)
    }
}
