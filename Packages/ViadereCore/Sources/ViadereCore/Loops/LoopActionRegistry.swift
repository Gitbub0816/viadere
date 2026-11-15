import Foundation

/// Risk class of a Loop action and, derived from its actions, of a whole Loop definition (spec A4). Ordered.
public enum LoopRiskClass: String, Sendable, Codable, CaseIterable, Hashable, Comparable {
    case low, medium, high

    var rank: Int {
        switch self {
        case .low: 0
        case .medium: 1
        case .high: 2
        }
    }

    public static func < (lhs: LoopRiskClass, rhs: LoopRiskClass) -> Bool { lhs.rank < rhs.rank }
}

/// How an action event reaches the business (spec A2). `connected` exists from Phase 4 (`LoopPlatformPhase.connected`).
public enum LoopRoutingMode: String, Sendable, Codable, CaseIterable, Hashable {
    case hosted, connected
}

/// The build phase the validator enforces. Phase 3 is hosted Loops only; Phase 4 adds connected routing and binding approvals.
public enum LoopPlatformPhase: Int, Sendable, Codable, CaseIterable, Hashable, Comparable {
    case hosted = 3
    case connected = 4

    public static func < (lhs: LoopPlatformPhase, rhs: LoopPlatformPhase) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// A typed parameter of a registered action. Values are supplied by the definition (`params`) and validated **before** anything else;
/// unknown parameters are rejected (`additionalProperties: false`), as for `CapabilityParameter`.
public struct LoopActionParameter: Sendable, Codable, Hashable {
    public enum Kind: String, Sendable, Codable, Hashable {
        /// Short business text, sanitized like every other Loop text (`DisplayTextSanitizer`, identity rules, content rules).
        case text
        /// `{"value":"285.28","currency":"USD"}` (`MoneyAmount`).
        case money
        /// A business reference: ASCII identifier grammar `[A-Za-z0-9_.:-]`.
        case reference
    }

    public var name: String
    public var kind: Kind
    public var required: Bool
    public var maxLength: Int

    public init(name: String, kind: Kind, required: Bool, maxLength: Int = 64) {
        self.name = name
        self.kind = kind
        self.required = required
        self.maxLength = maxLength
    }
}

/// The Viadere-written confirmation panel of a consequential action (spec A6a.2: it names the business responsible for the downstream
/// action). Holes: `{business}` (verified display name, from the server's business record), `{amount}` (formatted `MoneyAmount`),
/// `{effect}` (the action's fixed effect sentence). A definition can never supply or suppress it.
public struct LoopConfirmationTemplate: Sendable, Codable, Hashable {
    public var title: String
    public var statement: String
    public var effect: String
    public var confirmLabel: String

    public init(title: String, statement: String, effect: String, confirmLabel: String) {
        self.title = title
        self.statement = statement
        self.effect = effect
        self.confirmLabel = confirmLabel
    }
}

/// Idempotency of action events: one event per `(instance, idempotency_key)`; a replay inside the window returns the stored result.
public struct LoopIdempotencyRule: Sendable, Codable, Hashable {
    public enum Scope: String, Sendable, Codable, Hashable { case instance }
    public var scope: Scope
    public var windowSeconds: Int

    public init(scope: Scope = .instance, windowSeconds: Int) {
        self.scope = scope
        self.windowSeconds = windowSeconds
    }
}

/// Availability of a registry entry.
public enum LoopActionAvailability: Sendable, Codable, Hashable {
    /// Usable from `phase` on.
    case available(from: LoopPlatformPhase)
}

/// One registered action type (spec A4, plan section 4.9). Shaped like `CapabilityDefinition` and reusing its vocabulary
/// (`RequiredEvidence`, `BusinessRiskTier`, `ConsentRequirement`, `RevocationBehavior`).
///
/// **Integration point (WP-3.1 after WP-C1):** `capabilityId` is the string id of the `Capability` the policy engine evaluates for this
/// action (`loop.action.hosted`, `loop.action.connected`, `transaction.approve`). The `Capability` enum is not edited here; the server maps
/// the string through `Capability(rawValue:)` once the link-session milestone has added the `loop.*` capabilities. Until then the string
/// decodes as `.unknown`, which the policy engine never allows (fail closed).
public struct LoopActionDefinition: Sendable, Codable, Hashable {
    public var actionType: String
    public var title: String
    public var riskClass: LoopRiskClass
    public var parameters: [LoopActionParameter]
    /// Label keys from `LoopStringCatalog.actionLabels` the business may choose among.
    public var allowedLabelKeys: [String]
    /// Whether a sanitized custom label is allowed (only ever for `low` risk).
    public var customLabelAllowed: Bool
    /// Present for every action that needs a confirmation panel; **always** present for `high` risk (registry self-check).
    public var confirmation: LoopConfirmationTemplate?
    public var requiredEvidence: RequiredEvidence
    public var minimumTier: BusinessRiskTier
    public var consent: ConsentRequirement
    public var idempotency: LoopIdempotencyRule
    /// Seconds after submission at which a still-`pending` event becomes `timed_out`.
    public var timeoutSeconds: Int
    /// Routing modes the action may use. Empty: the action only advances the flow on the device and sends nothing on its own.
    public var routing: [LoopRoutingMode]
    public var auditFields: [String]
    public var revocation: RevocationBehavior
    public var availability: LoopActionAvailability
    /// String id of the policy capability (see the type documentation).
    public var capabilityId: String
    /// Carries an amount (`money` parameter).
    public var amountBearing: Bool
    /// Produces a binding approval through Approve v2 (never a payment; never paired with a checkout handoff).
    public var bindsApproval: Bool

    public var deliversToBusiness: Bool { !routing.isEmpty }

    public func isAvailable(in phase: LoopPlatformPhase) -> Bool {
        switch availability {
        case .available(let from): from <= phase
        }
    }
}

/// Why an action type is refused outright, whatever the definition says.
public enum LoopReservedReason: String, Sendable, Codable, Hashable {
    /// Identity and age attestation exist only as the first-party Verify module (spec A4.3d); business logic can never request them.
    case firstPartyVerificationOnly = "first_party_verification_only"
    /// Viadere takes no payment and creates no orders (FX-5). Commerce is a Shopify handoff module, not an action.
    case noPayments = "no_payments"
    /// Health information is never collected (FX-4).
    case healthcareBanned = "healthcare_banned"
}

/// How the registry resolves an action type.
public enum LoopActionResolution: Sendable, Hashable {
    case registered(LoopActionDefinition)
    case reserved(LoopReservedReason)
    case unregistered
}

/// The closed registry of Loop action types. Businesses bind buttons to these and pick labels from each entry's allowed set; they can
/// never define an operation through a string.
public struct LoopActionRegistry: Sendable {
    public let version: Int
    private let entries: [String: LoopActionDefinition]
    public var definitions: [LoopActionDefinition] { entries.values.sorted { $0.actionType < $1.actionType } }

    public init(version: Int, definitions: [LoopActionDefinition]) {
        self.version = version
        var map: [String: LoopActionDefinition] = [:]
        for definition in definitions { map[definition.actionType] = definition }
        entries = map
    }

    /// Reserved prefixes and names (checked before the registry, so a reserved name can never be registered by mistake).
    static let reservedExact: [String: LoopReservedReason] = [
        "verify_identity": .firstPartyVerificationOnly, "verify_age": .firstPartyVerificationOnly, "identity": .firstPartyVerificationOnly,
        "age_check": .firstPartyVerificationOnly, "checkout": .noPayments, "pay": .noPayments, "refund": .noPayments, "charge": .noPayments,
        "health_record": .healthcareBanned, "medical_history": .healthcareBanned,
    ]
    static let reservedPrefixes: [(String, LoopReservedReason)] = [
        ("payment.", .noPayments), ("payment_", .noPayments), ("order.", .noPayments), ("order_", .noPayments), ("shop.", .noPayments),
        ("verify_", .firstPartyVerificationOnly), ("identity.", .firstPartyVerificationOnly), ("age.", .firstPartyVerificationOnly),
        ("health", .healthcareBanned), ("medical", .healthcareBanned),
    ]

    public static func reservedReason(_ actionType: String) -> LoopReservedReason? {
        let lowered = actionType.lowercased()
        if let reason = reservedExact[lowered] { return reason }
        return reservedPrefixes.first { lowered.hasPrefix($0.0) }?.1
    }

    public func resolve(_ actionType: String) -> LoopActionResolution {
        if let reason = Self.reservedReason(actionType) { return .reserved(reason) }
        if let definition = entries[actionType] { return .registered(definition) }
        return .unregistered
    }

    /// Registry invariants (a test runs this on `.v1`): high risk always has a confirmation panel, custom labels only for low risk,
    /// every label key is in the catalog, no reserved name is registered, binding approvals are amount-bearing and confirmed.
    public func selfCheck() -> [String] {
        var problems: [String] = []
        for d in definitions {
            if d.riskClass == .high && d.confirmation == nil { problems.append("\(d.actionType): high risk without confirmation") }
            if d.customLabelAllowed && d.riskClass != .low { problems.append("\(d.actionType): custom label above low risk") }
            if d.allowedLabelKeys.isEmpty { problems.append("\(d.actionType): no labels") }
            for key in d.allowedLabelKeys where LoopStringCatalog.actionLabels[key] == nil { problems.append("\(d.actionType): unknown label \(key)") }
            if Self.reservedReason(d.actionType) != nil { problems.append("\(d.actionType): reserved name registered") }
            if d.bindsApproval && (!d.amountBearing || d.confirmation == nil) { problems.append("\(d.actionType): binding approval must carry amount and confirmation") }
            if d.amountBearing && !d.parameters.contains(where: { $0.kind == .money && $0.required }) { problems.append("\(d.actionType): amount-bearing without money parameter") }
            if d.timeoutSeconds <= 0 || d.idempotency.windowSeconds <= 0 { problems.append("\(d.actionType): timeouts") }
        }
        return problems
    }

    // MARK: Version 1

    private static func entry(_ type: String, _ title: String, _ risk: LoopRiskClass, labels: [String], custom: Bool = false,
                              parameters: [LoopActionParameter] = [], confirmation: LoopConfirmationTemplate? = nil,
                              evidence: RequiredEvidence = .registeredAuthenticator, tier: BusinessRiskTier = .m, routing: [LoopRoutingMode] = [.hosted, .connected],
                              timeout: Int = 7 * 24 * 3600, phase: LoopPlatformPhase = .hosted, capability: String = "loop.action.hosted",
                              amount: Bool = false, binds: Bool = false) -> LoopActionDefinition {
        LoopActionDefinition(actionType: type, title: title, riskClass: risk, parameters: parameters, allowedLabelKeys: labels,
                             customLabelAllowed: custom, confirmation: confirmation, requiredEvidence: evidence, minimumTier: tier,
                             consent: ConsentRequirement(mode: .activeRelationship, purpose: "loops"),
                             idempotency: LoopIdempotencyRule(windowSeconds: 24 * 3600), timeoutSeconds: timeout, routing: routing,
                             auditFields: ["instance_id", "step_id", "action_type", "idempotency_key", "outcome"],
                             revocation: .cancelsPending, availability: .available(from: phase), capabilityId: capability,
                             amountBearing: amount, bindsApproval: binds)
    }

    /// The initial registry (plan section 4.9). `review_estimate` is read-only in Phase 3 (shows terms and amount, sends an
    /// acknowledgment, authorizes nothing); `approve_estimate` binds through Approve v2 from Phase 4 and never charges.
    public static let v1 = LoopActionRegistry(version: 1, definitions: [
        entry("acknowledge", "Acknowledge", .low, labels: ["acknowledge", "got_it", "send_request", "confirm"], custom: true),
        entry("confirm_attendance", "Confirm attendance", .low, labels: ["confirm_attendance", "i_will_attend", "confirm"], custom: true),
        entry("request_callback", "Request a callback", .low, labels: ["request_callback", "call_me_back"], custom: true),
        entry("submit_inquiry", "Send an inquiry", .low, labels: ["send_inquiry", "send"], custom: true),
        entry("check_in", "Check in / arrival", .medium, labels: ["check_in", "i_have_arrived"],
              confirmation: LoopConfirmationTemplate(title: "Check in with {business}?", statement: "{business} will see that you've arrived.",
                                                     effect: "This only tells {business} you're here.", confirmLabel: "check_in"),
              timeout: 4 * 3600),
        entry("select_option", "Select an option", .medium, labels: ["continue", "choose", "next"], routing: []),
        entry("select_pickup_time", "Select a pickup time", .medium, labels: ["continue", "choose_time", "next"], routing: []),
        entry("review_estimate", "Review an estimate", .high, labels: ["review_estimate", "send_acknowledgement"],
              parameters: [LoopActionParameter(name: "amount", kind: .money, required: true),
                           LoopActionParameter(name: "terms", kind: .text, required: true, maxLength: 300),
                           LoopActionParameter(name: "reference", kind: .reference, required: false)],
              confirmation: LoopConfirmationTemplate(title: "Estimate from {business}", statement: "{business} sent you an estimate of {amount}.",
                                                     effect: "Sending this tells {business} you've seen it. It doesn't approve or charge anything.",
                                                     confirmLabel: "send_acknowledgement"),
              tier: .a, routing: [.hosted, .connected], timeout: 3 * 24 * 3600, amount: true),
        entry("approve_estimate", "Approve an estimate", .high, labels: ["approve_estimate"],
              parameters: [LoopActionParameter(name: "amount", kind: .money, required: true),
                           LoopActionParameter(name: "terms", kind: .text, required: true, maxLength: 300),
                           LoopActionParameter(name: "reference", kind: .reference, required: true)],
              confirmation: LoopConfirmationTemplate(title: "Approve the estimate from {business}?", statement: "This approves the estimate from {business} for {amount}.",
                                                     effect: "This approves the estimate. It does not charge you.", confirmLabel: "approve_estimate"),
              tier: .a, routing: [.hosted, .connected], timeout: 3 * 24 * 3600, phase: .connected, capability: "transaction.approve",
              amount: true, binds: true),
    ])
}
