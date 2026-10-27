import Foundation

/// The kind of evidence a capability needs about the **subject** before it may be exercised (spec §6.1/§6.2). The kinds are separate
/// assurance dimensions and are **not interchangeable** (VER-005, VER-009): a verified identity does not stand in for a verified age
/// threshold, and a registered authenticator proves neither.
public enum RequiredEvidence: String, Sendable, Codable, CaseIterable, Hashable {
    /// No evidence about the person: the capability only needs an established relationship.
    case none
    /// The subject holds a registered, non-revoked authenticator (an enrolled device key).
    case registeredAuthenticator
    /// A verified age-threshold result (`age.minimum`), backed by a verified birthdate or a trusted threshold credential (AGE-002).
    case verifiedAgeThreshold
    /// A verified identity (identity proofing evidence validated under VER-004).
    case verifiedIdentity
}

/// How the person is asked (spec §6.4 "customer UX").
public enum CustomerUX: String, Sendable, Codable, CaseIterable, Hashable {
    /// Nothing is shown (a business-side check that discloses nothing to the person).
    case none
    /// An actionable notification.
    case notification
    /// A secure sheet in the app that shows the verified business, the exact action and requires local authentication.
    case secureSheet
    /// A guided verification flow (Wallet ID or provider), with explicit consent to the presentation.
    case verificationFlow
}

/// Which customer consent a capability requires.
public enum ConsentMode: String, Sendable, Codable, CaseIterable, Hashable {
    /// None beyond the relationship itself being absent of objection.
    case none
    /// An **active relationship** (the customer connected to the business and has not disconnected).
    case activeRelationship
    /// The purpose-scoped consent of the relationship for the request's own purpose (`InteractionPurpose`; marketing and rewards are
    /// opt-in, essential purposes are on by default).
    case relationshipPurpose
    /// **Per-request granular consent** (spec §6.4): a consent receipt for exactly this request that names the purpose, the recipient
    /// business, the fields released and an expiry. A relationship-level consent, however broad, never satisfies it (no blanket consent).
    case perRequestReceipt
}

public struct ConsentRequirement: Sendable, Codable, Hashable {
    public var mode: ConsentMode
    /// The purpose the consent is for: an `InteractionPurpose` raw value, `"request_purpose"` (the purpose of the message being sent)
    /// or a disclosure purpose for per-request receipts.
    public var purpose: String

    public init(mode: ConsentMode, purpose: String) {
        self.mode = mode
        self.purpose = purpose
    }
}

/// What happens to an exercised capability when the customer or Viadere withdraws it.
public enum RevocationBehavior: String, Sendable, Codable, CaseIterable, Hashable {
    /// Future use stops immediately (consent withdrawn or relationship disconnected); nothing already delivered is recalled.
    case stopsFutureUse = "stops_future_use"
    /// Pending, unanswered requests are cancelled as well, and a result not yet delivered is destroyed.
    case cancelsPending = "cancels_pending"
    /// The result is a short-lived assertion that simply expires; a receipt revoked before use can no longer authorize a disclosure.
    case expiresAssertion = "expires_assertion"
}

/// The JSON type of a parameter or output field.
public enum SchemaType: String, Sendable, Codable, Hashable {
    case string, integer, boolean, timestamp, object
}

/// One typed input of a capability. Parameters are validated against the catalog **before** anything else happens (unknown parameters
/// are rejected: `additionalProperties: false`).
public struct CapabilityParameter: Sendable, Codable, Hashable {
    public var name: String
    public var type: SchemaType
    public var required: Bool
    /// Closed set of integers (e.g. `age.minimum` years).
    public var allowedIntegers: [Int]?
    /// Closed set of strings.
    public var allowedStrings: [String]?
    public var maxLength: Int?
    public var minimum: Int?
    public var maximum: Int?
    public var summary: String

    public init(name: String, type: SchemaType, required: Bool = true, allowedIntegers: [Int]? = nil, allowedStrings: [String]? = nil,
                maxLength: Int? = nil, minimum: Int? = nil, maximum: Int? = nil, summary: String) {
        self.name = name
        self.type = type
        self.required = required
        self.allowedIntegers = allowedIntegers
        self.allowedStrings = allowedStrings
        self.maxLength = maxLength
        self.minimum = minimum
        self.maximum = maximum
        self.summary = summary
    }

    /// `nil` when `value` is acceptable, else a machine code.
    func issue(for value: JSONValue) -> String? {
        switch (type, value) {
        case (.integer, .integer(let n)):
            if let allowed = allowedIntegers, !allowed.contains(Int(clamping: n)) { return "not_allowed" }
            if let minimum, n < Int64(minimum) { return "too_small" }
            if let maximum, n > Int64(maximum) { return "too_large" }
            return nil
        case (.string, .string(let s)), (.timestamp, .string(let s)):
            if let maxLength, s.count > maxLength { return "too_long" }
            if s.isEmpty { return "empty" }
            if s.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) { return "invalid_characters" }
            if let allowed = allowedStrings, !allowed.contains(s) { return "not_allowed" }
            return nil
        case (.boolean, .bool): return nil
        default: return "wrong_type"
        }
    }
}

/// How an output field relates to the person.
public enum OutputFieldClass: String, Sendable, Codable, Hashable {
    /// The claim itself (`meets_threshold`, `verified`, `decision`).
    case assertion
    /// How the claim was established (assurance level, method).
    case assurance
    /// Validity and binding (`issued_at`, `expires_at`, `audience`, identifiers of the result).
    case metadata
    /// Personal data about the person. Only the identity capabilities may release any, and only after a per-request receipt.
    case personalData = "personal_data"
}

/// One field of a capability's result.
public struct OutputField: Sendable, Codable, Hashable {
    public var name: String
    public var type: SchemaType
    public var fieldClass: OutputFieldClass
    public var summary: String

    public init(_ name: String, _ type: SchemaType, _ fieldClass: OutputFieldClass, _ summary: String) {
        self.name = name
        self.type = type
        self.fieldClass = fieldClass
        self.summary = summary
    }

    enum CodingKeys: String, CodingKey { case name, type, fieldClass = "class", summary }
}

/// The **explicit list of fields a capability discloses** (acceptance 6). A result is built from this list and nothing else:
/// anything outside it is dropped by `CapabilityDefinition.project(_:)` and rejected by `CapabilityDefinition.violations(in:)`.
public struct OutputSchema: Sendable, Codable, Hashable {
    public var fields: [OutputField]

    public init(_ fields: [OutputField]) { self.fields = fields }

    public var fieldNames: [String] { fields.map(\.name) }
    public var personalDataFields: [String] { fields.filter { $0.fieldClass == .personalData }.map(\.name) }
}

/// A capability's full contract (spec §6.4): inputs, required evidence, sensitivity, policy, customer UX, output schema, maximum
/// retention, audit fields and revocation behavior. This is the normative catalog documented in `docs/SECURITY.md`.
public struct CapabilityDefinition: Sendable, Codable, Hashable {
    public var capability: Capability
    public var title: String
    public var summary: String
    /// Typed inputs.
    public var parameters: [CapabilityParameter]
    /// Whether the request must carry a `purpose` (a snake_case disclosure purpose such as `age_restricted_access`).
    public var requiresPurpose: Bool
    public var requiredEvidence: RequiredEvidence
    public var sensitivity: Sensitivity
    /// The lowest business tier whose holders may be granted this capability. Holding the tier alone grants nothing.
    public var minimumTier: BusinessRiskTier
    public var consent: ConsentRequirement
    public var customerUX: CustomerUX
    public var output: OutputSchema
    /// Longest Viadere may keep the **result payload** (seconds). `0` means the result is not stored. Audit and consent receipts are
    /// separate evidence records with their own retention (`docs/ops/DATA-INVENTORY.md`).
    public var maxResultRetentionSeconds: Int
    /// Fields recorded in the audit event of every decision (never values of personal data).
    public var auditFields: [String]
    public var revocation: RevocationBehavior
    /// Whether a successful (allowed) decision is itself audited. Denials are always audited.
    public var auditsAllowedDecisions: Bool

    public init(capability: Capability, title: String, summary: String, parameters: [CapabilityParameter] = [], requiresPurpose: Bool = false,
                requiredEvidence: RequiredEvidence, sensitivity: Sensitivity, minimumTier: BusinessRiskTier, consent: ConsentRequirement,
                customerUX: CustomerUX, output: OutputSchema, maxResultRetentionSeconds: Int, auditFields: [String],
                revocation: RevocationBehavior, auditsAllowedDecisions: Bool) {
        self.capability = capability
        self.title = title
        self.summary = summary
        self.parameters = parameters
        self.requiresPurpose = requiresPurpose
        self.requiredEvidence = requiredEvidence
        self.sensitivity = sensitivity
        self.minimumTier = minimumTier
        self.consent = consent
        self.customerUX = customerUX
        self.output = output
        self.maxResultRetentionSeconds = maxResultRetentionSeconds
        self.auditFields = auditFields
        self.revocation = revocation
        self.auditsAllowedDecisions = auditsAllowedDecisions
    }

    /// Machine issues for `parameters`: a map of parameter name to code (`missing`, `unknown`, `wrong_type`, `not_allowed`, ...).
    /// Empty means valid. Unknown parameters are rejected, so a request cannot smuggle extra fields past the catalog.
    public func parameterIssues(_ values: [String: JSONValue]) -> [String: String] {
        var issues: [String: String] = [:]
        let known = Dictionary(uniqueKeysWithValues: parameters.map { ($0.name, $0) })
        for name in values.keys where known[name] == nil { issues[name] = "unknown" }
        for parameter in parameters {
            guard let value = values[parameter.name], value != .null else {
                if parameter.required { issues[parameter.name] = "missing" }
                continue
            }
            if let issue = parameter.issue(for: value) { issues[parameter.name] = issue }
        }
        return issues
    }

    /// Keeps only the fields in the output schema. A result builder must run its output through this: a field the catalog does not
    /// list cannot be disclosed, whatever the producer put into the dictionary.
    public func project(_ values: [String: JSONValue]) -> [String: JSONValue] {
        let allowed = Set(output.fieldNames)
        return values.filter { allowed.contains($0.key) }
    }

    /// Fields in `values` that this capability does not disclose (so a producer bug is detected, not silently shipped).
    public func violations(in values: [String: JSONValue]) -> [String] {
        let allowed = Set(output.fieldNames)
        return values.keys.filter { !allowed.contains($0) }.sorted()
    }
}

/// The catalog (spec §6.4). Order is stable and documented in `docs/SECURITY.md`.
public enum CapabilityCatalog {
    /// Field names that are personal data about the person. Only `identity.name` and `identity.address` may disclose any of them
    /// (see `audit()`); `age.minimum` and every other capability must never.
    public static let personalDataFieldNames: Set<String> = [
        "birthdate", "birth_date", "date_of_birth", "dob", "birth_year", "age", "exact_age", "name", "full_name", "given_name",
        "family_name", "middle_name", "address", "street", "street_address", "locality", "region", "postal_code", "document_number",
        "id_number", "passport_number", "license_number", "national_id", "ssn", "tax_id", "phone", "phone_number", "email", "photo", "portrait",
    ]

    /// Allowed personal-data fields per capability: the identity capabilities only.
    static let allowedPersonalData: [Capability: Set<String>] = [
        .identityName: ["given_name", "family_name"],
        .identityAddress: ["address"],
    ]

    private static let assuranceFields: [OutputField] = [
        OutputField("assurance", .string, .assurance, "Assurance level and method that established the claim."),
        OutputField("issued_at", .timestamp, .metadata, "When the result was issued."),
        OutputField("expires_at", .timestamp, .metadata, "When the result stops being valid."),
        OutputField("audience", .string, .metadata, "The business the result is bound to; it cannot be reused at another."),
    ]

    private static let decisionFields: [OutputField] = [
        OutputField("decision", .string, .assertion, "approved, declined or expired."),
        OutputField("assurance", .string, .assurance, "Local authentication method used (none, device passcode, biometric)."),
        OutputField("key_id", .string, .metadata, "Identifier of the pairwise device key that signed."),
        OutputField("decided_at", .timestamp, .metadata, "When the decision was signed."),
    ]

    public static let definitions: [CapabilityDefinition] = [
        CapabilityDefinition(
            capability: .messageSend, title: "Send a message",
            summary: "Deliver an interactive notification, status, reward or message to a connected customer.",
            requiredEvidence: .none, sensitivity: .low, minimumTier: .m,
            consent: ConsentRequirement(mode: .relationshipPurpose, purpose: "request_purpose"), customerUX: .notification,
            output: OutputSchema([OutputField("message_id", .string, .metadata, "Identifier of the message or interaction."),
                                  OutputField("status", .string, .metadata, "Delivery state."),
                                  OutputField("created_at", .timestamp, .metadata, "When it was accepted.")]),
            maxResultRetentionSeconds: 30 * 86_400, auditFields: ["capability", "purpose", "kind", "subject_ref", "outcome"],
            revocation: .cancelsPending, auditsAllowedDecisions: false),
        CapabilityDefinition(
            capability: .contactReachable, title: "Check reachability",
            summary: "Whether an existing connection can currently receive messages. Answers only for a subject_ref the business already holds; never for a raw phone number or email (no directory enumeration).",
            requiredEvidence: .none, sensitivity: .low, minimumTier: .m,
            consent: ConsentRequirement(mode: .activeRelationship, purpose: "relationship"), customerUX: .none,
            output: OutputSchema([OutputField("reachable", .boolean, .assertion, "Whether a message could be delivered now."),
                                  OutputField("checked_at", .timestamp, .metadata, "When it was checked.")]),
            maxResultRetentionSeconds: 0, auditFields: ["capability", "subject_ref", "outcome"],
            revocation: .stopsFutureUse, auditsAllowedDecisions: false),
        CapabilityDefinition(
            capability: .consentRequest, title: "Request consent",
            summary: "Ask a connected customer to grant a purpose (for example marketing or rewards). The customer decides in the app.",
            parameters: [CapabilityParameter(name: "purpose", type: .string, allowedStrings: ["support", "marketing", "rewards"],
                                             summary: "The purpose consent is requested for.")],
            requiredEvidence: .none, sensitivity: .standard, minimumTier: .m,
            consent: ConsentRequirement(mode: .activeRelationship, purpose: "relationship"), customerUX: .secureSheet,
            output: OutputSchema([OutputField("request_id", .string, .metadata, "Identifier of the consent request."),
                                  OutputField("status", .string, .metadata, "pending, granted, declined or expired."),
                                  OutputField("decided_at", .timestamp, .metadata, "When the customer decided.")]),
            maxResultRetentionSeconds: 90 * 86_400, auditFields: ["capability", "purpose", "subject_ref", "outcome"],
            revocation: .stopsFutureUse, auditsAllowedDecisions: true),
        CapabilityDefinition(
            capability: .authChallenge, title: "Authentication challenge",
            summary: "Ask a connected customer to approve a sign-in or step-up with a device-bound signature. The business keeps its own session and decides access.",
            requiredEvidence: .registeredAuthenticator, sensitivity: .high, minimumTier: .a,
            consent: ConsentRequirement(mode: .relationshipPurpose, purpose: "security"), customerUX: .notification,
            output: OutputSchema(decisionFields),
            maxResultRetentionSeconds: 400 * 86_400, auditFields: ["capability", "purpose", "kind", "subject_ref", "outcome"],
            revocation: .cancelsPending, auditsAllowedDecisions: true),
        CapabilityDefinition(
            capability: .transactionApprove, title: "Transaction approval",
            summary: "Ask a connected customer to approve one specific transaction. The result is signed over the exact displayed details and audience-bound.",
            parameters: [
                CapabilityParameter(name: "currency", type: .string, maxLength: 3, summary: "ISO 4217 code."),
                CapabilityParameter(name: "amount_minor", type: .integer, minimum: 1, maximum: 999_999_999_999, summary: "Amount in minor units."),
                CapabilityParameter(name: "payee_display", type: .string, maxLength: 80, summary: "Payee name as shown to the customer."),
                CapabilityParameter(name: "transaction_reference", type: .string, maxLength: 64, summary: "The business's reference."),
                CapabilityParameter(name: "challenge", type: .string, maxLength: 128, summary: "The business's base64url nonce."),
            ],
            requiredEvidence: .registeredAuthenticator, sensitivity: .critical, minimumTier: .a,
            consent: ConsentRequirement(mode: .relationshipPurpose, purpose: "security"), customerUX: .secureSheet,
            output: OutputSchema(decisionFields + [
                OutputField("transaction_digest", .string, .metadata, "SHA-256 over the exact displayed transaction."),
                OutputField("audience", .string, .metadata, "The business the signed result is bound to."),
                OutputField("expires_at", .timestamp, .metadata, "When the signed result stops being valid."),
            ]),
            maxResultRetentionSeconds: 400 * 86_400, auditFields: ["capability", "purpose", "subject_ref", "outcome", "request_id"],
            revocation: .cancelsPending, auditsAllowedDecisions: true),
        CapabilityDefinition(
            capability: .ageMinimum, title: "Minimum age",
            summary: "Whether the customer is at least N years old. Discloses only the yes/no result: never a birthdate, an age, a name or a document number (AGE-001, AGE-003).",
            parameters: [CapabilityParameter(name: "years", type: .integer, allowedIntegers: [13, 16, 18, 21, 25], summary: "The age threshold.")],
            requiresPurpose: true, requiredEvidence: .verifiedAgeThreshold, sensitivity: .high, minimumTier: .v,
            consent: ConsentRequirement(mode: .perRequestReceipt, purpose: "age_assurance"), customerUX: .verificationFlow,
            output: OutputSchema([OutputField("meets_threshold", .boolean, .assertion, "Whether the customer meets the threshold.")] + assuranceFields),
            maxResultRetentionSeconds: 86_400, auditFields: ["capability", "purpose", "years", "subject_ref", "outcome", "receipt_id"],
            revocation: .expiresAssertion, auditsAllowedDecisions: true),
        CapabilityDefinition(
            capability: .identityName, title: "Verified name",
            summary: "The customer's verified legal name, released only with a per-request receipt. Sensitive-industry access needs a recorded purpose justification and heightened review (AGE-007).",
            requiresPurpose: true, requiredEvidence: .verifiedIdentity, sensitivity: .critical, minimumTier: .v,
            consent: ConsentRequirement(mode: .perRequestReceipt, purpose: "identity_disclosure"), customerUX: .verificationFlow,
            output: OutputSchema([OutputField("given_name", .string, .personalData, "Verified given name."),
                                  OutputField("family_name", .string, .personalData, "Verified family name.")] + assuranceFields),
            maxResultRetentionSeconds: 86_400, auditFields: ["capability", "purpose", "subject_ref", "outcome", "receipt_id"],
            revocation: .expiresAssertion, auditsAllowedDecisions: true),
        CapabilityDefinition(
            capability: .identityAddress, title: "Verified address",
            summary: "The customer's verified postal address, released only with a per-request receipt.",
            requiresPurpose: true, requiredEvidence: .verifiedIdentity, sensitivity: .critical, minimumTier: .v,
            consent: ConsentRequirement(mode: .perRequestReceipt, purpose: "identity_disclosure"), customerUX: .verificationFlow,
            output: OutputSchema([OutputField("address", .object, .personalData, "Verified postal address.")] + assuranceFields),
            maxResultRetentionSeconds: 86_400, auditFields: ["capability", "purpose", "subject_ref", "outcome", "receipt_id"],
            revocation: .expiresAssertion, auditsAllowedDecisions: true),
        CapabilityDefinition(
            capability: .identityVerified, title: "Identity verified",
            summary: "Whether the customer has a verified identity at a stated assurance. A yes/no: no attribute is released.",
            requiresPurpose: true, requiredEvidence: .verifiedIdentity, sensitivity: .high, minimumTier: .v,
            consent: ConsentRequirement(mode: .perRequestReceipt, purpose: "identity_assurance"), customerUX: .verificationFlow,
            output: OutputSchema([OutputField("verified", .boolean, .assertion, "Whether a verified identity exists at the stated assurance.")] + assuranceFields),
            maxResultRetentionSeconds: 86_400, auditFields: ["capability", "purpose", "subject_ref", "outcome", "receipt_id"],
            revocation: .expiresAssertion, auditsAllowedDecisions: true),
    ]

    private static let byCapability: [Capability: CapabilityDefinition] =
        Dictionary(uniqueKeysWithValues: definitions.map { ($0.capability, $0) })

    public static func definition(for capability: Capability) -> CapabilityDefinition? { byCapability[capability] }

    /// Capabilities whose minimum tier is `tier`.
    public static func capabilities(minimumTier tier: BusinessRiskTier) -> [Capability] {
        definitions.filter { $0.minimumTier == tier }.map(\.capability)
    }

    /// Fields every capability result carries around the disclosed data. They are the same for all capabilities, hold no personal
    /// data, and are not part of any `OutputSchema`.
    public static let resultEnvelopeFields: [String] = ["request_id", "capability", "subject_ref", "parameters", "created_at"]

    /// Self-check of the catalog invariants (the unit tests assert this is empty):
    /// - one definition per known capability, no duplicates;
    /// - no output field outside `identity.name` / `identity.address` is personal data or carries a personal-data name;
    /// - the identity capabilities disclose only the personal-data fields allowed to them;
    /// - every capability that discloses personal data requires a per-request receipt, verified-identity evidence and tier V.
    public static func audit() -> [String] {
        var problems: [String] = []
        if Set(definitions.map(\.capability)).count != definitions.count { problems.append("duplicate capability") }
        for capability in Capability.known where definition(for: capability) == nil { problems.append("missing definition: \(capability)") }
        for definition in definitions {
            let names = definition.output.fieldNames
            if Set(names).count != names.count { problems.append("\(definition.capability): duplicate output field") }
            let allowed = allowedPersonalData[definition.capability] ?? []
            for field in definition.output.fields {
                let namesPersonalData = personalDataFieldNames.contains(field.name)
                if (field.fieldClass == .personalData || namesPersonalData) && !allowed.contains(field.name) {
                    problems.append("\(definition.capability): output field \(field.name) is personal data")
                }
            }
            if !definition.output.personalDataFields.isEmpty {
                if definition.consent.mode != .perRequestReceipt { problems.append("\(definition.capability): personal data without a per-request receipt") }
                if definition.requiredEvidence != .verifiedIdentity { problems.append("\(definition.capability): personal data without verified identity") }
                if definition.minimumTier != .v { problems.append("\(definition.capability): personal data below tier V") }
            }
            if definition.sensitivity >= .high && definition.minimumTier == .m { problems.append("\(definition.capability): high sensitivity at tier M") }
        }
        return problems
    }
}
