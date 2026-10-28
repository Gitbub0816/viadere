import Foundation

/// Structural validation of an `Interaction`. The server runs this on every business
/// submission; clients run it before rendering.
public enum InteractionValidation {
    /// Limits enforced by `validate`.
    public enum Limits {
        public static let shortText = 80
        public static let mediumText = 160
        public static let longText = 1000
        public static let identifier = 64
        public static let idempotencyKey = 128
        public static let correlationId = 128
        public static let maxRequestedActions = 4
        public static let minChoiceOptions = 2
        public static let maxChoiceOptions = 10
        public static let maxRiskIndicators = 8
        /// Longest permitted lifetime (`expiresAt - createdAt`).
        public static let maxLifetime: TimeInterval = 30 * 24 * 3600
        /// Longest lifetime for authenticate/authorize.
        public static let maxSecurityLifetime: TimeInterval = 15 * 60
    }

    /// A validation failure; `field` is a dotted path.
    public struct Issue: Error, Sendable, Hashable, CustomStringConvertible {
        public enum Code: String, Sendable, Codable {
            case unsupportedVersion, unknownKind, kindPayloadMismatch, expired, invalidLifetime
            case tooLong, empty, invalidIdentifier, invalidCount, duplicate, missingChannel
            case channelNotPermitted, purposeMismatch, invalidValue
            /// Bidirectional, zero-width, control or otherwise invisible characters (see `DisplayTextSanitizer`).
            case disallowedCharacters
            /// Display text that starts with (or, for names, mentions) "Viadere".
            case impersonation
        }

        public let code: Code
        public let field: String

        public init(_ code: Code, _ field: String) {
            self.code = code
            self.field = field
        }

        public var description: String { "\(code.rawValue): \(field)" }
    }

    /// Returns every issue found (empty array = valid). `now` is used for the expiry check.
    public static func issues(in interaction: Interaction, now: Date) -> [Issue] {
        var issues: [Issue] = []
        /// Business-supplied display text. `identity` fields (names of services, merchants, titles) may not mention
        /// Viadere at all; every field may not start with it. Plain line feeds are only tolerated in long free text.
        func text(_ value: String?, _ field: String, max: Int, required: Bool = false, identity: Bool = false) {
            guard let value else {
                if required { issues.append(Issue(.empty, field)) }
                return
            }
            if value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                if required { issues.append(Issue(.empty, field)) }
                // Whitespace-only is "empty", but invisible characters are still refused below.
                if DisplayTextSanitizer.containsDisallowedScalars(value, allowNewlines: true) {
                    issues.append(Issue(.disallowedCharacters, field))
                }
                return
            }
            switch DisplayTextSanitizer.violation(of: value, maxCharacters: max, allowNewlines: max >= Limits.longText, identity: identity) {
            case .disallowedCharacters?: issues.append(Issue(.disallowedCharacters, field))
            case .tooLong?: issues.append(Issue(.tooLong, field))
            case .impersonation?: issues.append(Issue(.impersonation, field))
            case nil: break
            }
        }
        func identifier(_ value: String, _ field: String, max: Int = Limits.identifier) {
            let ok = !value.isEmpty && value.count <= max && value.unicodeScalars.allSatisfy {
                $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "_.-:".unicodeScalars.contains($0))
            }
            if !ok { issues.append(Issue(.invalidIdentifier, field)) }
        }
        func risks(_ list: [RiskIndicator], _ field: String) {
            if list.count > Limits.maxRiskIndicators { issues.append(Issue(.invalidCount, field)) }
            for (i, r) in list.enumerated() {
                identifier(r.code, "\(field)[\(i)].code", max: 40)
                text(r.label, "\(field)[\(i)].label", max: Limits.shortText, required: true, identity: true)
            }
        }

        if !(1...Interaction.currentSchemaVersion).contains(interaction.schemaVersion) {
            issues.append(Issue(.unsupportedVersion, "schemaVersion"))
        }
        if case .unknown = interaction.kind { issues.append(Issue(.unknownKind, "kind")) }
        if let payloadKind = interaction.payload.kind, payloadKind != interaction.kind {
            issues.append(Issue(.kindPayloadMismatch, "payload"))
        } else if interaction.payload.kind == nil, !(interaction.kind.isUnknown) {
            issues.append(Issue(.kindPayloadMismatch, "payload"))
        }
        if interaction.isExpired(at: now) { issues.append(Issue(.expired, "expiresAt")) }
        let lifetime = interaction.expiresAt.timeIntervalSince(interaction.createdAt)
        let maxLifetime = interaction.kind.isSecuritySensitive ? Limits.maxSecurityLifetime : Limits.maxLifetime
        if lifetime <= 0 || lifetime > maxLifetime { issues.append(Issue(.invalidLifetime, "expiresAt")) }
        identifier(interaction.idempotencyKey, "idempotencyKey", max: Limits.idempotencyKey)
        if let correlationId = interaction.correlationId {
            identifier(correlationId, "correlationId", max: Limits.correlationId)
        }
        text(interaction.scope.accountReference, "scope.accountReference", max: Limits.identifier)
        if interaction.allowedChannels.isEmpty { issues.append(Issue(.missingChannel, "allowedChannels")) }
        if Set(interaction.allowedChannels).count != interaction.allowedChannels.count {
            issues.append(Issue(.duplicate, "allowedChannels"))
        }
        if interaction.requestedActions.count > Limits.maxRequestedActions {
            issues.append(Issue(.invalidCount, "requestedActions"))
        }
        var actionIds = Set<String>()
        for (i, action) in interaction.requestedActions.enumerated() {
            identifier(action.id, "requestedActions[\(i)].id")
            text(action.label, "requestedActions[\(i)].label", max: 32, required: true, identity: true)
            if !actionIds.insert(action.id).inserted { issues.append(Issue(.duplicate, "requestedActions[\(i)].id")) }
        }
        // Security kinds must be in the security / account-service / transactional purposes.
        if interaction.kind.isSecuritySensitive, interaction.purpose == .marketing || interaction.purpose == .rewards {
            issues.append(Issue(.purposeMismatch, "purpose"))
        }
        // The security purpose is non-revocable (consent never applies) and exempt from the emergency restriction: approvals only.
        if interaction.purpose == .security, !interaction.kind.mayCarrySecurityPurpose {
            issues.append(Issue(.purposeMismatch, "purpose"))
        }

        switch interaction.payload {
        case .authenticate(let p):
            text(p.service, "payload.service", max: Limits.shortText, required: true, identity: true)
            text(p.device, "payload.device", max: Limits.shortText, required: true)
            text(p.approximateLocation, "payload.approximateLocation", max: Limits.shortText)
            text(p.ipRegion, "payload.ipRegion", max: Limits.shortText)
            risks(p.riskIndicators, "payload.riskIndicators")
        case .authorize(let p):
            text(p.actionDescription, "payload.actionDescription", max: 120, required: true, identity: true)
            text(p.merchant, "payload.merchant", max: Limits.shortText, identity: true)
            text(p.location, "payload.location", max: Limits.shortText)
            text(p.effectOfApproval, "payload.effectOfApproval", max: Limits.mediumText)
            risks(p.riskIndicators, "payload.riskIndicators")
        case .confirm(let p):
            text(p.title, "payload.title", max: Limits.shortText, required: true, identity: true)
            text(p.details, "payload.details", max: Limits.longText)
            text(p.reference, "payload.reference", max: Limits.identifier)
        case .choose(let p):
            text(p.prompt, "payload.prompt", max: Limits.mediumText, required: true)
            if !(Limits.minChoiceOptions...Limits.maxChoiceOptions).contains(p.options.count) {
                issues.append(Issue(.invalidCount, "payload.options"))
            }
            var ids = Set<String>()
            for (i, option) in p.options.enumerated() {
                identifier(option.id, "payload.options[\(i)].id")
                text(option.label, "payload.options[\(i)].label", max: 40, required: true, identity: true)
                if !ids.insert(option.id).inserted { issues.append(Issue(.duplicate, "payload.options[\(i)].id")) }
            }
        case .acknowledge(let p):
            text(p.title, "payload.title", max: Limits.shortText, required: true, identity: true)
            text(p.body, "payload.body", max: Limits.longText, required: true)
            if let url = p.documentURL, url.scheme?.lowercased() != "https" {
                issues.append(Issue(.invalidValue, "payload.documentURL"))
            }
            text(p.documentVersion, "payload.documentVersion", max: 40)
            if let digest = p.documentDigest, !(digest.count == 64 && digest.allSatisfy { $0.isASCII && $0.isHexDigit && !$0.isUppercase }) {
                issues.append(Issue(.invalidValue, "payload.documentDigest"))
            }
        case .reply(let p):
            text(p.prompt, "payload.prompt", max: Limits.mediumText, required: true)
            if !(1...Limits.longText).contains(p.maxLength) { issues.append(Issue(.invalidValue, "payload.maxLength")) }
            if p.suggestedReplies.count > 4 { issues.append(Issue(.invalidCount, "payload.suggestedReplies")) }
            for (i, s) in p.suggestedReplies.enumerated() { text(s, "payload.suggestedReplies[\(i)]", max: 25, required: true) }
        case .status(let p):
            text(p.title, "payload.title", max: Limits.shortText, required: true, identity: true)
            text(p.body, "payload.body", max: Limits.longText)
        case .reward(let p):
            text(p.title, "payload.title", max: Limits.shortText, required: true, identity: true)
            text(p.details, "payload.details", max: Limits.longText)
        case .ticket(let p):
            text(p.title, "payload.title", max: Limits.shortText, required: true, identity: true)
            identifier(p.ticketType, "payload.ticketType", max: 40)
            text(p.holderName, "payload.holderName", max: Limits.shortText, identity: true)
            text(p.venue, "payload.venue", max: 80, identity: true)
            text(p.seat, "payload.seat", max: 80)
        case .message(let p):
            text(p.text, "payload.text", max: Limits.longText, required: true)
        case .unknown:
            break
        }
        return issues
    }

    /// Throws the first issue, if any.
    public static func validate(_ interaction: Interaction, now: Date) throws {
        if let first = issues(in: interaction, now: now).first { throw first }
    }
}

extension InteractionKind {
    var isUnknown: Bool {
        if case .unknown = self { return true }
        return false
    }
}
