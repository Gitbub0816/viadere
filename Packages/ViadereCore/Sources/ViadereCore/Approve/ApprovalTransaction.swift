import Crypto
import Foundation

/// The assurance an approval key (and so an `ApprovalResult`) carries.
public enum ApprovalAMR: String, Sendable, Codable, CaseIterable, Hashable {
    /// Signed with the `.biometryCurrentSet` key: Face ID / Touch ID of the biometrics enrolled when the key was created.
    case biometric
    /// The device passcode was used (an explicit passcode-only unlock).
    case passcode
    /// Signed with the `.userPresence` key: biometrics **or** passcode; the OS does not say which.
    case presence

    var rank: Int { self == .biometric ? 2 : 1 }

    /// Whether this claim meets the business's minimum.
    public func satisfies(_ minimum: ApprovalAMR) -> Bool { rank >= minimum.rank }

    /// The decision assurance this claim corresponds to (for assurance-policy reuse).
    public var decisionAssurance: DecisionAssurance { self == .biometric ? .biometric : .devicePasscode }

    /// The access-control class a key enrolled for `assurance` is created with: `.biometryCurrentSet` for high and critical, user
    /// presence otherwise. Never weaker than the capability's sensitivity requires.
    public static func required(for sensitivity: Sensitivity) -> ApprovalAMR { sensitivity >= .high ? .biometric : .presence }
}

/// Why an approval request's displayed parameters were refused.
public enum ApprovalTransactionError: Error, Sendable, Equatable {
    case invalid(field: String)
}

/// The exact, human-readable parameters of an `auth.challenge` approval (section 2.54). What is shown is what is signed.
public struct AuthenticationDetails: Sendable, Hashable, Codable {
    /// What the person is approving, for example `Sign in to Example Bank`. At most 120 characters.
    public var actionDisplay: String
    /// The business's own reference (a login attempt id). `[\x21-\x7E]`, at most 64 characters.
    public var reference: String?

    public init(actionDisplay: String, reference: String? = nil) {
        self.actionDisplay = actionDisplay
        self.reference = reference
    }

    enum CodingKeys: String, CodingKey { case actionDisplay = "action_display", reference }
}

/// The exact displayed parameters of a `transaction.approve` request (spec 14.2).
public struct TransactionDetails: Sendable, Hashable, Codable {
    /// ISO 4217, three uppercase letters.
    public var currency: String
    /// Positive amount in minor units (1...999,999,999,999).
    public var amountMinor: Int64
    /// The payee as shown, at most 80 characters, NFC.
    public var payeeDisplay: String
    /// The business's reference, `[\x21-\x7E]`, at most 64 characters.
    public var transactionReference: String

    public init(currency: String, amountMinor: Int64, payeeDisplay: String, transactionReference: String) {
        self.currency = currency
        self.amountMinor = amountMinor
        self.payeeDisplay = payeeDisplay
        self.transactionReference = transactionReference
    }

    enum CodingKeys: String, CodingKey {
        case currency
        case amountMinor = "amount_minor"
        case payeeDisplay = "payee_display"
        case transactionReference = "transaction_reference"
    }
}

/// What an approval is for: one of the two approval capabilities with its displayed parameters.
///
/// **Canonical form and digest (normative).** `canonicalJSON` is the canonical JSON (section 2.2) of
/// `{"amount_minor", "capability", "currency", "payee_display", "transaction_reference", "v": 1}` for `transaction.approve` and
/// `{"action_display", "capability", "reference"?, "v": 1}` for `auth.challenge`.
/// `digest = lowercase hex SHA-256("VIADERE-TXN-V1\n" ‖ canonicalJSON)`. The business computes it from **its own** record of the
/// transaction; the device computes it from what it displayed; they are equal only when the same parameters were shown.
public enum ApprovalSubject: Sendable, Hashable {
    case transaction(TransactionDetails)
    case authentication(AuthenticationDetails)

    public static let domain = "VIADERE-TXN-V1\n"

    public var capability: Capability {
        switch self {
        case .transaction: .transactionApprove
        case .authentication: .authChallenge
        }
    }

    // MARK: Validation

    private static func isPrintableASCII(_ text: String, max: Int) -> Bool {
        !text.isEmpty && text.utf8.count <= max && text.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7E }
    }

    private static func isValidDisplay(_ text: String, max: Int) -> Bool {
        // NFC so business and device hash the same bytes; the sanitizer rejects invisible, reordering and control characters.
        // Byte comparison: Swift's `==` treats canonically equivalent strings as equal, which would let a decomposed string through.
        !text.isEmpty && Array(text.utf8) == Array(text.precomposedStringWithCanonicalMapping.utf8) && text == text.trimmingCharacters(in: .whitespaces)
            && DisplayTextSanitizer.violation(of: text, maxCharacters: max) == nil
    }

    /// Throws `ApprovalTransactionError.invalid(field:)` for the first field that breaks the rules above.
    public func validate() throws {
        switch self {
        case .transaction(let value):
            guard value.currency.utf8.count == 3, value.currency.utf8.allSatisfy({ $0 >= 0x41 && $0 <= 0x5A }) else { throw ApprovalTransactionError.invalid(field: "currency") }
            guard (1...999_999_999_999).contains(value.amountMinor) else { throw ApprovalTransactionError.invalid(field: "amount_minor") }
            guard Self.isValidDisplay(value.payeeDisplay, max: 80) else { throw ApprovalTransactionError.invalid(field: "payee_display") }
            guard Self.isPrintableASCII(value.transactionReference, max: 64) else { throw ApprovalTransactionError.invalid(field: "transaction_reference") }
        case .authentication(let value):
            guard Self.isValidDisplay(value.actionDisplay, max: 120) else { throw ApprovalTransactionError.invalid(field: "action_display") }
            if let reference = value.reference, !Self.isPrintableASCII(reference, max: 64) { throw ApprovalTransactionError.invalid(field: "reference") }
        }
    }

    // MARK: Canonical form

    var object: [String: JSONValue] {
        switch self {
        case .transaction(let value):
            return ["v": .integer(1), "capability": .string(Capability.transactionApprove.rawValue), "currency": .string(value.currency),
                    "amount_minor": .integer(value.amountMinor), "payee_display": .string(value.payeeDisplay),
                    "transaction_reference": .string(value.transactionReference)]
        case .authentication(let value):
            var object: [String: JSONValue] = ["v": .integer(1), "capability": .string(Capability.authChallenge.rawValue), "action_display": .string(value.actionDisplay)]
            if let reference = value.reference { object["reference"] = .string(reference) }
            return object
        }
    }

    public func canonicalJSON() throws -> Data {
        try validate()
        return try CanonicalJSON.serialize(.object(object))
    }

    /// Lowercase hex SHA-256 of `"VIADERE-TXN-V1\n" ‖ canonicalJSON`.
    public func digest() throws -> String {
        SecureToken.sha256Hex(Data(Self.domain.utf8) + (try canonicalJSON()))
    }

    /// Parses the canonical object (used for the transaction inside a signed request).
    static func parse(_ value: JSONValue) throws -> ApprovalSubject {
        guard case .object(let o) = value, o["v"]?.int64Value == 1, let capability = o["capability"]?.stringValue else { throw ApprovalTransactionError.invalid(field: "transaction") }
        let subject: ApprovalSubject
        switch Capability(rawValue: capability) {
        case .transactionApprove:
            guard Set(o.keys) == ["v", "capability", "currency", "amount_minor", "payee_display", "transaction_reference"],
                  let currency = o["currency"]?.stringValue, let amount = o["amount_minor"]?.int64Value, let payee = o["payee_display"]?.stringValue,
                  let reference = o["transaction_reference"]?.stringValue else { throw ApprovalTransactionError.invalid(field: "transaction") }
            subject = .transaction(TransactionDetails(currency: currency, amountMinor: amount, payeeDisplay: payee, transactionReference: reference))
        case .authChallenge:
            guard Set(o.keys).isSubset(of: ["v", "capability", "action_display", "reference"]), let action = o["action_display"]?.stringValue else { throw ApprovalTransactionError.invalid(field: "transaction") }
            if o["reference"] != nil, o["reference"]?.stringValue == nil { throw ApprovalTransactionError.invalid(field: "reference") }
            subject = .authentication(AuthenticationDetails(actionDisplay: action, reference: o["reference"]?.stringValue))
        default:
            throw ApprovalTransactionError.invalid(field: "capability")
        }
        try subject.validate()
        return subject
    }

    /// A one-line summary for logs and prompts that never includes the reference.
    public var promptSummary: String {
        switch self {
        case .transaction(let value): "Approve \(MoneyFormatting.display(minor: value.amountMinor, currency: value.currency)) to \(value.payeeDisplay)"
        case .authentication(let value): value.actionDisplay
        }
    }
}

/// Formats a minor-unit amount for display (`2500.00 USD`). Currencies are shown with two decimals except the zero-decimal ones.
public enum MoneyFormatting {
    static let zeroDecimal: Set<String> = ["JPY", "KRW", "VND", "CLP", "ISK", "UGX", "XAF", "XOF", "XPF", "PYG", "RWF", "VUV"]
    static let threeDecimal: Set<String> = ["BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"]

    public static func display(minor: Int64, currency: String) -> String {
        let digits = zeroDecimal.contains(currency) ? 0 : (threeDecimal.contains(currency) ? 3 : 2)
        guard digits > 0 else { return "\(minor) \(currency)" }
        var scale: Int64 = 1
        for _ in 0..<digits { scale *= 10 }
        let whole = minor / scale
        let fraction = String(minor % scale)
        return "\(whole).\(String(repeating: "0", count: digits - fraction.count) + fraction) \(currency)"
    }
}
