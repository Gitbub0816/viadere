import Crypto
import Foundation

/// The number a person types on the phone (ADR-0022 §2): drawn by the **business** (its SDK), shown on the business's own sign-in or payment screen,
/// never shown by the phone. 2 digits (`10...99`) for `auth.challenge` at low or medium risk; 3 digits (`100...999`) for `transaction.approve` and every
/// high or critical request, and whenever the api answers `409 match_digits_required`. A leading zero never occurs, so an entry is never ambiguous.
public struct ApprovalNumberMatch: Sendable, Hashable {
    public var digits: Int
    public var code: String

    public init(digits: Int, code: String) {
        self.digits = digits
        self.code = code
    }

    /// `code` is exactly `digits` ASCII digits, `digits` is 2 or 3, no leading zero.
    public var isValid: Bool { Self.isValid(code: code, digits: digits) }

    public static func isValid(code: String, digits: Int) -> Bool {
        (2...3).contains(digits) && code.utf8.count == digits && code.utf8.allSatisfy { (0x30...0x39).contains($0) } && code.utf8.first != 0x30
    }

    /// Digits a request needs (ADR-0022 §2.1, §4.1): 3 for payments and high or critical risk, otherwise 2 (the api may still require 3).
    public static func requiredDigits(capability: Capability, risk: AuthApprovalRisk) -> Int {
        capability == .transactionApprove || risk >= .high ? 3 : 2
    }

    /// A uniformly random code of `digits` digits without a leading zero, from a CSPRNG with **rejection sampling** (no modulo bias):
    /// a 16-bit sample is accepted only below the largest multiple of the range size, then reduced. `random` yields bytes (tests inject
    /// a fixed stream to check the sampler against the vectors in `docs/protocol/vectors/approval-result-v2.json`).
    public static func draw(digits: Int, random: (Int) -> Data = { SecureToken.randomBytes($0) }) -> ApprovalNumberMatch {
        precondition((2...3).contains(digits))
        let low: UInt32 = digits == 2 ? 10 : 100
        let span: UInt32 = digits == 2 ? 90 : 900
        let limit: UInt32 = (65_536 / span) * span
        while true {
            let bytes = random(2)
            guard bytes.count == 2 else { continue }
            let sample = UInt32(bytes[bytes.startIndex]) << 8 | UInt32(bytes[bytes.startIndex + 1])
            if sample < limit { return ApprovalNumberMatch(digits: digits, code: String(low + sample % span)) }
        }
    }

    /// The signed object inside an end-to-end `ApprovalRequest` v2.
    var object: JSONValue { .object(["code": .string(code), "digits": .integer(Int64(digits))]) }

    static func parse(_ value: JSONValue?) -> ApprovalNumberMatch? {
        guard case .object(let o)? = value, Set(o.keys) == ["code", "digits"], let code = o["code"]?.stringValue, let digits = o["digits"]?.int64Value,
              isValid(code: code, digits: Int(digits)) else { return nil }
        return ApprovalNumberMatch(digits: Int(digits), code: code)
    }
}

/// The risk a business declares for an `auth-approvals` request (ADR-0022 §2.1, §4). `high` and `critical` need 3 digits and end-to-end encryption.
public enum AuthApprovalRisk: String, Codable, Sendable, Hashable, CaseIterable, Comparable {
    case low, medium, high, critical

    var rank: Int {
        switch self {
        case .low: 0
        case .medium: 1
        case .high: 2
        case .critical: 3
        }
    }

    public static func < (lhs: AuthApprovalRisk, rhs: AuthApprovalRisk) -> Bool { lhs.rank < rhs.rank }
}

/// Why a v2 result says no (ADR-0022 §3).
public enum ApprovalDenyReason: String, Codable, Sendable, Hashable, CaseIterable {
    /// Three wrong numbers on the device: the device denied the request (or the whole group).
    case numberMismatch = "number_mismatch"
    /// "This wasn't me" (`decision: report`).
    case notMe = "not_me"
    /// The destination failed verification on the device (ADR-0031 §4); never counted toward the pause.
    case destinationUnverified = "destination_unverified"
}

/// What a verifier requires about number matching (ADR-0022 §3, S1-A3-08). **Every `ApprovalExpectation` initializer requires one, with no default**, so a
/// verifier can never silently accept a result without the typed number for a request that asked for it (downgrade).
///
/// * `.notRequested`: `match` must be absent; a v1 or v2 result is accepted.
/// * `.required(code)`: the result must be v2; an approve must carry `match` equal (constant time) to the code **the verifier recorded**.
/// * `relayRequired(digits:)` (the relay of an end-to-end request, which never sees the code): v2, and an approve carries a well-formed `match` of that length.
///   Defense in depth only; the business checks the code.
public struct NumberMatchExpectation: Sendable, Hashable {
    enum Kind: Sendable, Hashable {
        case notRequested
        case required(String)
        case relayRequired(Int)
    }

    let kind: Kind

    public static let notRequested = NumberMatchExpectation(kind: .notRequested)
    public static func required(code: String) -> NumberMatchExpectation { NumberMatchExpectation(kind: .required(code)) }
    public static func relayRequired(digits: Int) -> NumberMatchExpectation { NumberMatchExpectation(kind: .relayRequired(digits)) }

    public var isRequired: Bool {
        if case .notRequested = kind { return false }
        return true
    }
}
