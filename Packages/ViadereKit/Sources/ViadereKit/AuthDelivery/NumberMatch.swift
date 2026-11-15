import Foundation

/// What the phone needs to check a typed number (ADR-0022 §2, §5.2 item 2). The phone never displays the codes: they exist only so the
/// typed entry can be compared. One code per open request of the business in the group; the typed number selects the request.
public struct NumberMatchRequirement: Sendable, Equatable {
    /// The **field** length: the longest code in the group. Codes of one group may have different lengths (2 for sign-in at low or medium risk, 3 for
    /// payments, high and critical requests, and for every new request once the api escalates at 30 open requests; ADR-0022 §5.2 item 6), so each
    /// candidate is checked against its own length, never against this one (Stage 5 review S5-01).
    public var digits: Int
    /// One entry per open request in the group (`requestId`, `code`). Never rendered, never logged.
    public var candidates: [Candidate]

    public struct Candidate: Sendable, Equatable {
        public var requestId: String
        public var code: String
        public init(requestId: String, code: String) {
            self.requestId = requestId
            self.code = code
        }
    }

    public init(digits: Int, candidates: [Candidate]) {
        self.digits = digits
        self.candidates = candidates
    }

    /// A well-formed requirement: a field of 2 or 3 digits, at least one candidate, and every code 2 or 3 ASCII digits (never longer than the field)
    /// without a leading zero. A group may mix 2- and 3-digit codes.
    public var isWellFormed: Bool {
        (2...3).contains(digits) && !candidates.isEmpty && candidates.allSatisfy {
            (2...digits).contains($0.code.utf8.count) && $0.code.utf8.allSatisfy { (0x30...0x39).contains($0) } && $0.code.utf8.first != 0x30
        }
    }

    /// The distinct code lengths in the group.
    public var codeLengths: Set<Int> { Set(candidates.map { $0.code.utf8.count }) }

    /// More than one code length in the group: the helper line then names no digit count.
    public var hasMixedLengths: Bool { codeLengths.count > 1 }

    /// Digits required for this request kind (ADR-0022 §2.1): 3 for payments, otherwise whatever the business drew (2 unless escalated).
    public static func digits(forPayment payment: Bool, requested: Int?) -> Int {
        if payment { return 3 }
        return requested == 3 ? 3 : 2
    }
}

public enum NumberMatchResult: Sendable, Equatable {
    /// Exactly one open request has this code: that request is the one to approve.
    case match(requestId: String)
    case noMatch
    /// More than one open request has this code (inconsistent tags at the business): nothing is signed (S-MFA-15).
    case ambiguous
}

/// The number field's rules and the comparison. Pure; the App's field only forwards edits here.
public enum NumberMatcher {
    /// Constant-time comparison of the typed entry against **every** candidate, with no early exit, so neither timing nor the number of
    /// wrong entries before a hit reveals which request or digit matched.
    public static func evaluate(entry: String, requirement: NumberMatchRequirement) -> NumberMatchResult {
        let typed = Array(entry.utf8)
        var hits: [String] = []
        for candidate in requirement.candidates {
            if constantTimeEqual(typed, Array(candidate.code.utf8)) { hits.append(candidate.requestId) }
        }
        switch hits.count {
        case 0: return .noMatch
        case 1: return .match(requestId: hits[0])
        default: return .ambiguous
        }
    }

    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        // The lengths are compared as a whole: truncating `a.count ^ b.count` to 8 bits would call lengths that differ by 256 equal.
        var diff: UInt8 = a.count == b.count ? 0 : 1
        let count = max(a.count, b.count)
        for i in 0..<count {
            let x: UInt8 = i < a.count ? a[i] : 0
            let y: UInt8 = i < b.count ? b[i] : 0
            diff |= x ^ y
        }
        return diff == 0
    }

    /// The entry after an edit. Only a person typing one digit at a time (or deleting) can change the field:
    /// - a paste, AutoFill or "replace the selection" arrives as more than one new character or a rewritten value, and is **refused**
    ///   (the previous value stays; ADR-0022 §2.3: the field refuses pasted text and is never prefilled);
    /// - anything that is not an ASCII digit 0-9 is dropped (no Arabic-Indic or full-width digits: the comparison is on bytes);
    /// - a leading zero is refused (codes never start with 0);
    /// - the length is capped at `digits`.
    public static func applyEdit(previous: String, proposed: String, digits: Int) -> String {
        if proposed == previous { return previous }
        let isDeletion = previous.hasPrefix(proposed)
        let isSingleAppend = proposed.hasPrefix(previous) && proposed.count == previous.count + 1
        guard isDeletion || isSingleAppend else { return previous }
        let kept = proposed.unicodeScalars.filter { (0x30...0x39).contains($0.value) }
        guard kept.count == proposed.unicodeScalars.count else { return previous }
        var text = String(String.UnicodeScalarView(kept))
        if text.hasPrefix("0") { return previous }
        if text.count > digits { text = String(text.prefix(digits)) }
        return text
    }

    public static func isComplete(_ entry: String, digits: Int) -> Bool {
        entry.utf8.count == digits && entry.utf8.allSatisfy { (0x30...0x39).contains($0) }
    }

    /// Whether the entry has reached the length of some code of the group (S5-01). It says nothing about whether the digits are right: Approve
    /// enables for **any** entry of a candidate's length, so the button never reveals a hit and a miss at any length is a counted wrong entry.
    public static func isComplete(_ entry: String, requirement: NumberMatchRequirement) -> Bool {
        guard entry.utf8.allSatisfy({ (0x30...0x39).contains($0) }) else { return false }
        return entry.utf8.count == requirement.digits || requirement.codeLengths.contains(entry.utf8.count)
    }
}

/// The attributes the App must put on the number field (A6/A7 finding 15, ADR-0022 §2.3). The App's `UITextField` reads these; a test
/// pins them so a refactor cannot turn AutoFill back on.
public struct NumberFieldTraits: Sendable, Equatable {
    public var numericKeypad = true
    /// `UITextContentType` stays unset: no `oneTimeCode`, no password or contact suggestions.
    public var textContentTypeIsUnset = true
    public var allowsPaste = false
    public var autocorrection = false
    public var prefilled = false
    public var announcesWrongEntryToVoiceOver = true
    public static let required = NumberFieldTraits()
}
