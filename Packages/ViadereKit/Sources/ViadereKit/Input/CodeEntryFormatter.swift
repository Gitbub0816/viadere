import Foundation
import ViadereCore

/// Live formatting for business codes: type `af2345`, see `AF-2345`. Normalizes exactly like `BusinessCode`:
/// uppercase, `I → 1`, `O → 0`, `L` stays `L`; separators are ignored.
public enum CodeEntryFormatter {
    public enum State: Equatable, Sendable {
        case empty
        /// Valid so far; `remaining` characters to go.
        case incomplete(remaining: Int)
        case valid
        /// A character that can never be part of a code.
        case invalid(Character)
    }

    public struct Result: Equatable, Sendable {
        /// What to show in the field, e.g. `AF-2345`.
        public var display: String
        /// Canonical characters typed so far (`AF2345`), at most 6.
        public var canonical: String
        public var state: State

        public var isValid: Bool { state == .valid }
        public var code: BusinessCode? { isValid ? BusinessCode(parsing: canonical) : nil }
    }

    public static func format(_ raw: String) -> Result {
        var canonical = ""
        var offender: Character?
        for character in raw {
            if BusinessCode.separators.contains(character) || character.isWhitespace { continue }
            guard character.isASCII, let ascii = character.asciiValue else { offender = offender ?? character; continue }
            let upper = (ascii >= 97 && ascii <= 122) ? ascii - 32 : ascii
            switch upper {
            case UInt8(ascii: "I"): canonical.append("1")
            case UInt8(ascii: "O"): canonical.append("0")
            case UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "A")...UInt8(ascii: "Z"):
                canonical.append(Character(Unicode.Scalar(upper)))
            default:
                offender = offender ?? character
            }
        }
        if canonical.count > BusinessCode.length { canonical = String(canonical.prefix(BusinessCode.length)) }
        let display = canonical.count > 2 ? String(canonical.prefix(2)) + "-" + String(canonical.dropFirst(2)) : canonical
        let state: State
        if let offender { state = .invalid(offender) }
        else if canonical.isEmpty { state = .empty }
        else if canonical.count < BusinessCode.length { state = .incomplete(remaining: BusinessCode.length - canonical.count) }
        else { state = .valid }
        return Result(display: display, canonical: canonical, state: state)
    }
}
