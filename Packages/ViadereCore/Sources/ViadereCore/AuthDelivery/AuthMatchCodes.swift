import Crypto
import Foundation

/// Number-match tags for `auth-approvals` (ADR-0020 section 2a, ADR-0022 section 5.2 item 6; revision 3.1).
///
/// The business's SDK computes `match_tag = base64url(HMAC-SHA256(K_match, "viadere-match-tag-v1\n" || subject_ref || "\n" || code))` and, for 3-digit codes, the same
/// HMAC over the first two digits as `match_prefix_tag`. Viadere never sees a code: it only keeps the tags of one person's open requests **collision-free and
/// prefix-free**, so the number the person types always selects exactly one request. Tags are class T and are deleted at the terminal state.
public enum AuthMatchTags {
    public static let tagDomain = "viadere-match-tag-v1\n"

    /// The tag of `code` for `subjectRef`.
    public static func tag(key: SymmetricKey, subjectRef: SubjectRef, code: String) -> String {
        let message = Data((tagDomain + subjectRef.rawValue + "\n" + code).utf8)
        return Base64URL.encode(Data(HMAC<SHA256>.authenticationCode(for: message, using: key)))
    }

    /// `(tag, prefixTag)` for a 2- or 3-digit code (`10...99` or `100...999`); `nil` for anything else.
    public static func tags(key: SymmetricKey, subjectRef: SubjectRef, code: String) -> (tag: String, prefixTag: String?)? {
        guard code.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), code.first != "0", (2...3).contains(code.count) else { return nil }
        return (tag(key: key, subjectRef: subjectRef, code: code), code.count == 3 ? tag(key: key, subjectRef: subjectRef, code: String(code.prefix(2))) : nil)
    }

    /// 43 base64url characters of a 32-byte value.
    public static func isValidTag(_ value: String) -> Bool { Base64URL.isValid(value, minLength: 43, maxLength: 43) && Base64URL.decode(value)?.count == 32 }
}

/// What the api answers to a new request's tags (all refusals are `409` with nothing created).
public enum MatchGroupDecision: Equatable, Sendable {
    case accepted
    /// `match_code_in_use`: the tag equals an open tag or prefix tag, or the prefix tag equals an open tag. The SDK redraws.
    case inUse
    /// `match_digits_required` (`{digits: 3}`): the group has 30 or more open requests and the new code has 2 digits. The SDK redraws with 3 digits.
    case digitsRequired
    /// `match_code_space_exhausted`: no free 3-digit code can exist. Critical operator alert.
    case exhausted
}

/// The allocation rule, pure and shared (the server's `AuthMatchGroups` stores the tags, this decides). One (tenant, subject) group; `open` are the tags of its open
/// requests. **This is the one type to change when the rule changes** (revision 3.1 is the rule below).
public enum MatchGroupPolicy {
    /// From this many open requests in a group a new request needs 3 digits.
    public static let threeDigitThreshold = 30
    /// Above this many open requests the api writes `auth_delivery.group_pressure` (at most once per group per hour).
    public static let pressureThreshold = 10
    /// 3-digit codes `100...999`.
    public static let threeDigitSpace = 900
    /// Each open 2-digit code removes the ten 3-digit codes that start with it.
    public static let threeDigitsPerTwoDigit = 10

    public struct Open: Sendable, Hashable {
        public var tag: String
        public var prefixTag: String?
        public init(tag: String, prefixTag: String?) {
            self.tag = tag
            self.prefixTag = prefixTag
        }
    }

    public static func evaluate(new: (tag: String, prefixTag: String?), open: [Open]) -> MatchGroupDecision {
        let isThreeDigit = new.prefixTag != nil
        if !isThreeDigit && open.count >= threeDigitThreshold { return .digitsRequired }
        // Exact free-space count: open codes are prefix-free, so a 2-digit code occupies ten 3-digit slots and a 3-digit one slot. No free 3-digit code: exhausted.
        let twoDigit = open.filter { $0.prefixTag == nil }.count
        let occupied = twoDigit * threeDigitsPerTwoDigit + (open.count - twoDigit)
        if occupied >= threeDigitSpace && (isThreeDigit || open.count >= threeDigitThreshold) { return .exhausted }
        let openTags = Set(open.map(\.tag))
        let openPrefixes = Set(open.compactMap(\.prefixTag))
        if openTags.contains(new.tag) || openPrefixes.contains(new.tag) { return .inUse }
        if let prefix = new.prefixTag, openTags.contains(prefix) { return .inUse }
        return .accepted
    }
}
